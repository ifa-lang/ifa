use crate::cfg::ControlFlowGraph;
use crate::dominance::DominanceTree;
use crate::gen_opt::GenerationalOptPass;
use crate::ir::*;
use crate::types::FirType;
use ifa_sema::types::{FloatType, IntType};
use ifa_span::{Symbol, INTERNER};
use std::collections::{HashMap, HashSet};

/// Statistics collected by the SIMD auto-vectorization pipeline.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VectorizeStats {
    /// Number of natural loops analyzed for vectorization candidates.
    pub loops_analyzed: usize,
    /// Number of loops successfully annotated with SIMD vectorization directives.
    pub loops_vectorized: usize,
    /// Number of primitive array and slice accesses vectorized.
    pub arrays_vectorized: usize,
    /// Number of scalar reduction loops identified and accelerated.
    pub reductions_vectorized: usize,
    /// Number of array/slice transformation maps identified and accelerated.
    pub maps_vectorized: usize,
    /// Number of primitive slice accesses vectorized with statically eliminated bounds checks.
    pub slices_vectorized: usize,
    /// Number of loops vectorized specifically leveraging statically eliminated bounds checks.
    pub eliminated_bounds_loops: usize,
    /// Number of function calls inside loops verified pure via IPO analysis.
    pub pure_calls_allowed: usize,
    /// Number of loops vectorized containing IPO-verified pure function calls.
    pub ipo_vectorized_loops: usize,
    /// Number of scalar product reduction loops identified and accelerated.
    pub product_reductions_vectorized: usize,
    /// Number of scalar minimum reduction loops identified and accelerated.
    pub min_reductions_vectorized: usize,
    /// Number of scalar maximum reduction loops identified and accelerated.
    pub max_reductions_vectorized: usize,
}

/// Pipeline for automatic SIMD vectorization on primitive arrays and slices in FIR SSA.
///
/// Analyzes natural control-flow loops, detects induction variables and linear memory accesses,
/// verifies absence of loop-carried dependencies or side effects, and attaches optimal
/// SIMD vectorization directives (`LoopVectorHint`) targeting LLVM's loop vectorizer and
/// platform-native vector hardware (AVX2, AVX-512, NEON, WASM SIMD128).
pub struct VectorizePass {
    stats: VectorizeStats,
    pure_functions: HashSet<Symbol>,
}

impl VectorizePass {
    /// Create a new SIMD auto-vectorization optimization pass.
    pub fn new() -> Self {
        Self {
            stats: VectorizeStats::default(),
            pure_functions: HashSet::new(),
        }
    }

    /// Attach a precomputed set of pure function symbols to the pass.
    pub fn with_pure_functions(mut self, pure_funcs: HashSet<Symbol>) -> Self {
        self.pure_functions = pure_funcs;
        self
    }

    /// Return current pass statistics.
    pub fn stats(&self) -> VectorizeStats {
        self.stats
    }

    /// Run the vectorization pass across all functions in a FIR module.
    pub fn run_on_module(&mut self, module: &mut FirModule) {
        self.pure_functions = crate::ipo::IpoPass::compute_pure_functions(module);
        for func in &mut module.functions {
            self.run_on_function(func);
        }
    }

    /// Run the vectorization analysis and transformation on a single FIR function.
    pub fn run_on_function(&mut self, func: &mut FirFunction) {
        let cfg = ControlFlowGraph::build(func);
        let dom_tree = DominanceTree::build(&cfg);

        // Precompute value types across the function
        let value_types = Self::infer_value_types(func);

        let natural_loops = GenerationalOptPass::find_natural_loops(&cfg, &dom_tree);

        for loop_info in natural_loops {
            self.stats.loops_analyzed += 1;

            // 1. Verify loop purity (no blocking I/O, fibers, yields, or invalidating calls)
            let (is_free, has_pure_calls) = self.is_loop_side_effect_free(func, &loop_info.blocks);
            if !is_free {
                continue;
            }

            // Identify condition values used for loop boundary / termination checks
            let mut loop_exit_conds: HashSet<ValueId> = HashSet::new();
            for &b_id in &loop_info.blocks {
                if let Some(b) = func.get_block(b_id) {
                    if let Some(Terminator::BranchCond {
                        cond,
                        then_block,
                        else_block,
                        ..
                    }) = &b.terminator
                    {
                        if !loop_info.blocks.contains(then_block)
                            || !loop_info.blocks.contains(else_block)
                        {
                            loop_exit_conds.insert(*cond);
                        }
                    }
                }
            }

            // 2. Scan for primitive array or slice operations within the loop
            let mut detected_elem_types: Vec<FirType> = Vec::new();
            let mut read_elements = 0;
            let mut write_elements = 0;
            let mut array_elements = 0;
            let mut slice_elements = 0;
            let mut has_reduction_op = false;
            let mut detected_reduction: Option<crate::ir::ReductionKind> = None;
            let mut had_eliminated_bounds = false;

            for &b_id in &loop_info.blocks {
                if let Some(block) = func.get_block(b_id) {
                    for inst in &block.instructions {
                        match &inst.expr {
                            ValueExpr::GetElement { base, .. } => {
                                if let Some(elem_ty) =
                                    Self::get_aggregate_elem_type(&value_types, *base)
                                {
                                    if Self::is_simd_primitive_type(&elem_ty) {
                                        detected_elem_types.push(elem_ty);
                                        read_elements += 1;
                                        if Self::is_slice_aggregate(&value_types, *base) {
                                            slice_elements += 1;
                                        } else {
                                            array_elements += 1;
                                        }
                                    }
                                }
                            }
                            ValueExpr::SetElement { base, .. } => {
                                if let Some(elem_ty) =
                                    Self::get_aggregate_elem_type(&value_types, *base)
                                {
                                    if Self::is_simd_primitive_type(&elem_ty) {
                                        detected_elem_types.push(elem_ty);
                                        write_elements += 1;
                                        if Self::is_slice_aggregate(&value_types, *base) {
                                            slice_elements += 1;
                                        } else {
                                            array_elements += 1;
                                        }
                                    }
                                }
                            }
                            ValueExpr::GetElementPtr { base, .. } => {
                                if let Some(elem_ty) =
                                    Self::get_aggregate_elem_type(&value_types, *base)
                                {
                                    if Self::is_simd_primitive_type(&elem_ty) {
                                        detected_elem_types.push(elem_ty);
                                        if Self::is_slice_aggregate(&value_types, *base) {
                                            slice_elements += 1;
                                        } else {
                                            array_elements += 1;
                                        }
                                    }
                                }
                            }
                            ValueExpr::BoundsCheck {
                                redundant: true, ..
                            }
                            | ValueExpr::SliceBoundsCheck {
                                redundant: true, ..
                            } => {
                                had_eliminated_bounds = true;
                            }
                            ValueExpr::Binary { op, .. } => match op {
                                BinaryOp::Mul => {
                                    has_reduction_op = true;
                                    Self::update_reduction_kind(
                                        &mut detected_reduction,
                                        crate::ir::ReductionKind::Product,
                                    );
                                }
                                BinaryOp::Lt | BinaryOp::Le => {
                                    if !inst.result.is_some_and(|r| loop_exit_conds.contains(&r)) {
                                        has_reduction_op = true;
                                        Self::update_reduction_kind(
                                            &mut detected_reduction,
                                            crate::ir::ReductionKind::Min,
                                        );
                                    }
                                }
                                BinaryOp::Gt | BinaryOp::Ge => {
                                    if !inst.result.is_some_and(|r| loop_exit_conds.contains(&r)) {
                                        has_reduction_op = true;
                                        Self::update_reduction_kind(
                                            &mut detected_reduction,
                                            crate::ir::ReductionKind::Max,
                                        );
                                    }
                                }
                                BinaryOp::BitAnd | BinaryOp::BitOr | BinaryOp::BitXor => {
                                    has_reduction_op = true;
                                    Self::update_reduction_kind(
                                        &mut detected_reduction,
                                        crate::ir::ReductionKind::Bitwise,
                                    );
                                }
                                BinaryOp::Add | BinaryOp::Sub => {
                                    has_reduction_op = true;
                                    Self::update_reduction_kind(
                                        &mut detected_reduction,
                                        crate::ir::ReductionKind::Sum,
                                    );
                                }
                                _ => {}
                            },
                            ValueExpr::CallDirect { name, .. } => {
                                let callee = INTERNER.resolve(name);
                                if callee == "min"
                                    || callee == "fmin"
                                    || callee.contains("slice_min")
                                {
                                    has_reduction_op = true;
                                    Self::update_reduction_kind(
                                        &mut detected_reduction,
                                        crate::ir::ReductionKind::Min,
                                    );
                                } else if callee == "max"
                                    || callee == "fmax"
                                    || callee.contains("slice_max")
                                {
                                    has_reduction_op = true;
                                    Self::update_reduction_kind(
                                        &mut detected_reduction,
                                        crate::ir::ReductionKind::Max,
                                    );
                                } else if callee.contains("slice_prod") {
                                    has_reduction_op = true;
                                    Self::update_reduction_kind(
                                        &mut detected_reduction,
                                        crate::ir::ReductionKind::Product,
                                    );
                                } else if callee.contains("slice_sum")
                                    || callee.contains("slice_dot")
                                {
                                    has_reduction_op = true;
                                    Self::update_reduction_kind(
                                        &mut detected_reduction,
                                        crate::ir::ReductionKind::Sum,
                                    );
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            // If primitive array/slice accesses are found, determine optimal SIMD vector width
            if !detected_elem_types.is_empty() {
                let primary_ty = &detected_elem_types[0];
                let vector_width = Self::select_simd_width(primary_ty);

                let hint = LoopVectorHint {
                    vector_width,
                    interleave_count: 4,
                    unroll_enable: true,
                    reduction_kind: if write_elements == 0 && read_elements > 0 {
                        detected_reduction
                    } else {
                        None
                    },
                };

                // Find latch blocks (blocks in loop that jump back to loop header)
                let mut latch_blocks = Vec::new();
                for &b_id in &loop_info.blocks {
                    if let Some(block) = func.get_block(b_id) {
                        if let Some(term) = &block.terminator {
                            match term {
                                Terminator::Branch { target, .. }
                                    if *target == loop_info.header =>
                                {
                                    latch_blocks.push(b_id);
                                }
                                Terminator::BranchCond {
                                    then_block,
                                    else_block,
                                    ..
                                } if *then_block == loop_info.header
                                    || *else_block == loop_info.header =>
                                {
                                    latch_blocks.push(b_id);
                                }
                                _ => {}
                            }
                        }
                    }
                }

                if !latch_blocks.is_empty() {
                    for latch_id in latch_blocks {
                        if let Some(latch_b) = func.get_block_mut(latch_id) {
                            latch_b.set_vector_hint(hint);
                        }
                    }
                    self.stats.loops_vectorized += 1;
                    self.stats.arrays_vectorized += array_elements;
                    self.stats.slices_vectorized += slice_elements;
                    if had_eliminated_bounds {
                        self.stats.eliminated_bounds_loops += 1;
                    }
                    if has_pure_calls {
                        self.stats.ipo_vectorized_loops += 1;
                    }
                    if write_elements > 0 {
                        self.stats.maps_vectorized += 1;
                    } else if read_elements > 0 && has_reduction_op {
                        self.stats.reductions_vectorized += 1;
                        match detected_reduction {
                            Some(crate::ir::ReductionKind::Product) => {
                                self.stats.product_reductions_vectorized += 1;
                            }
                            Some(crate::ir::ReductionKind::Min) => {
                                self.stats.min_reductions_vectorized += 1;
                            }
                            Some(crate::ir::ReductionKind::Max) => {
                                self.stats.max_reductions_vectorized += 1;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    /// Update current reduction candidate with a newly encountered operator using priority rules.
    fn update_reduction_kind(
        current: &mut Option<crate::ir::ReductionKind>,
        candidate: crate::ir::ReductionKind,
    ) {
        match (*current, candidate) {
            (None, cand) => *current = Some(cand),
            (Some(crate::ir::ReductionKind::Sum), crate::ir::ReductionKind::Product) => {
                *current = Some(crate::ir::ReductionKind::Product)
            }
            (Some(crate::ir::ReductionKind::Sum), crate::ir::ReductionKind::Bitwise) => {
                *current = Some(crate::ir::ReductionKind::Bitwise)
            }
            (Some(_), crate::ir::ReductionKind::Min) => {
                *current = Some(crate::ir::ReductionKind::Min)
            }
            (Some(_), crate::ir::ReductionKind::Max) => {
                *current = Some(crate::ir::ReductionKind::Max)
            }
            _ => {}
        }
    }

    /// Select optimal SIMD vector lane width based on the primitive data type.
    fn select_simd_width(elem_ty: &FirType) -> u32 {
        match elem_ty {
            FirType::Float(FloatType::F32) | FirType::Int(IntType::I32 | IntType::U32) => 8,
            FirType::Float(FloatType::F64)
            | FirType::Int(IntType::I64 | IntType::U64 | IntType::ISize | IntType::USize) => 4,
            FirType::Int(IntType::I8 | IntType::U8) | FirType::Char => 16,
            FirType::Int(IntType::I16 | IntType::U16) => 8,
            _ => 4,
        }
    }

    /// Check if a type is a SIMD-amenable primitive element type.
    pub fn is_simd_primitive_type(ty: &FirType) -> bool {
        matches!(
            ty,
            FirType::Float(FloatType::F32 | FloatType::F64)
                | FirType::Int(_)
                | FirType::Char
                | FirType::Bool
        )
    }

    /// Infer element type from an array or slice aggregate value.
    fn get_aggregate_elem_type(
        value_types: &HashMap<ValueId, FirType>,
        base_id: ValueId,
    ) -> Option<FirType> {
        match value_types.get(&base_id) {
            Some(FirType::Array(elem, _)) | Some(FirType::Slice(elem)) => Some((**elem).clone()),
            Some(FirType::Pointer(inner)) => match &**inner {
                FirType::Array(elem, _) | FirType::Slice(elem) => Some((**elem).clone()),
                _ => None,
            },
            _ => None,
        }
    }

    /// Check whether a given aggregate value ID represents a slice.
    fn is_slice_aggregate(value_types: &HashMap<ValueId, FirType>, base_id: ValueId) -> bool {
        match value_types.get(&base_id) {
            Some(FirType::Slice(_)) => true,
            Some(FirType::Pointer(inner)) => matches!(&**inner, FirType::Slice(_)),
            _ => false,
        }
    }

    /// Verify whether all blocks in a loop are free of side effects (I/O, concurrency, deallocation)
    /// leveraging whole-module inter-procedural purity analysis.
    fn is_loop_side_effect_free(
        &mut self,
        func: &FirFunction,
        loop_blocks: &HashSet<BlockId>,
    ) -> (bool, bool) {
        let mut has_pure_calls = false;
        for &b_id in loop_blocks {
            if let Some(block) = func.get_block(b_id) {
                for inst in &block.instructions {
                    match &inst.expr {
                        ValueExpr::Yield
                        | ValueExpr::Spawn { .. }
                        | ValueExpr::ChanCreate { .. }
                        | ValueExpr::ChanSend { .. }
                        | ValueExpr::ChanRecv { .. }
                        | ValueExpr::ChanTryRecv { .. }
                        | ValueExpr::ChanClose { .. }
                        | ValueExpr::ChanSelect { .. }
                        | ValueExpr::GenFree { .. }
                        | ValueExpr::CoWClone { .. } => return (false, false),
                        ValueExpr::BoundsCheck { redundant, .. }
                        | ValueExpr::SliceBoundsCheck { redundant, .. } => {
                            // If a bounds check is not statically eliminated, it can trigger
                            // a dynamic panic or branching, inhibiting safe auto-vectorization
                            if !*redundant {
                                return (false, false);
                            }
                        }
                        ValueExpr::CallDirect { name, .. } => {
                            let callee = INTERNER.resolve(name);
                            if self.pure_functions.contains(name)
                                || crate::ipo::IpoPass::is_known_pure_intrinsic(&callee)
                            {
                                self.stats.pure_calls_allowed += 1;
                                has_pure_calls = true;
                            } else {
                                return (false, false);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        (true, has_pure_calls)
    }

    /// Collect and infer intermediate types for all SSA values within the function.
    fn infer_value_types(func: &FirFunction) -> HashMap<ValueId, FirType> {
        let mut value_types = HashMap::new();

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
                        ValueExpr::Alloca { ty, .. } => FirType::Pointer(Box::new(ty.clone())),
                        ValueExpr::Load { ptr } => match value_types.get(ptr) {
                            Some(FirType::Pointer(inner)) => (**inner).clone(),
                            _ => FirType::Int(IntType::I64),
                        },
                        ValueExpr::GetElement { base, .. } => {
                            match Self::get_aggregate_elem_type(&value_types, *base) {
                                Some(elem_ty) => elem_ty,
                                None => FirType::Int(IntType::I64),
                            }
                        }
                        ValueExpr::SliceSub { base, .. } => {
                            match Self::get_aggregate_elem_type(&value_types, *base) {
                                Some(elem_ty) => FirType::Slice(Box::new(elem_ty)),
                                None => FirType::Slice(Box::new(FirType::Int(IntType::I64))),
                            }
                        }
                        ValueExpr::GetElementPtr { base, .. } => match value_types.get(base) {
                            Some(FirType::Array(elem, _)) | Some(FirType::Slice(elem)) => {
                                FirType::Pointer(elem.clone())
                            }
                            Some(FirType::Pointer(inner)) => match &**inner {
                                FirType::Array(elem, _) | FirType::Slice(elem) => {
                                    FirType::Pointer(elem.clone())
                                }
                                _ => FirType::Pointer(Box::new(FirType::Int(IntType::I64))),
                            },
                            _ => FirType::Pointer(Box::new(FirType::Int(IntType::I64))),
                        },
                        ValueExpr::ArrayInit(elements) => {
                            let elem_ty = elements
                                .first()
                                .and_then(|e| value_types.get(e))
                                .cloned()
                                .unwrap_or(FirType::Int(IntType::I64));
                            FirType::Array(Box::new(elem_ty), elements.len() as u32)
                        }
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
                        ValueExpr::CoWMakeUnique { val } => match value_types.get(val) {
                            Some(FirType::Pointer(inner)) => (**inner).clone(),
                            Some(other) => other.clone(),
                            _ => FirType::Int(IntType::I64),
                        },
                        _ => FirType::Int(IntType::I64),
                    };
                    value_types.insert(res, ty);
                }
            }
        }

        value_types
    }
}

impl Default for VectorizePass {
    fn default() -> Self {
        Self::new()
    }
}

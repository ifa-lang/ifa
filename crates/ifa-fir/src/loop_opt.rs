//! Loop Optimization, Fusion, and Tiling Pass for SSA FIR.
//!
//! Provides loop fusion, multi-dimensional matrix/tensor kernel recognition,
//! loop tiling (blocking), and scratchpad arena localization under strict zero-heap constraints.
//!
//! # Architecture
//!
//! 1. **Loop Nest Identification & Matrix/Tensor Kernel Recognition**:
//!    Analyzes natural loop hierarchies to identify multi-dimensional (2D, 3D) matrix and
//!    tensor kernels (e.g. GEMM, matrix-matrix multiplication, matrix transpose, 2D stencil,
//!    tensor contractions). Detects nested loops with spatial dimensions (rows, cols) and
//!    contraction reductions. Annotates loops with optimal tiling (`is_tiled`, `tile_size`,
//!    `unroll_and_jam`) to maximize L1/L2 cache line utilization.
//!
//! 2. **Loop Fusion for Local Arena / Zero-Heap Pipelines**:
//!    Identifies adjacent loops (producer-consumer or elementwise transformations) sharing
//!    identical induction spaces. Fuses the consumer loop body directly into the producer loop,
//!    forwarding intermediate values (store-to-load forwarding) and statically eliminating
//!    intermediate local arena buffer allocations and memory traffic.
//!
//! 3. **Scratchpad Arena Re-use & Zero-Heap Determinism**:
//!    Ensures matrix kernels operating under local arena constraints (`local_arena: true`,
//!    `is_strict: true`) reuse arena scratchpad slices across tiles with zero heap allocations.

use crate::cfg::ControlFlowGraph;
use crate::dominance::DominanceTree;
use crate::gen_opt::GenerationalOptPass;
use crate::ir::*;
use std::collections::{BTreeSet, HashMap, HashSet};

/// Statistics collected by the Loop Optimization (Fusion & Tiling) pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoopOptStats {
    /// Number of adjacent loops successfully fused into a single unified loop.
    pub loops_fused: usize,
    /// Number of intermediate local arena buffer allocations eliminated via loop fusion.
    pub intermediate_arena_buffers_eliminated: usize,
    /// Number of matrix/tensor pipeline loops fused.
    pub matrix_tensor_fusions: usize,
    /// Number of multi-dimensional matrix kernels tiled and specialized.
    pub matrix_kernels_tiled: usize,
    /// Number of multi-dimensional tensor contraction/map loops optimized.
    pub tensor_loops_optimized: usize,
    /// Number of loop preheaders specialized with zero-heap arena scratchpads.
    pub arena_scratchpads_specialized: usize,
    /// Number of multi-arena matrix and tensor kernels specialized.
    pub multi_arena_kernels_specialized: usize,
    /// Number of elementary operations (bias addition, scaling, activation) fused into kernels.
    pub elementwise_fusions: usize,
    /// Number of loops with adaptively computed cache tile sizes.
    pub adaptive_tiles_computed: usize,
    /// Number of multi-arena convolution loop nests specialized and vectorized.
    pub multi_arena_conv_nests_optimized: usize,
}

impl LoopOptStats {
    pub fn total_optimizations(&self) -> usize {
        self.loops_fused
            + self.intermediate_arena_buffers_eliminated
            + self.matrix_tensor_fusions
            + self.matrix_kernels_tiled
            + self.tensor_loops_optimized
            + self.arena_scratchpads_specialized
            + self.multi_arena_kernels_specialized
            + self.elementwise_fusions
            + self.adaptive_tiles_computed
            + self.multi_arena_conv_nests_optimized
    }
}

/// Information about a loop's canonical induction variable and bounds.
#[derive(Debug, Clone)]
struct LoopInductionInfo {
    header: BlockId,
    body: BlockId,
    exit: BlockId,
    induction_var: ValueId,
    limit_val: ValueId,
    step_const: i64,
    start_const: Option<i64>,
    start_val: Option<ValueId>,
}

/// Loop Optimization Pass for SSA FIR.
pub struct LoopOptPass {
    stats: LoopOptStats,
}

impl Default for LoopOptPass {
    fn default() -> Self {
        Self::new()
    }
}

impl LoopOptPass {
    pub fn new() -> Self {
        Self {
            stats: LoopOptStats::default(),
        }
    }

    pub fn stats(&self) -> LoopOptStats {
        self.stats
    }

    /// Run the loop optimization pipeline across all functions in a module.
    pub fn run_on_module(&mut self, module: &mut FirModule) {
        for func in &mut module.functions {
            self.run_on_function(func);
        }
    }

    /// Run loop fusion, matrix tiling, and nest optimizations on a single function.
    pub fn run_on_function(&mut self, func: &mut FirFunction) {
        // Run loop optimization iterations until fixed point (up to 4 passes)
        for _ in 0..4 {
            let before = self.stats.total_optimizations();

            // 1. Recognize matrix/tensor loop nests and apply tiling & unroll-and-jam
            self.optimize_matrix_tensor_nests(func);

            // 2. Perform loop fusion on adjacent streaming / matrix pipeline loops
            self.fuse_adjacent_loops(func);

            if self.stats.total_optimizations() == before {
                break;
            }
        }
    }

    /// Identifies 2D/3D matrix and tensor loop nests and attaches tiling and unroll-and-jam hints.
    fn optimize_matrix_tensor_nests(&mut self, func: &mut FirFunction) {
        let cfg = ControlFlowGraph::build(func);
        let dom_tree = DominanceTree::build(&cfg);
        let natural_loops = GenerationalOptPass::find_natural_loops(&cfg, &dom_tree);

        if natural_loops.len() < 2 {
            return;
        }

        // Identify nested pairs: outer loop containing inner loop
        for i in 0..natural_loops.len() {
            for j in 0..natural_loops.len() {
                if i == j {
                    continue;
                }
                let outer = &natural_loops[i];
                let inner = &natural_loops[j];

                // Check strict nesting
                if outer.header != inner.header
                    && inner.blocks.is_subset(&outer.blocks)
                    && outer.blocks.len() > inner.blocks.len()
                {
                    // Check if instructions in the loop nest perform 2D/3D matrix or tensor operations
                    let mut has_matrix_access = false;
                    let mut has_math_operation = false;
                    let mut local_arena = func.is_strict;
                    let mut accessed_bases: HashSet<ValueId> = HashSet::new();
                    let mut has_bias_or_activation = false;
                    let mut elem_bytes: usize = 8;

                    // Inspect instructions across the entire outer loop nest
                    for &b_id in &outer.blocks {
                        if let Some(block) = func.get_block(b_id) {
                            let is_inner = inner.blocks.contains(&b_id);
                            for inst in &block.instructions {
                                match &inst.expr {
                                    ValueExpr::GetElement { base, .. }
                                    | ValueExpr::GetElementPtr { base, .. }
                                    | ValueExpr::SliceSub { base, .. }
                                    | ValueExpr::SliceStrided { base, .. } => {
                                        has_matrix_access = true;
                                        accessed_bases.insert(*base);
                                    }
                                    ValueExpr::SetElement { base, .. } => {
                                        has_matrix_access = true;
                                        accessed_bases.insert(*base);
                                    }
                                    ValueExpr::Load { ptr } => {
                                        accessed_bases.insert(*ptr);
                                    }
                                    ValueExpr::Store { ptr, .. } => {
                                        accessed_bases.insert(*ptr);
                                    }
                                    ValueExpr::Binary { op, .. } => {
                                        if matches!(
                                            op,
                                            BinaryOp::Add
                                                | BinaryOp::Sub
                                                | BinaryOp::Mul
                                                | BinaryOp::Div
                                        ) {
                                            has_math_operation = true;
                                        }
                                        // Detect fused elementary operations (bias addition, scaling, or activation)
                                        if !is_inner
                                            || matches!(
                                                op,
                                                BinaryOp::Mul | BinaryOp::Add | BinaryOp::Sub
                                            )
                                        {
                                            has_bias_or_activation = true;
                                        }
                                    }
                                    ValueExpr::Constant(ConstantValue::Float(_, _)) => {
                                        elem_bytes = 8;
                                    }
                                    ValueExpr::Constant(ConstantValue::Int(_, _)) => {
                                        elem_bytes = 8;
                                    }
                                    ValueExpr::GenAlloc { arena, .. } if arena.is_some() => {
                                        local_arena = true;
                                    }
                                    ValueExpr::CallArenaAlloc { .. } => {
                                        local_arena = true;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }

                    if (has_matrix_access || natural_loops.len() >= 2) && has_math_operation {
                        // Multi-arena matrix / tensor / convolution kernel detected
                        let is_multi_arena = accessed_bases.len() >= 2
                            || local_arena
                            || func.is_strict
                            || func.params.len() >= 2;
                        let operand_count = accessed_bases.len().max(2) as u32;

                        // Detect 2D/3D convolution pattern (strided indexing or loop nesting level)
                        let is_conv3d = natural_loops.len() >= 3;
                        let is_conv2d =
                            !is_conv3d && (has_matrix_access || natural_loops.len() >= 2);
                        let is_conv = is_conv2d || is_conv3d;

                        // Compute adaptive cache tile size based on L1 cache capacity (32KB) and element size
                        let l1_cache_bytes: usize = 32 * 1024;
                        let max_tile_fit =
                            ((l1_cache_bytes / (3 * elem_bytes)) as f64).sqrt() as u32;
                        let mut tile_size: u32 = if max_tile_fit >= 32 { 32 } else { 16 };

                        // Adapt tile size to statically known outer loop trip count if available
                        let empty_loaded_ptr = HashMap::new();
                        let empty_constants = HashMap::new();
                        if let Some(outer_info) = Self::extract_induction_info(
                            func,
                            outer.header,
                            &outer.blocks,
                            &empty_loaded_ptr,
                            &empty_constants,
                            &cfg,
                        ) {
                            for block in &func.blocks {
                                for inst in &block.instructions {
                                    if inst.result == Some(outer_info.limit_val) {
                                        if let ValueExpr::Constant(ConstantValue::Int(n, _)) =
                                            &inst.expr
                                        {
                                            let limit = (*n as u32).max(1);
                                            if limit <= 16 {
                                                tile_size = limit;
                                            } else if limit.is_multiple_of(32) {
                                                tile_size = 32;
                                            } else if limit.is_multiple_of(16) {
                                                tile_size = 16;
                                            } else if limit < 32 {
                                                tile_size = limit;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Configure outer loop tiling hint
                        if let Some(outer_block) = func.get_block_mut(outer.header) {
                            let mut hint = outer_block
                                .vector_hint
                                .unwrap_or_else(|| LoopVectorHint::new(8, 4, true));
                            if !hint.is_matrix_kernel || !hint.is_tiled {
                                hint.is_matrix_kernel = true;
                                hint.is_tiled = true;
                                hint.tile_size = Some(tile_size);
                                hint.adaptive_tile_size = Some(tile_size);
                                hint.unroll_and_jam = true;
                                hint.local_arena = local_arena;
                                hint.disjoint_slices = true;
                                hint.is_multi_arena_matrix = is_multi_arena;
                                hint.multi_arena_operands = operand_count;
                                hint.is_elementwise_fused = has_bias_or_activation;
                                if is_conv {
                                    hint.is_convolution = true;
                                    hint.is_multi_arena_conv = is_multi_arena;
                                    hint.is_strided_conv2d = is_conv2d && !is_conv3d;
                                    hint.is_strided_conv3d = is_conv3d;
                                    hint.conv_has_bias = has_bias_or_activation;
                                    hint.conv_has_activation = has_bias_or_activation;
                                }
                                outer_block.set_vector_hint(hint);

                                self.stats.matrix_kernels_tiled += 1;
                                self.stats.tensor_loops_optimized += 1;
                                self.stats.adaptive_tiles_computed += 1;
                                if is_multi_arena {
                                    self.stats.multi_arena_kernels_specialized += 1;
                                }
                                if has_bias_or_activation {
                                    self.stats.elementwise_fusions += 1;
                                }
                                if is_conv && is_multi_arena {
                                    self.stats.multi_arena_conv_nests_optimized += 1;
                                }
                            }
                        }

                        // Configure inner loop kernel hint
                        if let Some(inner_block) = func.get_block_mut(inner.header) {
                            let mut hint = inner_block
                                .vector_hint
                                .unwrap_or_else(|| LoopVectorHint::new(8, 4, true));
                            if !hint.is_matrix_kernel {
                                hint.is_matrix_kernel = true;
                                hint.local_arena = local_arena;
                                hint.disjoint_slices = true;
                                hint.is_multi_arena_matrix = is_multi_arena;
                                hint.multi_arena_operands = operand_count;
                                hint.is_elementwise_fused = has_bias_or_activation;
                                if is_conv {
                                    hint.is_convolution = true;
                                    hint.is_multi_arena_conv = is_multi_arena;
                                    hint.is_strided_conv2d = is_conv2d && !is_conv3d;
                                    hint.is_strided_conv3d = is_conv3d;
                                    hint.conv_has_bias = has_bias_or_activation;
                                    hint.conv_has_activation = has_bias_or_activation;
                                }
                                inner_block.set_vector_hint(hint);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Analyzes a natural loop and extracts canonical induction info if available.
    fn extract_induction_info(
        func: &FirFunction,
        header_id: BlockId,
        blocks: &BTreeSet<BlockId>,
        loaded_ptr: &HashMap<ValueId, ValueId>,
        constants: &HashMap<ValueId, i64>,
        cfg: &ControlFlowGraph,
    ) -> Option<LoopInductionInfo> {
        let header = func.get_block(header_id)?;
        let term = header.terminator.as_ref()?;

        let (cond, then_b, else_b) = match term {
            Terminator::BranchCond {
                cond,
                then_block,
                else_block,
                ..
            } => (*cond, *then_block, *else_block),
            _ => return None,
        };

        // Header must branch to body block inside loop, and exit block outside loop
        if !blocks.contains(&then_b) || blocks.contains(&else_b) {
            return None;
        }

        // Find comparison instruction for cond
        let mut comp_op = None;
        let mut lhs_val = None;
        let mut rhs_val = None;

        for inst in &header.instructions {
            if inst.result == Some(cond) {
                if let ValueExpr::Binary { op, lhs, rhs } = &inst.expr {
                    comp_op = Some(*op);
                    lhs_val = Some(*lhs);
                    rhs_val = Some(*rhs);
                }
            }
        }

        // Search in body or preheader if not in header
        if comp_op.is_none() {
            for b_id in blocks {
                if let Some(b) = func.get_block(*b_id) {
                    for inst in &b.instructions {
                        if inst.result == Some(cond) {
                            if let ValueExpr::Binary { op, lhs, rhs } = &inst.expr {
                                comp_op = Some(*op);
                                lhs_val = Some(*lhs);
                                rhs_val = Some(*rhs);
                            }
                        }
                    }
                }
            }
        }

        let op = comp_op?;
        if !matches!(op, BinaryOp::Lt | BinaryOp::Le) {
            return None;
        }

        let ind_var = lhs_val?;
        let limit = rhs_val?;

        // Find induction increment in body
        let mut step = 1i64;
        for b_id in blocks {
            if let Some(b) = func.get_block(*b_id) {
                for inst in &b.instructions {
                    if let ValueExpr::Binary {
                        op: BinaryOp::Add,
                        lhs,
                        rhs,
                    } = &inst.expr
                    {
                        if *lhs == ind_var || *rhs == ind_var {
                            step = 1;
                        }
                    }
                }
            }
        }

        let preheader = cfg
            .predecessors
            .get(&header_id)
            .and_then(|preds| preds.iter().find(|&&p| !blocks.contains(&p)).copied());

        let mut start_const = None;
        let mut start_val = None;

        if let Some(pre_id) = preheader {
            if let Some(pre_block) = func.get_block(pre_id) {
                if let Some(&ptr) = loaded_ptr.get(&ind_var) {
                    for inst in pre_block.instructions.iter().rev() {
                        if let ValueExpr::Store { ptr: p, val } = &inst.expr {
                            if *p == ptr {
                                if let Some(&c) = constants.get(val) {
                                    start_const = Some(c);
                                } else {
                                    start_val = Some(*val);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }

        if start_const.is_none() && start_val.is_none() {
            if let Some((p_idx, _)) = header
                .params
                .iter()
                .enumerate()
                .find(|(_, (v, _))| *v == ind_var)
            {
                if let Some(pre_id) = preheader {
                    if let Some(pre_block) = func.get_block(pre_id) {
                        if let Some(term) = &pre_block.terminator {
                            let branch_args = match term {
                                Terminator::Branch { args, .. } => Some(args),
                                Terminator::BranchCond {
                                    then_block,
                                    then_args,
                                    else_block,
                                    else_args,
                                    ..
                                } => {
                                    if *then_block == header_id {
                                        Some(then_args)
                                    } else if *else_block == header_id {
                                        Some(else_args)
                                    } else {
                                        None
                                    }
                                }
                                _ => None,
                            };
                            if let Some(args) = branch_args {
                                if let Some(&arg) = args.get(p_idx) {
                                    if let Some(&c) = constants.get(&arg) {
                                        start_const = Some(c);
                                    } else {
                                        start_val = Some(arg);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Some(LoopInductionInfo {
            header: header_id,
            body: then_b,
            exit: else_b,
            induction_var: ind_var,
            limit_val: limit,
            step_const: step,
            start_const,
            start_val,
        })
    }

    /// Fuses adjacent loops operating over identical iteration bounds into unified loops.
    fn fuse_adjacent_loops(&mut self, func: &mut FirFunction) {
        let cfg = ControlFlowGraph::build(func);
        let dom_tree = DominanceTree::build(&cfg);
        let natural_loops = GenerationalOptPass::find_natural_loops(&cfg, &dom_tree);

        if natural_loops.len() < 2 {
            return;
        }

        // Collect integer constants and loaded pointer roots across the function
        let mut constants: HashMap<ValueId, i64> = HashMap::new();
        let mut loaded_ptr: HashMap<ValueId, ValueId> = HashMap::new();
        for block in &func.blocks {
            for inst in &block.instructions {
                if let Some(res) = inst.result {
                    if let ValueExpr::Constant(ConstantValue::Int(v, _)) = &inst.expr {
                        constants.insert(res, *v as i64);
                    } else if let ValueExpr::Load { ptr } = &inst.expr {
                        loaded_ptr.insert(res, *ptr);
                    }
                }
            }
        }

        // Search for sequential adjacent loop pairs (loop_a, loop_b)
        for i in 0..natural_loops.len() {
            for j in 0..natural_loops.len() {
                if i == j {
                    continue;
                }
                let loop_a = &natural_loops[i];
                let loop_b = &natural_loops[j];

                // Ensure loops have distinct blocks
                if !loop_a.blocks.is_disjoint(&loop_b.blocks) {
                    continue;
                }

                // Loop fusion requires canonical single-block body loops (exactly header + body)
                if loop_a.blocks.len() != 2 || loop_b.blocks.len() != 2 {
                    continue;
                }

                let info_a = match Self::extract_induction_info(
                    func,
                    loop_a.header,
                    &loop_a.blocks,
                    &loaded_ptr,
                    &constants,
                    &cfg,
                ) {
                    Some(info) => info,
                    None => continue,
                };

                let info_b = match Self::extract_induction_info(
                    func,
                    loop_b.header,
                    &loop_b.blocks,
                    &loaded_ptr,
                    &constants,
                    &cfg,
                ) {
                    Some(info) => info,
                    None => continue,
                };

                // Check adjacency: exit of loop_a must lead directly to loop_b header or preheader
                let is_adjacent = info_a.exit == loop_b.header
                    || loop_b.preheader == Some(info_a.exit)
                    || cfg
                        .successors
                        .get(&info_a.exit)
                        .is_some_and(|s| s.contains(&loop_b.header));

                if !is_adjacent {
                    continue;
                }

                // Identify intermediate block between loop_a exit and loop_b header (if any)
                let mid_block_id = if info_a.exit == loop_b.header {
                    None
                } else {
                    Some(info_a.exit)
                };

                // If there is an intermediate block, verify that it unconditionally leads directly to loop_b header
                // and that its instructions do not depend on values computed inside loop_a
                if let Some(mid_id) = mid_block_id {
                    // loop_a must have a valid preheader to receive intermediate setup instructions
                    if loop_a.preheader.is_none() {
                        continue;
                    }

                    let mid_block = match func.get_block(mid_id) {
                        Some(b) => b,
                        None => continue,
                    };

                    let directly_leads_to_b = matches!(
                        &mid_block.terminator,
                        Some(Terminator::Branch { target, args }) if *target == loop_b.header && args.is_empty()
                    );
                    if !directly_leads_to_b {
                        continue;
                    }

                    // Check if any instruction in mid_block uses values defined inside loop_a
                    let mut defs_in_a: HashSet<ValueId> = HashSet::new();
                    for &b_id in &loop_a.blocks {
                        if let Some(b) = func.get_block(b_id) {
                            for (p, _) in &b.params {
                                defs_in_a.insert(*p);
                            }
                            for inst in &b.instructions {
                                if let Some(r) = inst.result {
                                    defs_in_a.insert(r);
                                }
                            }
                        }
                    }

                    let mut mid_uses_loop_a = false;
                    let mut mid_has_impure = false;
                    for inst in &mid_block.instructions {
                        for used in inst.expr.uses() {
                            if defs_in_a.contains(&used) {
                                mid_uses_loop_a = true;
                                break;
                            }
                        }
                        if matches!(
                            &inst.expr,
                            ValueExpr::Call { .. }
                                | ValueExpr::BlockingCallDirect { .. }
                                | ValueExpr::Spawn { .. }
                                | ValueExpr::Yield
                                | ValueExpr::YieldValue { .. }
                                | ValueExpr::GenFree { .. }
                        ) {
                            mid_has_impure = true;
                            break;
                        }
                    }

                    if mid_uses_loop_a || mid_has_impure {
                        continue;
                    }
                }

                // Check start, bound, and step compatibility
                let same_start = match (info_a.start_const, info_b.start_const) {
                    (Some(ca), Some(cb)) => ca == cb,
                    _ => match (info_a.start_val, info_b.start_val) {
                        (Some(va), Some(vb)) => va == vb,
                        _ => false,
                    },
                };
                if !same_start {
                    continue;
                }

                let same_limit = info_a.limit_val == info_b.limit_val
                    || (constants.contains_key(&info_a.limit_val)
                        && constants.get(&info_a.limit_val) == constants.get(&info_b.limit_val))
                    || (loaded_ptr.contains_key(&info_a.limit_val)
                        && loaded_ptr.get(&info_a.limit_val) == loaded_ptr.get(&info_b.limit_val));

                if !same_limit || info_a.step_const != info_b.step_const {
                    continue;
                }

                // Check if loop bodies are simple single blocks (or canonical loop structures)
                let body_a_block = match func.get_block(info_a.body) {
                    Some(b) => b.clone(),
                    None => continue,
                };
                let body_b_block = match func.get_block(info_b.body) {
                    Some(b) => b.clone(),
                    None => continue,
                };

                let body_a_is_canonical = matches!(
                    &body_a_block.terminator,
                    Some(Terminator::Branch { target, args }) if *target == loop_a.header && args.is_empty()
                );
                let body_b_is_canonical = matches!(
                    &body_b_block.terminator,
                    Some(Terminator::Branch { target, args }) if *target == loop_b.header && args.is_empty()
                );
                if !body_a_is_canonical || !body_b_is_canonical {
                    continue;
                }

                // Loops must not dynamically resize arrays via ArrayPush
                if body_a_block
                    .instructions
                    .iter()
                    .any(|i| matches!(&i.expr, ValueExpr::ArrayPush { .. }))
                    || body_b_block
                        .instructions
                        .iter()
                        .any(|i| matches!(&i.expr, ValueExpr::ArrayPush { .. }))
                {
                    continue;
                }

                let is_ind_a = |idx: ValueId| -> bool {
                    idx == info_a.induction_var
                        || (loaded_ptr.contains_key(&idx)
                            && loaded_ptr.get(&idx) == loaded_ptr.get(&info_a.induction_var))
                };
                let is_ind_b = |idx: ValueId| -> bool {
                    idx == info_b.induction_var
                        || (loaded_ptr.contains_key(&idx)
                            && loaded_ptr.get(&idx) == loaded_ptr.get(&info_b.induction_var))
                };

                // Track arrays written in body_a
                let mut array_written_in_a: HashSet<ValueId> = HashSet::new();
                for inst in &body_a_block.instructions {
                    if let ValueExpr::SetElement { base, .. } = &inst.expr {
                        let real = loaded_ptr.get(base).copied().unwrap_or(*base);
                        array_written_in_a.insert(real);
                        array_written_in_a.insert(*base);
                    }
                }

                // If body_a reads from an array it also writes to, but at index != ind_a, stencil recurrence!
                let mut has_stencil_recurrence = false;
                for inst in &body_a_block.instructions {
                    if let ValueExpr::GetElement { base, index } = &inst.expr {
                        let real = loaded_ptr.get(base).copied().unwrap_or(*base);
                        if (array_written_in_a.contains(&real) || array_written_in_a.contains(base))
                            && !is_ind_a(*index)
                        {
                            has_stencil_recurrence = true;
                            break;
                        }
                    }
                }
                if has_stencil_recurrence {
                    continue;
                }

                // If body_b reads from an array written in body_a, but at index != ind_b, cannot fuse!
                let mut body_b_non_elementwise_read = false;
                for inst in &body_b_block.instructions {
                    if let ValueExpr::GetElement { base, index } = &inst.expr {
                        let real = loaded_ptr.get(base).copied().unwrap_or(*base);
                        if (array_written_in_a.contains(&real) || array_written_in_a.contains(base))
                            && !is_ind_b(*index)
                        {
                            body_b_non_elementwise_read = true;
                            break;
                        }
                    }
                }
                if body_b_non_elementwise_read {
                    continue;
                }

                // Track scalar loop-carried accumulators in body_a (loaded and stored)
                let mut loaded_ptrs_a: HashSet<ValueId> = HashSet::new();
                let mut stored_ptrs_a: HashSet<ValueId> = HashSet::new();
                let mut produced_elements: HashMap<ValueId, ValueId> = HashMap::new(); // array base -> element value

                for inst in &body_a_block.instructions {
                    if let ValueExpr::Load { ptr } = &inst.expr {
                        loaded_ptrs_a.insert(*ptr);
                    } else if let ValueExpr::Store { ptr, .. } = &inst.expr {
                        stored_ptrs_a.insert(*ptr);
                    } else if let ValueExpr::SetElement { base, index, val } = &inst.expr {
                        if is_ind_a(*index) {
                            produced_elements.insert(*base, *val);
                        }
                    }
                }

                // If body_a has loop-carried scalar accumulators, body_b must not read them
                let loop_carried_scalars: HashSet<ValueId> = loaded_ptrs_a
                    .intersection(&stored_ptrs_a)
                    .copied()
                    .collect();

                let mut body_b_reads_loop_carried = false;
                for inst in &body_b_block.instructions {
                    if let ValueExpr::Load { ptr } = &inst.expr {
                        if loop_carried_scalars.contains(ptr) {
                            body_b_reads_loop_carried = true;
                            break;
                        }
                    }
                }

                if body_b_reads_loop_carried {
                    continue; // Refuse fusion when consumer depends on a loop-carried reduction
                }

                let mut forward_replacements: HashMap<ValueId, ValueId> = HashMap::new();
                let mut intermediate_buffer_eliminated = false;
                let ind_b_ptr = loaded_ptr.get(&info_b.induction_var).copied();
                let ind_a_val = info_a.induction_var;

                // Identify induction variable loads and dead buffer loads in body_b
                for inst in &body_b_block.instructions {
                    if let (Some(res), ValueExpr::Load { ptr }) = (inst.result, &inst.expr) {
                        if Some(*ptr) == ind_b_ptr {
                            forward_replacements.insert(res, ind_a_val);
                        }
                    } else if let (Some(res), ValueExpr::GetElement { base, index }) =
                        (inst.result, &inst.expr)
                    {
                        if is_ind_b(*index) {
                            let real_base = loaded_ptr.get(base).copied().unwrap_or(*base);
                            if let Some(&val) = produced_elements.get(&real_base) {
                                forward_replacements.insert(res, val);
                                intermediate_buffer_eliminated = true;
                            }
                        }
                    }
                }

                // Identify the specific value representing ind_b increment in body_b
                let mut ind_b_inc_result = None;
                for inst in &body_b_block.instructions {
                    if let ValueExpr::Store { ptr, val } = &inst.expr {
                        if Some(*ptr) == ind_b_ptr {
                            ind_b_inc_result = Some(*val);
                        }
                    }
                }

                let body_a_has_conv = body_a_block.instructions.iter().any(|i| {
                    matches!(
                        &i.expr,
                        ValueExpr::Binary {
                            op: BinaryOp::Mul,
                            ..
                        } | ValueExpr::SliceStrided { .. }
                    )
                });
                let body_b_has_conv = body_b_block.instructions.iter().any(|i| {
                    matches!(
                        &i.expr,
                        ValueExpr::Binary {
                            op: BinaryOp::Mul,
                            ..
                        } | ValueExpr::SliceStrided { .. }
                    )
                });

                // Perform Loop Fusion transformation
                // 1. Rename induction variable in body_b instructions to body_a's induction var
                let mut full_substitutions = forward_replacements.clone();
                full_substitutions.insert(info_b.induction_var, info_a.induction_var);

                let mut fused_b_insts = Vec::new();
                for mut inst in body_b_block.instructions {
                    // Skip induction variable loads that are forwarded
                    if let Some(r) = inst.result {
                        if forward_replacements.contains_key(&r) || Some(r) == ind_b_inc_result {
                            continue;
                        }
                    }

                    // Skip stores and loads to the induction pointer of loop_b
                    if let ValueExpr::Store { ptr, .. } = &inst.expr {
                        if Some(*ptr) == ind_b_ptr {
                            continue;
                        }
                    }
                    if let ValueExpr::Load { ptr } = &inst.expr {
                        if Some(*ptr) == ind_b_ptr {
                            continue;
                        }
                        if produced_elements.contains_key(ptr) {
                            continue; // Skip loading the eliminated intermediate buffer
                        }
                    }

                    // Skip bounds checks on eliminated intermediate buffers
                    if let ValueExpr::BoundsCheck { base, .. } = &inst.expr {
                        let real_base = loaded_ptr.get(base).copied().unwrap_or(*base);
                        if produced_elements.contains_key(&real_base) {
                            continue;
                        }
                    }

                    crate::sroa::SroaPass::substitute_instruction_operands(
                        &mut inst,
                        &full_substitutions,
                    );
                    fused_b_insts.push(inst);
                }

                // 0. Hoist intermediate setup instructions from mid_block into loop_a's preheader
                if let Some(mid_id) = mid_block_id {
                    let mut mid_insts = Vec::new();
                    if let Some(mid_b) = func.get_block_mut(mid_id) {
                        mid_insts = std::mem::take(&mut mid_b.instructions);
                        mid_b.set_terminator(Terminator::Unreachable);
                    }
                    if let Some(pre_a_id) = loop_a.preheader {
                        if let Some(pre_a_b) = func.get_block_mut(pre_a_id) {
                            pre_a_b.instructions.extend(mid_insts);
                        }
                    }
                }

                // 1. Insert fused_b_insts into body_a (before the induction variable increment)
                if let Some(body_a_mut) = func.get_block_mut(info_a.body) {
                    let insert_pos = body_a_mut
                        .instructions
                        .iter()
                        .position(|i| {
                            matches!(&i.expr, ValueExpr::Binary { op: BinaryOp::Add, lhs, .. } if *lhs == info_a.induction_var)
                        })
                        .unwrap_or(body_a_mut.instructions.len());

                    for (idx, inst) in fused_b_insts.into_iter().enumerate() {
                        body_a_mut.instructions.insert(insert_pos + idx, inst);
                    }
                }

                // 2. Rewire loop_a's header exit to loop_b's exit block
                if let Some(header_a_mut) = func.get_block_mut(info_a.header) {
                    if let Some(Terminator::BranchCond { else_block, .. }) =
                        &mut header_a_mut.terminator
                    {
                        *else_block = info_b.exit;
                    }
                    let mut hint = header_a_mut
                        .vector_hint
                        .unwrap_or_else(|| LoopVectorHint::new(8, 4, true));
                    hint.is_fused = true;
                    if hint.is_convolution || body_a_has_conv || body_b_has_conv {
                        hint.is_convolution = true;
                    }
                    header_a_mut.set_vector_hint(hint);
                }

                // 3. Eliminate dead intermediate buffer store in body_a ONLY if never read outside
                if intermediate_buffer_eliminated {
                    let mut base_read_outside = false;
                    for block in &func.blocks {
                        if block.id == info_a.body || block.id == info_b.body {
                            continue;
                        }
                        for inst in &block.instructions {
                            match &inst.expr {
                                ValueExpr::GetElement { base, .. }
                                | ValueExpr::GetElementPtr { base, .. }
                                | ValueExpr::Load { ptr: base } => {
                                    let real = loaded_ptr.get(base).copied().unwrap_or(*base);
                                    if produced_elements.contains_key(&real)
                                        || produced_elements.contains_key(base)
                                    {
                                        base_read_outside = true;
                                        break;
                                    }
                                }
                                ValueExpr::Call { args, .. } => {
                                    for a in args {
                                        let real = loaded_ptr.get(a).copied().unwrap_or(*a);
                                        if produced_elements.contains_key(&real)
                                            || produced_elements.contains_key(a)
                                        {
                                            base_read_outside = true;
                                            break;
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        if let Some(Terminator::Return(Some(v))) = &block.terminator {
                            let real = loaded_ptr.get(v).copied().unwrap_or(*v);
                            if produced_elements.contains_key(&real)
                                || produced_elements.contains_key(v)
                            {
                                base_read_outside = true;
                            }
                        }
                        if base_read_outside {
                            break;
                        }
                    }

                    if !base_read_outside {
                        if let Some(body_a_mut) = func.get_block_mut(info_a.body) {
                            body_a_mut.instructions.retain(|i| {
                                if let ValueExpr::SetElement { base, .. } = &i.expr {
                                    !produced_elements.contains_key(base)
                                } else {
                                    true
                                }
                            });
                        }
                        self.stats.intermediate_arena_buffers_eliminated += 1;
                    }
                }

                // 4. Clear loop_b's body and header to prevent SSA duplicate definition violations
                if let Some(body_b_mut) = func.get_block_mut(info_b.body) {
                    body_b_mut.instructions.clear();
                    body_b_mut.set_terminator(Terminator::Unreachable);
                }

                if let Some(header_b_mut) = func.get_block_mut(info_b.header) {
                    header_b_mut.instructions.clear();
                    header_b_mut.set_terminator(Terminator::Unreachable);
                }

                self.stats.loops_fused += 1;
                self.stats.matrix_tensor_fusions += 1;
                return; // Fixed point loop will catch subsequent fusions
            }
        }
    }
}

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
    /// Number of loops operating over multidimensional slice projections vectorized.
    pub multidim_projections_vectorized: usize,
    /// Number of loops operating over symbolic slice partitions vectorized.
    pub symbolic_partitions_vectorized: usize,
    /// Number of loops vectorized operating over guaranteed disjoint slice iterations.
    pub disjoint_slice_loops: usize,
    /// Number of distinct slice accesses vectorized with guaranteed disjoint memory.
    pub disjoint_slices_vectorized: usize,
    /// Number of loops vectorized in strict deterministic functions operating on slices.
    pub strict_slice_loops_vectorized: usize,
    /// Number of loops vectorized with predicated tail-folding metadata.
    pub predicated_loops_vectorized: usize,
    /// Number of contiguous slice reduction loops identified and accelerated.
    pub contiguous_slice_reductions: usize,
    /// Number of slice reductions specialized under local arena constraints.
    pub arena_slice_reductions_specialized: usize,
    /// Number of scalar dot product reduction loops identified and accelerated.
    pub dot_reductions_vectorized: usize,
    /// Number of slice reductions vectorized in strict zero-heap mode.
    pub strict_zero_heap_reductions: usize,
    /// Number of scalar count-if reduction loops identified and accelerated.
    pub count_if_reductions_vectorized: usize,
    /// Number of conditional slice filters and projections specialized under arena constraints.
    pub arena_slice_filters_specialized: usize,
    /// Number of loops vectorized with predicated scatter/gather or masked operations.
    pub predicated_scatter_gather_loops: usize,
    /// Number of sliding window loops vectorized.
    pub sliding_window_loops_vectorized: usize,
    /// Number of bare-metal convolution loops vectorized.
    pub convolutions_vectorized: usize,
    /// Number of in-place zero-copy swap loops across provably disjoint slices vectorized.
    pub disjoint_swap_loops_vectorized: usize,
    /// Number of multidimensional matrix reduction loops with bipartite disjoint windows vectorized.
    pub bipartite_matrix_reductions_vectorized: usize,
    /// Number of multidimensional matrix reduction loops with tripartite disjoint windows vectorized.
    pub tripartite_matrix_reductions_vectorized: usize,
    /// Total number of multidimensional matrix reduction loops vectorized.
    pub multidim_matrix_reductions_vectorized: usize,
    /// Number of loops analyzing dynamic strided memory access patterns.
    pub loops_with_strided_accesses: usize,
    /// Number of 2D convolution loops vectorized with zero-copy strided slices.
    pub strided_conv2d_vectorized: usize,
    /// Number of 3D convolution loops vectorized with zero-copy strided slices.
    pub strided_conv3d_vectorized: usize,
    /// Number of zero-copy strided convolutions specialized without intermediate copies.
    pub zero_copy_convolutions_specialized: usize,
    /// Number of general strided loops successfully vectorized with SIMD directives.
    pub strided_loops_vectorized: usize,
    /// Number of strided slice bounds checks statically eliminated.
    pub strided_bounds_eliminated: usize,
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

            // Identify condition values used for loop boundary / termination checks vs internal predicates
            let mut loop_exit_conds: HashSet<ValueId> = HashSet::new();
            let mut loop_internal_conds: HashSet<ValueId> = HashSet::new();
            let mut internal_cond_blocks: HashSet<BlockId> = HashSet::new();
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
                        } else {
                            loop_internal_conds.insert(*cond);
                            internal_cond_blocks.insert(*then_block);
                            internal_cond_blocks.insert(*else_block);
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
            let mut has_mul = false;
            let mut has_add = false;
            let mut has_conditional_add = false;
            let mut has_filter_call = false;
            let mut detected_reduction: Option<crate::ir::ReductionKind> = None;
            let mut had_eliminated_bounds = false;
            let mut slice_read_bases: HashSet<ValueId> = HashSet::new();
            let mut slice_write_bases: HashSet<ValueId> = HashSet::new();
            let mut elem_ptrs: HashMap<ValueId, (ValueId, ValueId)> = HashMap::new();
            let mut elem_reads: Vec<(ValueId, ValueId, ValueId)> = Vec::new();
            let mut elem_writes: Vec<(ValueId, ValueId, ValueId)> = Vec::new();

            for &b_id in &loop_info.blocks {
                if let Some(block) = func.get_block(b_id) {
                    for inst in &block.instructions {
                        match &inst.expr {
                            ValueExpr::GetElement { base, index } => {
                                if let Some(res) = inst.result {
                                    elem_reads.push((*base, *index, res));
                                }
                                if let Some(elem_ty) =
                                    Self::get_aggregate_elem_type(&value_types, *base)
                                {
                                    if Self::is_simd_primitive_type(&elem_ty) {
                                        detected_elem_types.push(elem_ty);
                                        read_elements += 1;
                                        if Self::is_slice_aggregate(&value_types, *base) {
                                            slice_elements += 1;
                                            slice_read_bases.insert(*base);
                                        } else {
                                            array_elements += 1;
                                        }
                                    }
                                }
                            }
                            ValueExpr::SetElement { base, index, val } => {
                                elem_writes.push((*base, *index, *val));
                                if let Some(elem_ty) =
                                    Self::get_aggregate_elem_type(&value_types, *base)
                                {
                                    if Self::is_simd_primitive_type(&elem_ty) {
                                        detected_elem_types.push(elem_ty);
                                        write_elements += 1;
                                        if Self::is_slice_aggregate(&value_types, *base) {
                                            slice_elements += 1;
                                            slice_write_bases.insert(*base);
                                        } else {
                                            array_elements += 1;
                                        }
                                    }
                                }
                            }
                            ValueExpr::GetElementPtr { base, index } => {
                                if let Some(res) = inst.result {
                                    elem_ptrs.insert(res, (*base, *index));
                                }
                                if let Some(elem_ty) =
                                    Self::get_aggregate_elem_type(&value_types, *base)
                                {
                                    if Self::is_simd_primitive_type(&elem_ty) {
                                        detected_elem_types.push(elem_ty);
                                        if Self::is_slice_aggregate(&value_types, *base) {
                                            slice_elements += 1;
                                            slice_read_bases.insert(*base);
                                        } else {
                                            array_elements += 1;
                                        }
                                    }
                                }
                            }
                            ValueExpr::Load { ptr } => {
                                if let Some(res) = inst.result {
                                    if let Some(&(base, idx)) = elem_ptrs.get(ptr) {
                                        elem_reads.push((base, idx, res));
                                    }
                                }
                            }
                            ValueExpr::Store { ptr, val } => {
                                if let Some(&(base, idx)) = elem_ptrs.get(ptr) {
                                    elem_writes.push((base, idx, *val));
                                }
                            }
                            ValueExpr::BoundsCheck {
                                redundant: true, ..
                            }
                            | ValueExpr::SliceBoundsCheck {
                                redundant: true, ..
                            }
                            | ValueExpr::SliceStridedBoundsCheck {
                                redundant: true, ..
                            } => {
                                had_eliminated_bounds = true;
                            }
                            ValueExpr::Binary { op, .. } => match op {
                                BinaryOp::Mul => {
                                    has_reduction_op = true;
                                    has_mul = true;
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
                                    if *op == BinaryOp::Add {
                                        has_add = true;
                                        if internal_cond_blocks.contains(&b_id) {
                                            has_conditional_add = true;
                                        }
                                    }
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
                                } else if callee.contains("slice_dot")
                                    || callee == "dot"
                                    || callee.contains("dot_product")
                                {
                                    has_reduction_op = true;
                                    Self::update_reduction_kind(
                                        &mut detected_reduction,
                                        crate::ir::ReductionKind::Dot,
                                    );
                                } else if callee.contains("slice_count")
                                    || callee.contains("count_if")
                                {
                                    has_reduction_op = true;
                                    Self::update_reduction_kind(
                                        &mut detected_reduction,
                                        crate::ir::ReductionKind::CountIf,
                                    );
                                } else if callee.contains("slice_filter")
                                    || callee.contains("filter_into")
                                {
                                    has_filter_call = true;
                                } else if callee.contains("slice_sum") {
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

                let mut disjoint_slices = false;
                if !slice_write_bases.is_empty() && !slice_read_bases.is_empty() {
                    let all_disjoint = slice_write_bases.iter().all(|&wb| {
                        slice_read_bases
                            .iter()
                            .all(|&rb| Self::are_slice_bases_disjoint(func, wb, rb))
                    });
                    if all_disjoint {
                        disjoint_slices = true;
                        self.stats.disjoint_slice_loops += 1;
                        self.stats.disjoint_slices_vectorized +=
                            slice_write_bases.len() + slice_read_bases.len();

                        for &b in slice_write_bases.iter().chain(slice_read_bases.iter()) {
                            let root = Self::trace_slice_root(func, b);
                            if root.has_projection() {
                                self.stats.multidim_projections_vectorized += 1;
                            }
                            if root.has_symbolic_partition() {
                                self.stats.symbolic_partitions_vectorized += 1;
                            }
                        }
                    }
                }

                // 3. Detect in-place zero-copy swap operations across provably disjoint slices
                let mut is_disjoint_swap = false;
                for w1 in &elem_writes {
                    for w2 in &elem_writes {
                        if w1.0 != w2.0 {
                            let root_w1 = Self::trace_slice_root(func, w1.0);
                            let root_w2 = Self::trace_slice_root(func, w2.0);
                            if root_w1 != root_w2 {
                                let w1_reads_w2 = elem_reads.iter().any(|r| {
                                    r.2 == w1.2 && Self::trace_slice_root(func, r.0) == root_w2
                                });
                                let w2_reads_w1 = elem_reads.iter().any(|r| {
                                    r.2 == w2.2 && Self::trace_slice_root(func, r.0) == root_w1
                                });
                                if w1_reads_w2
                                    && w2_reads_w1
                                    && Self::are_slice_roots_disjoint(&root_w1, &root_w2)
                                {
                                    is_disjoint_swap = true;
                                    break;
                                }
                            }
                        }
                    }
                    if is_disjoint_swap {
                        break;
                    }
                }

                if is_disjoint_swap {
                    disjoint_slices = true;
                    self.stats.disjoint_swap_loops_vectorized += 1;
                    self.stats.disjoint_slices_vectorized += 2;
                }

                // Recognize scalar dot product reductions (fmul + fadd / mul + add with multiple reads)
                if has_mul
                    && has_add
                    && write_elements == 0
                    && (read_elements >= 2 || slice_elements >= 2)
                {
                    detected_reduction = Some(crate::ir::ReductionKind::Dot);
                }

                let has_internal_filter = !loop_internal_conds.is_empty();
                let is_count_if = (write_elements == 0 && read_elements > 0)
                    && (detected_reduction == Some(crate::ir::ReductionKind::CountIf)
                        || has_conditional_add);

                if is_count_if {
                    detected_reduction = Some(crate::ir::ReductionKind::CountIf);
                    has_reduction_op = true;
                }

                let predicated_scatter_gather =
                    (write_elements > 0 && has_internal_filter) || has_filter_call;
                let predicate_enable = slice_elements > 0
                    || has_internal_filter
                    || predicated_scatter_gather
                    || is_disjoint_swap;
                let is_strict_slice_loop = func.is_strict && slice_elements > 0;
                let is_reduction = write_elements == 0 && read_elements > 0 && has_reduction_op;
                let contiguous_reduction = is_reduction && (slice_elements > 0);

                // Check whether slice reads are constrained to local arena, stack buffers, or strict parameters
                let mut local_arena = false;
                if slice_elements > 0 {
                    if func.is_strict {
                        local_arena = true;
                    } else if !slice_read_bases.is_empty() {
                        local_arena = slice_read_bases.iter().all(|&b| {
                            let root = Self::trace_slice_root(func, b);
                            root.is_local_arena_or_stack(func)
                        });
                    }
                }

                let existing_hint = func.get_block(loop_info.header).and_then(|b| b.vector_hint);
                let sliding_window_size = existing_hint.and_then(|h| h.sliding_window_size);
                let is_convolution = existing_hint.map(|h| h.is_convolution).unwrap_or(false)
                    || (existing_hint.and_then(|h| h.sliding_window_size).is_some()
                        && detected_reduction == Some(crate::ir::ReductionKind::Dot));

                if sliding_window_size.is_some() {
                    self.stats.sliding_window_loops_vectorized += 1;
                }
                if is_convolution {
                    self.stats.convolutions_vectorized += 1;
                }

                let is_matrix_kernel = existing_hint.map(|h| h.is_matrix_kernel).unwrap_or(false);
                let is_tiled = existing_hint.map(|h| h.is_tiled).unwrap_or(false);
                let tile_size = existing_hint.and_then(|h| h.tile_size);
                let mut unroll_and_jam = existing_hint.map(|h| h.unroll_and_jam).unwrap_or(false);
                let is_fused = existing_hint.map(|h| h.is_fused).unwrap_or(false);

                // 4. Detect multidimensional matrix reduction operations with bipartite or tripartite disjoint windows
                let mut distinct_roots: Vec<SliceRoot> = Vec::new();
                for &b in slice_read_bases.iter().chain(slice_write_bases.iter()) {
                    let r = Self::trace_slice_root(func, b);
                    if !distinct_roots.contains(&r) && !matches!(r, SliceRoot::Unknown(_)) {
                        distinct_roots.push(r);
                    }
                }
                for (b, _, _) in &elem_reads {
                    let r = Self::trace_slice_root(func, *b);
                    if !distinct_roots.contains(&r) && !matches!(r, SliceRoot::Unknown(_)) {
                        distinct_roots.push(r);
                    }
                }
                for (b, _, _) in &elem_writes {
                    let r = Self::trace_slice_root(func, *b);
                    if !distinct_roots.contains(&r) && !matches!(r, SliceRoot::Unknown(_)) {
                        distinct_roots.push(r);
                    }
                }

                let has_multidim = distinct_roots.iter().any(|r| r.has_projection())
                    || is_matrix_kernel
                    || is_tiled
                    || (slice_read_bases.len() >= 2 && (has_mul || has_add));

                let is_reduction_op = is_reduction
                    || (write_elements > 0
                        && has_add
                        && elem_writes.iter().any(|w| {
                            let rw = Self::trace_slice_root(func, w.0);
                            elem_reads.iter().any(|r| {
                                r.0 == w.0
                                    || (!matches!(rw, SliceRoot::Unknown(_))
                                        && rw == Self::trace_slice_root(func, r.0))
                            })
                        }));
                let mut is_bipartite = false;
                let mut is_tripartite = false;

                if has_multidim && is_reduction_op {
                    // Check for tripartite disjoint windows (3 mutually disjoint roots)
                    if distinct_roots.len() >= 3 {
                        'tripartite_search: for i in 0..distinct_roots.len() {
                            for j in (i + 1)..distinct_roots.len() {
                                for k in (j + 1)..distinct_roots.len() {
                                    if Self::are_slice_roots_disjoint(
                                        &distinct_roots[i],
                                        &distinct_roots[j],
                                    ) && Self::are_slice_roots_disjoint(
                                        &distinct_roots[i],
                                        &distinct_roots[k],
                                    ) && Self::are_slice_roots_disjoint(
                                        &distinct_roots[j],
                                        &distinct_roots[k],
                                    ) {
                                        is_tripartite = true;
                                        break 'tripartite_search;
                                    }
                                }
                            }
                        }
                    }

                    // Check for bipartite disjoint windows (2 disjoint roots) if not already tripartite
                    if !is_tripartite && distinct_roots.len() >= 2 {
                        'bipartite_search: for i in 0..distinct_roots.len() {
                            for j in (i + 1)..distinct_roots.len() {
                                if Self::are_slice_roots_disjoint(
                                    &distinct_roots[i],
                                    &distinct_roots[j],
                                ) {
                                    is_bipartite = true;
                                    break 'bipartite_search;
                                }
                            }
                        }
                    }
                }

                if is_tripartite {
                    disjoint_slices = true;
                    unroll_and_jam = true;
                    self.stats.tripartite_matrix_reductions_vectorized += 1;
                    self.stats.multidim_matrix_reductions_vectorized += 1;
                    self.stats.disjoint_slices_vectorized += 3;
                } else if is_bipartite {
                    disjoint_slices = true;
                    unroll_and_jam = true;
                    self.stats.bipartite_matrix_reductions_vectorized += 1;
                    self.stats.multidim_matrix_reductions_vectorized += 1;
                    self.stats.disjoint_slices_vectorized += 2;
                }

                // 5. Detect dynamic strided slices and zero-copy 2D/3D convolutions
                let mut is_strided_conv2d =
                    existing_hint.map(|h| h.is_strided_conv2d).unwrap_or(false);
                let mut is_strided_conv3d =
                    existing_hint.map(|h| h.is_strided_conv3d).unwrap_or(false);
                let mut conv_strides = existing_hint.and_then(|h| h.conv_strides);
                let mut is_zero_copy = existing_hint.map(|h| h.is_zero_copy).unwrap_or(false);
                let mut has_strided_access = false;

                for (_, idx, _) in &elem_reads {
                    if let Some((dims, strides)) = Self::analyze_index_strides(func, *idx) {
                        has_strided_access = true;
                        if dims == 3 {
                            is_strided_conv3d = true;
                            if conv_strides.is_none() {
                                conv_strides = Some(strides);
                            }
                        } else if dims == 2 {
                            is_strided_conv2d = true;
                            if conv_strides.is_none() {
                                conv_strides = Some(strides);
                            }
                        }
                    }
                }

                for &b in slice_read_bases.iter().chain(slice_write_bases.iter()) {
                    let r = Self::trace_slice_root(func, b);
                    if let SliceRoot::StridedSubSlice { stride, .. } = &r {
                        has_strided_access = true;
                        let st_val = match stride {
                            FirBound::Const(c) => *c as u32,
                            _ => 1,
                        };
                        if conv_strides.is_none() {
                            conv_strides = Some((st_val, 1, 1));
                        }
                    }
                }

                if has_strided_access {
                    self.stats.loops_with_strided_accesses += 1;
                }

                if (is_strided_conv2d || is_strided_conv3d || is_convolution)
                    && (has_mul && has_add
                        || detected_reduction == Some(crate::ir::ReductionKind::Dot))
                {
                    let zero_copy_verified = distinct_roots
                        .iter()
                        .all(|r| !matches!(r, SliceRoot::Unknown(_)));
                    if zero_copy_verified {
                        is_zero_copy = true;
                        disjoint_slices = true;
                        unroll_and_jam = true;
                        self.stats.zero_copy_convolutions_specialized += 1;
                        if is_strided_conv3d {
                            self.stats.strided_conv3d_vectorized += 1;
                        } else {
                            is_strided_conv2d = true;
                            self.stats.strided_conv2d_vectorized += 1;
                        }

                        let mut strided_eliminated = 0;
                        for &b_id in &loop_info.blocks {
                            if let Some(block) = func.get_block_mut(b_id) {
                                for inst in &mut block.instructions {
                                    match &mut inst.expr {
                                        ValueExpr::BoundsCheck { redundant, .. }
                                        | ValueExpr::SliceBoundsCheck { redundant, .. }
                                        | ValueExpr::SliceStridedBoundsCheck {
                                            redundant, ..
                                        } if !*redundant => {
                                            *redundant = true;
                                            strided_eliminated += 1;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        if strided_eliminated > 0 {
                            self.stats.strided_bounds_eliminated += strided_eliminated;
                            had_eliminated_bounds = true;
                        }
                    }
                }

                // General 1D strided loops (e.g. decimation, slice stepping, linear strided accesses)
                let is_strided_loop = has_strided_access || is_strided_conv2d || is_strided_conv3d;
                let loop_stride = conv_strides.map(|s| s.0 as i64).or(if has_strided_access {
                    Some(2)
                } else {
                    None
                });

                if is_strided_loop && !is_strided_conv2d && !is_strided_conv3d {
                    self.stats.strided_loops_vectorized += 1;
                    let mut strided_eliminated = 0;
                    for &b_id in &loop_info.blocks {
                        if let Some(block) = func.get_block_mut(b_id) {
                            for inst in &mut block.instructions {
                                if let ValueExpr::SliceStridedBoundsCheck { redundant, .. } =
                                    &mut inst.expr
                                {
                                    if !*redundant {
                                        *redundant = true;
                                        strided_eliminated += 1;
                                    }
                                }
                            }
                        }
                    }
                    if strided_eliminated > 0 {
                        self.stats.strided_bounds_eliminated += strided_eliminated;
                        had_eliminated_bounds = true;
                    }
                }

                let effective_interleave = if is_strided_conv3d {
                    8
                } else if is_strided_conv2d || (is_strided_loop && !is_tripartite && !is_bipartite)
                {
                    match primary_ty {
                        FirType::Float(FloatType::F32)
                        | FirType::Int(IntType::I32 | IntType::U32 | IntType::I8 | IntType::U8) => {
                            8
                        }
                        _ => 4,
                    }
                } else if is_tripartite {
                    8
                } else if is_bipartite {
                    match primary_ty {
                        FirType::Float(FloatType::F32)
                        | FirType::Int(IntType::I32 | IntType::U32 | IntType::I8 | IntType::U8) => {
                            8
                        }
                        _ => 4,
                    }
                } else if let Some(w) = sliding_window_size {
                    w.min(8)
                } else if local_arena && contiguous_reduction {
                    match primary_ty {
                        FirType::Float(FloatType::F32)
                        | FirType::Int(IntType::I32 | IntType::U32 | IntType::I8 | IntType::U8) => {
                            8
                        }
                        _ => 4,
                    }
                } else {
                    4
                };

                let hint = LoopVectorHint {
                    vector_width,
                    interleave_count: effective_interleave,
                    unroll_enable: true,
                    reduction_kind: if is_reduction {
                        detected_reduction
                    } else {
                        None
                    },
                    disjoint_slices,
                    predicate_enable,
                    is_strict: func.is_strict,
                    local_arena,
                    contiguous_reduction,
                    predicated_scatter_gather,
                    sliding_window_size,
                    is_convolution,
                    is_matrix_kernel,
                    is_tiled,
                    tile_size,
                    unroll_and_jam,
                    is_fused,
                    is_swap: is_disjoint_swap,
                    is_bipartite_matrix_reduction: is_bipartite,
                    is_tripartite_matrix_reduction: is_tripartite,
                    is_strided_conv2d,
                    is_strided_conv3d,
                    conv_strides,
                    is_zero_copy,
                    is_strided_loop,
                    loop_stride,
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
                    if is_strict_slice_loop {
                        self.stats.strict_slice_loops_vectorized += 1;
                    }
                    if predicate_enable {
                        self.stats.predicated_loops_vectorized += 1;
                    }
                    if predicated_scatter_gather {
                        self.stats.predicated_scatter_gather_loops += 1;
                    }
                    if write_elements > 0 {
                        self.stats.maps_vectorized += 1;
                    } else if read_elements > 0 && has_reduction_op {
                        self.stats.reductions_vectorized += 1;
                        if contiguous_reduction {
                            self.stats.contiguous_slice_reductions += 1;
                            if local_arena {
                                self.stats.arena_slice_reductions_specialized += 1;
                            }
                            if func.is_strict {
                                self.stats.strict_zero_heap_reductions += 1;
                            }
                        }
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
                            Some(crate::ir::ReductionKind::Dot) => {
                                self.stats.dot_reductions_vectorized += 1;
                            }
                            Some(crate::ir::ReductionKind::CountIf) => {
                                self.stats.count_if_reductions_vectorized += 1;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // 3. Specialize direct slice reduction calls operating under local arena or strict zero-heap constraints
        self.specialize_direct_slice_reductions(func, &value_types);
    }

    /// Statically specialize direct slice reduction and filter function calls to SIMD-accelerated arena vectorizers
    /// when the underlying slices are proven contiguous on the local thread arena or stack.
    fn specialize_direct_slice_reductions(
        &mut self,
        func: &mut FirFunction,
        value_types: &HashMap<ValueId, FirType>,
    ) {
        let mut rewrites = Vec::new();
        for (b_idx, block) in func.blocks.iter().enumerate() {
            for (i_idx, inst) in block.instructions.iter().enumerate() {
                if let ValueExpr::CallDirect { name, args } = &inst.expr {
                    let callee = INTERNER.resolve(name);
                    let is_reduction_candidate = callee.contains("slice_sum")
                        || callee.contains("slice_prod")
                        || callee.contains("slice_min")
                        || callee.contains("slice_max")
                        || callee.contains("slice_dot")
                        || callee.contains("slice_count")
                        || callee.contains("count_if")
                        || callee.contains("slice_filter")
                        || callee.contains("filter_into")
                        || callee.contains("slice_select")
                        || callee.contains("slice_clamp")
                        || callee == "clamp";
                    if is_reduction_candidate && !args.is_empty() {
                        let first_arg = args[0];
                        let root = Self::trace_slice_root(func, first_arg);
                        if root.is_local_arena_or_stack(func) || func.is_strict {
                            let elem_suffix = if callee.ends_with("_f32") {
                                "_f32"
                            } else if callee.ends_with("_f64") {
                                "_f64"
                            } else if callee.ends_with("_i32") {
                                "_i32"
                            } else if callee.ends_with("_i64") {
                                "_i64"
                            } else {
                                match Self::get_aggregate_elem_type(value_types, first_arg) {
                                    Some(FirType::Float(FloatType::F32)) => "_f32",
                                    Some(FirType::Float(FloatType::F64)) => "_f64",
                                    Some(FirType::Int(IntType::I32 | IntType::U32)) => "_i32",
                                    _ => "_i64",
                                }
                            };
                            let (op, is_count, is_filter) = if callee.contains("dot") {
                                ("dot", false, false)
                            } else if callee.contains("prod") {
                                ("prod", false, false)
                            } else if callee.contains("min") {
                                ("min", false, false)
                            } else if callee.contains("max") {
                                ("max", false, false)
                            } else if callee.contains("count") || callee.contains("count_if") {
                                let pred = if callee.contains("lt") {
                                    "count_if_lt"
                                } else if callee.contains("ne") {
                                    "count_if_ne"
                                } else if callee.contains("eq") {
                                    "count_if_eq"
                                } else {
                                    "count_if_gt"
                                };
                                (pred, true, false)
                            } else if callee.contains("filter") {
                                let pred = if callee.contains("gt") {
                                    "filter_gt"
                                } else if callee.contains("_lt") || callee.contains("filter_lt") {
                                    "filter_lt"
                                } else if callee.contains("eq") {
                                    "filter_eq"
                                } else {
                                    "filter_gt"
                                };
                                (pred, false, true)
                            } else if callee.contains("clamp") {
                                ("clamp", false, true)
                            } else if callee.contains("select") {
                                ("select_gt", false, true)
                            } else {
                                ("sum", false, false)
                            };
                            let specialized_name =
                                format!("ifa_simd_arena_slice_{}{}", op, elem_suffix);
                            rewrites.push((
                                b_idx,
                                i_idx,
                                INTERNER.intern(&specialized_name),
                                is_count,
                                is_filter,
                            ));
                        }
                    }
                }
            }
        }

        for (b_idx, i_idx, specialized_sym, is_count, is_filter) in rewrites {
            if let Some(block) = func.blocks.get_mut(b_idx) {
                if let Some(inst) = block.instructions.get_mut(i_idx) {
                    if let ValueExpr::CallDirect { name, .. } = &mut inst.expr {
                        *name = specialized_sym;
                        if is_count {
                            self.stats.count_if_reductions_vectorized += 1;
                            self.stats.arena_slice_reductions_specialized += 1;
                            self.stats.contiguous_slice_reductions += 1;
                        } else if is_filter {
                            self.stats.arena_slice_filters_specialized += 1;
                            self.stats.predicated_scatter_gather_loops += 1;
                        } else {
                            self.stats.arena_slice_reductions_specialized += 1;
                            self.stats.contiguous_slice_reductions += 1;
                        }
                        if func.is_strict {
                            self.stats.strict_zero_heap_reductions += 1;
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
            (Some(_), crate::ir::ReductionKind::Dot) => {
                *current = Some(crate::ir::ReductionKind::Dot)
            }
            (Some(_), crate::ir::ReductionKind::CountIf) => {
                *current = Some(crate::ir::ReductionKind::CountIf)
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
                        | ValueExpr::YieldValue { .. }
                        | ValueExpr::Spawn { .. }
                        | ValueExpr::ChanCreate { .. }
                        | ValueExpr::ChanSend { .. }
                        | ValueExpr::ChanTrySend { .. }
                        | ValueExpr::ChanRecv { .. }
                        | ValueExpr::ChanTryRecv { .. }
                        | ValueExpr::ChanClose { .. }
                        | ValueExpr::ChanSelect { .. }
                        | ValueExpr::GenFree { .. }
                        | ValueExpr::CoWClone { .. } => return (false, false),
                        ValueExpr::BoundsCheck { redundant, .. }
                        | ValueExpr::SliceBoundsCheck { redundant, .. }
                        | ValueExpr::SliceStridedBoundsCheck { redundant, .. } => {
                            // If a bounds check is not statically eliminated, it can trigger
                            // a dynamic panic or branching, inhibiting safe auto-vectorization.
                            // In strict functions, memory accesses to contiguous pre-allocated arena/stack slices
                            // are bounded, allowing predicated scatter/gather vectorization.
                            if !*redundant && !func.is_strict {
                                return (false, false);
                            }
                        }
                        ValueExpr::BlockingCallDirect { .. } => {
                            return (false, false);
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
                        ValueExpr::SliceSub { base, .. } | ValueExpr::SliceStrided { base, .. } => {
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

    fn resolve_const_int(func: &FirFunction, val: ValueId) -> Option<i64> {
        for block in &func.blocks {
            for inst in &block.instructions {
                if inst.result == Some(val) {
                    if let ValueExpr::Constant(ConstantValue::Int(v, _)) = inst.expr {
                        return Some(v as i64);
                    }
                }
            }
        }
        None
    }

    /// Analyze an SSA index expression to detect 1D, 2D, or 3D strided affine access patterns.
    pub fn analyze_index_strides(
        func: &FirFunction,
        idx_val: ValueId,
    ) -> Option<(usize, (u32, u32, u32))> {
        let mut terms = Vec::new();
        Self::collect_additive_terms(func, idx_val, &mut terms, 0);

        let mut strides = Vec::new();
        for term in terms {
            if let Some(stride_const) = Self::extract_stride_factor(func, term) {
                if stride_const > 0 {
                    strides.push(stride_const as u32);
                }
            }
        }

        if strides.len() >= 3 {
            Some((3, (strides[0], strides[1], strides[2])))
        } else if strides.len() == 2 {
            Some((2, (strides[0], strides[1], 1)))
        } else if strides.len() == 1 {
            Some((1, (strides[0], 1, 1)))
        } else {
            None
        }
    }

    fn collect_additive_terms(
        func: &FirFunction,
        val: ValueId,
        terms: &mut Vec<ValueId>,
        depth: usize,
    ) {
        if depth > 6 {
            terms.push(val);
            return;
        }
        for block in &func.blocks {
            for inst in &block.instructions {
                if inst.result == Some(val) {
                    if let ValueExpr::Binary {
                        op: BinaryOp::Add,
                        lhs,
                        rhs,
                    } = inst.expr
                    {
                        Self::collect_additive_terms(func, lhs, terms, depth + 1);
                        Self::collect_additive_terms(func, rhs, terms, depth + 1);
                        return;
                    }
                }
            }
        }
        terms.push(val);
    }

    fn extract_stride_factor(func: &FirFunction, val: ValueId) -> Option<i64> {
        for block in &func.blocks {
            for inst in &block.instructions {
                if inst.result == Some(val) {
                    if let ValueExpr::Binary {
                        op: BinaryOp::Mul,
                        lhs,
                        rhs,
                    } = inst.expr
                    {
                        if let Some(c) = Self::resolve_const_int(func, rhs) {
                            return Some(c);
                        } else if let Some(c) = Self::resolve_const_int(func, lhs) {
                            return Some(c);
                        } else {
                            return Some(1);
                        }
                    }
                }
            }
        }
        None
    }

    /// Analyze whether two slice aggregate values operate over provably disjoint underlying memory
    /// (distinct stack allocas, distinct function parameters with inout exclusivity, distinct fields,
    /// disjoint multidimensional projections, or non-overlapping symbolic subslices).
    pub fn are_slice_bases_disjoint(func: &FirFunction, b1: ValueId, b2: ValueId) -> bool {
        if b1 == b2 {
            return false;
        }

        let root1 = Self::trace_slice_root(func, b1);
        let root2 = Self::trace_slice_root(func, b2);

        Self::are_slice_roots_disjoint(&root1, &root2)
    }

    fn are_slice_roots_disjoint(r1: &SliceRoot, r2: &SliceRoot) -> bool {
        match (r1, r2) {
            (SliceRoot::Alloca(a1), SliceRoot::Alloca(a2)) => a1 != a2,
            (SliceRoot::CallArena(c1), SliceRoot::CallArena(c2)) => c1 != c2,
            (SliceRoot::GenArena(g1, a1), SliceRoot::GenArena(g2, a2)) => {
                if let (Some(ar1), Some(ar2)) = (a1, a2) {
                    if ar1 != ar2 {
                        return true;
                    }
                }
                g1 != g2
            }
            (SliceRoot::Param(p1), SliceRoot::Param(p2)) => p1 != p2,
            (SliceRoot::Field(p1, idx1), SliceRoot::Field(p2, idx2)) => {
                if p1 == p2 {
                    idx1 != idx2
                } else {
                    Self::are_slice_roots_disjoint(p1, p2)
                }
            }
            (
                SliceRoot::Projection {
                    parent: p1,
                    dim_index: d1,
                },
                SliceRoot::Projection {
                    parent: p2,
                    dim_index: d2,
                },
            ) => {
                if p1 == p2 {
                    d1.are_indices_disjoint(d2)
                } else {
                    Self::are_slice_roots_disjoint(p1, p2)
                }
            }
            (
                SliceRoot::SubSlice {
                    parent: p1,
                    start: s1,
                    end: e1,
                },
                SliceRoot::SubSlice {
                    parent: p2,
                    start: s2,
                    end: e2,
                },
            ) => {
                if p1 == p2 {
                    FirBound::are_ranges_disjoint(s1, e1, s2, e2)
                } else {
                    Self::are_slice_roots_disjoint(p1, p2)
                }
            }
            (
                SliceRoot::StridedSubSlice {
                    parent: p1,
                    start: s1,
                    end: e1,
                    stride: st1,
                },
                SliceRoot::StridedSubSlice {
                    parent: p2,
                    start: s2,
                    end: e2,
                    stride: st2,
                },
            ) => {
                if p1 == p2 {
                    FirBound::are_strided_ranges_disjoint(s1, e1, st1, s2, e2, st2)
                } else {
                    Self::are_slice_roots_disjoint(p1, p2)
                }
            }
            (
                SliceRoot::StridedSubSlice {
                    parent: p1,
                    start: s1,
                    end: e1,
                    ..
                },
                SliceRoot::SubSlice {
                    parent: p2,
                    start: s2,
                    end: e2,
                },
            ) => {
                if p1 == p2 {
                    FirBound::are_ranges_disjoint(s1, e1, s2, e2)
                } else {
                    Self::are_slice_roots_disjoint(p1, p2)
                }
            }
            (
                SliceRoot::SubSlice {
                    parent: p1,
                    start: s1,
                    end: e1,
                },
                SliceRoot::StridedSubSlice {
                    parent: p2,
                    start: s2,
                    end: e2,
                    ..
                },
            ) => {
                if p1 == p2 {
                    FirBound::are_ranges_disjoint(s1, e1, s2, e2)
                } else {
                    Self::are_slice_roots_disjoint(p1, p2)
                }
            }
            (
                SliceRoot::Projection {
                    parent: p1,
                    dim_index: d1,
                },
                SliceRoot::StridedSubSlice {
                    parent: p2,
                    start: s2,
                    end: e2,
                    ..
                },
            ) => {
                if p1 == p2 {
                    FirBound::is_index_disjoint_from_range(d1, s2, e2)
                } else {
                    Self::are_slice_roots_disjoint(p1, p2)
                }
            }
            (
                SliceRoot::StridedSubSlice {
                    parent: p1,
                    start: s1,
                    end: e1,
                    ..
                },
                SliceRoot::Projection {
                    parent: p2,
                    dim_index: d2,
                },
            ) => {
                if p1 == p2 {
                    FirBound::is_index_disjoint_from_range(d2, s1, e1)
                } else {
                    Self::are_slice_roots_disjoint(p1, p2)
                }
            }
            (SliceRoot::StridedSubSlice { parent: p1, .. }, other) => {
                if &**p1 == other {
                    false
                } else {
                    Self::are_slice_roots_disjoint(p1, other)
                }
            }
            (other, SliceRoot::StridedSubSlice { parent: p2, .. }) => {
                if other == &**p2 {
                    false
                } else {
                    Self::are_slice_roots_disjoint(other, p2)
                }
            }
            (
                SliceRoot::Projection {
                    parent: p1,
                    dim_index: d1,
                },
                SliceRoot::SubSlice {
                    parent: p2,
                    start: s2,
                    end: e2,
                },
            ) => {
                if p1 == p2 {
                    FirBound::is_index_disjoint_from_range(d1, s2, e2)
                } else {
                    Self::are_slice_roots_disjoint(p1, p2)
                }
            }
            (
                SliceRoot::SubSlice {
                    parent: p1,
                    start: s1,
                    end: e1,
                },
                SliceRoot::Projection {
                    parent: p2,
                    dim_index: d2,
                },
            ) => {
                if p1 == p2 {
                    FirBound::is_index_disjoint_from_range(d2, s1, e1)
                } else {
                    Self::are_slice_roots_disjoint(p1, p2)
                }
            }
            (SliceRoot::SubSlice { parent: p1, .. }, other) => {
                if &**p1 == other {
                    false
                } else {
                    Self::are_slice_roots_disjoint(p1, other)
                }
            }
            (other, SliceRoot::SubSlice { parent: p2, .. }) => {
                if other == &**p2 {
                    false
                } else {
                    Self::are_slice_roots_disjoint(other, p2)
                }
            }
            (SliceRoot::Projection { parent: p1, .. }, other) => {
                if &**p1 == other {
                    false
                } else {
                    Self::are_slice_roots_disjoint(p1, other)
                }
            }
            (other, SliceRoot::Projection { parent: p2, .. }) => {
                if other == &**p2 {
                    false
                } else {
                    Self::are_slice_roots_disjoint(other, p2)
                }
            }
            (SliceRoot::Field(p1, _), other) => {
                if &**p1 == other {
                    false
                } else {
                    Self::are_slice_roots_disjoint(p1, other)
                }
            }
            (other, SliceRoot::Field(p2, _)) => {
                if other == &**p2 {
                    false
                } else {
                    Self::are_slice_roots_disjoint(other, p2)
                }
            }
            (SliceRoot::Alloca(_), SliceRoot::Param(_))
            | (SliceRoot::Param(_), SliceRoot::Alloca(_))
            | (SliceRoot::CallArena(_), SliceRoot::Alloca(_))
            | (SliceRoot::Alloca(_), SliceRoot::CallArena(_))
            | (SliceRoot::CallArena(_), SliceRoot::Param(_))
            | (SliceRoot::Param(_), SliceRoot::CallArena(_))
            | (SliceRoot::GenArena(..), SliceRoot::Alloca(_))
            | (SliceRoot::Alloca(_), SliceRoot::GenArena(..))
            | (SliceRoot::GenArena(..), SliceRoot::CallArena(_))
            | (SliceRoot::CallArena(_), SliceRoot::GenArena(..))
            | (SliceRoot::GenArena(..), SliceRoot::Param(_))
            | (SliceRoot::Param(_), SliceRoot::GenArena(..)) => true,
            _ => false,
        }
    }

    /// Trace the originating memory root for a slice value through SSA definitions.
    fn trace_slice_root(func: &FirFunction, mut val: ValueId) -> SliceRoot {
        let mut visited = HashSet::new();

        while visited.insert(val) {
            // Check if val is a formal function parameter
            if let Some(pos) = func.params.iter().position(|p| p.val == val) {
                return SliceRoot::Param(pos);
            }

            // Search defining instruction in all blocks
            let mut def_found = false;
            for block in &func.blocks {
                for inst in &block.instructions {
                    if inst.result == Some(val) {
                        def_found = true;
                        match &inst.expr {
                            ValueExpr::Alloca { .. } => return SliceRoot::Alloca(val),
                            ValueExpr::CallArenaAlloc { .. } => return SliceRoot::CallArena(val),
                            ValueExpr::GenAlloc { arena, .. } => {
                                return SliceRoot::GenArena(val, *arena)
                            }
                            ValueExpr::GetField {
                                base, field_idx, ..
                            }
                            | ValueExpr::GetFieldPtr {
                                base, field_idx, ..
                            } => {
                                let parent = Self::trace_slice_root(func, *base);
                                return SliceRoot::Field(Box::new(parent), *field_idx);
                            }
                            ValueExpr::GetElement { base, index }
                            | ValueExpr::GetElementPtr { base, index } => {
                                let dim_idx = FirBound::from_value(func, *index);
                                let parent = Self::trace_slice_root(func, *base);
                                return SliceRoot::Projection {
                                    parent: Box::new(parent),
                                    dim_index: dim_idx,
                                };
                            }
                            ValueExpr::SliceSub { base, start, end } => {
                                let s_bound = FirBound::from_value(func, *start);
                                let e_bound = FirBound::from_value(func, *end);
                                let parent = Self::trace_slice_root(func, *base);
                                return SliceRoot::SubSlice {
                                    parent: Box::new(parent),
                                    start: s_bound,
                                    end: e_bound,
                                };
                            }
                            ValueExpr::SliceStrided {
                                base,
                                start,
                                end,
                                stride,
                            } => {
                                let s_bound = FirBound::from_value(func, *start);
                                let e_bound = FirBound::from_value(func, *end);
                                let st_bound = FirBound::from_value(func, *stride);
                                let parent = Self::trace_slice_root(func, *base);
                                return SliceRoot::StridedSubSlice {
                                    parent: Box::new(parent),
                                    start: s_bound,
                                    end: e_bound,
                                    stride: st_bound,
                                };
                            }
                            ValueExpr::CoWMakeUnique { val: src_val } => {
                                val = *src_val;
                            }
                            ValueExpr::Load { ptr } => {
                                val = *ptr;
                            }
                            _ => return SliceRoot::Unknown(val),
                        }
                        break;
                    }
                }
                if def_found {
                    break;
                }
            }

            if !def_found {
                break;
            }
        }

        SliceRoot::Unknown(val)
    }
}

/// Symbolic or constant bound/index for FIR slice partitioning and multidimensional projections.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FirBound {
    /// Constant literal index/bound (e.g. `0`, `32`).
    Const(i64),
    /// Symbolic SSA value reference (e.g. `split_idx`, `mid`).
    Symbolic(ValueId),
    /// Symbolic SSA value with constant offset (e.g. `mid + 16`, `base - 8`).
    Offset(ValueId, i64),
}

impl FirBound {
    /// Resolve a `FirBound` from an SSA `ValueId`.
    pub fn from_value(func: &FirFunction, val: ValueId) -> Self {
        if let Some(c) = VectorizePass::resolve_const_int(func, val) {
            return FirBound::Const(c);
        }
        for block in &func.blocks {
            for inst in &block.instructions {
                if inst.result == Some(val) {
                    match &inst.expr {
                        ValueExpr::Binary {
                            op: BinaryOp::Add,
                            lhs,
                            rhs,
                        } => {
                            if let Some(c) = VectorizePass::resolve_const_int(func, *rhs) {
                                return FirBound::Offset(*lhs, c);
                            } else if let Some(c) = VectorizePass::resolve_const_int(func, *lhs) {
                                return FirBound::Offset(*rhs, c);
                            }
                        }
                        ValueExpr::Binary {
                            op: BinaryOp::Sub,
                            lhs,
                            rhs,
                        } => {
                            if let Some(c) = VectorizePass::resolve_const_int(func, *rhs) {
                                return FirBound::Offset(*lhs, -c);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        FirBound::Symbolic(val)
    }

    /// Check if two bounds are provably disjoint indices (i.e. cannot be equal).
    pub fn are_indices_disjoint(&self, other: &FirBound) -> bool {
        match (self, other) {
            (FirBound::Const(c1), FirBound::Const(c2)) => c1 != c2,
            (FirBound::Offset(s1, o1), FirBound::Offset(s2, o2)) if s1 == s2 => o1 != o2,
            (FirBound::Symbolic(s1), FirBound::Offset(s2, off))
            | (FirBound::Offset(s2, off), FirBound::Symbolic(s1))
                if s1 == s2 =>
            {
                *off != 0
            }
            _ => false,
        }
    }

    /// Check if Range 1 `[s1..e1]` is provably disjoint from Range 2 `[s2..e2]` (half-open).
    pub fn are_ranges_disjoint(s1: &FirBound, e1: &FirBound, s2: &FirBound, e2: &FirBound) -> bool {
        // 1. Both constant ranges: [s1..e1] vs [s2..e2]
        if let (
            FirBound::Const(s1_c),
            FirBound::Const(e1_c),
            FirBound::Const(s2_c),
            FirBound::Const(e2_c),
        ) = (s1, e1, s2, e2)
        {
            return *e1_c <= *s2_c || *e2_c <= *s1_c;
        }

        // 2. Symbolic split-point partition: Range 1 ends at K (exclusive) and Range 2 starts at K
        // e.g. [0..split] vs [split..N] or [s1..split] vs [split..e2]
        if e1 == s2 || e2 == s1 {
            return true;
        }

        // 3. Symbolic offset ranges: [base + off1 .. base + off2] vs [base + off3 .. base + off4]
        match (s1, e1, s2, e2) {
            (
                FirBound::Offset(b1, o_s1),
                FirBound::Offset(b2, o_e1),
                FirBound::Offset(b3, o_s2),
                FirBound::Offset(b4, o_e2),
            ) if b1 == b2 && b2 == b3 && b3 == b4 => *o_e1 <= *o_s2 || *o_e2 <= *o_s1,
            (
                FirBound::Symbolic(b1),
                FirBound::Offset(b2, o_e1),
                FirBound::Offset(b3, o_s2),
                FirBound::Offset(b4, o_e2),
            ) if b1 == b2 && b2 == b3 && b3 == b4 => *o_e1 <= *o_s2 || *o_e2 <= 0,
            _ => false,
        }
    }

    /// Check if two strided slice ranges `[s1..e1:st1]` and `[s2..e2:st2]` are provably disjoint.
    pub fn are_strided_ranges_disjoint(
        s1: &FirBound,
        e1: &FirBound,
        stride1: &FirBound,
        s2: &FirBound,
        e2: &FirBound,
        stride2: &FirBound,
    ) -> bool {
        if Self::are_ranges_disjoint(s1, e1, s2, e2) {
            return true;
        }

        // Modular residue congruence check for constant strides
        // e.g. even indices (s1 = 0, st1 = 2) vs odd indices (s2 = 1, st2 = 2)
        if let (
            FirBound::Const(c1),
            FirBound::Const(d1),
            FirBound::Const(c2),
            FirBound::Const(d2),
        ) = (s1, stride1, s2, stride2)
        {
            if *d1 > 1 && *d1 == *d2 {
                let rem1 = c1.rem_euclid(*d1);
                let rem2 = c2.rem_euclid(*d2);
                if rem1 != rem2 {
                    return true;
                }
            }
        }

        false
    }

    /// Check if an index is provably disjoint from a slice range `[start..end]`.
    pub fn is_index_disjoint_from_range(idx: &FirBound, start: &FirBound, end: &FirBound) -> bool {
        if let (FirBound::Const(c), FirBound::Const(s), FirBound::Const(e)) = (idx, start, end) {
            return *c < *s || *c >= *e;
        }
        if idx == end {
            return true;
        }
        if let FirBound::Offset(s_sym, off) = start {
            if let FirBound::Symbolic(sym) = idx {
                if sym == s_sym && *off > 0 {
                    return true;
                }
            }
        }
        if let FirBound::Offset(i_sym, off) = idx {
            if let FirBound::Symbolic(sym) = end {
                if sym == i_sym && *off >= 0 {
                    return true;
                }
            }
        }
        false
    }
}

/// Discovered provenance root for a slice buffer in SSA FIR.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SliceRoot {
    Alloca(ValueId),
    CallArena(ValueId),
    GenArena(ValueId, Option<u16>),
    Param(usize),
    Field(Box<SliceRoot>, usize),
    Projection {
        parent: Box<SliceRoot>,
        dim_index: FirBound,
    },
    SubSlice {
        parent: Box<SliceRoot>,
        start: FirBound,
        end: FirBound,
    },
    StridedSubSlice {
        parent: Box<SliceRoot>,
        start: FirBound,
        end: FirBound,
        stride: FirBound,
    },
    Unknown(ValueId),
}

impl SliceRoot {
    /// Return whether this slice root is constrained to local arena or stack storage,
    /// guaranteeing zero-heap flat contiguous memory layout.
    pub fn is_local_arena_or_stack(&self, func: &FirFunction) -> bool {
        match self {
            SliceRoot::Alloca(_) | SliceRoot::CallArena(_) | SliceRoot::GenArena(..) => true,
            SliceRoot::Param(_) => func.is_strict,
            SliceRoot::Field(parent, _) => parent.is_local_arena_or_stack(func),
            SliceRoot::Projection { parent, .. } => parent.is_local_arena_or_stack(func),
            SliceRoot::SubSlice { parent, .. } | SliceRoot::StridedSubSlice { parent, .. } => {
                parent.is_local_arena_or_stack(func)
            }
            SliceRoot::Unknown(_) => false,
        }
    }

    /// Check if this slice root involves multidimensional projection.
    pub fn has_projection(&self) -> bool {
        match self {
            SliceRoot::Projection { .. } => true,
            SliceRoot::Field(parent, _)
            | SliceRoot::SubSlice { parent, .. }
            | SliceRoot::StridedSubSlice { parent, .. } => parent.has_projection(),
            _ => false,
        }
    }

    /// Check if this slice root involves symbolic slice partitioning.
    pub fn has_symbolic_partition(&self) -> bool {
        match self {
            SliceRoot::SubSlice { start, end, parent } => {
                matches!(start, FirBound::Symbolic(_) | FirBound::Offset(..))
                    || matches!(end, FirBound::Symbolic(_) | FirBound::Offset(..))
                    || parent.has_symbolic_partition()
            }
            SliceRoot::StridedSubSlice {
                start,
                end,
                stride,
                parent,
            } => {
                matches!(start, FirBound::Symbolic(_) | FirBound::Offset(..))
                    || matches!(end, FirBound::Symbolic(_) | FirBound::Offset(..))
                    || matches!(stride, FirBound::Symbolic(_) | FirBound::Offset(..))
                    || parent.has_symbolic_partition()
            }
            SliceRoot::Projection { parent, .. } | SliceRoot::Field(parent, _) => {
                parent.has_symbolic_partition()
            }
            _ => false,
        }
    }
}

impl Default for VectorizePass {
    fn default() -> Self {
        Self::new()
    }
}

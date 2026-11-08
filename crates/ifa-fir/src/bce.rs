use crate::cfg::ControlFlowGraph;
use crate::dominance::DominanceTree;
use crate::gen_opt::GenerationalOptPass;
use crate::ir::*;
use crate::types::FirType;
use ifa_span::Span;
use std::collections::{HashMap, HashSet};

/// Statistics collected by the Bounds Check Elimination (BCE) pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BceStats {
    /// Total number of static and dynamic bounds check instructions encountered.
    pub total_checks: usize,
    /// Number of bounds checks successfully eliminated.
    pub eliminated_checks: usize,
    /// Number of bounds checks eliminated through constant propagation.
    pub constant_checks_eliminated: usize,
    /// Number of bounds checks eliminated through loop induction variable analysis.
    pub loop_induction_checks_eliminated: usize,
    /// Number of redundant bounds checks eliminated via dominance tree traversal.
    pub dominance_checks_eliminated: usize,
    /// Number of invariant bounds checks hoisted out of loops into preheaders.
    pub hoisted_checks: usize,
}

impl BceStats {
    /// Percentage of bounds checks statically eliminated (0.0 to 100.0).
    pub fn elimination_rate(&self) -> f64 {
        if self.total_checks == 0 {
            100.0
        } else {
            (self.eliminated_checks as f64 / self.total_checks as f64) * 100.0
        }
    }
}

/// Optimizes array and slice accesses by statically eliminating redundant bounds verification
/// through constant propagation, induction variable range analysis on loops, dominance trees,
/// and loop-invariant check hoisting (LICM).
pub struct BcePass {
    stats: BceStats,
}

type InferredRanges = (
    HashMap<ValueId, i64>,
    HashMap<ValueId, usize>,
    HashMap<ValueId, usize>,
    HashMap<ValueId, ValueId>,
);

impl BcePass {
    /// Creates a new Bounds Check Elimination pass instance.
    pub fn new() -> Self {
        Self {
            stats: BceStats::default(),
        }
    }

    /// Returns the accumulated statistics of this pass.
    pub fn stats(&self) -> BceStats {
        self.stats
    }

    /// Runs the Bounds Check Elimination pass on all functions of a FIR module.
    pub fn run_on_module(&mut self, module: &mut FirModule) {
        for func in &mut module.functions {
            self.run_on_function(func);
        }
    }

    /// Runs the complete BCE pipeline on a single FIR function.
    pub fn run_on_function(&mut self, func: &mut FirFunction) {
        let cfg = ControlFlowGraph::build(func);
        let dom_tree = DominanceTree::build(&cfg);

        // 1. Infer constants, array capacities, and slice bounds
        let ranges = Self::infer_ranges(func);
        let (constants, array_capacities, slice_lengths, aliases) = &ranges;

        // 2. Loop-Invariant Check Hoisting (LICM for Bounds Checks)
        self.hoist_loop_invariant_checks(func, &cfg, &dom_tree, constants, aliases);

        // 3. Constant Propagation Elimination
        self.eliminate_constant_checks(func, constants, array_capacities, slice_lengths, aliases);

        // 4. Induction Variable Range Elimination in Natural Loops
        self.eliminate_loop_induction_checks(func, &cfg, &dom_tree, &ranges);

        // 5. Dominance-based and Lexical Redundancy Elimination
        self.eliminate_dominance_checks(func, &dom_tree, aliases);
    }

    /// Resolves a value through single-store load alias chains to its canonical root definition.
    fn canonical(mut val: ValueId, aliases: &HashMap<ValueId, ValueId>) -> ValueId {
        let mut visited = HashSet::new();
        while let Some(&target) = aliases.get(&val) {
            if !visited.insert(val) {
                break;
            }
            val = target;
        }
        val
    }

    /// Gathers statically known integer constants and container sizes across the function.
    fn infer_ranges(func: &FirFunction) -> InferredRanges {
        let mut constants: HashMap<ValueId, i64> = HashMap::new();
        let mut array_capacities: HashMap<ValueId, usize> = HashMap::new();
        let mut slice_lengths: HashMap<ValueId, usize> = HashMap::new();
        let mut aliases: HashMap<ValueId, ValueId> = HashMap::new();

        for param in &func.params {
            if let FirType::Array(_, count) = &param.ty {
                array_capacities.insert(param.val, *count as usize);
            }
        }
        for block in &func.blocks {
            for (p_val, p_ty) in &block.params {
                if let FirType::Array(_, count) = p_ty {
                    array_capacities.insert(*p_val, *count as usize);
                }
            }
        }

        // Single-store memory tracking to forward constants and arrays through allocas
        let mut store_counts: HashMap<ValueId, usize> = HashMap::new();
        let mut single_store_val: HashMap<ValueId, ValueId> = HashMap::new();
        for block in &func.blocks {
            for inst in &block.instructions {
                if let ValueExpr::Store { ptr, val } = &inst.expr {
                    *store_counts.entry(*ptr).or_default() += 1;
                    single_store_val.insert(*ptr, *val);
                }
            }
        }
        single_store_val.retain(|ptr, _| store_counts.get(ptr) == Some(&1));

        for block in &func.blocks {
            for inst in &block.instructions {
                if let ValueExpr::Load { ptr } = &inst.expr {
                    if let (Some(res), Some(&val)) = (inst.result, single_store_val.get(ptr)) {
                        aliases.insert(res, val);
                    }
                }
            }
        }

        // Scan instructions iteratively to resolve constant expressions and sizes
        for _ in 0..3 {
            for block in &func.blocks {
                for inst in &block.instructions {
                    if let Some(res) = inst.result {
                        match &inst.expr {
                            ValueExpr::Constant(ConstantValue::Int(v, _)) => {
                                constants.insert(res, *v as i64);
                            }
                            ValueExpr::Alloca {
                                ty: FirType::Array(_, count),
                                ..
                            } => {
                                array_capacities.insert(res, *count as usize);
                            }
                            ValueExpr::ArrayInit(elems) => {
                                array_capacities.insert(res, elems.len());
                            }
                            ValueExpr::Load { ptr } => {
                                if let Some(&stored) = single_store_val.get(ptr) {
                                    if let Some(&c) = constants.get(&stored) {
                                        constants.insert(res, c);
                                    }
                                    if let Some(&cap) = array_capacities.get(&stored) {
                                        array_capacities.insert(res, cap);
                                    }
                                    if let Some(&slen) = slice_lengths.get(&stored) {
                                        slice_lengths.insert(res, slen);
                                    }
                                }
                                if let Some(&cap) = array_capacities.get(ptr) {
                                    array_capacities.insert(res, cap);
                                }
                                if let Some(&slen) = slice_lengths.get(ptr) {
                                    slice_lengths.insert(res, slen);
                                }
                            }
                            ValueExpr::ArrayLen { array } => {
                                if let Some(&cap) = array_capacities.get(array) {
                                    constants.insert(res, cap as i64);
                                } else if let Some(&slen) = slice_lengths.get(array) {
                                    constants.insert(res, slen as i64);
                                }
                            }
                            ValueExpr::SliceSub { base, start, end } => {
                                if let (Some(&s), Some(&e)) =
                                    (constants.get(start), constants.get(end))
                                {
                                    if e >= s && s >= 0 {
                                        slice_lengths.insert(res, (e - s) as usize);
                                    }
                                } else if let Some(&cap) = array_capacities
                                    .get(base)
                                    .or_else(|| slice_lengths.get(base))
                                {
                                    slice_lengths.insert(res, cap);
                                }
                            }
                            ValueExpr::SliceStrided {
                                base,
                                start,
                                end,
                                stride,
                            } => {
                                if let (Some(&s), Some(&e), Some(&st)) = (
                                    constants.get(start),
                                    constants.get(end),
                                    constants.get(stride),
                                ) {
                                    if e >= s && s >= 0 && st > 0 {
                                        slice_lengths.insert(res, ((e - s + st - 1) / st) as usize);
                                    }
                                } else if let Some(&cap) = array_capacities
                                    .get(base)
                                    .or_else(|| slice_lengths.get(base))
                                {
                                    slice_lengths.insert(res, cap);
                                }
                            }
                            ValueExpr::Binary { op, lhs, rhs } => {
                                if let (Some(&l), Some(&r)) =
                                    (constants.get(lhs), constants.get(rhs))
                                {
                                    let folded = match op {
                                        BinaryOp::Add => Some(l.wrapping_add(r)),
                                        BinaryOp::Sub => Some(l.wrapping_sub(r)),
                                        BinaryOp::Mul => Some(l.wrapping_mul(r)),
                                        _ => None,
                                    };
                                    if let Some(val) = folded {
                                        constants.insert(res, val);
                                    }
                                }
                            }
                            _ => {}
                        }
                    } else if let ValueExpr::Store { ptr, val } = &inst.expr {
                        if let Some(&cap) = array_capacities.get(val) {
                            array_capacities.insert(*ptr, cap);
                        }
                        if let Some(&slen) = slice_lengths.get(val) {
                            slice_lengths.insert(*ptr, slen);
                        }
                    }
                }
            }
        }

        (constants, array_capacities, slice_lengths, aliases)
    }

    /// Hoists loop-invariant bounds checks into loop preheaders.
    fn hoist_loop_invariant_checks(
        &mut self,
        func: &mut FirFunction,
        cfg: &ControlFlowGraph,
        dom_tree: &DominanceTree,
        constants: &HashMap<ValueId, i64>,
        aliases: &HashMap<ValueId, ValueId>,
    ) {
        let loops = GenerationalOptPass::find_natural_loops(cfg, dom_tree);
        let param_values: HashSet<ValueId> = func.params.iter().map(|p| p.val).collect();

        let mut def_block: HashMap<ValueId, BlockId> = HashMap::new();
        for param in &func.params {
            def_block.insert(param.val, func.entry_block);
        }
        for block in &func.blocks {
            for (p_val, _) in &block.params {
                def_block.insert(*p_val, block.id);
            }
            for inst in &block.instructions {
                if let Some(res) = inst.result {
                    def_block.insert(res, block.id);
                }
            }
        }

        for loop_info in loops {
            let preheader_id = match loop_info.preheader {
                Some(p) => p,
                None => continue,
            };

            let mut hoisted_candidates: Vec<(ValueId, ValueId, Span)> = Vec::new();

            for &b_id in &loop_info.blocks {
                if let Some(block) = func.get_block(b_id) {
                    for inst in &block.instructions {
                        if let ValueExpr::BoundsCheck {
                            base,
                            index,
                            redundant,
                        } = &inst.expr
                        {
                            if !*redundant {
                                let c_base = Self::canonical(*base, aliases);
                                let c_index = Self::canonical(*index, aliases);
                                let base_outside = param_values.contains(base)
                                    || param_values.contains(&c_base)
                                    || def_block.get(base).is_some_and(|&d| {
                                        !loop_info.blocks.contains(&d)
                                            && dom_tree.dominates(d, preheader_id)
                                    })
                                    || def_block.get(&c_base).is_some_and(|&d| {
                                        !loop_info.blocks.contains(&d)
                                            && dom_tree.dominates(d, preheader_id)
                                    });
                                let index_outside = param_values.contains(index)
                                    || param_values.contains(&c_index)
                                    || constants.contains_key(index)
                                    || constants.contains_key(&c_index)
                                    || def_block.get(index).is_some_and(|&d| {
                                        !loop_info.blocks.contains(&d)
                                            && dom_tree.dominates(d, preheader_id)
                                    })
                                    || def_block.get(&c_index).is_some_and(|&d| {
                                        !loop_info.blocks.contains(&d)
                                            && dom_tree.dominates(d, preheader_id)
                                    });

                                if base_outside && index_outside {
                                    hoisted_candidates.push((*base, *index, inst.span));
                                }
                            }
                        }
                    }
                }
            }

            for (base, index, span) in hoisted_candidates {
                let c_base = Self::canonical(base, aliases);
                let c_index = Self::canonical(index, aliases);
                let already_in_preheader = func.get_block(preheader_id).is_some_and(|pb| {
                    pb.instructions.iter().any(|inst| match &inst.expr {
                        ValueExpr::BoundsCheck {
                            base: b, index: i, ..
                        } => {
                            let cb = Self::canonical(*b, aliases);
                            let ci = Self::canonical(*i, aliases);
                            (*b == base && *i == index) || (cb == c_base && ci == c_index)
                        }
                        _ => false,
                    })
                });

                if !already_in_preheader {
                    if let Some(pb) = func.get_block_mut(preheader_id) {
                        let check_inst = Instruction::new(
                            None,
                            ValueExpr::BoundsCheck {
                                base,
                                index,
                                redundant: false,
                            },
                            span,
                        );
                        pb.instructions.push(check_inst);
                        self.stats.hoisted_checks += 1;
                    }
                }

                // Mark inside-loop checks as redundant
                for &b_id in &loop_info.blocks {
                    if let Some(block) = func.get_block_mut(b_id) {
                        for inst in &mut block.instructions {
                            if let ValueExpr::BoundsCheck {
                                base: b,
                                index: i,
                                redundant,
                            } = &mut inst.expr
                            {
                                let cb = Self::canonical(*b, aliases);
                                let ci = Self::canonical(*i, aliases);
                                if ((*b == base && *i == index) || (cb == c_base && ci == c_index))
                                    && !*redundant
                                {
                                    *redundant = true;
                                    self.stats.eliminated_checks += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Statically eliminates bounds checks whose indices and container bounds are constant.
    fn eliminate_constant_checks(
        &mut self,
        func: &mut FirFunction,
        constants: &HashMap<ValueId, i64>,
        array_capacities: &HashMap<ValueId, usize>,
        slice_lengths: &HashMap<ValueId, usize>,
        aliases: &HashMap<ValueId, ValueId>,
    ) {
        for block in &mut func.blocks {
            for inst in &mut block.instructions {
                match &mut inst.expr {
                    ValueExpr::BoundsCheck {
                        base,
                        index,
                        redundant,
                    } => {
                        if !*redundant {
                            self.stats.total_checks += 1;
                            let c_base = Self::canonical(*base, aliases);
                            let c_idx = Self::canonical(*index, aliases);
                            if let Some(&idx) =
                                constants.get(index).or_else(|| constants.get(&c_idx))
                            {
                                if idx >= 0 {
                                    let cap = array_capacities
                                        .get(base)
                                        .or_else(|| array_capacities.get(&c_base))
                                        .copied()
                                        .or_else(|| {
                                            slice_lengths
                                                .get(base)
                                                .or_else(|| slice_lengths.get(&c_base))
                                                .copied()
                                        });
                                    if let Some(bound) = cap {
                                        if (idx as usize) < bound {
                                            *redundant = true;
                                            self.stats.eliminated_checks += 1;
                                            self.stats.constant_checks_eliminated += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    ValueExpr::SliceBoundsCheck {
                        base,
                        start,
                        end,
                        redundant,
                    } if !*redundant => {
                        self.stats.total_checks += 1;
                        let c_base = Self::canonical(*base, aliases);
                        let c_start = Self::canonical(*start, aliases);
                        let c_end = Self::canonical(*end, aliases);
                        let s_opt = constants.get(start).or_else(|| constants.get(&c_start));
                        let e_opt = constants.get(end).or_else(|| constants.get(&c_end));
                        if let (Some(&s), Some(&e)) = (s_opt, e_opt) {
                            if s >= 0 && e >= s {
                                let cap = array_capacities
                                    .get(base)
                                    .or_else(|| array_capacities.get(&c_base))
                                    .copied()
                                    .or_else(|| {
                                        slice_lengths
                                            .get(base)
                                            .or_else(|| slice_lengths.get(&c_base))
                                            .copied()
                                    });
                                if let Some(bound) = cap {
                                    if (e as usize) <= bound {
                                        *redundant = true;
                                        self.stats.eliminated_checks += 1;
                                        self.stats.constant_checks_eliminated += 1;
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Eliminates bounds checks within loops when an induction variable is bounded by array length.
    fn eliminate_loop_induction_checks(
        &mut self,
        func: &mut FirFunction,
        cfg: &ControlFlowGraph,
        dom_tree: &DominanceTree,
        ranges: &InferredRanges,
    ) {
        let (constants, array_capacities, slice_lengths, aliases) = ranges;
        let loops = GenerationalOptPass::find_natural_loops(cfg, dom_tree);

        for loop_info in loops {
            let header_block = match func.get_block(loop_info.header) {
                Some(b) => b,
                None => continue,
            };

            // Detect loop condition: Lt comparison of induction variable against upper limit
            let mut induction_var: Option<ValueId> = None;
            let mut induction_limit: Option<ValueId> = None;
            let mut induction_limit_arr: Option<ValueId> = None;
            let mut constant_limit: Option<usize> = None;

            for inst in &header_block.instructions {
                if let ValueExpr::Binary {
                    op: BinaryOp::Lt,
                    lhs,
                    rhs,
                } = &inst.expr
                {
                    induction_var = Some(*lhs);
                    induction_limit = Some(*rhs);

                    let c_rhs = Self::canonical(*rhs, aliases);
                    if let Some(&c) = constants.get(rhs).or_else(|| constants.get(&c_rhs)) {
                        if c >= 0 {
                            constant_limit = Some(c as usize);
                        }
                    }
                }
            }

            // Also check if induction limit comes from an ArrayLen instruction
            if let Some(limit_val) = induction_limit {
                let c_lim = Self::canonical(limit_val, aliases);
                for b in &func.blocks {
                    for inst in &b.instructions {
                        if inst.result == Some(limit_val) || inst.result == Some(c_lim) {
                            if let ValueExpr::ArrayLen { array } = &inst.expr {
                                induction_limit_arr = Some(*array);
                            }
                        }
                    }
                }
            }

            let mut induction_limit_ptr: Option<ValueId> = None;
            if let Some(arr_val) = induction_limit_arr {
                let c_arr = Self::canonical(arr_val, aliases);
                for b in &func.blocks {
                    for inst in &b.instructions {
                        if inst.result == Some(arr_val) || inst.result == Some(c_arr) {
                            if let ValueExpr::Load { ptr } = &inst.expr {
                                induction_limit_ptr = Some(*ptr);
                            }
                        }
                    }
                }
            }

            let ind_var = match induction_var {
                Some(v) => v,
                None => continue,
            };
            let c_ind = Self::canonical(ind_var, aliases);

            let mut induction_var_ptr: Option<ValueId> = None;
            for inst in &header_block.instructions {
                if inst.result == Some(ind_var) {
                    if let ValueExpr::Load { ptr } = &inst.expr {
                        induction_var_ptr = Some(*ptr);
                    }
                }
            }

            // Eliminate matching bounds checks in the loop body
            for &b_id in &loop_info.blocks {
                if b_id == loop_info.header {
                    continue;
                }
                if let Some(block) = func.get_block_mut(b_id) {
                    let mut body_aliases: HashSet<ValueId> = HashSet::new();
                    body_aliases.insert(ind_var);
                    body_aliases.insert(c_ind);
                    let mut ptr_modified = false;

                    for inst in &mut block.instructions {
                        if let ValueExpr::Store { ptr, .. } = &inst.expr {
                            if Some(*ptr) == induction_var_ptr {
                                ptr_modified = true;
                            }
                        }
                        if !ptr_modified {
                            if let ValueExpr::Load { ptr } = &inst.expr {
                                if Some(*ptr) == induction_var_ptr {
                                    if let Some(res) = inst.result {
                                        body_aliases.insert(res);
                                    }
                                }
                            }
                        }

                        if let ValueExpr::BoundsCheck {
                            base,
                            index,
                            redundant,
                        } = &mut inst.expr
                        {
                            let c_base = Self::canonical(*base, aliases);
                            let c_idx = Self::canonical(*index, aliases);
                            let is_ind_idx =
                                body_aliases.contains(index) || body_aliases.contains(&c_idx);
                            if !*redundant && is_ind_idx {
                                let mut is_safe = false;
                                if let Some(lim_arr) = induction_limit_arr {
                                    let c_lim_arr = Self::canonical(lim_arr, aliases);
                                    if *base == lim_arr
                                        || c_base == lim_arr
                                        || c_base == c_lim_arr
                                        || Some(*base) == induction_limit_ptr
                                        || Some(c_base) == induction_limit_ptr
                                    {
                                        is_safe = true;
                                    }
                                }
                                if !is_safe {
                                    if let Some(lim_c) = constant_limit {
                                        let cap = array_capacities
                                            .get(base)
                                            .or_else(|| array_capacities.get(&c_base))
                                            .copied()
                                            .or_else(|| {
                                                slice_lengths
                                                    .get(base)
                                                    .or_else(|| slice_lengths.get(&c_base))
                                                    .copied()
                                            });
                                        if let Some(c) = cap {
                                            if lim_c <= c {
                                                is_safe = true;
                                            }
                                        }
                                    }
                                }

                                if is_safe {
                                    *redundant = true;
                                    self.stats.eliminated_checks += 1;
                                    self.stats.loop_induction_checks_eliminated += 1;
                                }
                            }
                        }
                        if let ValueExpr::SliceBoundsCheck {
                            base,
                            start: _,
                            end,
                            redundant,
                        } = &mut inst.expr
                        {
                            let c_base = Self::canonical(*base, aliases);
                            let c_end = Self::canonical(*end, aliases);
                            let is_ind_end =
                                body_aliases.contains(end) || body_aliases.contains(&c_end);
                            if !*redundant && is_ind_end {
                                let mut is_safe = false;
                                if let Some(lim_arr) = induction_limit_arr {
                                    let c_lim_arr = Self::canonical(lim_arr, aliases);
                                    if *base == lim_arr
                                        || c_base == lim_arr
                                        || c_base == c_lim_arr
                                        || Some(*base) == induction_limit_ptr
                                        || Some(c_base) == induction_limit_ptr
                                    {
                                        is_safe = true;
                                    }
                                }
                                if !is_safe {
                                    if let Some(lim_c) = constant_limit {
                                        let cap = array_capacities
                                            .get(base)
                                            .or_else(|| array_capacities.get(&c_base))
                                            .copied()
                                            .or_else(|| {
                                                slice_lengths
                                                    .get(base)
                                                    .or_else(|| slice_lengths.get(&c_base))
                                                    .copied()
                                            });
                                        if let Some(c) = cap {
                                            if lim_c <= c {
                                                is_safe = true;
                                            }
                                        }
                                    }
                                }

                                if is_safe {
                                    *redundant = true;
                                    self.stats.eliminated_checks += 1;
                                    self.stats.loop_induction_checks_eliminated += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Eliminates subsequent checks that are strictly dominated by identical preceding checks.
    fn eliminate_dominance_checks(
        &mut self,
        func: &mut FirFunction,
        dom_tree: &DominanceTree,
        aliases: &HashMap<ValueId, ValueId>,
    ) {
        let mut checked_indices: HashMap<BlockId, HashSet<(ValueId, ValueId)>> = HashMap::new();
        let mut checked_slices: HashMap<BlockId, HashSet<(ValueId, ValueId, ValueId)>> =
            HashMap::new();

        for &b_id in &dom_tree.rpo_blocks {
            let mut current_block_indices: HashSet<(ValueId, ValueId)> = HashSet::new();
            let mut current_block_slices: HashSet<(ValueId, ValueId, ValueId)> = HashSet::new();

            if let Some(block) = func.get_block_mut(b_id) {
                for inst in &mut block.instructions {
                    match &mut inst.expr {
                        ValueExpr::BoundsCheck {
                            base,
                            index,
                            redundant,
                        } => {
                            if !*redundant {
                                let key = (
                                    Self::canonical(*base, aliases),
                                    Self::canonical(*index, aliases),
                                );
                                let already_checked = current_block_indices.contains(&key)
                                    || dom_tree.rpo_blocks.iter().any(|&prev_b| {
                                        prev_b != b_id
                                            && dom_tree.dominates(prev_b, b_id)
                                            && checked_indices
                                                .get(&prev_b)
                                                .is_some_and(|set| set.contains(&key))
                                    });

                                if already_checked {
                                    *redundant = true;
                                    self.stats.eliminated_checks += 1;
                                    self.stats.dominance_checks_eliminated += 1;
                                } else {
                                    current_block_indices.insert(key);
                                }
                            }
                        }
                        ValueExpr::SliceBoundsCheck {
                            base,
                            start,
                            end,
                            redundant,
                        } if !*redundant => {
                            let key = (
                                Self::canonical(*base, aliases),
                                Self::canonical(*start, aliases),
                                Self::canonical(*end, aliases),
                            );
                            let already_checked = current_block_slices.contains(&key)
                                || dom_tree.rpo_blocks.iter().any(|&prev_b| {
                                    prev_b != b_id
                                        && dom_tree.dominates(prev_b, b_id)
                                        && checked_slices
                                            .get(&prev_b)
                                            .is_some_and(|set| set.contains(&key))
                                });

                            if already_checked {
                                *redundant = true;
                                self.stats.eliminated_checks += 1;
                                self.stats.dominance_checks_eliminated += 1;
                            } else {
                                current_block_slices.insert(key);
                            }
                        }
                        _ => {}
                    }
                }
            }

            checked_indices.insert(b_id, current_block_indices);
            checked_slices.insert(b_id, current_block_slices);
        }
    }

    /// Physically removes all `BoundsCheck` and `SliceBoundsCheck` instructions marked redundant.
    pub fn purge_redundant_checks(&self, func: &mut FirFunction) {
        for block in &mut func.blocks {
            block.instructions.retain(|inst| match &inst.expr {
                ValueExpr::BoundsCheck { redundant, .. }
                | ValueExpr::SliceBoundsCheck { redundant, .. } => !*redundant,
                _ => true,
            });
        }
    }
}

impl Default for BcePass {
    fn default() -> Self {
        Self::new()
    }
}

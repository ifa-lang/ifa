use crate::cfg::ControlFlowGraph;
use crate::dominance::DominanceTree;
use crate::gen_opt::GenerationalOptPass;
use crate::ir::*;
use ifa_span::Symbol;
use std::collections::{HashMap, HashSet};

/// Statistics collected by the Loop-Invariant Code Motion (LICM) pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LicmStats {
    /// Total number of field/element projection instructions hoisted out of loops.
    pub hoisted_projections: usize,
    /// Total number of invariant memory load instructions hoisted out of loops.
    pub hoisted_loads: usize,
    /// Total number of invariant bounds check instructions hoisted out of loops.
    pub hoisted_bounds_checks: usize,
    /// Total number of invariant allocation instructions hoisted out of loops.
    pub hoisted_allocs: usize,
    /// Total number of invariant generational reference instructions hoisted out of loops.
    pub hoisted_gen_refs: usize,
    /// Total number of partial aliases eliminated on disjoint composite paths.
    pub eliminated_partial_aliases: usize,
    /// Total number of loops optimized.
    pub loops_optimized: usize,
}

impl LicmStats {
    pub fn total_hoisted(&self) -> usize {
        self.hoisted_projections
            + self.hoisted_loads
            + self.hoisted_bounds_checks
            + self.hoisted_allocs
            + self.hoisted_gen_refs
            + self.eliminated_partial_aliases
    }
}

/// Classification of aliasing between FIR structured memory access paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FirPathAliasKind {
    /// Provably disjoint memory locations (NoAlias).
    Disjoint,
    /// Identical memory location (MustAlias, exact matching root, arena, and segments).
    Exact,
    /// Partial aliasing (PartialAlias): one path is an aggregate prefix of another or overlapping sub-slices.
    Partial,
}

#[derive(Debug, Clone)]
struct DisjointFieldUse {
    result: ValueId,
    field_idx: usize,
    field_name: Symbol,
}

#[derive(Debug, Clone)]
struct PartialAliasElimCandidate {
    block_id: BlockId,
    inst_index: usize,
    inst: Instruction,
    ptr: ValueId,
    disjoint_field_uses: Vec<DisjointFieldUse>,
}

/// A segment in a FIR structured memory access path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FirPathSegment {
    Field(usize),
    ElementConst(i64),
    ElementSymbolic(ValueId),
    ElementOffset(ValueId, i64),
    ElementUnknown,
    SliceConst {
        start: Option<i64>,
        end: Option<i64>,
        inclusive: bool,
    },
    SliceSymbolic {
        start: Option<ValueId>,
        end: Option<ValueId>,
    },
    Arena(u16),
    Deref,
}

/// A path-sensitive memory access descriptor representing FIR projections (e.g. `p.first.val` or `outer.data[0]`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FirAccessPath {
    pub root: ValueId,
    pub arena_id: Option<u16>,
    pub segments: Vec<FirPathSegment>,
}

impl FirAccessPath {
    /// Classifies the aliasing relationship between two FIR structured memory access paths.
    pub fn alias_kind(&self, other: &FirAccessPath) -> FirPathAliasKind {
        // Memory arena isolation: distinct non-zero generational arenas can never alias
        if let (Some(a1), Some(a2)) = (self.arena_id, other.arena_id) {
            if a1 != a2 && a1 > 0 && a2 > 0 {
                return FirPathAliasKind::Disjoint;
            }
        }

        if self.root != other.root {
            return FirPathAliasKind::Disjoint;
        }

        let min_len = self.segments.len().min(other.segments.len());
        for i in 0..min_len {
            match (&self.segments[i], &other.segments[i]) {
                (FirPathSegment::Field(f1), FirPathSegment::Field(f2)) if f1 != f2 => {
                    return FirPathAliasKind::Disjoint; // distinct fields at the same depth are provably disjoint
                }
                (FirPathSegment::ElementConst(c1), FirPathSegment::ElementConst(c2))
                    if c1 != c2 =>
                {
                    return FirPathAliasKind::Disjoint; // distinct constant element indices are provably disjoint
                }
                (
                    FirPathSegment::ElementOffset(v1, off1),
                    FirPathSegment::ElementOffset(v2, off2),
                ) if v1 == v2 && off1 != off2 => {
                    return FirPathAliasKind::Disjoint;
                }
                (FirPathSegment::ElementSymbolic(v1), FirPathSegment::ElementOffset(v2, off))
                | (FirPathSegment::ElementOffset(v2, off), FirPathSegment::ElementSymbolic(v1))
                    if v1 == v2 && *off != 0 =>
                {
                    return FirPathAliasKind::Disjoint;
                }
                (
                    FirPathSegment::SliceConst {
                        start: s1,
                        end: e1,
                        inclusive: inc1,
                    },
                    FirPathSegment::SliceConst {
                        start: s2,
                        end: e2,
                        inclusive: inc2,
                    },
                ) => {
                    let min1 = s1.unwrap_or(0);
                    let min2 = s2.unwrap_or(0);
                    if let Some(end1) = e1 {
                        let max1 = if *inc1 { *end1 } else { *end1 - 1 };
                        if max1 < min2 {
                            return FirPathAliasKind::Disjoint; // slice 1 ends strictly before slice 2 starts
                        }
                    }
                    if let Some(end2) = e2 {
                        let max2 = if *inc2 { *end2 } else { *end2 - 1 };
                        if max2 < min1 {
                            return FirPathAliasKind::Disjoint; // slice 2 ends strictly before slice 1 starts
                        }
                    }
                }
                (
                    FirPathSegment::SliceSymbolic { end: Some(e1), .. },
                    FirPathSegment::SliceSymbolic {
                        start: Some(s2), ..
                    },
                ) if e1 == s2 => {
                    return FirPathAliasKind::Disjoint; // provably disjoint symbolic split point
                }
                (
                    FirPathSegment::SliceSymbolic {
                        start: Some(s1), ..
                    },
                    FirPathSegment::SliceSymbolic { end: Some(e2), .. },
                ) if s1 == e2 => {
                    return FirPathAliasKind::Disjoint; // provably disjoint symbolic split point
                }
                (
                    FirPathSegment::ElementConst(c),
                    FirPathSegment::SliceConst {
                        start,
                        end,
                        inclusive,
                    },
                )
                | (
                    FirPathSegment::SliceConst {
                        start,
                        end,
                        inclusive,
                    },
                    FirPathSegment::ElementConst(c),
                ) => {
                    let min_idx = start.unwrap_or(0);
                    if *c < min_idx {
                        return FirPathAliasKind::Disjoint;
                    }
                    if let Some(e) = end {
                        let past_end = if *inclusive { *c > *e } else { *c >= *e };
                        if past_end {
                            return FirPathAliasKind::Disjoint;
                        }
                    }
                }
                (FirPathSegment::Arena(a1), FirPathSegment::Arena(a2))
                    if a1 != a2 && *a1 > 0 && *a2 > 0 =>
                {
                    return FirPathAliasKind::Disjoint;
                }
                _ => {}
            }
        }

        if self.segments.len() == other.segments.len() {
            let has_unknown = self
                .segments
                .iter()
                .any(|s| matches!(s, FirPathSegment::ElementUnknown));
            if has_unknown {
                FirPathAliasKind::Partial
            } else {
                FirPathAliasKind::Exact
            }
        } else {
            FirPathAliasKind::Partial
        }
    }

    /// Determines whether two access paths overlap (alias).
    /// If both paths refer to the same root, and their prefix of field/index segments match
    /// without proven disjointness, they overlap.
    pub fn overlaps(&self, other: &FirAccessPath) -> bool {
        self.alias_kind(other) != FirPathAliasKind::Disjoint
    }
}

/// Resolves a value expression to its canonical memory access path across projections.
fn resolve_access_path(
    val: ValueId,
    inst_defs: &HashMap<ValueId, ValueExpr>,
    constants: &HashMap<ValueId, i64>,
    depth: usize,
) -> FirAccessPath {
    if depth > 16 {
        return FirAccessPath {
            root: val,
            arena_id: None,
            segments: Vec::new(),
        };
    }

    if let Some(expr) = inst_defs.get(&val) {
        match expr {
            ValueExpr::GetField {
                base, field_idx, ..
            }
            | ValueExpr::GetFieldPtr {
                base, field_idx, ..
            } => {
                let mut path = resolve_access_path(*base, inst_defs, constants, depth + 1);
                path.segments.push(FirPathSegment::Field(*field_idx));
                return path;
            }
            ValueExpr::GetElement { base, index } | ValueExpr::GetElementPtr { base, index } => {
                let mut path = resolve_access_path(*base, inst_defs, constants, depth + 1);
                if let Some(&c) = constants.get(index) {
                    path.segments.push(FirPathSegment::ElementConst(c));
                } else if let Some(ValueExpr::Binary {
                    op: BinaryOp::Add,
                    lhs,
                    rhs,
                }) = inst_defs.get(index)
                {
                    if let Some(&off) = constants.get(rhs) {
                        path.segments.push(FirPathSegment::ElementOffset(*lhs, off));
                    } else if let Some(&off) = constants.get(lhs) {
                        path.segments.push(FirPathSegment::ElementOffset(*rhs, off));
                    } else {
                        path.segments.push(FirPathSegment::ElementSymbolic(*index));
                    }
                } else if let Some(ValueExpr::Binary {
                    op: BinaryOp::Sub,
                    lhs,
                    rhs,
                }) = inst_defs.get(index)
                {
                    if let Some(&off) = constants.get(rhs) {
                        path.segments
                            .push(FirPathSegment::ElementOffset(*lhs, -off));
                    } else {
                        path.segments.push(FirPathSegment::ElementSymbolic(*index));
                    }
                } else {
                    path.segments.push(FirPathSegment::ElementSymbolic(*index));
                }
                return path;
            }
            ValueExpr::SliceSub { base, start, end } => {
                let mut path = resolve_access_path(*base, inst_defs, constants, depth + 1);
                let c_start = constants.get(start).copied();
                let c_end = constants.get(end).copied();
                if c_start.is_some() || c_end.is_some() {
                    path.segments.push(FirPathSegment::SliceConst {
                        start: c_start,
                        end: c_end,
                        inclusive: false,
                    });
                } else {
                    path.segments.push(FirPathSegment::SliceSymbolic {
                        start: Some(*start),
                        end: Some(*end),
                    });
                }
                return path;
            }
            ValueExpr::GenAlloc { arena, .. } => {
                let mut path = FirAccessPath {
                    root: val,
                    arena_id: *arena,
                    segments: Vec::new(),
                };
                if let Some(a_id) = arena {
                    path.segments.push(FirPathSegment::Arena(*a_id));
                }
                return path;
            }
            ValueExpr::GenDeref { ref_val } => {
                let mut path = resolve_access_path(*ref_val, inst_defs, constants, depth + 1);
                path.segments.push(FirPathSegment::Deref);
                return path;
            }
            _ => {}
        }
    }

    FirAccessPath {
        root: val,
        arena_id: None,
        segments: Vec::new(),
    }
}

/// Loop-Invariant Code Motion (LICM) Pass for SSA FIR.
///
/// Detects natural loops and hoists:
/// 1. Invariant struct projections (`GetField`, `GetFieldPtr`, `GenDeref`, `GetElement`, `GetElementPtr`, `ArrayLen`)
/// 2. Invariant bounds checks (`BoundsCheck`, `SliceBoundsCheck`)
/// 3. Invariant memory allocations (`Alloca`) and generational references (`GenRef`, `GenCheck`)
/// 4. Invariant memory loads (`Load`)
///
/// Integrates path-sensitive exclusivity analysis (`FirAccessPath`) to prove disjointness
/// between field modifications (e.g. `outer.second`) and invariant projections/loads (e.g. `outer.first`).
pub struct LicmPass {
    stats: LicmStats,
}

impl Default for LicmPass {
    fn default() -> Self {
        Self::new()
    }
}

impl LicmPass {
    pub fn new() -> Self {
        Self {
            stats: LicmStats::default(),
        }
    }

    pub fn stats(&self) -> LicmStats {
        self.stats
    }

    /// Runs LICM on all functions in the module.
    pub fn run_on_module(&mut self, module: &mut FirModule) {
        for func in &mut module.functions {
            self.run_on_function(func);
        }
    }

    /// Runs LICM on a single function until fixed point.
    pub fn run_on_function(&mut self, func: &mut FirFunction) {
        let cfg = ControlFlowGraph::build(func);
        let dom_tree = DominanceTree::build(&cfg);
        let natural_loops = GenerationalOptPass::find_natural_loops(&cfg, &dom_tree);

        if natural_loops.is_empty() {
            return;
        }

        let param_values: HashSet<ValueId> = func.params.iter().map(|p| p.val).collect();

        // 1. Collect instruction definitions and integer constants across the function
        let mut inst_defs: HashMap<ValueId, ValueExpr> = HashMap::new();
        let mut constants: HashMap<ValueId, i64> = HashMap::new();

        for block in &func.blocks {
            for inst in &block.instructions {
                if let Some(res) = inst.result {
                    inst_defs.insert(res, inst.expr.clone());
                    if let ValueExpr::Constant(ConstantValue::Int(v, _)) = &inst.expr {
                        constants.insert(res, *v as i64);
                    }
                }
            }
        }

        // Fold simple constant binary arithmetic
        for _ in 0..2 {
            for block in &func.blocks {
                for inst in &block.instructions {
                    if let Some(res) = inst.result {
                        if let ValueExpr::Binary { op, lhs, rhs } = &inst.expr {
                            if let (Some(&l), Some(&r)) = (constants.get(lhs), constants.get(rhs)) {
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
                    }
                }
            }
        }

        for loop_info in natural_loops {
            let preheader_id = match loop_info.preheader {
                Some(p) => p,
                None => continue,
            };

            let mut loop_optimized = false;

            // Compute written memory paths and side-effect calls within loop blocks
            let mut written_paths: Vec<FirAccessPath> = Vec::new();
            let mut has_impure_call = false;
            let mut loop_has_gen_free = false;

            for &b_id in &loop_info.blocks {
                if let Some(b) = func.get_block(b_id) {
                    for inst in &b.instructions {
                        match &inst.expr {
                            ValueExpr::Store { ptr, .. } => {
                                written_paths
                                    .push(resolve_access_path(*ptr, &inst_defs, &constants, 0));
                            }
                            ValueExpr::SetField {
                                base, field_idx, ..
                            } => {
                                let mut p = resolve_access_path(*base, &inst_defs, &constants, 0);
                                p.segments.push(FirPathSegment::Field(*field_idx));
                                written_paths.push(p);
                            }
                            ValueExpr::SetElement { base, index, .. } => {
                                let mut p = resolve_access_path(*base, &inst_defs, &constants, 0);
                                if let Some(&c) = constants.get(index) {
                                    p.segments.push(FirPathSegment::ElementConst(c));
                                } else if let Some(ValueExpr::Binary {
                                    op: BinaryOp::Add,
                                    lhs,
                                    rhs,
                                }) = inst_defs.get(index)
                                {
                                    if let Some(&off) = constants.get(rhs) {
                                        p.segments.push(FirPathSegment::ElementOffset(*lhs, off));
                                    } else if let Some(&off) = constants.get(lhs) {
                                        p.segments.push(FirPathSegment::ElementOffset(*rhs, off));
                                    } else {
                                        p.segments.push(FirPathSegment::ElementSymbolic(*index));
                                    }
                                } else if let Some(ValueExpr::Binary {
                                    op: BinaryOp::Sub,
                                    lhs,
                                    rhs,
                                }) = inst_defs.get(index)
                                {
                                    if let Some(&off) = constants.get(rhs) {
                                        p.segments.push(FirPathSegment::ElementOffset(*lhs, -off));
                                    } else {
                                        p.segments.push(FirPathSegment::ElementSymbolic(*index));
                                    }
                                } else {
                                    p.segments.push(FirPathSegment::ElementSymbolic(*index));
                                }
                                written_paths.push(p);
                            }
                            ValueExpr::StructPushField {
                                base, field_idx, ..
                            } => {
                                let mut p = resolve_access_path(*base, &inst_defs, &constants, 0);
                                p.segments.push(FirPathSegment::Field(*field_idx));
                                written_paths.push(p);
                            }
                            ValueExpr::ArrayPush { array: base, .. } => {
                                written_paths
                                    .push(resolve_access_path(*base, &inst_defs, &constants, 0));
                            }
                            ValueExpr::GenFree { ptr } => {
                                loop_has_gen_free = true;
                                written_paths
                                    .push(resolve_access_path(*ptr, &inst_defs, &constants, 0));
                            }
                            ValueExpr::Call { .. }
                            | ValueExpr::BlockingCallDirect { .. }
                            | ValueExpr::Spawn { .. }
                            | ValueExpr::Yield
                            | ValueExpr::YieldValue { .. } => {
                                has_impure_call = true;
                            }
                            _ => {}
                        }
                    }
                }
            }

            // Detection and elimination of partial aliases on composite paths under SSA loop:
            // If a coarse aggregate load `Load { ptr }` in the loop overlaps with written_paths only partially
            // (i.e. written_paths only writes to disjoint sub-paths like `ptr.field_b`),
            // and inside the loop the loaded aggregate is only queried for provably disjoint sub-paths like `ptr.field_a`:
            // We eliminate the partial alias by hoisting the disjoint field access into the preheader.
            if !has_impure_call {
                // Compute current definition blocks for loop invariance
                let mut def_block_init: HashMap<ValueId, BlockId> = HashMap::new();
                for p in &func.params {
                    def_block_init.insert(p.val, func.entry_block);
                }
                for block in &func.blocks {
                    for (p_val, _) in &block.params {
                        def_block_init.insert(*p_val, block.id);
                    }
                    for inst in &block.instructions {
                        if let Some(res) = inst.result {
                            def_block_init.insert(res, block.id);
                        }
                    }
                }

                let mut eliminated_candidates: Vec<PartialAliasElimCandidate> = Vec::new();

                for &b_id in &loop_info.blocks {
                    if let Some(b) = func.get_block(b_id) {
                        for (i_idx, inst) in b.instructions.iter().enumerate() {
                            if let (Some(load_res), ValueExpr::Load { ptr }) =
                                (inst.result, &inst.expr)
                            {
                                let ptr_operands = inst.expr.uses();
                                let ptr_invariant = ptr_operands.iter().all(|u| {
                                    param_values.contains(u)
                                        || constants.contains_key(u)
                                        || def_block_init.get(u).is_some_and(|&d_b| {
                                            !loop_info.blocks.contains(&d_b)
                                                && dom_tree.dominates(d_b, preheader_id)
                                        })
                                });

                                if !ptr_invariant {
                                    continue;
                                }

                                let load_path =
                                    resolve_access_path(*ptr, &inst_defs, &constants, 0);
                                let overlaps_any =
                                    written_paths.iter().any(|w| load_path.overlaps(w));
                                if !overlaps_any {
                                    continue;
                                }

                                // Check if all overlaps are partial aliases
                                let only_partial_aliases = written_paths.iter().all(|w| {
                                    let ak = load_path.alias_kind(w);
                                    ak == FirPathAliasKind::Disjoint
                                        || ak == FirPathAliasKind::Partial
                                });

                                if !only_partial_aliases {
                                    continue;
                                }

                                // Collect all uses of load_res in the entire function
                                let mut all_uses_in_loop = Vec::new();
                                let mut used_outside_loop = false;

                                for blk in &func.blocks {
                                    let in_loop = loop_info.blocks.contains(&blk.id);
                                    for (inst_pos, other_inst) in
                                        blk.instructions.iter().enumerate()
                                    {
                                        if other_inst.expr.uses().contains(&load_res) {
                                            if in_loop {
                                                all_uses_in_loop.push((
                                                    blk.id,
                                                    inst_pos,
                                                    other_inst.clone(),
                                                ));
                                            } else {
                                                used_outside_loop = true;
                                            }
                                        }
                                    }
                                    if let Some(term) = &blk.terminator {
                                        if term.uses().contains(&load_res) {
                                            used_outside_loop = true;
                                        }
                                    }
                                }

                                if used_outside_loop || all_uses_in_loop.is_empty() {
                                    continue;
                                }

                                // Check if EVERY use in the loop is a field projection provably disjoint from written_paths
                                let mut disjoint_uses = Vec::new();
                                let mut all_uses_disjoint = true;

                                for (_u_bid, _u_idx, u_inst) in &all_uses_in_loop {
                                    match &u_inst.expr {
                                        ValueExpr::GetField {
                                            base,
                                            field_idx,
                                            field_name,
                                        } if *base == load_res => {
                                            let mut field_path = load_path.clone();
                                            field_path
                                                .segments
                                                .push(FirPathSegment::Field(*field_idx));
                                            if written_paths.iter().any(|w| field_path.overlaps(w))
                                            {
                                                all_uses_disjoint = false;
                                                break;
                                            }
                                            if let Some(res) = u_inst.result {
                                                disjoint_uses.push(DisjointFieldUse {
                                                    result: res,
                                                    field_idx: *field_idx,
                                                    field_name: *field_name,
                                                });
                                            } else {
                                                all_uses_disjoint = false;
                                                break;
                                            }
                                        }
                                        _ => {
                                            all_uses_disjoint = false;
                                            break;
                                        }
                                    }
                                }

                                if all_uses_disjoint && !disjoint_uses.is_empty() {
                                    eliminated_candidates.push(PartialAliasElimCandidate {
                                        block_id: b_id,
                                        inst_index: i_idx,
                                        inst: inst.clone(),
                                        ptr: *ptr,
                                        disjoint_field_uses: disjoint_uses,
                                    });
                                }
                            }
                        }
                    }
                }

                for cand in eliminated_candidates {
                    let hoisted_whole = func.alloc_value();
                    let mut preheader_insts = Vec::new();
                    preheader_insts.push((hoisted_whole, ValueExpr::Load { ptr: cand.ptr }));

                    for field_use in cand.disjoint_field_uses {
                        preheader_insts.push((
                            field_use.result,
                            ValueExpr::GetField {
                                base: hoisted_whole,
                                field_idx: field_use.field_idx,
                                field_name: field_use.field_name,
                            },
                        ));
                    }

                    if let Some(src_b) = func.get_block_mut(cand.block_id) {
                        if cand.inst_index < src_b.instructions.len()
                            && src_b.instructions[cand.inst_index].result == cand.inst.result
                        {
                            src_b.instructions.remove(cand.inst_index);
                        }
                    }

                    let hoisted_results: HashSet<ValueId> =
                        preheader_insts.iter().map(|(res, _)| *res).collect();
                    for &b in &loop_info.blocks {
                        if let Some(blk) = func.get_block_mut(b) {
                            blk.instructions.retain(|in_i| {
                                if let Some(r) = in_i.result {
                                    !hoisted_results.contains(&r)
                                } else {
                                    true
                                }
                            });
                        }
                    }

                    if let Some(pre_b) = func.get_block_mut(preheader_id) {
                        for (res, expr) in preheader_insts {
                            inst_defs.insert(res, expr.clone());
                            pre_b.instructions.push(Instruction::new(
                                Some(res),
                                expr,
                                cand.inst.span,
                            ));
                        }
                        self.stats.eliminated_partial_aliases += 1;
                        self.stats.hoisted_loads += 1;
                        self.stats.hoisted_projections += 1;
                        loop_optimized = true;
                    }
                }
            }

            // Perform iterative hoisting passes (up to 8 passes for nested struct access chains `p.first.second.val`)
            for _ in 0..8 {
                // Track where each value is currently defined: val -> defining BlockId
                let mut def_block: HashMap<ValueId, BlockId> = HashMap::new();
                for p in &func.params {
                    def_block.insert(p.val, func.entry_block);
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

                let mut to_hoist: Vec<(BlockId, usize, Instruction)> = Vec::new();

                for &b_id in &loop_info.blocks {
                    if let Some(block) = func.get_block(b_id) {
                        for (i_idx, inst) in block.instructions.iter().enumerate() {
                            // Check if all operands are defined outside the loop or constant
                            let operands = inst.expr.uses();
                            let all_operands_invariant = operands.iter().all(|u| {
                                param_values.contains(u)
                                    || constants.contains_key(u)
                                    || def_block.get(u).is_some_and(|&d_b| {
                                        !loop_info.blocks.contains(&d_b)
                                            && dom_tree.dominates(d_b, preheader_id)
                                    })
                            });

                            if !all_operands_invariant {
                                continue;
                            }

                            if let Some(res_val) = inst.result {
                                // Category 1: Invariant projection, allocation, or memory load
                                let is_projection = match &inst.expr {
                                    ValueExpr::GetField {
                                        base, field_idx, ..
                                    }
                                    | ValueExpr::GetFieldPtr {
                                        base, field_idx, ..
                                    } => {
                                        let mut proj_path =
                                            resolve_access_path(*base, &inst_defs, &constants, 0);
                                        proj_path.segments.push(FirPathSegment::Field(*field_idx));
                                        !written_paths.iter().any(|w| proj_path.overlaps(w))
                                    }
                                    ValueExpr::GetElement { base, index }
                                    | ValueExpr::GetElementPtr { base, index } => {
                                        let mut proj_path =
                                            resolve_access_path(*base, &inst_defs, &constants, 0);
                                        if let Some(&c) = constants.get(index) {
                                            proj_path
                                                .segments
                                                .push(FirPathSegment::ElementConst(c));
                                        } else if let Some(ValueExpr::Binary {
                                            op: BinaryOp::Add,
                                            lhs,
                                            rhs,
                                        }) = inst_defs.get(index)
                                        {
                                            if let Some(&off) = constants.get(rhs) {
                                                proj_path
                                                    .segments
                                                    .push(FirPathSegment::ElementOffset(*lhs, off));
                                            } else if let Some(&off) = constants.get(lhs) {
                                                proj_path
                                                    .segments
                                                    .push(FirPathSegment::ElementOffset(*rhs, off));
                                            } else {
                                                proj_path
                                                    .segments
                                                    .push(FirPathSegment::ElementSymbolic(*index));
                                            }
                                        } else if let Some(ValueExpr::Binary {
                                            op: BinaryOp::Sub,
                                            lhs,
                                            rhs,
                                        }) = inst_defs.get(index)
                                        {
                                            if let Some(&off) = constants.get(rhs) {
                                                proj_path.segments.push(
                                                    FirPathSegment::ElementOffset(*lhs, -off),
                                                );
                                            } else {
                                                proj_path
                                                    .segments
                                                    .push(FirPathSegment::ElementSymbolic(*index));
                                            }
                                        } else {
                                            proj_path
                                                .segments
                                                .push(FirPathSegment::ElementSymbolic(*index));
                                        }
                                        !written_paths.iter().any(|w| proj_path.overlaps(w))
                                    }
                                    ValueExpr::GenDeref { ref_val } => {
                                        let mut proj_path = resolve_access_path(
                                            *ref_val, &inst_defs, &constants, 0,
                                        );
                                        proj_path.segments.push(FirPathSegment::Deref);
                                        !written_paths.iter().any(|w| proj_path.overlaps(w))
                                    }
                                    ValueExpr::ArrayLen { array } => {
                                        let arr_path =
                                            resolve_access_path(*array, &inst_defs, &constants, 0);
                                        !written_paths.iter().any(|w| arr_path.overlaps(w))
                                    }
                                    _ => false,
                                };

                                let is_alloca = matches!(&inst.expr, ValueExpr::Alloca { .. });

                                let is_gen_ref = match &inst.expr {
                                    ValueExpr::GenRef { ptr } => {
                                        if has_impure_call || loop_has_gen_free {
                                            false
                                        } else {
                                            let ref_path = resolve_access_path(
                                                *ptr, &inst_defs, &constants, 0,
                                            );
                                            !written_paths.iter().any(|w| ref_path.overlaps(w))
                                        }
                                    }
                                    _ => false,
                                };

                                let is_safe_load = match &inst.expr {
                                    ValueExpr::Load { ptr } => {
                                        if has_impure_call {
                                            false
                                        } else {
                                            let load_path = resolve_access_path(
                                                *ptr, &inst_defs, &constants, 0,
                                            );
                                            !written_paths.iter().any(|w| load_path.overlaps(w))
                                        }
                                    }
                                    _ => false,
                                };

                                if is_projection || is_alloca || is_gen_ref || is_safe_load {
                                    to_hoist.push((b_id, i_idx, inst.clone()));
                                    def_block.insert(res_val, preheader_id);
                                    break; // Hoist one candidate per block per sub-iteration
                                }
                            } else {
                                // Category 2: Invariant array / slice bounds check (BCE) or generational check
                                match &inst.expr {
                                    ValueExpr::BoundsCheck {
                                        base, redundant, ..
                                    } if !*redundant => {
                                        let base_path =
                                            resolve_access_path(*base, &inst_defs, &constants, 0);
                                        let is_safe_container = !has_impure_call
                                            && !written_paths.iter().any(|w| base_path.overlaps(w));
                                        if is_safe_container {
                                            to_hoist.push((b_id, i_idx, inst.clone()));
                                            break;
                                        }
                                    }
                                    ValueExpr::SliceBoundsCheck {
                                        base, redundant, ..
                                    } if !*redundant => {
                                        let base_path =
                                            resolve_access_path(*base, &inst_defs, &constants, 0);
                                        let is_safe_container = !has_impure_call
                                            && !written_paths.iter().any(|w| base_path.overlaps(w));
                                        if is_safe_container {
                                            to_hoist.push((b_id, i_idx, inst.clone()));
                                            break;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }

                if to_hoist.is_empty() {
                    break;
                }

                for (src_block_id, inst_idx, inst) in to_hoist {
                    // 1. Remove from inside loop
                    if let Some(src_b) = func.get_block_mut(src_block_id) {
                        if inst_idx < src_b.instructions.len() {
                            src_b.instructions.remove(inst_idx);
                        }
                    }

                    // 2. Insert into preheader
                    let is_load = matches!(&inst.expr, ValueExpr::Load { .. });
                    let is_alloca = matches!(&inst.expr, ValueExpr::Alloca { .. });
                    let is_gen_ref = matches!(&inst.expr, ValueExpr::GenRef { .. });
                    let is_bounds_check = matches!(
                        &inst.expr,
                        ValueExpr::BoundsCheck { .. } | ValueExpr::SliceBoundsCheck { .. }
                    );

                    if is_bounds_check {
                        let already_in_preheader = func.get_block(preheader_id).is_some_and(|pb| {
                            pb.instructions.iter().any(|existing| {
                                match (&existing.expr, &inst.expr) {
                                    (
                                        ValueExpr::BoundsCheck {
                                            base: b1,
                                            index: i1,
                                            ..
                                        },
                                        ValueExpr::BoundsCheck {
                                            base: b2,
                                            index: i2,
                                            ..
                                        },
                                    ) => b1 == b2 && i1 == i2,
                                    (
                                        ValueExpr::SliceBoundsCheck {
                                            base: b1,
                                            start: s1,
                                            end: e1,
                                            ..
                                        },
                                        ValueExpr::SliceBoundsCheck {
                                            base: b2,
                                            start: s2,
                                            end: e2,
                                            ..
                                        },
                                    ) => b1 == b2 && s1 == s2 && e1 == e2,
                                    _ => false,
                                }
                            })
                        });

                        if !already_in_preheader {
                            if let Some(pre_b) = func.get_block_mut(preheader_id) {
                                pre_b.instructions.push(inst);
                                self.stats.hoisted_bounds_checks += 1;
                                loop_optimized = true;
                            }
                        } else {
                            // Redundant within preheader as well; removed from loop
                            self.stats.hoisted_bounds_checks += 1;
                            loop_optimized = true;
                        }
                    } else if let Some(pre_b) = func.get_block_mut(preheader_id) {
                        pre_b.instructions.push(inst);
                        if is_load {
                            self.stats.hoisted_loads += 1;
                        } else if is_alloca {
                            self.stats.hoisted_allocs += 1;
                        } else if is_gen_ref {
                            self.stats.hoisted_gen_refs += 1;
                        } else {
                            self.stats.hoisted_projections += 1;
                        }
                        loop_optimized = true;
                    }
                }
            }

            if loop_optimized {
                self.stats.loops_optimized += 1;
            }
        }
    }
}

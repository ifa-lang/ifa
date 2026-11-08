use crate::cfg::ControlFlowGraph;
use crate::dominance::DominanceTree;
use crate::ir::*;
use ifa_span::{Span, Symbol, INTERNER};
use std::collections::{HashMap, HashSet, VecDeque};

/// Representation of an interprocedural call-site (caller, block, instruction index, argument values).
type CallSite = (Symbol, BlockId, usize, Vec<ValueId>);

/// Describes an explicit or interprocedural memory freeing operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreeOperation {
    pub block: BlockId,
    pub ptr: ValueId,
    pub arena: Option<u16>,
}

impl FreeOperation {
    /// Determines whether this freeing operation could potentially invalidate `ref_val`.
    ///
    /// If both `self.arena` and `ref_arena` are known, non-zero, and distinct (`a1 != a2`),
    /// the memory allocations reside in strictly disjoint arenas, so this free can never
    /// affect or invalidate `ref_val`.
    pub fn interferes_with_ref(
        &self,
        ref_val: ValueId,
        ref_arena: Option<u16>,
        aliases: &HashMap<ValueId, ValueId>,
    ) -> bool {
        let canon_ref = canonical_ref(ref_val, aliases);
        let canon_free = canonical_ref(self.ptr, aliases);

        // If they resolve to the exact same canonical root value, interference is guaranteed
        if canon_ref == canon_free {
            return true;
        }

        // Memory arena isolation: distinct non-zero arenas can never alias or interfere
        if let (Some(a_ref), Some(a_free)) = (ref_arena, self.arena) {
            if a_ref > 0 && a_free > 0 && a_ref != a_free {
                return false;
            }
        }

        // Conservatively assume interference
        true
    }
}

/// Helper determining whether any freeing operation potentially interferes with `ref_val`.
fn is_interfering_free(
    free_operations: &[FreeOperation],
    ref_val: ValueId,
    ref_arena: Option<u16>,
    aliases: &HashMap<ValueId, ValueId>,
    alloca_values: &HashSet<ValueId>,
) -> bool {
    let canon_ref = canonical_ref(ref_val, aliases);
    // Stack-allocated alloca pointers reside on the function/coroutine frame and can never
    // be invalidated by heap or arena freeing operations.
    if alloca_values.contains(&ref_val) || alloca_values.contains(&canon_ref) {
        return false;
    }

    free_operations
        .iter()
        .any(|op| op.interferes_with_ref(ref_val, ref_arena, aliases))
}

/// Analysis context bundled for dominance-based generational check elimination.
struct DominanceContext<'a> {
    cfg: &'a ControlFlowGraph,
    dom_tree: &'a DominanceTree,
    free_operations: &'a [FreeOperation],
    val_arenas: &'a HashMap<ValueId, u16>,
    aliases: &'a HashMap<ValueId, ValueId>,
    callee_has_free: &'a HashMap<Symbol, bool>,
    inst_defs: &'a HashMap<ValueId, ValueExpr>,
}

/// Analysis context bundled for loop-invariant generational check hoisting.
struct LoopHoistContext<'a> {
    cfg: &'a ControlFlowGraph,
    dom_tree: &'a DominanceTree,
    free_operations: &'a [FreeOperation],
    val_arenas: &'a HashMap<ValueId, u16>,
    ref_defs: &'a HashMap<ValueId, BlockId>,
    aliases: &'a HashMap<ValueId, ValueId>,
    inst_defs: &'a HashMap<ValueId, ValueExpr>,
}

/// Statistics collected by the generational check elimination (GCE) pass.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct GenOptStats {
    pub total_checks: usize,
    pub eliminated_checks: usize,
    pub hoisted_checks: usize,
    pub interprocedural_eliminated_checks: usize,
    pub coroutine_sync_barriers_eliminated: usize,
}

impl GenOptStats {
    /// Percentage of checks statically eliminated (0.0 to 100.0).
    pub fn elimination_rate(&self) -> f64 {
        if self.total_checks == 0 {
            100.0
        } else {
            (self.eliminated_checks as f64 / self.total_checks as f64) * 100.0
        }
    }
}

/// A natural loop representation in the Control Flow Graph.
#[derive(Debug, Clone)]
pub struct NaturalLoop {
    pub header: BlockId,
    pub blocks: HashSet<BlockId>,
    pub preheader: Option<BlockId>,
}

/// Helper resolving canonical root value through alias chains.
fn canonical_ref(mut val: ValueId, aliases: &HashMap<ValueId, ValueId>) -> ValueId {
    let mut visited = HashSet::new();
    while let Some(&target) = aliases.get(&val) {
        if !visited.insert(val) {
            break;
        }
        val = target;
    }
    val
}

/// Traverses projections (GetField, GetElement, SliceSub, SliceStrided, GenDeref, GenRef)
/// upwards to discover the enclosing composite structure or slice allocation root.
pub fn find_allocation_root(
    mut val: ValueId,
    inst_defs: &HashMap<ValueId, ValueExpr>,
    aliases: &HashMap<ValueId, ValueId>,
) -> ValueId {
    let mut visited = HashSet::new();
    while visited.insert(val) {
        let canon = canonical_ref(val, aliases);
        match inst_defs.get(&canon).or_else(|| inst_defs.get(&val)) {
            Some(
                ValueExpr::GetField { base, .. }
                | ValueExpr::GetFieldPtr { base, .. }
                | ValueExpr::GetElement { base, .. }
                | ValueExpr::GetElementPtr { base, .. }
                | ValueExpr::SliceSub { base, .. }
                | ValueExpr::SliceStrided { base, .. }
                | ValueExpr::GenDeref { ref_val: base }
                | ValueExpr::GenRef { ptr: base },
            ) => {
                val = *base;
            }
            _ => {
                val = canon;
                break;
            }
        }
    }
    canonical_ref(val, aliases)
}

/// Helper extracting arguments slice targeted by a terminator towards a specific block.
fn get_branch_args(term: &Terminator, target: BlockId) -> Option<Vec<ValueId>> {
    match term {
        Terminator::Branch { target: t, args } if *t == target => Some(args.clone()),
        Terminator::BranchCond {
            then_block,
            then_args,
            else_block,
            else_args,
            ..
        } => {
            if *then_block == target {
                Some(then_args.clone())
            } else if *else_block == target {
                Some(else_args.clone())
            } else {
                None
            }
        }
        Terminator::Switch {
            cases,
            default_block,
            default_args,
            ..
        } => {
            for (_, c_target, c_args) in cases {
                if *c_target == target {
                    return Some(c_args.clone());
                }
            }
            if *default_block == target {
                Some(default_args.clone())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Computes single-store alias chains and invariant block parameter mappings for a function.
fn compute_function_aliases(
    func: &FirFunction,
    cfg: &ControlFlowGraph,
) -> HashMap<ValueId, ValueId> {
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

    let mut global_aliases: HashMap<ValueId, ValueId> = HashMap::new();
    for block in &func.blocks {
        for inst in &block.instructions {
            if let ValueExpr::Load { ptr } = &inst.expr {
                if let (Some(res), Some(&stored_val)) = (inst.result, single_store_val.get(ptr)) {
                    global_aliases.insert(res, stored_val);
                }
            }
        }
    }

    // Invariant block parameter inputs
    for block in &func.blocks {
        if !block.params.is_empty() {
            if let Some(preds) = cfg.predecessors.get(&block.id) {
                if !preds.is_empty() {
                    for (param_idx, (p_val, _)) in block.params.iter().enumerate() {
                        let mut common_arg: Option<ValueId> = None;
                        let mut all_same = true;
                        for &pred_id in preds {
                            if let Some(pred_b) = func.get_block(pred_id) {
                                if let Some(term) = &pred_b.terminator {
                                    if let Some(args_vec) = get_branch_args(term, block.id) {
                                        if let Some(&arg) = args_vec.get(param_idx) {
                                            let canon_arg = canonical_ref(arg, &global_aliases);
                                            match common_arg {
                                                None => common_arg = Some(canon_arg),
                                                Some(prev) if prev == canon_arg => {}
                                                _ => {
                                                    all_same = false;
                                                    break;
                                                }
                                            }
                                        } else {
                                            all_same = false;
                                            break;
                                        }
                                    } else {
                                        all_same = false;
                                        break;
                                    }
                                } else {
                                    all_same = false;
                                    break;
                                }
                            } else {
                                all_same = false;
                                break;
                            }
                        }
                        if all_same {
                            if let Some(v) = common_arg {
                                global_aliases.insert(*p_val, v);
                            }
                        }
                    }
                }
            }
        }
    }

    global_aliases
}

/// Collects all explicit and interprocedural memory freeing operations in a function.
fn compute_free_operations(
    func: &FirFunction,
    val_arenas: &HashMap<ValueId, u16>,
    global_aliases: &HashMap<ValueId, ValueId>,
    callee_has_free: &HashMap<Symbol, bool>,
) -> Vec<FreeOperation> {
    let mut free_operations = Vec::new();
    for block in &func.blocks {
        for inst in &block.instructions {
            match &inst.expr {
                ValueExpr::GenFree { ptr } => {
                    let canon_ptr = canonical_ref(*ptr, global_aliases);
                    let free_arena = val_arenas
                        .get(ptr)
                        .or_else(|| val_arenas.get(&canon_ptr))
                        .copied();
                    free_operations.push(FreeOperation {
                        block: block.id,
                        ptr: *ptr,
                        arena: free_arena,
                    });
                }
                ValueExpr::CallArenaRewind { .. } => {
                    free_operations.push(FreeOperation {
                        block: block.id,
                        ptr: ValueId(0),
                        arena: Some(crate::closure_opt::ARENA_THREAD_LOCAL_CALL),
                    });
                }
                ValueExpr::CallDirect { name, .. } | ValueExpr::BlockingCallDirect { name, .. }
                    if callee_has_free.get(name) == Some(&true) =>
                {
                    free_operations.push(FreeOperation {
                        block: block.id,
                        ptr: ValueId(0),
                        arena: None,
                    });
                }
                _ => {}
            }
        }
    }
    free_operations
}

/// Context bundling inputs for forward confluent dataflow analysis.
pub struct DataflowContext<'a> {
    pub func: &'a FirFunction,
    pub cfg: &'a ControlFlowGraph,
    pub dom_tree: &'a DominanceTree,
    pub aliases: &'a HashMap<ValueId, ValueId>,
    pub val_arenas: &'a HashMap<ValueId, u16>,
    pub free_operations: &'a [FreeOperation],
    pub callee_has_free: &'a HashMap<Symbol, bool>,
    pub safe_params: &'a HashSet<(Symbol, usize)>,
    pub safe_env_captures: &'a HashSet<(Symbol, usize)>,
    pub inst_defs: &'a HashMap<ValueId, ValueExpr>,
}

/// Confluent forward dataflow analysis computing available generational references at each program point.
///
/// Handles arbitrary control-flow topologies (cyclic loops, reducible and irreducible graphs,
/// convergent branches such as if-else, match, and switch merges) via monotonic fixed-point iteration.
#[derive(Debug, Clone)]
pub struct GenerationalDataflowAnalysis {
    pub block_in: HashMap<BlockId, HashSet<ValueId>>,
    pub block_out: HashMap<BlockId, HashSet<ValueId>>,
    pub inst_available: HashMap<(BlockId, usize), HashSet<ValueId>>,
}

impl GenerationalDataflowAnalysis {
    pub fn compute(cx: &DataflowContext<'_>) -> Self {
        let mut block_in: HashMap<BlockId, HashSet<ValueId>> = HashMap::new();
        let mut block_out: HashMap<BlockId, HashSet<ValueId>> = HashMap::new();
        let mut inst_available: HashMap<(BlockId, usize), HashSet<ValueId>> = HashMap::new();

        if cx.func.blocks.is_empty() {
            return Self {
                block_in,
                block_out,
                inst_available,
            };
        }

        // 1. Alloca pointers are allocated on the stack frame and are strictly safe throughout function execution
        let mut alloca_values = HashSet::new();
        for block in &cx.func.blocks {
            for inst in &block.instructions {
                if let ValueExpr::Alloca { .. } = &inst.expr {
                    if let Some(res) = inst.result {
                        alloca_values.insert(res);
                        alloca_values.insert(canonical_ref(res, cx.aliases));
                    }
                }
            }
        }
        for block in &cx.func.blocks {
            for inst in &block.instructions {
                if let ValueExpr::GenRef { ptr } = &inst.expr {
                    let canon_ptr = canonical_ref(*ptr, cx.aliases);
                    if alloca_values.contains(ptr) || alloca_values.contains(&canon_ptr) {
                        if let Some(res) = inst.result {
                            alloca_values.insert(res);
                            alloca_values.insert(canonical_ref(res, cx.aliases));
                        }
                    }
                }
            }
        }

        let is_func_lambda = INTERNER.resolve(&cx.func.name).starts_with("__ifa_lambda_");
        let env_param_val = cx.func.params.first().map(|p| p.val);
        let func_params: HashSet<ValueId> = cx.func.params.iter().map(|p| p.val).collect();

        // 2. Initial facts available at function entry
        let mut entry_in: HashSet<ValueId> = HashSet::new();
        entry_in.extend(alloca_values.clone());

        for (p_idx, p) in cx.func.params.iter().enumerate() {
            if cx.safe_params.contains(&(cx.func.name, p_idx)) {
                entry_in.insert(p.val);
                entry_in.insert(canonical_ref(p.val, cx.aliases));
            }
        }

        if let Some(entry_b) = cx.func.get_block(cx.func.entry_block) {
            for inst in &entry_b.instructions {
                if let ValueExpr::GetField {
                    base, field_idx, ..
                } = &inst.expr
                {
                    let is_env = (is_func_lambda && *base == ValueId(0))
                        || env_param_val.is_some_and(|p| p == *base);
                    if is_env && cx.safe_env_captures.contains(&(cx.func.name, *field_idx)) {
                        if let Some(res) = inst.result {
                            entry_in.insert(res);
                            entry_in.insert(canonical_ref(res, cx.aliases));
                        }
                    }
                }
            }
        }

        // 3. Monotonic fixed-point iteration over the meet-semilattice (intersection across all predecessors)
        let mut computed_blocks: HashSet<BlockId> = HashSet::new();
        let mut changed = true;
        let mut iteration = 0;

        while changed && iteration < 16 {
            changed = false;
            iteration += 1;

            for &b_id in &cx.dom_tree.rpo_blocks {
                let preds = cx.cfg.predecessors.get(&b_id);

                let mut in_facts: HashSet<ValueId> = if b_id == cx.func.entry_block {
                    entry_in.clone()
                } else if let Some(pred_list) = preds {
                    if pred_list.is_empty() {
                        HashSet::new()
                    } else {
                        let evaluated_preds: Vec<BlockId> = pred_list
                            .iter()
                            .copied()
                            .filter(|p| computed_blocks.contains(p))
                            .collect();

                        if evaluated_preds.is_empty() {
                            if let Some(idom) = cx.dom_tree.immediate_dominator(b_id) {
                                block_out.get(&idom).cloned().unwrap_or_default()
                            } else {
                                HashSet::new()
                            }
                        } else {
                            let mut common: Option<HashSet<ValueId>> = None;
                            for &pred_id in &evaluated_preds {
                                if let Some(pred_facts) = block_out.get(&pred_id) {
                                    match &mut common {
                                        None => common = Some(pred_facts.clone()),
                                        Some(set) => set.retain(|v| pred_facts.contains(v)),
                                    }
                                }
                            }
                            common.unwrap_or_default()
                        }
                    }
                } else {
                    HashSet::new()
                };

                // Propagate SSA block parameters (phi nodes) across convergent branches
                if let Some(block) = cx.func.get_block(b_id) {
                    if !block.params.is_empty() {
                        if let Some(pred_list) = preds {
                            if !pred_list.is_empty() {
                                for (param_idx, (p_val, _)) in block.params.iter().enumerate() {
                                    let mut all_preds_safe = true;
                                    for &pred_id in pred_list {
                                        if !computed_blocks.contains(&pred_id) {
                                            continue;
                                        }
                                        if let Some(pred_b) = cx.func.get_block(pred_id) {
                                            if let Some(term) = &pred_b.terminator {
                                                if let Some(args) = get_branch_args(term, b_id) {
                                                    if let Some(&arg_v) = args.get(param_idx) {
                                                        let canon_arg =
                                                            canonical_ref(arg_v, cx.aliases);
                                                        let is_safe = block_out
                                                            .get(&pred_id)
                                                            .is_some_and(|s| {
                                                                s.contains(&arg_v)
                                                                    || s.contains(&canon_arg)
                                                            });
                                                        if !is_safe {
                                                            all_preds_safe = false;
                                                            break;
                                                        }
                                                    } else {
                                                        all_preds_safe = false;
                                                        break;
                                                    }
                                                } else {
                                                    all_preds_safe = false;
                                                    break;
                                                }
                                            } else {
                                                all_preds_safe = false;
                                                break;
                                            }
                                        } else {
                                            all_preds_safe = false;
                                            break;
                                        }
                                    }

                                    if all_preds_safe {
                                        in_facts.insert(*p_val);
                                        in_facts.insert(canonical_ref(*p_val, cx.aliases));
                                    }
                                }
                            }
                        }
                    }
                }

                // Transfer function across instructions of block
                let mut cur = in_facts.clone();
                let mut ptr_aliases: HashMap<ValueId, ValueId> = HashMap::new();
                let mut projection_roots: HashMap<ValueId, ValueId> = HashMap::new();

                if let Some(block) = cx.func.get_block(b_id) {
                    for (inst_idx, inst) in block.instructions.iter().enumerate() {
                        inst_available.insert((b_id, inst_idx), cur.clone());

                        match &inst.expr {
                            ValueExpr::GenCheck { ref_val, .. } => {
                                let canon = canonical_ref(*ref_val, cx.aliases);
                                cur.insert(*ref_val);
                                cur.insert(canon);
                                if let Some(&root) = projection_roots.get(ref_val) {
                                    cur.insert(root);
                                    cur.insert(canonical_ref(root, cx.aliases));
                                }
                            }
                            ValueExpr::GenRef { .. }
                            | ValueExpr::GenAlloc { .. }
                            | ValueExpr::CallArenaAlloc { .. }
                            | ValueExpr::Alloca { .. } => {
                                if let Some(res) = inst.result {
                                    cur.insert(res);
                                    cur.insert(canonical_ref(res, cx.aliases));
                                }
                            }
                            ValueExpr::Store { ptr, val } => {
                                ptr_aliases.insert(*ptr, *val);
                            }
                            ValueExpr::GenDeref { ref_val } => {
                                if let Some(res) = inst.result {
                                    let root =
                                        projection_roots.get(ref_val).copied().unwrap_or(*ref_val);
                                    projection_roots.insert(res, root);
                                }
                            }
                            ValueExpr::GetField {
                                base, field_idx, ..
                            }
                            | ValueExpr::GetFieldPtr {
                                base, field_idx, ..
                            } => {
                                if let Some(res) = inst.result {
                                    let root = projection_roots.get(base).copied().unwrap_or(*base);
                                    let canon_root = canonical_ref(root, cx.aliases);
                                    let canon_base = canonical_ref(*base, cx.aliases);
                                    projection_roots.insert(res, root);

                                    if cur.contains(&root)
                                        || cur.contains(&canon_root)
                                        || cur.contains(base)
                                        || cur.contains(&canon_base)
                                    {
                                        cur.insert(res);
                                        cur.insert(canonical_ref(res, cx.aliases));
                                    }

                                    let is_env = (is_func_lambda && *base == ValueId(0))
                                        || env_param_val.is_some_and(|p| p == *base);
                                    if is_env
                                        && cx
                                            .safe_env_captures
                                            .contains(&(cx.func.name, *field_idx))
                                    {
                                        cur.insert(res);
                                        cur.insert(canonical_ref(res, cx.aliases));
                                    }
                                }
                            }
                            ValueExpr::GetElement { base, .. }
                            | ValueExpr::GetElementPtr { base, .. }
                            | ValueExpr::SliceSub { base, .. }
                            | ValueExpr::SliceStrided { base, .. } => {
                                if let Some(res) = inst.result {
                                    let root = projection_roots.get(base).copied().unwrap_or(*base);
                                    let canon_root = canonical_ref(root, cx.aliases);
                                    let canon_base = canonical_ref(*base, cx.aliases);
                                    projection_roots.insert(res, root);

                                    if cur.contains(&root)
                                        || cur.contains(&canon_root)
                                        || cur.contains(base)
                                        || cur.contains(&canon_base)
                                    {
                                        cur.insert(res);
                                        cur.insert(canonical_ref(res, cx.aliases));
                                    }
                                }
                            }
                            ValueExpr::Load { ptr } => {
                                if let Some(res) = inst.result {
                                    let stored = ptr_aliases
                                        .get(ptr)
                                        .copied()
                                        .or_else(|| cx.aliases.get(&res).copied());
                                    if let Some(val) = stored {
                                        let canon = canonical_ref(val, cx.aliases);
                                        if cur.contains(&val) || cur.contains(&canon) {
                                            cur.insert(res);
                                            cur.insert(canonical_ref(res, cx.aliases));
                                        }
                                    }
                                }
                            }
                            ValueExpr::CallArenaRewind { .. } => {
                                let free_op = FreeOperation {
                                    block: b_id,
                                    ptr: ValueId(0),
                                    arena: Some(crate::closure_opt::ARENA_THREAD_LOCAL_CALL),
                                };
                                cur.retain(|&val| {
                                    let val_canon = canonical_ref(val, cx.aliases);
                                    if alloca_values.contains(&val)
                                        || alloca_values.contains(&val_canon)
                                    {
                                        return true;
                                    }
                                    let val_arena = cx
                                        .val_arenas
                                        .get(&val)
                                        .or_else(|| cx.val_arenas.get(&val_canon))
                                        .copied();
                                    !free_op.interferes_with_ref(val, val_arena, cx.aliases)
                                });
                            }
                            ValueExpr::GenFree { ptr } => {
                                let canon = canonical_ref(*ptr, cx.aliases);
                                let free_arena = cx
                                    .val_arenas
                                    .get(ptr)
                                    .or_else(|| cx.val_arenas.get(&canon))
                                    .copied();
                                let free_op = FreeOperation {
                                    block: b_id,
                                    ptr: *ptr,
                                    arena: free_arena,
                                };
                                cur.retain(|&val| {
                                    let val_canon = canonical_ref(val, cx.aliases);
                                    if alloca_values.contains(&val)
                                        || alloca_values.contains(&val_canon)
                                    {
                                        return true;
                                    }
                                    let val_arena = cx
                                        .val_arenas
                                        .get(&val)
                                        .or_else(|| cx.val_arenas.get(&val_canon))
                                        .copied();
                                    !free_op.interferes_with_ref(val, val_arena, cx.aliases)
                                });
                                ptr_aliases.remove(ptr);
                            }
                            ValueExpr::CallDirect { name, args }
                            | ValueExpr::BlockingCallDirect { name, args } => {
                                let callee_frees =
                                    cx.callee_has_free.get(name).copied().unwrap_or(true);
                                if callee_frees {
                                    cur.retain(|&val| {
                                        let val_canon = canonical_ref(val, cx.aliases);
                                        // Alloca pointers reside on the caller's stack/frame and cannot be freed by callee
                                        if alloca_values.contains(&val)
                                            || alloca_values.contains(&val_canon)
                                        {
                                            return true;
                                        }
                                        let val_arena = cx
                                            .val_arenas
                                            .get(&val)
                                            .or_else(|| cx.val_arenas.get(&val_canon))
                                            .copied();
                                        val_arena.is_some_and(|a| {
                                            a > 0
                                                && a != crate::closure_opt::ARENA_THREAD_LOCAL_CALL
                                        })
                                    });
                                } else {
                                    for (arg_idx, &arg_val) in args.iter().enumerate() {
                                        if cx.safe_params.contains(&(*name, arg_idx)) {
                                            let canon = canonical_ref(arg_val, cx.aliases);
                                            cur.insert(arg_val);
                                            cur.insert(canon);
                                        }
                                    }
                                }
                            }
                            ValueExpr::Yield
                            | ValueExpr::YieldValue { .. }
                            | ValueExpr::ChanRecv { .. }
                            | ValueExpr::ChanSend { .. }
                            | ValueExpr::ChanSelect {
                                has_default: false, ..
                            } => {
                                cur.retain(|&val| {
                                    let val_canon = canonical_ref(val, cx.aliases);

                                    // 1. Stack frame / coroutine-local frame allocations strictly survive suspensions
                                    if alloca_values.contains(&val)
                                        || alloca_values.contains(&val_canon)
                                    {
                                        return true;
                                    }

                                    let val_arena = cx
                                        .val_arenas
                                        .get(&val)
                                        .or_else(|| cx.val_arenas.get(&val_canon))
                                        .copied();

                                    // If any explicit or callee freeing operation interferes, invalidate the reference
                                    let interferes = is_interfering_free(
                                        cx.free_operations,
                                        val,
                                        val_arena,
                                        cx.aliases,
                                        &alloca_values,
                                    );

                                    if interferes {
                                        return false;
                                    }

                                    // 2. Formal parameters (guaranteed alive by caller over coroutine execution scope)
                                    if func_params.contains(&val)
                                        || func_params.contains(&val_canon)
                                        || cx.safe_params.iter().any(|(f, _)| *f == cx.func.name)
                                    {
                                        return true;
                                    }

                                    // 2b. Composite and slice projections derived from formal parameters or stack frame
                                    if let Some(&root) = projection_roots
                                        .get(&val)
                                        .or_else(|| projection_roots.get(&val_canon))
                                    {
                                        let canon_root = canonical_ref(root, cx.aliases);
                                        if func_params.contains(&root)
                                            || func_params.contains(&canon_root)
                                            || alloca_values.contains(&root)
                                            || alloca_values.contains(&canon_root)
                                            || cx
                                                .safe_params
                                                .iter()
                                                .any(|(f, _)| *f == cx.func.name)
                                        {
                                            return true;
                                        }
                                    }

                                    // 3. Isolated non-zero memory arenas
                                    if val_arena.is_some_and(|a| a > 0) {
                                        return true;
                                    }

                                    // 4. Invariant dominance: if no freeing operation can touch this reference anywhere
                                    // in the coroutine or invoked callees, the reference is invariant across suspension.
                                    !interferes
                                });
                            }
                            _ => {}
                        }
                    }
                }

                block_in.insert(b_id, in_facts);

                if block_out.get(&b_id) != Some(&cur) {
                    block_out.insert(b_id, cur);
                    computed_blocks.insert(b_id);
                    changed = true;
                }
            }
        }

        Self {
            block_in,
            block_out,
            inst_available,
        }
    }

    /// Checks whether `val` (or its canonical alias) is guaranteed safe and checked immediately
    /// before instruction `inst_idx` in block `block_id`.
    pub fn is_available_at(
        &self,
        block_id: BlockId,
        inst_idx: usize,
        val: ValueId,
        aliases: &HashMap<ValueId, ValueId>,
    ) -> bool {
        let canon = canonical_ref(val, aliases);
        if let Some(set) = self.inst_available.get(&(block_id, inst_idx)) {
            set.contains(&val) || set.contains(&canon)
        } else {
            false
        }
    }
}

/// Interprocedural generational safety summary discovered across the entire module.
#[derive(Debug, Clone, Default)]
pub struct InterproceduralGenSafety {
    /// Function parameters proven safe across all call-sites: (func_name, param_idx).
    pub safe_params: HashSet<(Symbol, usize)>,
    /// Closure environment captured fields proven safe across all invocations: (lambda_func_name, field_idx).
    pub safe_env_captures: HashSet<(Symbol, usize)>,
}

/// Optimizes generational references by statically eliminating redundant `GenCheck` instructions
/// and hoisting loop-invariant checks out of loops (Section 9.3).
pub struct GenerationalOptPass {
    stats: GenOptStats,
    safe_params: HashSet<(Symbol, usize)>,
    safe_env_captures: HashSet<(Symbol, usize)>,
}

impl GenerationalOptPass {
    pub fn new() -> Self {
        Self {
            stats: GenOptStats::default(),
            safe_params: HashSet::new(),
            safe_env_captures: HashSet::new(),
        }
    }

    pub fn with_safe_params(safe_params: HashSet<(Symbol, usize)>) -> Self {
        Self {
            stats: GenOptStats::default(),
            safe_params,
            safe_env_captures: HashSet::new(),
        }
    }

    pub fn with_safety(
        safe_params: HashSet<(Symbol, usize)>,
        safe_env_captures: HashSet<(Symbol, usize)>,
    ) -> Self {
        Self {
            stats: GenOptStats::default(),
            safe_params,
            safe_env_captures,
        }
    }

    /// Computes mapping from FIR values to their known generational arena IDs (if non-zero).
    pub fn compute_val_arenas(
        func: &FirFunction,
        global_aliases: &HashMap<ValueId, ValueId>,
    ) -> HashMap<ValueId, u16> {
        let mut val_arenas: HashMap<ValueId, u16> = HashMap::new();

        // 1. Initial direct seed from GenAlloc instructions
        for block in &func.blocks {
            for inst in &block.instructions {
                if let (
                    Some(res),
                    ValueExpr::GenAlloc {
                        arena: Some(a_id), ..
                    },
                ) = (inst.result, &inst.expr)
                {
                    if *a_id > 0 {
                        val_arenas.insert(res, *a_id);
                    }
                } else if let (Some(res), ValueExpr::CallArenaAlloc { .. }) =
                    (inst.result, &inst.expr)
                {
                    val_arenas.insert(res, crate::closure_opt::ARENA_THREAD_LOCAL_CALL);
                }
            }
        }

        // 2. Fixed-point propagation across references, field projections, dereferences, loads, and stores
        let mut changed = true;
        let mut iter = 0;
        while changed && iter < 10 {
            changed = false;
            iter += 1;

            // Alias synchronisation
            for (&val, &canon) in global_aliases {
                if let Some(&a) = val_arenas.get(&canon) {
                    if val_arenas.insert(val, a).is_none() {
                        changed = true;
                    }
                } else if let Some(&a) = val_arenas.get(&val) {
                    if val_arenas.insert(canon, a).is_none() {
                        changed = true;
                    }
                }
            }

            for block in &func.blocks {
                for inst in &block.instructions {
                    let res_opt = inst.result;
                    match &inst.expr {
                        ValueExpr::GenRef { ptr } => {
                            let canon_ptr = canonical_ref(*ptr, global_aliases);
                            if let Some(&a) =
                                val_arenas.get(ptr).or_else(|| val_arenas.get(&canon_ptr))
                            {
                                if let Some(res) = res_opt {
                                    if val_arenas.insert(res, a).is_none() {
                                        changed = true;
                                    }
                                }
                            }
                        }
                        ValueExpr::GetField { base, .. }
                        | ValueExpr::GetFieldPtr { base, .. }
                        | ValueExpr::GenDeref { ref_val: base }
                        | ValueExpr::SliceSub { base, .. }
                        | ValueExpr::SliceStrided { base, .. }
                        | ValueExpr::GetElement { base, .. }
                        | ValueExpr::GetElementPtr { base, .. } => {
                            let canon_base = canonical_ref(*base, global_aliases);
                            if let Some(&a) =
                                val_arenas.get(base).or_else(|| val_arenas.get(&canon_base))
                            {
                                if let Some(res) = res_opt {
                                    if val_arenas.insert(res, a).is_none() {
                                        changed = true;
                                    }
                                }
                            }
                        }
                        ValueExpr::Store { ptr, val } => {
                            let canon_ptr = canonical_ref(*ptr, global_aliases);
                            let canon_val = canonical_ref(*val, global_aliases);
                            let a_opt = val_arenas
                                .get(val)
                                .or_else(|| val_arenas.get(&canon_val))
                                .or_else(|| val_arenas.get(ptr))
                                .or_else(|| val_arenas.get(&canon_ptr))
                                .copied();
                            if let Some(a) = a_opt {
                                if val_arenas.insert(*ptr, a).is_none() {
                                    changed = true;
                                }
                                if val_arenas.insert(*val, a).is_none() {
                                    changed = true;
                                }
                            }
                        }
                        ValueExpr::Load { ptr } => {
                            let canon_ptr = canonical_ref(*ptr, global_aliases);
                            if let Some(&a) =
                                val_arenas.get(ptr).or_else(|| val_arenas.get(&canon_ptr))
                            {
                                if let Some(res) = res_opt {
                                    if val_arenas.insert(res, a).is_none() {
                                        changed = true;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        val_arenas
    }

    pub fn stats(&self) -> GenOptStats {
        self.stats
    }

    /// Run post-IPO optimization to eliminate and hoist generational checks introduced by inlining.
    pub fn run_post_ipo(&mut self, module: &mut FirModule) -> GenOptStats {
        let before_elim = self.stats.eliminated_checks;
        let before_hoist = self.stats.hoisted_checks;
        let before_total = self.stats.total_checks;
        let before_interprocedural = self.stats.interprocedural_eliminated_checks;
        let before_coro_sync = self.stats.coroutine_sync_barriers_eliminated;

        self.run_on_module(module);

        GenOptStats {
            total_checks: self.stats.total_checks - before_total,
            eliminated_checks: self.stats.eliminated_checks - before_elim,
            hoisted_checks: self.stats.hoisted_checks - before_hoist,
            interprocedural_eliminated_checks: self.stats.interprocedural_eliminated_checks
                - before_interprocedural,
            coroutine_sync_barriers_eliminated: self.stats.coroutine_sync_barriers_eliminated
                - before_coro_sync,
        }
    }

    /// Inter-procedurally computes parameters that are guaranteed to receive valid (already checked
    /// or locally allocated) references across all call-sites in the module.
    pub fn compute_interprocedural_safe_params(module: &FirModule) -> HashSet<(Symbol, usize)> {
        Self::compute_interprocedural_safety(module).safe_params
    }

    /// Computes full interprocedural generational safety summary: formal parameters and closure environment captures.
    pub fn compute_interprocedural_safety(module: &FirModule) -> InterproceduralGenSafety {
        let mut callee_has_free = HashMap::new();
        for f in &module.functions {
            let has_free = f.blocks.iter().any(|b| {
                b.instructions
                    .iter()
                    .any(|i| matches!(i.expr, ValueExpr::GenFree { .. }))
            });
            callee_has_free.insert(f.name, has_free);
        }

        struct FuncContext {
            cfg: ControlFlowGraph,
            dom_tree: DominanceTree,
            aliases: HashMap<ValueId, ValueId>,
            val_arenas: HashMap<ValueId, u16>,
            free_operations: Vec<FreeOperation>,
            struct_inits: HashMap<ValueId, (Symbol, Vec<ValueId>, BlockId, usize)>,
            closure_creations: Vec<(Symbol, ValueId, BlockId, usize)>,
            inst_defs: HashMap<ValueId, ValueExpr>,
        }

        let mut func_contexts: HashMap<Symbol, FuncContext> = HashMap::new();
        let mut call_sites_by_target: HashMap<Symbol, Vec<CallSite>> = HashMap::new();

        for func in &module.functions {
            let cfg = ControlFlowGraph::build(func);
            let dom_tree = DominanceTree::build(&cfg);
            let aliases = compute_function_aliases(func, &cfg);
            let val_arenas = Self::compute_val_arenas(func, &aliases);
            let free_operations =
                compute_free_operations(func, &val_arenas, &aliases, &callee_has_free);

            let mut inst_defs: HashMap<ValueId, ValueExpr> = HashMap::new();
            let mut string_constants: HashMap<ValueId, Symbol> = HashMap::new();
            for block in &func.blocks {
                for inst in &block.instructions {
                    if let Some(res) = inst.result {
                        inst_defs.insert(res, inst.expr.clone());
                        if let ValueExpr::Constant(ConstantValue::String(s)) = &inst.expr {
                            string_constants.insert(res, *s);
                        } else if let ValueExpr::Constant(ConstantValue::Function(s)) = &inst.expr {
                            string_constants.insert(res, *s);
                        }
                    }
                }
            }

            let mut struct_inits = HashMap::new();
            let mut closure_creations = Vec::new();

            for block in &func.blocks {
                for (inst_idx, inst) in block.instructions.iter().enumerate() {
                    match &inst.expr {
                        ValueExpr::StructInit { name, fields } => {
                            if let Some(res) = inst.result {
                                struct_inits
                                    .insert(res, (*name, fields.clone(), block.id, inst_idx));
                                let name_str = INTERNER.resolve(name);
                                if (name_str.starts_with("__ifa_closure_")
                                    || name_str.starts_with("__ifa_fnref_"))
                                    && fields.len() >= 2
                                {
                                    let fn_val = fields[0];
                                    let env_val = fields[1];
                                    if let Some(&lambda_sym) = string_constants.get(&fn_val) {
                                        closure_creations
                                            .push((lambda_sym, env_val, block.id, inst_idx));
                                    }
                                }
                            }
                        }
                        ValueExpr::CallDirect { name, args }
                        | ValueExpr::BlockingCallDirect { name, args } => {
                            call_sites_by_target.entry(*name).or_default().push((
                                func.name,
                                block.id,
                                inst_idx,
                                args.clone(),
                            ));
                        }
                        _ => {}
                    }
                }
            }

            func_contexts.insert(
                func.name,
                FuncContext {
                    cfg,
                    dom_tree,
                    aliases,
                    val_arenas,
                    free_operations,
                    struct_inits,
                    closure_creations,
                    inst_defs,
                },
            );
        }

        let mut safe_params: HashSet<(Symbol, usize)> = HashSet::new();
        let mut safe_env_captures: HashSet<(Symbol, usize)> = HashSet::new();

        let mut changed = true;
        let mut iter = 0;
        while changed && iter < 16 {
            changed = false;
            iter += 1;

            let mut dataflows: HashMap<Symbol, GenerationalDataflowAnalysis> = HashMap::new();
            for func in &module.functions {
                let ctx = match func_contexts.get(&func.name) {
                    Some(c) => c,
                    None => continue,
                };
                let cx = DataflowContext {
                    func,
                    cfg: &ctx.cfg,
                    dom_tree: &ctx.dom_tree,
                    aliases: &ctx.aliases,
                    val_arenas: &ctx.val_arenas,
                    free_operations: &ctx.free_operations,
                    callee_has_free: &callee_has_free,
                    safe_params: &safe_params,
                    safe_env_captures: &safe_env_captures,
                    inst_defs: &ctx.inst_defs,
                };
                let df = GenerationalDataflowAnalysis::compute(&cx);
                dataflows.insert(func.name, df);
            }

            for func in &module.functions {
                let target_name = func.name;
                let target_name_str = INTERNER.resolve(&target_name);

                // 1. Scalar direct function parameters
                if let Some(call_sites) = call_sites_by_target.get(&target_name) {
                    if !call_sites.is_empty() {
                        for p_idx in 0..func.params.len() {
                            if safe_params.contains(&(target_name, p_idx)) {
                                continue;
                            }

                            let all_callers_safe =
                                call_sites
                                    .iter()
                                    .all(|(caller_name, block_id, inst_idx, args)| {
                                        if let Some(&arg_val) = args.get(p_idx) {
                                            let caller_df = match dataflows.get(caller_name) {
                                                Some(df) => df,
                                                None => return false,
                                            };
                                            let caller_aliases =
                                                match func_contexts.get(caller_name) {
                                                    Some(ctx) => &ctx.aliases,
                                                    None => return false,
                                                };
                                            caller_df.is_available_at(
                                                *block_id,
                                                *inst_idx,
                                                arg_val,
                                                caller_aliases,
                                            )
                                        } else {
                                            false
                                        }
                                    });

                            if all_callers_safe {
                                safe_params.insert((target_name, p_idx));
                                changed = true;
                            }
                        }
                    }
                }

                // 2. Closure captured fields
                if target_name_str.starts_with("__ifa_lambda_") {
                    let env_field_indices: Vec<usize> = func
                        .blocks
                        .first()
                        .map(|b| {
                            b.instructions
                                .iter()
                                .filter_map(|i| match &i.expr {
                                    ValueExpr::GetField {
                                        base, field_idx, ..
                                    } if *base == ValueId(0)
                                        || func.params.first().is_some_and(|p| p.val == *base) =>
                                    {
                                        Some(*field_idx)
                                    }
                                    _ => None,
                                })
                                .collect()
                        })
                        .unwrap_or_default();

                    for f_idx in env_field_indices {
                        if safe_env_captures.contains(&(target_name, f_idx)) {
                            continue;
                        }

                        // Check via direct call sites passing env_val as args[0]
                        if let Some(call_sites) = call_sites_by_target.get(&target_name) {
                            if !call_sites.is_empty() {
                                let all_calls_safe = call_sites.iter().all(
                                    |(caller_name, block_id, inst_idx, args)| {
                                        if let Some(&env_val) = args.first() {
                                            if let Some(caller_ctx) = func_contexts.get(caller_name)
                                            {
                                                let canon_env =
                                                    canonical_ref(env_val, &caller_ctx.aliases);
                                                let struct_init =
                                                    caller_ctx.struct_inits.get(&env_val).or_else(
                                                        || caller_ctx.struct_inits.get(&canon_env),
                                                    );
                                                if let Some((_, fields, _, _)) = struct_init {
                                                    if let Some(&cap_val) = fields.get(f_idx) {
                                                        if let Some(caller_df) =
                                                            dataflows.get(caller_name)
                                                        {
                                                            return caller_df.is_available_at(
                                                                *block_id,
                                                                *inst_idx,
                                                                cap_val,
                                                                &caller_ctx.aliases,
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        false
                                    },
                                );

                                if all_calls_safe {
                                    safe_env_captures.insert((target_name, f_idx));
                                    changed = true;
                                    continue;
                                }
                            }
                        }

                        // Check via closure instantiation point across all module functions
                        let mut creation_sites = Vec::new();
                        for (c_fn_sym, ctx) in &func_contexts {
                            for (lambda_sym, env_val, b_id, i_idx) in &ctx.closure_creations {
                                if *lambda_sym == target_name {
                                    creation_sites.push((*c_fn_sym, *env_val, *b_id, *i_idx));
                                }
                            }
                        }

                        if !creation_sites.is_empty() {
                            let all_creations_safe = creation_sites.iter().all(
                                |(caller_name, env_val, block_id, inst_idx)| {
                                    if let Some(caller_ctx) = func_contexts.get(caller_name) {
                                        let canon_env =
                                            canonical_ref(*env_val, &caller_ctx.aliases);
                                        let struct_init = caller_ctx
                                            .struct_inits
                                            .get(env_val)
                                            .or_else(|| caller_ctx.struct_inits.get(&canon_env));
                                        if let Some((_, fields, _, _)) = struct_init {
                                            if let Some(&cap_val) = fields.get(f_idx) {
                                                let no_frees =
                                                    caller_ctx.free_operations.is_empty();
                                                if let Some(caller_df) = dataflows.get(caller_name)
                                                {
                                                    let is_safe = caller_df.is_available_at(
                                                        *block_id,
                                                        *inst_idx,
                                                        cap_val,
                                                        &caller_ctx.aliases,
                                                    );
                                                    return is_safe && no_frees;
                                                }
                                            }
                                        }
                                    }
                                    false
                                },
                            );

                            if all_creations_safe {
                                safe_env_captures.insert((target_name, f_idx));
                                changed = true;
                            }
                        }
                    }
                }
            }
        }

        InterproceduralGenSafety {
            safe_params,
            safe_env_captures,
        }
    }

    /// Run the optimization on an entire module with whole-program interprocedural constraint propagation.
    pub fn run_on_module(&mut self, module: &mut FirModule) {
        let safety = Self::compute_interprocedural_safety(module);
        self.safe_params.extend(safety.safe_params);
        self.safe_env_captures.extend(safety.safe_env_captures);

        let mut callee_has_free = HashMap::new();
        for f in &module.functions {
            let has_free = f.blocks.iter().any(|b| {
                b.instructions
                    .iter()
                    .any(|i| matches!(i.expr, ValueExpr::GenFree { .. }))
            });
            callee_has_free.insert(f.name, has_free);
        }

        for func in &mut module.functions {
            self.run_on_function_internal(func, &callee_has_free);
        }
    }

    /// Run the full GCE pass on a function.
    pub fn run_on_function(&mut self, func: &mut FirFunction) {
        let callee_has_free = HashMap::new();
        self.run_on_function_internal(func, &callee_has_free);
    }

    fn run_on_function_internal(
        &mut self,
        func: &mut FirFunction,
        callee_has_free: &HashMap<Symbol, bool>,
    ) {
        if func.blocks.is_empty() {
            return;
        }

        let cfg = ControlFlowGraph::build(func);
        let dom_tree = DominanceTree::build(&cfg);

        // 1. Identify where each value was created/defined: val -> creating BlockId
        let mut ref_creation_block: HashMap<ValueId, BlockId> = HashMap::new();
        let mut inst_defs: HashMap<ValueId, ValueExpr> = HashMap::new();

        for p in &func.params {
            ref_creation_block.insert(p.val, func.entry_block);
        }
        for block in &func.blocks {
            for (p_val, _) in &block.params {
                ref_creation_block.insert(*p_val, block.id);
            }
            for inst in &block.instructions {
                if let Some(res) = inst.result {
                    ref_creation_block.insert(res, block.id);
                    inst_defs.insert(res, inst.expr.clone());
                }
            }
        }

        // Build global alias mappings (e.g. single-store allocas and invariant block parameters)
        let global_aliases = compute_function_aliases(func, &cfg);

        // Compute memory arena mappings for values and tracking of explicit free operations
        let val_arenas = Self::compute_val_arenas(func, &global_aliases);
        let free_operations =
            compute_free_operations(func, &val_arenas, &global_aliases, callee_has_free);

        // 2. Loop-Invariant Check Hoisting (LICM for Generational Checks - Section 9.3 Rule 2)
        // Repeat until fixed point (up to 5 passes) for nested loops
        let loop_cx = LoopHoistContext {
            cfg: &cfg,
            dom_tree: &dom_tree,
            free_operations: &free_operations,
            val_arenas: &val_arenas,
            ref_defs: &ref_creation_block,
            aliases: &global_aliases,
            inst_defs: &inst_defs,
        };

        for _ in 0..5 {
            let before_hoisted = self.stats.hoisted_checks;
            self.hoist_loop_invariant_checks(func, &loop_cx);
            if self.stats.hoisted_checks == before_hoisted {
                break;
            }
        }

        // 3. Dominance-based and Dataflow Elimination (Section 9.3 Rules 1 & 3)
        let cx = DominanceContext {
            cfg: &cfg,
            dom_tree: &dom_tree,
            free_operations: &free_operations,
            val_arenas: &val_arenas,
            aliases: &global_aliases,
            callee_has_free,
            inst_defs: &inst_defs,
        };
        self.run_dominance_elimination(func, &cx);
    }

    /// Identifies natural loops and hoists invariant `GenCheck` instructions into loop preheaders
    /// taking into account memory arena disjointness.
    fn hoist_loop_invariant_checks(&mut self, func: &mut FirFunction, cx: &LoopHoistContext<'_>) {
        let is_coroutine = func.is_coroutine();
        let loops = Self::find_natural_loops(cx.cfg, cx.dom_tree);
        let param_values: HashSet<ValueId> = func.params.iter().map(|p| p.val).collect();

        for loop_info in loops {
            let preheader_id = match loop_info.preheader {
                Some(p) => p,
                None => continue,
            };

            // Collect all invariant references checked inside the loop whose arena is disjoint
            // from any freeing operation inside the loop
            let mut candidate_checks: Vec<(ValueId, ValueId, Span)> = Vec::new();

            for &b_id in &loop_info.blocks {
                if let Some(block) = func.get_block(b_id) {
                    for inst in &block.instructions {
                        if let ValueExpr::GenCheck { ref_val, redundant } = &inst.expr {
                            if !*redundant {
                                let canon = canonical_ref(*ref_val, cx.aliases);
                                let root = find_allocation_root(*ref_val, cx.inst_defs, cx.aliases);
                                let canon_root = canonical_ref(root, cx.aliases);

                                let is_ref_invariant = param_values.contains(ref_val)
                                    || param_values.contains(&canon)
                                    || cx.ref_defs.get(ref_val).is_some_and(|&def_b| {
                                        !loop_info.blocks.contains(&def_b)
                                            && cx.dom_tree.dominates(def_b, preheader_id)
                                    })
                                    || cx.ref_defs.get(&canon).is_some_and(|&def_b| {
                                        !loop_info.blocks.contains(&def_b)
                                            && cx.dom_tree.dominates(def_b, preheader_id)
                                    });

                                let is_root_invariant = param_values.contains(&root)
                                    || param_values.contains(&canon_root)
                                    || cx.ref_defs.get(&root).is_some_and(|&def_b| {
                                        !loop_info.blocks.contains(&def_b)
                                            && cx.dom_tree.dominates(def_b, preheader_id)
                                    })
                                    || cx.ref_defs.get(&canon_root).is_some_and(|&def_b| {
                                        !loop_info.blocks.contains(&def_b)
                                            && cx.dom_tree.dominates(def_b, preheader_id)
                                    });

                                let target_hoist_val = if is_ref_invariant {
                                    canon
                                } else if is_root_invariant {
                                    canon_root
                                } else {
                                    continue;
                                };

                                if !candidate_checks.iter().any(|(v, c, _)| {
                                    *v == target_hoist_val || *c == target_hoist_val
                                }) {
                                    // Verify that no freeing operation inside the loop interferes with target_hoist_val
                                    let ref_arena = cx
                                        .val_arenas
                                        .get(&target_hoist_val)
                                        .or_else(|| cx.val_arenas.get(ref_val))
                                        .or_else(|| cx.val_arenas.get(&canon))
                                        .copied();

                                    let has_interfering_free =
                                        cx.free_operations.iter().any(|op| {
                                            loop_info.blocks.contains(&op.block)
                                                && op.interferes_with_ref(
                                                    target_hoist_val,
                                                    ref_arena,
                                                    cx.aliases,
                                                )
                                        });

                                    if !has_interfering_free {
                                        candidate_checks.push((
                                            target_hoist_val,
                                            target_hoist_val,
                                            inst.span,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if candidate_checks.is_empty() {
                continue;
            }

            // Hoist checks to preheader and mark inside-loop checks as redundant
            for (ref_val, canon, span) in candidate_checks {
                let already_checked_in_preheader = func.get_block(preheader_id).is_some_and(|pb| {
                    pb.instructions.iter().any(|inst| match &inst.expr {
                        ValueExpr::GenCheck { ref_val: r, .. } => {
                            *r == ref_val
                                || *r == canon
                                || canonical_ref(*r, cx.aliases) == canon
                                || find_allocation_root(*r, cx.inst_defs, cx.aliases) == canon
                        }
                        _ => false,
                    })
                });

                if !already_checked_in_preheader {
                    if let Some(pb) = func.get_block_mut(preheader_id) {
                        let hoist_val = if param_values.contains(&canon)
                            || cx
                                .ref_defs
                                .get(&canon)
                                .is_some_and(|&d| cx.dom_tree.dominates(d, preheader_id))
                        {
                            canon
                        } else {
                            ref_val
                        };
                        pb.instructions.push(Instruction::new(
                            None,
                            ValueExpr::GenCheck {
                                ref_val: hoist_val,
                                redundant: false,
                            },
                            span,
                        ));
                        self.stats.hoisted_checks += 1;
                    }
                }

                // Eliminate all instances of this check within loop blocks
                for &b_id in &loop_info.blocks {
                    if let Some(block) = func.get_block_mut(b_id) {
                        for inst in &mut block.instructions {
                            if let ValueExpr::GenCheck {
                                ref_val: r,
                                redundant,
                            } = &mut inst.expr
                            {
                                let r_canon = canonical_ref(*r, cx.aliases);
                                let r_root = find_allocation_root(*r, cx.inst_defs, cx.aliases);
                                let r_canon_root = canonical_ref(r_root, cx.aliases);
                                let matches_check = *r == ref_val
                                    || *r == canon
                                    || r_canon == canon
                                    || r_root == canon
                                    || r_root == ref_val
                                    || r_canon_root == canon
                                    || r_canon_root == ref_val;

                                if matches_check && !*redundant {
                                    *redundant = true;
                                    self.stats.eliminated_checks += 1;
                                    if is_coroutine {
                                        self.stats.coroutine_sync_barriers_eliminated += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Performs dominance-based and dataflow elimination using confluent fixed-point availability analysis.
    fn run_dominance_elimination(&mut self, func: &mut FirFunction, cx: &DominanceContext<'_>) {
        let is_strict = func.is_strict;
        let is_coroutine = func.is_coroutine();

        let dataflow_cx = DataflowContext {
            func,
            cfg: cx.cfg,
            dom_tree: cx.dom_tree,
            aliases: cx.aliases,
            val_arenas: cx.val_arenas,
            free_operations: cx.free_operations,
            callee_has_free: cx.callee_has_free,
            safe_params: &self.safe_params,
            safe_env_captures: &self.safe_env_captures,
            inst_defs: cx.inst_defs,
        };
        let dataflow = GenerationalDataflowAnalysis::compute(&dataflow_cx);

        for block in &mut func.blocks {
            for (inst_idx, inst) in block.instructions.iter_mut().enumerate() {
                if let ValueExpr::GenCheck { ref_val, redundant } = &mut inst.expr {
                    self.stats.total_checks += 1;

                    if *redundant {
                        // Already marked redundant by LICM hoisting
                        continue;
                    }

                    let root = find_allocation_root(*ref_val, cx.inst_defs, cx.aliases);
                    let canon_root = canonical_ref(root, cx.aliases);

                    if is_strict
                        || block.vector_hint.is_some_and(|h| {
                            (h.is_multi_arena_conv || h.is_multi_arena_matrix || h.disjoint_slices)
                                && cx.free_operations.is_empty()
                        })
                        || dataflow.is_available_at(block.id, inst_idx, *ref_val, cx.aliases)
                        || dataflow.is_available_at(block.id, inst_idx, root, cx.aliases)
                        || dataflow.is_available_at(block.id, inst_idx, canon_root, cx.aliases)
                    {
                        *redundant = true;
                        self.stats.eliminated_checks += 1;
                        self.stats.interprocedural_eliminated_checks += 1;
                        if is_coroutine {
                            self.stats.coroutine_sync_barriers_eliminated += 1;
                        }
                    }
                }
            }
        }
    }

    /// Finds all natural loops in the CFG using dominance back-edges.
    pub fn find_natural_loops(
        cfg: &ControlFlowGraph,
        dom_tree: &DominanceTree,
    ) -> Vec<NaturalLoop> {
        let mut back_edges: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for (&block_id, succs) in &cfg.successors {
            for &succ in succs {
                if dom_tree.dominates(succ, block_id) {
                    back_edges.entry(succ).or_default().push(block_id);
                }
            }
        }

        let mut loops = Vec::new();
        for (header, srcs) in back_edges {
            let mut loop_blocks = HashSet::new();
            loop_blocks.insert(header);
            let mut worklist = VecDeque::new();

            for &src in &srcs {
                if loop_blocks.insert(src) {
                    worklist.push_back(src);
                }
            }

            while let Some(b) = worklist.pop_front() {
                if let Some(preds) = cfg.predecessors.get(&b) {
                    for &pred in preds {
                        if loop_blocks.insert(pred) {
                            worklist.push_back(pred);
                        }
                    }
                }
            }

            let preheader = cfg.predecessors.get(&header).and_then(|preds| {
                let outside: Vec<BlockId> = preds
                    .iter()
                    .copied()
                    .filter(|p| !loop_blocks.contains(p))
                    .collect();
                if outside.len() == 1 {
                    Some(outside[0])
                } else {
                    dom_tree
                        .immediate_dominator(header)
                        .filter(|idom| !loop_blocks.contains(idom))
                }
            });

            loops.push(NaturalLoop {
                header,
                blocks: loop_blocks,
                preheader,
            });
        }

        // Deterministic hierarchical ordering:
        // Outermost loops first (largest block count), with header BlockId as deterministic tie-breaker.
        // This ensures that loop-invariant checks are hoisted directly to their highest enclosing loop preheader.
        loops.sort_by(|a, b| {
            b.blocks
                .len()
                .cmp(&a.blocks.len())
                .then_with(|| a.header.0.cmp(&b.header.0))
        });

        loops
    }

    /// Physically removes all `GenCheck` instructions marked as redundant from the function.
    pub fn strip_redundant_checks(func: &mut FirFunction) -> usize {
        let mut stripped = 0;
        for block in &mut func.blocks {
            let before = block.instructions.len();
            block.instructions.retain(|inst| {
                !matches!(
                    &inst.expr,
                    ValueExpr::GenCheck {
                        redundant: true,
                        ..
                    }
                )
            });
            stripped += before - block.instructions.len();
        }
        stripped
    }
}

impl Default for GenerationalOptPass {
    fn default() -> Self {
        Self::new()
    }
}

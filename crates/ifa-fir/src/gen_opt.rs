use crate::cfg::ControlFlowGraph;
use crate::dominance::DominanceTree;
use crate::ir::*;
use ifa_span::Span;
use std::collections::{HashMap, HashSet, VecDeque};

/// Statistics collected by the generational check elimination (GCE) pass.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct GenOptStats {
    pub total_checks: usize,
    pub eliminated_checks: usize,
    pub hoisted_checks: usize,
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

/// Optimizes generational references by statically eliminating redundant `GenCheck` instructions
/// and hoisting loop-invariant checks out of loops (Section 9.3).
pub struct GenerationalOptPass {
    stats: GenOptStats,
}

impl GenerationalOptPass {
    pub fn new() -> Self {
        Self {
            stats: GenOptStats::default(),
        }
    }

    pub fn stats(&self) -> GenOptStats {
        self.stats
    }

    /// Run the optimization on an entire module.
    pub fn run_on_module(&mut self, module: &mut FirModule) {
        for func in &mut module.functions {
            self.run_on_function(func);
        }
    }

    /// Run the full GCE pass (Loop-Invariant Hoisting + Dominance Elimination) on a function.
    pub fn run_on_function(&mut self, func: &mut FirFunction) {
        let cfg = ControlFlowGraph::build(func);
        let dom_tree = DominanceTree::build(&cfg);

        // 1. Identify which blocks contain freeing or invalidating operations
        let mut freeing_blocks: HashSet<BlockId> = HashSet::new();
        // Track where each value was created/defined: val -> creating BlockId
        let mut ref_creation_block: HashMap<ValueId, BlockId> = HashMap::new();
        // Specifically track where GenRef/GenAlloc occurred
        let mut gen_ref_creations: HashMap<ValueId, BlockId> = HashMap::new();

        for p in &func.params {
            ref_creation_block.insert(p.val, func.entry_block);
        }
        for block in &func.blocks {
            for (p_val, _) in &block.params {
                ref_creation_block.insert(*p_val, block.id);
            }
            for inst in &block.instructions {
                if matches!(&inst.expr, ValueExpr::GenFree { .. }) {
                    freeing_blocks.insert(block.id);
                }
                if let Some(res) = inst.result {
                    ref_creation_block.insert(res, block.id);
                    if matches!(
                        &inst.expr,
                        ValueExpr::GenRef { .. } | ValueExpr::GenAlloc { .. }
                    ) {
                        gen_ref_creations.insert(res, block.id);
                    }
                }
            }
        }

        // Build global alias mappings (e.g. single-store allocas where Loads produce known values)
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
                    if let (Some(res), Some(&stored_val)) = (inst.result, single_store_val.get(ptr))
                    {
                        global_aliases.insert(res, stored_val);
                    }
                }
            }
        }

        // 2. Loop-Invariant Check Hoisting (LICM for Generational Checks - Section 9.3 Rule 2)
        // Repeat until fixed point (up to 5 passes) for nested loops
        for _ in 0..5 {
            let before_hoisted = self.stats.hoisted_checks;
            self.hoist_loop_invariant_checks(
                func,
                &cfg,
                &dom_tree,
                &freeing_blocks,
                &ref_creation_block,
                &global_aliases,
            );
            if self.stats.hoisted_checks == before_hoisted {
                break;
            }
        }

        // 3. Dominance-based and Dataflow Elimination (Section 9.3 Rules 1 & 3)
        self.run_dominance_elimination(
            func,
            &cfg,
            &dom_tree,
            &freeing_blocks,
            &gen_ref_creations,
            &global_aliases,
        );
    }

    /// Identifies natural loops and hoists invariant `GenCheck` instructions into loop preheaders.
    fn hoist_loop_invariant_checks(
        &mut self,
        func: &mut FirFunction,
        cfg: &ControlFlowGraph,
        dom_tree: &DominanceTree,
        freeing_blocks: &HashSet<BlockId>,
        ref_defs: &HashMap<ValueId, BlockId>,
        aliases: &HashMap<ValueId, ValueId>,
    ) {
        let loops = Self::find_natural_loops(cfg, dom_tree);
        let param_values: HashSet<ValueId> = func.params.iter().map(|p| p.val).collect();

        for loop_info in loops {
            // Rule 2 condition: if any block in the loop frees memory, checks cannot be hoisted safely
            let loop_has_free = loop_info.blocks.iter().any(|b| freeing_blocks.contains(b));
            if loop_has_free {
                continue;
            }

            let preheader_id = match loop_info.preheader {
                Some(p) => p,
                None => continue,
            };

            // Collect all invariant references checked inside the loop
            let mut candidate_checks: Vec<(ValueId, ValueId, Span)> = Vec::new();

            for &b_id in &loop_info.blocks {
                if let Some(block) = func.get_block(b_id) {
                    for inst in &block.instructions {
                        if let ValueExpr::GenCheck { ref_val, redundant } = &inst.expr {
                            if !*redundant {
                                let canon = canonical_ref(*ref_val, aliases);
                                let is_param =
                                    param_values.contains(ref_val) || param_values.contains(&canon);
                                let is_defined_outside =
                                    ref_defs.get(ref_val).is_some_and(|&def_b| {
                                        !loop_info.blocks.contains(&def_b)
                                            && dom_tree.dominates(def_b, preheader_id)
                                    }) || ref_defs.get(&canon).is_some_and(|&def_b| {
                                        !loop_info.blocks.contains(&def_b)
                                            && dom_tree.dominates(def_b, preheader_id)
                                    });

                                if (is_param || is_defined_outside)
                                    && !candidate_checks
                                        .iter()
                                        .any(|(v, c, _)| *v == *ref_val || *c == canon)
                                {
                                    candidate_checks.push((*ref_val, canon, inst.span));
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
                            *r == ref_val || *r == canon || canonical_ref(*r, aliases) == canon
                        }
                        _ => false,
                    })
                });

                if !already_checked_in_preheader {
                    if let Some(pb) = func.get_block_mut(preheader_id) {
                        let hoist_val = if param_values.contains(&canon)
                            || ref_defs
                                .get(&canon)
                                .is_some_and(|&d| dom_tree.dominates(d, preheader_id))
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
                                if (*r == ref_val
                                    || *r == canon
                                    || canonical_ref(*r, aliases) == canon)
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

    /// Performs dominance-based and dataflow elimination in Reverse Post-Order.
    fn run_dominance_elimination(
        &mut self,
        func: &mut FirFunction,
        cfg: &ControlFlowGraph,
        dom_tree: &DominanceTree,
        freeing_blocks: &HashSet<BlockId>,
        ref_defs: &HashMap<ValueId, BlockId>,
        aliases: &HashMap<ValueId, ValueId>,
    ) {
        let is_strict = func.is_strict;
        let mut verified_at_exit: HashMap<BlockId, HashSet<ValueId>> = HashMap::new();

        // Helper to extract argument slice passed to a specific target block from a terminator
        let get_branch_args = |term: &Terminator, target: BlockId| -> Option<Vec<ValueId>> {
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
        };

        for &block_id in &dom_tree.rpo_blocks {
            let mut available: HashSet<ValueId> = HashSet::new();

            if is_strict {
                // In strict mode, function guarantees zero dynamic generational checks
            } else if block_id != func.entry_block {
                // 1. Inherit verified references from immediate dominator if no frees intervene
                if let Some(idom) = dom_tree.immediate_dominator(block_id) {
                    if let Some(dom_checks) = verified_at_exit.get(&idom) {
                        let no_free = !freeing_blocks.iter().any(|&fb| {
                            fb != idom
                                && dom_tree.dominates(idom, fb)
                                && dom_tree.dominates(fb, block_id)
                        });
                        if no_free {
                            available.extend(dom_checks.iter().copied());
                        }
                    }
                }

                // 2. Confluent dataflow intersection across all predecessors
                if let Some(preds) = cfg.predecessors.get(&block_id) {
                    if !preds.is_empty() {
                        let processed_preds: Vec<BlockId> = preds
                            .iter()
                            .copied()
                            .filter(|p| verified_at_exit.contains_key(p))
                            .collect();

                        if processed_preds.len() == preds.len() {
                            let mut common: Option<HashSet<ValueId>> = None;
                            for &pred_id in &processed_preds {
                                if let Some(pred_checks) = verified_at_exit.get(&pred_id) {
                                    match &mut common {
                                        None => common = Some(pred_checks.clone()),
                                        Some(c) => c.retain(|val| pred_checks.contains(val)),
                                    }
                                }
                            }
                            if let Some(c) = common {
                                available.extend(c);
                            }
                        }
                    }
                }

                // 3. SSA Block Parameters / Phi Promotion Resolution (SROA Stability)
                if let Some(block) = func.get_block(block_id) {
                    if !block.params.is_empty() {
                        if let Some(preds) = cfg.predecessors.get(&block_id) {
                            for (param_idx, (param_val, _)) in block.params.iter().enumerate() {
                                let mut all_preds_verified = !preds.is_empty();
                                for &pred_id in preds {
                                    if let Some(pred_block) = func.get_block(pred_id) {
                                        if let Some(term) = &pred_block.terminator {
                                            if let Some(args) = get_branch_args(term, block_id) {
                                                if let Some(&arg_val) = args.get(param_idx) {
                                                    let is_verified_in_pred = verified_at_exit
                                                        .get(&pred_id)
                                                        .is_some_and(|set| set.contains(&arg_val));
                                                    if !is_verified_in_pred {
                                                        all_preds_verified = false;
                                                        break;
                                                    }
                                                } else {
                                                    all_preds_verified = false;
                                                    break;
                                                }
                                            } else {
                                                all_preds_verified = false;
                                                break;
                                            }
                                        } else {
                                            all_preds_verified = false;
                                            break;
                                        }
                                    } else {
                                        all_preds_verified = false;
                                        break;
                                    }
                                }

                                if all_preds_verified {
                                    available.insert(*param_val);
                                }
                            }
                        }
                    }
                }

                // 4. Direct lexical dominance: created in dominating block with no intervening frees
                for (&ref_val, &def_block) in ref_defs {
                    if dom_tree.dominates(def_block, block_id) {
                        let no_free = !freeing_blocks.iter().any(|&fb| {
                            dom_tree.dominates(def_block, fb) && dom_tree.dominates(fb, block_id)
                        });
                        if no_free {
                            available.insert(ref_val);
                            available.insert(canonical_ref(ref_val, aliases));
                        }
                    }
                }
            }

            // Local store-to-load reference alias tracking
            let mut ptr_aliases: HashMap<ValueId, ValueId> = HashMap::new();

            if let Some(block) = func.get_block_mut(block_id) {
                for inst in &mut block.instructions {
                    match &mut inst.expr {
                        ValueExpr::Store { ptr, val } => {
                            ptr_aliases.insert(*ptr, *val);
                        }
                        ValueExpr::Load { ptr } => {
                            if let Some(res) = inst.result {
                                let stored = ptr_aliases
                                    .get(ptr)
                                    .copied()
                                    .or_else(|| aliases.get(&res).copied());
                                if let Some(val) = stored {
                                    let canon = canonical_ref(val, aliases);
                                    if available.contains(&val) || available.contains(&canon) {
                                        available.insert(res);
                                        available.insert(canonical_ref(res, aliases));
                                    }
                                }
                            }
                        }
                        ValueExpr::GenRef { .. } | ValueExpr::GenAlloc { .. } => {
                            if let Some(res) = inst.result {
                                available.insert(res);
                                available.insert(canonical_ref(res, aliases));
                            }
                        }
                        ValueExpr::GenFree { ptr } => {
                            let canon = canonical_ref(*ptr, aliases);
                            available.remove(ptr);
                            available.remove(&canon);
                            ptr_aliases.remove(ptr);
                        }
                        ValueExpr::GenCheck { ref_val, redundant } => {
                            self.stats.total_checks += 1;
                            let canon = canonical_ref(*ref_val, aliases);

                            if *redundant {
                                // Already eliminated by LICM hoisting
                                available.insert(*ref_val);
                                available.insert(canon);
                            } else if is_strict
                                || available.contains(ref_val)
                                || available.contains(&canon)
                            {
                                *redundant = true;
                                self.stats.eliminated_checks += 1;
                                available.insert(*ref_val);
                                available.insert(canon);
                            } else {
                                // First dynamic check in path: available for following instructions
                                available.insert(*ref_val);
                                available.insert(canon);
                            }
                        }
                        _ => {}
                    }
                }
            }

            verified_at_exit.insert(block_id, available);
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

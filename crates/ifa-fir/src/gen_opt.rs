use crate::cfg::ControlFlowGraph;
use crate::dominance::DominanceTree;
use crate::ir::*;
use std::collections::{HashMap, HashSet};

/// Statistics collected by the generational check elimination pass.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct GenOptStats {
    pub total_checks: usize,
    pub eliminated_checks: usize,
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

/// Optimizes generational references by statically eliminating redundant `GenCheck` instructions.
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

    /// Run the dominance-based elimination on a single function.
    pub fn run_on_function(&mut self, func: &mut FirFunction) {
        let cfg = ControlFlowGraph::build(func);
        let dom_tree = DominanceTree::build(&cfg);

        // 1. Identify which blocks contain freeing or invalidating operations
        let mut freeing_blocks: HashSet<BlockId> = HashSet::new();
        // Track where each reference was created: ref_val -> creating BlockId
        let mut ref_creation_block: HashMap<ValueId, BlockId> = HashMap::new();

        for block in &func.blocks {
            for inst in &block.instructions {
                match &inst.expr {
                    ValueExpr::GenFree { .. } => {
                        freeing_blocks.insert(block.id);
                    }
                    ValueExpr::GenRef { .. } => {
                        if let Some(res) = inst.result {
                            ref_creation_block.insert(res, block.id);
                        }
                    }
                    _ => {}
                }
            }
        }

        // 2. Map of verified references: ref_val -> Set of blocks that dominate and have verified it
        let mut verified_in_block: HashMap<BlockId, HashSet<ValueId>> = HashMap::new();

        for block in &mut func.blocks {
            let block_id = block.id;
            let mut checked_in_this_block: HashSet<ValueId> = HashSet::new();

            for inst in &mut block.instructions {
                if let ValueExpr::GenCheck { ref_val, redundant } = &mut inst.expr {
                    self.stats.total_checks += 1;

                    // Condition 1: Has this reference already been checked earlier in the same block without free?
                    let already_checked_in_block = checked_in_this_block.contains(ref_val);

                    // Condition 2: Is the creation block dominating this block, and no frees intervene?
                    let created_in_dominating =
                        ref_creation_block.get(ref_val).is_some_and(|&def_block| {
                            dom_tree.dominates(def_block, block_id)
                                && !freeing_blocks.iter().any(|&fb| {
                                    dom_tree.dominates(def_block, fb)
                                        && dom_tree.dominates(fb, block_id)
                                })
                        });

                    // Condition 3: Has a dominating predecessor block already checked this reference?
                    let checked_in_dominator =
                        verified_in_block.iter().any(|(&dom_b, checked_refs)| {
                            dom_tree.dominates(dom_b, block_id)
                                && checked_refs.contains(ref_val)
                                && !freeing_blocks.iter().any(|&fb| {
                                    dom_tree.dominates(dom_b, fb)
                                        && dom_tree.dominates(fb, block_id)
                                })
                        });

                    // Condition 4: Strict function guarantees zero generational dynamic checks
                    let is_strict_func = func.is_strict;

                    if already_checked_in_block
                        || created_in_dominating
                        || checked_in_dominator
                        || is_strict_func
                    {
                        *redundant = true;
                        self.stats.eliminated_checks += 1;
                    } else {
                        // First dynamic check in this block: mark as verified for successors
                        checked_in_this_block.insert(*ref_val);
                    }
                }
            }

            if !checked_in_this_block.is_empty() {
                verified_in_block.insert(block_id, checked_in_this_block);
            }
        }
    }
}

impl Default for GenerationalOptPass {
    fn default() -> Self {
        Self::new()
    }
}

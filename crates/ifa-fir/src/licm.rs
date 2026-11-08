use crate::cfg::ControlFlowGraph;
use crate::dominance::DominanceTree;
use crate::gen_opt::GenerationalOptPass;
use crate::ir::*;
use std::collections::{HashMap, HashSet};

/// Statistics collected by the Loop-Invariant Code Motion (LICM) pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LicmStats {
    /// Total number of field/element projection instructions hoisted out of loops.
    pub hoisted_projections: usize,
    /// Total number of invariant memory load instructions hoisted out of loops.
    pub hoisted_loads: usize,
    /// Total number of loops optimized.
    pub loops_optimized: usize,
}

impl LicmStats {
    pub fn total_hoisted(&self) -> usize {
        self.hoisted_projections + self.hoisted_loads
    }
}

/// Loop-Invariant Code Motion (LICM) Pass for SSA FIR.
///
/// Detects natural loops and hoists invariant struct projections (`GetField`, `GetFieldPtr`,
/// `GenDeref`, `GetElement`, `GetElementPtr`, `ArrayLen`) and invariant `Load` instructions
/// out of loops into preheaders. This eliminates repeated memory addressing overhead and
/// maximizes L1/L2 data cache throughput.
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

        for loop_info in natural_loops {
            let preheader_id = match loop_info.preheader {
                Some(p) => p,
                None => continue,
            };

            let mut loop_optimized = false;

            // Compute written memory locations and side-effect calls within loop blocks
            let mut written_ptrs: HashSet<ValueId> = HashSet::new();
            let mut has_impure_call = false;

            for &b_id in &loop_info.blocks {
                if let Some(b) = func.get_block(b_id) {
                    for inst in &b.instructions {
                        match &inst.expr {
                            ValueExpr::Store { ptr, .. } => {
                                written_ptrs.insert(*ptr);
                            }
                            ValueExpr::SetField { base, .. }
                            | ValueExpr::SetElement { base, .. }
                            | ValueExpr::StructPushField { base, .. }
                            | ValueExpr::ArrayPush { array: base, .. } => {
                                written_ptrs.insert(*base);
                            }
                            ValueExpr::GenFree { ptr } => {
                                written_ptrs.insert(*ptr);
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
                            let res_val = match inst.result {
                                Some(r) => r,
                                None => continue,
                            };

                            // Check if instruction is a hoistable projection or load
                            let is_projection = matches!(
                                &inst.expr,
                                ValueExpr::GetField { .. }
                                    | ValueExpr::GetFieldPtr { .. }
                                    | ValueExpr::GetElement { .. }
                                    | ValueExpr::GetElementPtr { .. }
                                    | ValueExpr::GenDeref { .. }
                                    | ValueExpr::ArrayLen { .. }
                            );

                            let is_safe_load = match &inst.expr {
                                ValueExpr::Load { ptr } => {
                                    !has_impure_call && !written_ptrs.contains(ptr)
                                }
                                _ => false,
                            };

                            if !is_projection && !is_safe_load {
                                continue;
                            }

                            // Check if all operands are defined outside the loop
                            let operands = inst.expr.uses();
                            let all_operands_invariant = operands.iter().all(|u| {
                                param_values.contains(u)
                                    || def_block.get(u).is_some_and(|&d_b| {
                                        !loop_info.blocks.contains(&d_b)
                                            && dom_tree.dominates(d_b, preheader_id)
                                    })
                            });

                            if all_operands_invariant {
                                to_hoist.push((b_id, i_idx, inst.clone()));
                                def_block.insert(res_val, preheader_id);
                                break; // Hoist one candidate per block per sub-iteration
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
                    if let Some(pre_b) = func.get_block_mut(preheader_id) {
                        pre_b.instructions.push(inst);
                        if is_load {
                            self.stats.hoisted_loads += 1;
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

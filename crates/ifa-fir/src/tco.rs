use crate::ipo::IpoCallGraph;
use crate::ir::*;
use crate::sroa::SroaPass;
use ifa_span::Symbol;
use std::collections::{HashMap, HashSet};

/// Statistics collected by the Tail-Call Optimization (TCO) pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcoStats {
    /// Total number of functions analyzed for tail-call recursion.
    pub functions_analyzed: usize,
    /// Number of functions successfully transformed from recursive to iterative loops.
    pub functions_transformed: usize,
    /// Total number of direct tail-call recursion sites eliminated and replaced by loop back-edges.
    pub tail_calls_eliminated: usize,
    /// Number of mutual tail-recursive calls inlined to expose direct self-tail recursion.
    pub mutual_tail_calls_inlined: usize,
}

/// Description of a direct or mutually recursive tail call site within a basic block.
#[derive(Debug, Clone)]
struct TailCallSite {
    block_id: BlockId,
    inst_idx: usize,
    args: Vec<ValueId>,
}

/// Tail-Call Optimization (TCO / Tail Recursion Elimination) pass for SSA FIR.
///
/// Transforms direct self-tail recursive functions and mutually recursive pure functions
/// into iterative loops using SSA block arguments (phi nodes) and CFG back-edges.
///
/// Eliminates runtime call stack overhead (O(N) stack frames -> O(1) space), prevents
/// stack overflows on deep recursions, and exposes the resulting loops to subsequent FIR
/// optimization passes (such as SROA, BCE, LICM, and SIMD vectorization).
pub struct TcoPass {
    stats: TcoStats,
}

impl Default for TcoPass {
    fn default() -> Self {
        Self::new()
    }
}

impl TcoPass {
    /// Create a new TCO optimization pass with default statistics.
    pub fn new() -> Self {
        Self {
            stats: TcoStats::default(),
        }
    }

    /// Return statistics collected during TCO optimization passes.
    pub fn stats(&self) -> TcoStats {
        self.stats
    }

    /// Run tail-call optimization across all functions in a FIR module.
    pub fn run_on_module(&mut self, module: &mut FirModule) {
        let call_graph = IpoCallGraph::build(module);
        let pure_functions =
            crate::ipo::IpoPass::compute_pure_functions_with_graph(module, &call_graph);
        self.run_on_module_with_purity(module, &pure_functions, &call_graph);
    }

    /// Run tail-call optimization using precomputed purity and call graph analysis.
    pub fn run_on_module_with_purity(
        &mut self,
        module: &mut FirModule,
        pure_functions: &HashSet<Symbol>,
        call_graph: &IpoCallGraph,
    ) {
        self.stats.functions_analyzed = module.functions.len();

        // Phase 1: Mutual tail-call inlining for pure function cycles (SCC size == 2)
        self.inline_mutual_tail_calls(module, pure_functions, call_graph);

        // Phase 2: Direct self-tail recursion elimination into SSA loops
        for func in &mut module.functions {
            Self::eliminate_tail_recursion_in_function(func, &mut self.stats);
        }
    }

    /// Inlines mutual tail-recursive calls between pairs of pure functions to expose
    /// direct self-tail recursion for loop transformation.
    fn inline_mutual_tail_calls(
        &mut self,
        module: &mut FirModule,
        pure_functions: &HashSet<Symbol>,
        call_graph: &IpoCallGraph,
    ) {
        // Collect candidate functions map
        let func_map: HashMap<Symbol, FirFunction> = module
            .functions
            .iter()
            .map(|f| (f.name, f.clone()))
            .collect();

        let mut transformed_symbols = HashSet::new();

        for scc in &call_graph.sccs {
            if scc.len() == 2 {
                let mut iter = scc.iter().copied();
                let sym_a = iter.next().unwrap();
                let sym_b = iter.next().unwrap();

                // Both functions must be proven pure and not already transformed
                if pure_functions.contains(&sym_a)
                    && pure_functions.contains(&sym_b)
                    && !transformed_symbols.contains(&sym_a)
                    && !transformed_symbols.contains(&sym_b)
                {
                    if let (Some(fn_a), Some(fn_b)) = (func_map.get(&sym_a), func_map.get(&sym_b)) {
                        // Check if fn_a has tail calls to fn_b and fn_b has tail calls to fn_a
                        let a_calls_b = fn_a
                            .blocks
                            .iter()
                            .any(|b| Self::find_tail_call_in_block(b, sym_b).is_some());
                        let b_calls_a = fn_b
                            .blocks
                            .iter()
                            .any(|b| Self::find_tail_call_in_block(b, sym_a).is_some());

                        if a_calls_b && b_calls_a {
                            // Choose the smaller function to inline into the larger one (or fn_b into fn_a)
                            let (target_sym, inlinee) = if fn_b.blocks.len() <= fn_a.blocks.len()
                                && fn_b.blocks.len() <= 8
                            {
                                (sym_a, fn_b.clone())
                            } else if fn_a.blocks.len() <= 8 {
                                (sym_b, fn_a.clone())
                            } else {
                                continue;
                            };

                            let caller = module
                                .functions
                                .iter_mut()
                                .find(|f| f.name == target_sym)
                                .unwrap();

                            if Self::inline_callee_tail_calls(caller, &inlinee) {
                                self.stats.mutual_tail_calls_inlined += 1;
                                transformed_symbols.insert(target_sym);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Inlines calls to `callee` located in tail position within `caller`.
    fn inline_callee_tail_calls(caller: &mut FirFunction, callee: &FirFunction) -> bool {
        let callee_name = callee.name;
        let mut tail_sites = Vec::new();

        for block in &caller.blocks {
            if let Some((inst_idx, args)) = Self::find_tail_call_in_block(block, callee_name) {
                if args.len() == callee.params.len() {
                    tail_sites.push(TailCallSite {
                        block_id: block.id,
                        inst_idx,
                        args,
                    });
                }
            }
        }

        if tail_sites.is_empty() {
            return false;
        }

        let mut inlined_any = false;

        for site in tail_sites {
            // Allocate new BlockIds for callee blocks
            let mut block_mapping: HashMap<BlockId, BlockId> = HashMap::new();
            for b in &callee.blocks {
                let fresh_b = BlockId(caller.next_block_id);
                caller.next_block_id += 1;
                block_mapping.insert(b.id, fresh_b);
            }

            // Map callee parameters to caller argument values
            let mut val_mapping: HashMap<ValueId, ValueId> = HashMap::new();
            for (p_idx, p) in callee.params.iter().enumerate() {
                val_mapping.insert(p.val, site.args[p_idx]);
            }

            // Map callee block parameters and instruction results to fresh ValueIds
            for b in &callee.blocks {
                for (param_val, _) in &b.params {
                    let fresh_v = ValueId(caller.next_value_id);
                    caller.next_value_id += 1;
                    val_mapping.insert(*param_val, fresh_v);
                }
                for inst in &b.instructions {
                    if let Some(res) = inst.result {
                        let fresh_v = ValueId(caller.next_value_id);
                        caller.next_value_id += 1;
                        val_mapping.insert(res, fresh_v);
                    }
                }
            }

            // Clone and remap callee blocks
            let mut cloned_blocks = Vec::with_capacity(callee.blocks.len());
            for b in &callee.blocks {
                let mapped_id = block_mapping[&b.id];
                let mut cloned_block = BasicBlock::new(mapped_id);

                for (p_val, p_ty) in &b.params {
                    let mapped_p = val_mapping[p_val];
                    cloned_block.push_param(mapped_p, p_ty.clone());
                }

                for inst in &b.instructions {
                    let mut mapped_inst = inst.clone();
                    if let Some(res) = mapped_inst.result {
                        mapped_inst.result = Some(val_mapping[&res]);
                    }
                    SroaPass::substitute_instruction_operands(&mut mapped_inst, &val_mapping);
                    cloned_block.push_instruction(mapped_inst);
                }

                if let Some(term) = &b.terminator {
                    let mut mapped_term = term.clone();
                    SroaPass::substitute_terminator_operands(&mut mapped_term, &val_mapping);

                    // Remap successor blocks
                    match &mut mapped_term {
                        Terminator::Branch { target, .. } => {
                            if let Some(&new_target) = block_mapping.get(target) {
                                *target = new_target;
                            }
                        }
                        Terminator::BranchCond {
                            then_block,
                            else_block,
                            ..
                        } => {
                            if let Some(&new_then) = block_mapping.get(then_block) {
                                *then_block = new_then;
                            }
                            if let Some(&new_else) = block_mapping.get(else_block) {
                                *else_block = new_else;
                            }
                        }
                        Terminator::Switch {
                            cases,
                            default_block,
                            ..
                        } => {
                            for (_, target, _) in cases {
                                if let Some(&new_target) = block_mapping.get(target) {
                                    *target = new_target;
                                }
                            }
                            if let Some(&new_default) = block_mapping.get(default_block) {
                                *default_block = new_default;
                            }
                        }
                        Terminator::Return(_) | Terminator::Fail(_) | Terminator::Unreachable => {}
                    }

                    cloned_block.set_terminator(mapped_term);
                }

                cloned_blocks.push(cloned_block);
            }

            // In the caller block, truncate instructions before CallDirect and branch to entry of inlined callee
            if let Some(block) = caller.get_block_mut(site.block_id) {
                block.instructions.truncate(site.inst_idx);
                let callee_entry = block_mapping[&callee.entry_block];
                block.set_terminator(Terminator::Branch {
                    target: callee_entry,
                    args: Vec::new(),
                });
            }

            caller.blocks.extend(cloned_blocks);
            inlined_any = true;
        }

        inlined_any
    }

    /// Transforms direct self-tail recursive calls into iterative SSA loop back-edges.
    pub fn eliminate_tail_recursion_in_function(
        func: &mut FirFunction,
        stats: &mut TcoStats,
    ) -> bool {
        let param_count = func.params.len();
        let mut tail_sites = Vec::new();

        for block in &func.blocks {
            if let Some((inst_idx, args)) = Self::find_tail_call_in_block(block, func.name) {
                if args.len() == param_count {
                    tail_sites.push(TailCallSite {
                        block_id: block.id,
                        inst_idx,
                        args,
                    });
                }
            }
        }

        if tail_sites.is_empty() {
            return false;
        }

        let old_entry_id = func.entry_block;
        let prologue_id = BlockId(func.next_block_id);
        func.next_block_id += 1;

        let mut prologue_block = BasicBlock::new(prologue_id);

        // 1. Create loop parameters for the old entry block (loop header)
        let mut loop_params = Vec::with_capacity(param_count);
        let mut param_subst = HashMap::new();

        for p in &func.params {
            let loop_param_val = ValueId(func.next_value_id);
            func.next_value_id += 1;
            loop_params.push((loop_param_val, p.ty.clone()));
            param_subst.insert(p.val, loop_param_val);
        }

        // 2. Partition instructions of the old entry block:
        // Move Alloca instructions into the new prologue block so they are executed only once.
        let old_entry_block = func.get_block_mut(old_entry_id).unwrap();
        let mut non_alloca_insts = Vec::with_capacity(old_entry_block.instructions.len());
        for inst in old_entry_block.instructions.drain(..) {
            if matches!(inst.expr, ValueExpr::Alloca { .. }) {
                prologue_block.push_instruction(inst);
            } else {
                non_alloca_insts.push(inst);
            }
        }
        old_entry_block.instructions = non_alloca_insts;
        old_entry_block.params = loop_params;

        // 3. Prologue jumps to old_entry_id passing the initial function parameters
        let initial_args: Vec<ValueId> = func.params.iter().map(|p| p.val).collect();
        prologue_block.set_terminator(Terminator::Branch {
            target: old_entry_id,
            args: initial_args,
        });

        // 4. Replace CallDirect in tail sites with back-edge Branch to loop header
        let count_eliminated = tail_sites.len();
        for site in tail_sites {
            if let Some(block) = func.get_block_mut(site.block_id) {
                block.instructions.truncate(site.inst_idx);
                block.set_terminator(Terminator::Branch {
                    target: old_entry_id,
                    args: site.args,
                });
            }
        }

        // 5. Update entry block and insert prologue at index 0
        func.entry_block = prologue_id;
        func.blocks.insert(0, prologue_block);

        // 6. Substitute original parameter references with loop_params across all blocks except prologue
        for block in &mut func.blocks {
            if block.id == prologue_id {
                continue;
            }
            for inst in &mut block.instructions {
                SroaPass::substitute_instruction_operands(inst, &param_subst);
            }
            if let Some(term) = &mut block.terminator {
                SroaPass::substitute_terminator_operands(term, &param_subst);
            }
        }

        stats.functions_transformed += 1;
        stats.tail_calls_eliminated += count_eliminated;
        true
    }

    /// Detects if a basic block ends with a tail call to `target_name`.
    /// Returns the instruction index of the call and its argument values.
    fn find_tail_call_in_block(
        block: &BasicBlock,
        target_name: Symbol,
    ) -> Option<(usize, Vec<ValueId>)> {
        let term = block.terminator.as_ref()?;
        match term {
            Terminator::Return(Some(ret_val)) => {
                // Find instruction producing ret_val
                for (idx, inst) in block.instructions.iter().enumerate().rev() {
                    if inst.result == Some(*ret_val) {
                        if let ValueExpr::CallDirect { name, args } = &inst.expr {
                            if *name == target_name {
                                let is_clean_tail = block.instructions[idx + 1..]
                                    .iter()
                                    .all(|i| Self::is_side_effect_free(&i.expr));
                                if is_clean_tail {
                                    return Some((idx, args.clone()));
                                }
                            }
                        }
                        break;
                    }
                }
                None
            }
            Terminator::Return(None) => {
                // Check if the last instruction is a direct call returning Unit
                if let Some((idx, inst)) = block.instructions.iter().enumerate().next_back() {
                    if let ValueExpr::CallDirect { name, args } = &inst.expr {
                        if *name == target_name {
                            return Some((idx, args.clone()));
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Returns true if an expression is completely free of observable side-effects.
    fn is_side_effect_free(expr: &ValueExpr) -> bool {
        matches!(
            expr,
            ValueExpr::Constant(_)
                | ValueExpr::Alloca { .. }
                | ValueExpr::Load { .. }
                | ValueExpr::Binary { .. }
                | ValueExpr::Unary { .. }
                | ValueExpr::GetField { .. }
                | ValueExpr::GetFieldPtr { .. }
                | ValueExpr::GetElement { .. }
                | ValueExpr::GetElementPtr { .. }
                | ValueExpr::TupleInit(_)
                | ValueExpr::ArrayInit(_)
                | ValueExpr::ArrayLen { .. }
                | ValueExpr::SliceSub { .. }
                | ValueExpr::BoundsCheck { .. }
                | ValueExpr::SliceBoundsCheck { .. }
        )
    }
}

use crate::cfg::ControlFlowGraph;
use crate::dominance::DominanceTree;
use crate::gen_opt::GenerationalOptPass;
use crate::ir::*;
use crate::sroa::SroaPass;
use ifa_span::{Symbol, INTERNER};
use std::collections::{HashMap, HashSet};

/// Statistics collected by the Inter-Procedural Optimization (IPO) pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IpoStats {
    /// Total number of functions analyzed for purity across the module.
    pub functions_analyzed: usize,
    /// Number of functions proven pure inter-procedurally.
    pub pure_functions: usize,
    /// Number of pure helper function calls inlined inside natural loops.
    pub pure_calls_inlined_in_loops: usize,
    /// Number of loops transformed by pure function inlining.
    pub loops_transformed: usize,
}

/// Inter-Procedural Optimization (IPO) pass for SSA FIR.
///
/// Computes whole-module inter-procedural purity via call graph fixed-point analysis,
/// and inlines small pure helper functions directly into vectorizable loops. This exposes
/// fine-grained primitive arithmetic directly to the SIMD loop auto-vectorizer, eliminating
/// call overhead and enabling full vector lane utilization.
pub struct IpoPass {
    stats: IpoStats,
}

impl Default for IpoPass {
    fn default() -> Self {
        Self::new()
    }
}

impl IpoPass {
    /// Create a new IPO optimization pass.
    pub fn new() -> Self {
        Self {
            stats: IpoStats::default(),
        }
    }

    /// Return statistics from the IPO optimization run.
    pub fn stats(&self) -> IpoStats {
        self.stats
    }

    /// Run inter-procedural purity analysis and pure loop inlining across a FIR module.
    pub fn run_on_module(&mut self, module: &mut FirModule) {
        self.stats.functions_analyzed = module.functions.len();

        // 1. Compute inter-procedural purity across all module functions
        let pure_functions = Self::compute_pure_functions(module);
        self.stats.pure_functions = pure_functions.len();

        // 2. Inline pure leaf helpers inside natural loops
        self.inline_pure_calls_in_loops(module, &pure_functions);
    }

    /// Analyzes the entire FIR module and computes the set of provably pure function symbols.
    ///
    /// A function is pure if:
    /// - It contains no I/O, panic, dynamic free, or concurrency primitives (yield, spawn, channels).
    /// - It does not mutate memory through non-local pointers.
    /// - All functions it invokes directly are themselves proven pure (or pure intrinsics).
    pub fn compute_pure_functions(module: &FirModule) -> HashSet<Symbol> {
        let mut call_graph: HashMap<Symbol, HashSet<Symbol>> = HashMap::new();
        let mut directly_impure: HashSet<Symbol> = HashSet::new();

        for func in &module.functions {
            let mut callees = HashSet::new();
            let mut is_impure = false;

            if func.is_extern.is_some() {
                let name_str = INTERNER.resolve(&func.name);
                if !Self::is_known_pure_intrinsic(&name_str) {
                    is_impure = true;
                }
            }

            let mut local_allocas = HashSet::new();
            for block in &func.blocks {
                for inst in &block.instructions {
                    if let Some(res) = inst.result {
                        if matches!(inst.expr, ValueExpr::Alloca { .. }) {
                            local_allocas.insert(res);
                        }
                    }
                }
            }

            for block in &func.blocks {
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
                        | ValueExpr::CoWClone { .. } => {
                            is_impure = true;
                        }
                        ValueExpr::Store { ptr, .. } => {
                            if !local_allocas.contains(ptr) {
                                is_impure = true;
                            }
                        }
                        ValueExpr::CallDirect { name, .. } => {
                            let callee_str = INTERNER.resolve(name);
                            if Self::is_known_side_effect_function(&callee_str) {
                                is_impure = true;
                            } else if !Self::is_known_pure_intrinsic(&callee_str) {
                                callees.insert(*name);
                            }
                        }
                        _ => {}
                    }
                }
            }

            call_graph.insert(func.name, callees);
            if is_impure {
                directly_impure.insert(func.name);
            }
        }

        // Reverse call graph for fixed-point propagation
        let mut callers: HashMap<Symbol, HashSet<Symbol>> = HashMap::new();
        for (caller, callee_set) in &call_graph {
            for callee in callee_set {
                callers.entry(*callee).or_default().insert(*caller);
            }
        }

        // Propagate impurity via worklist
        let mut impure_set = directly_impure;
        let mut worklist: Vec<Symbol> = impure_set.iter().copied().collect();

        while let Some(impure_func) = worklist.pop() {
            if let Some(caller_list) = callers.get(&impure_func) {
                for &caller in caller_list {
                    if impure_set.insert(caller) {
                        worklist.push(caller);
                    }
                }
            }
        }

        let mut pure_functions = HashSet::new();
        for func in &module.functions {
            if !impure_set.contains(&func.name) {
                pure_functions.insert(func.name);
            }
        }

        pure_functions
    }

    /// Check if a function identifier corresponds to a known pure runtime or math intrinsic.
    pub fn is_known_pure_intrinsic(callee: &str) -> bool {
        callee.starts_with("ifa_simd_")
            || callee.starts_with("llvm.")
            || matches!(
                callee,
                "sin"
                    | "cos"
                    | "sqrt"
                    | "abs"
                    | "min"
                    | "max"
                    | "pow"
                    | "floor"
                    | "ceil"
                    | "fabs"
                    | "fmin"
                    | "fmax"
            )
    }

    /// Check if a function identifier corresponds to a side-effecting runtime or standard call.
    pub fn is_known_side_effect_function(callee: &str) -> bool {
        matches!(
            callee,
            "println"
                | "print"
                | "ifa_rt_println"
                | "ifa_rt_print"
                | "ifa_rt_println_i64"
                | "ifa_rt_panic_uaf"
                | "ifa_rt_bounds_check"
                | "ifa_rt_panic_bounds"
                | "panic"
                | "exit"
                | "abort"
                | "read_line"
                | "read_to_string"
                | "flush"
        )
    }

    /// Inlines calls to pure helper functions located within natural loops.
    fn inline_pure_calls_in_loops(&mut self, module: &mut FirModule, pure_funcs: &HashSet<Symbol>) {
        // Collect single-block inline candidates (<= 50 instructions, with Return terminator)
        let mut candidates: HashMap<Symbol, FirFunction> = HashMap::new();
        for func in &module.functions {
            if pure_funcs.contains(&func.name)
                && func.blocks.len() == 1
                && func.blocks[0].instructions.len() <= 50
                && matches!(func.blocks[0].terminator, Some(Terminator::Return(_)))
            {
                candidates.insert(func.name, func.clone());
            }
        }

        if candidates.is_empty() {
            return;
        }

        for func in &mut module.functions {
            let cfg = ControlFlowGraph::build(func);
            let dom_tree = DominanceTree::build(&cfg);
            let natural_loops = GenerationalOptPass::find_natural_loops(&cfg, &dom_tree);

            if natural_loops.is_empty() {
                continue;
            }

            let mut loop_blocks = HashSet::new();
            for loop_info in &natural_loops {
                loop_blocks.extend(&loop_info.blocks);
            }

            let caller_name = func.name;
            let mut next_val = func.next_value_id;
            let mut func_subst: HashMap<ValueId, ValueId> = HashMap::new();
            let mut transformed_any_loop = false;

            for &b_id in &loop_blocks {
                if let Some(block) = func.get_block_mut(b_id) {
                    let mut new_instructions = Vec::with_capacity(block.instructions.len());
                    let mut inlined_in_block = false;

                    for inst in block.instructions.drain(..) {
                        if let (Some(res), ValueExpr::CallDirect { name, args }) =
                            (inst.result, &inst.expr)
                        {
                            if *name != caller_name {
                                if let Some(target) = candidates.get(name) {
                                    // 1. Map callee parameters to argument values
                                    let mut subst: HashMap<ValueId, ValueId> = HashMap::new();
                                    for (p_idx, param) in target.params.iter().enumerate() {
                                        if let Some(&arg_val) = args.get(p_idx) {
                                            let resolved = func_subst
                                                .get(&arg_val)
                                                .copied()
                                                .unwrap_or(arg_val);
                                            subst.insert(param.val, resolved);
                                        }
                                    }

                                    // 2. Clone and inline callee instructions
                                    for target_inst in &target.blocks[0].instructions {
                                        let mut cloned = target_inst.clone();
                                        let fresh_val = ValueId(next_val);
                                        next_val += 1;

                                        if let Some(orig_res) = cloned.result {
                                            subst.insert(orig_res, fresh_val);
                                            cloned.result = Some(fresh_val);
                                        }

                                        SroaPass::substitute_instruction_operands(
                                            &mut cloned,
                                            &subst,
                                        );
                                        new_instructions.push(cloned);
                                    }

                                    // 3. Map return value to replace the CallDirect result
                                    if let Some(Terminator::Return(Some(ret_val))) =
                                        &target.blocks[0].terminator
                                    {
                                        let actual_ret =
                                            subst.get(ret_val).copied().unwrap_or(*ret_val);
                                        func_subst.insert(res, actual_ret);
                                    } else {
                                        // Callee returns Unit
                                        let unit_val = ValueId(next_val);
                                        next_val += 1;
                                        new_instructions.push(Instruction::new(
                                            Some(unit_val),
                                            ValueExpr::Constant(ConstantValue::Unit),
                                            inst.span,
                                        ));
                                        func_subst.insert(res, unit_val);
                                    }

                                    self.stats.pure_calls_inlined_in_loops += 1;
                                    inlined_in_block = true;
                                    continue;
                                }
                            }
                        }

                        let mut remaining_inst = inst;
                        SroaPass::substitute_instruction_operands(&mut remaining_inst, &func_subst);
                        new_instructions.push(remaining_inst);
                    }

                    block.instructions = new_instructions;
                    if inlined_in_block {
                        transformed_any_loop = true;
                    }
                }
            }

            func.next_value_id = next_val;

            if transformed_any_loop {
                self.stats.loops_transformed += 1;
                // Propagate substitutions across all basic blocks in the function
                if !func_subst.is_empty() {
                    for block in &mut func.blocks {
                        for inst in &mut block.instructions {
                            SroaPass::substitute_instruction_operands(inst, &func_subst);
                        }
                        if let Some(term) = &mut block.terminator {
                            SroaPass::substitute_terminator_operands(term, &func_subst);
                        }
                    }
                }
            }
        }
    }
}

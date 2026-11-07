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
    /// Number of functions participating in direct or mutual recursion.
    pub recursive_functions_detected: usize,
    /// Number of pure helper function calls inlined inside natural loops.
    pub pure_calls_inlined_in_loops: usize,
    /// Number of redundant pure function calls eliminated via inter-procedural CSE.
    pub pure_calls_cse_eliminated: usize,
    /// Number of loops transformed by pure function inlining.
    pub loops_transformed: usize,
}

/// Call graph structure capturing caller-callee relationships, recursive cycles,
/// and Strongly Connected Components (SCC) using Tarjan's algorithm.
#[derive(Debug, Clone, Default)]
pub struct IpoCallGraph {
    /// Mapping from caller function symbol to the set of callees it directly invokes.
    pub callees: HashMap<Symbol, HashSet<Symbol>>,
    /// Mapping from callee function symbol to the set of callers directly invoking it.
    pub callers: HashMap<Symbol, HashSet<Symbol>>,
    /// Strongly Connected Components (SCC) decomposed in topological order.
    pub sccs: Vec<HashSet<Symbol>>,
    /// Set of function symbols proven to participate in self-recursion or mutual recursion.
    pub recursive_functions: HashSet<Symbol>,
}

impl IpoCallGraph {
    /// Builds the whole-module inter-procedural call graph and computes recursive SCC components.
    pub fn build(module: &FirModule) -> Self {
        let mut callees: HashMap<Symbol, HashSet<Symbol>> = HashMap::new();
        let mut callers: HashMap<Symbol, HashSet<Symbol>> = HashMap::new();
        let mut all_funcs: HashSet<Symbol> = HashSet::new();

        for func in &module.functions {
            all_funcs.insert(func.name);
            let mut callee_set = HashSet::new();

            for block in &func.blocks {
                for inst in &block.instructions {
                    if let ValueExpr::CallDirect { name, .. } = &inst.expr {
                        callee_set.insert(*name);
                    }
                }
            }

            for callee in &callee_set {
                callers.entry(*callee).or_default().insert(func.name);
            }
            callees.insert(func.name, callee_set);
        }

        // Tarjan's strongly connected components algorithm
        let mut ctx = TarjanContext {
            callees: &callees,
            all_funcs: &all_funcs,
            index: 0,
            indices: HashMap::new(),
            lowlink: HashMap::new(),
            on_stack: HashSet::new(),
            stack: Vec::new(),
            sccs: Vec::new(),
        };

        for &func_name in &all_funcs {
            if !ctx.indices.contains_key(&func_name) {
                ctx.scc(func_name);
            }
        }

        let sccs = ctx.sccs;

        // Identify recursive functions
        let mut recursive_functions = HashSet::new();
        for scc in &sccs {
            if scc.len() > 1 {
                recursive_functions.extend(scc.iter().copied());
            } else if scc.len() == 1 {
                let node = *scc.iter().next().unwrap();
                if callees.get(&node).is_some_and(|c| c.contains(&node)) {
                    recursive_functions.insert(node);
                }
            }
        }

        Self {
            callees,
            callers,
            sccs,
            recursive_functions,
        }
    }
}

struct TarjanContext<'a> {
    callees: &'a HashMap<Symbol, HashSet<Symbol>>,
    all_funcs: &'a HashSet<Symbol>,
    index: usize,
    indices: HashMap<Symbol, usize>,
    lowlink: HashMap<Symbol, usize>,
    on_stack: HashSet<Symbol>,
    stack: Vec<Symbol>,
    sccs: Vec<HashSet<Symbol>>,
}

impl<'a> TarjanContext<'a> {
    fn scc(&mut self, u: Symbol) {
        self.indices.insert(u, self.index);
        self.lowlink.insert(u, self.index);
        self.index += 1;
        self.stack.push(u);
        self.on_stack.insert(u);

        if let Some(children) = self.callees.get(&u) {
            for &v in children {
                if self.all_funcs.contains(&v) {
                    if !self.indices.contains_key(&v) {
                        self.scc(v);
                        let v_low = self.lowlink[&v];
                        let u_low = self.lowlink.get_mut(&u).unwrap();
                        *u_low = (*u_low).min(v_low);
                    } else if self.on_stack.contains(&v) {
                        let v_idx = self.indices[&v];
                        let u_low = self.lowlink.get_mut(&u).unwrap();
                        *u_low = (*u_low).min(v_idx);
                    }
                }
            }
        }

        if self.lowlink[&u] == self.indices[&u] {
            let mut component = HashSet::new();
            while let Some(w) = self.stack.pop() {
                self.on_stack.remove(&w);
                component.insert(w);
                if w == u {
                    break;
                }
            }
            self.sccs.push(component);
        }
    }
}

/// Inter-Procedural Optimization (IPO) pass for SSA FIR.
///
/// Computes whole-module inter-procedural purity via call graph fixed-point analysis,
/// handles mutually and self-recursive call graphs, performs inter-procedural pure call CSE,
/// and inlines small non-recursive pure helper functions directly into vectorizable loops.
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

    /// Run inter-procedural purity analysis, pure call CSE, and pure loop inlining across a FIR module.
    pub fn run_on_module(&mut self, module: &mut FirModule) {
        self.stats.functions_analyzed = module.functions.len();

        // 1. Build module call graph and identify recursive cycles
        let call_graph = IpoCallGraph::build(module);
        self.stats.recursive_functions_detected = call_graph.recursive_functions.len();

        // 2. Compute inter-procedural purity across all module functions
        let pure_functions = Self::compute_pure_functions_with_graph(module, &call_graph);
        self.stats.pure_functions = pure_functions.len();

        // 3. Eliminate redundant pure function calls within basic blocks (Pure Call CSE)
        self.eliminate_redundant_pure_calls(module, &pure_functions);

        // 4. Inline non-recursive pure leaf helpers inside natural loops for SIMD vectorization
        self.inline_pure_calls_in_loops(module, &pure_functions, &call_graph);
    }

    /// Analyzes the entire FIR module and computes the set of provably pure function symbols.
    pub fn compute_pure_functions(module: &FirModule) -> HashSet<Symbol> {
        let call_graph = IpoCallGraph::build(module);
        Self::compute_pure_functions_with_graph(module, &call_graph)
    }

    /// Analyzes module functions and computes the set of provably pure symbols using the precomputed call graph.
    ///
    /// A function is pure if:
    /// - It contains no I/O, panic, dynamic free, or concurrency primitives (yield, spawn, channels).
    /// - It does not mutate memory through non-local pointers (local stack allocas and derived GEPs are pure).
    /// - All functions it invokes directly are themselves proven pure (or pure intrinsics).
    /// - Mutually recursive cycles (SCCs) are proven pure as a whole if every constituent function has no side-effects.
    pub fn compute_pure_functions_with_graph(
        module: &FirModule,
        call_graph: &IpoCallGraph,
    ) -> HashSet<Symbol> {
        let mut directly_impure: HashSet<Symbol> = HashSet::new();

        for func in &module.functions {
            let mut is_impure = false;

            if func.is_extern.is_some() {
                let name_str = INTERNER.resolve(&func.name);
                if !Self::is_known_pure_intrinsic(&name_str) {
                    is_impure = true;
                }
            }

            // Compute the transitive set of pointers originating strictly from local stack allocas
            let mut local_pointers = HashSet::new();
            for block in &func.blocks {
                for inst in &block.instructions {
                    if let Some(res) = inst.result {
                        if matches!(inst.expr, ValueExpr::Alloca { .. }) {
                            local_pointers.insert(res);
                        }
                    }
                }
            }

            let mut pt_changed = true;
            while pt_changed {
                pt_changed = false;
                for block in &func.blocks {
                    for inst in &block.instructions {
                        if let Some(res) = inst.result {
                            if !local_pointers.contains(&res) {
                                match &inst.expr {
                                    ValueExpr::GetFieldPtr { base, .. }
                                    | ValueExpr::GetElementPtr { base, .. }
                                        if local_pointers.contains(base) =>
                                    {
                                        local_pointers.insert(res);
                                        pt_changed = true;
                                    }
                                    _ => {}
                                }
                            }
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
                            // Storing into locally-allocated stack frame does not escape or create external side-effects
                            if !local_pointers.contains(ptr) {
                                is_impure = true;
                            }
                        }
                        ValueExpr::CallDirect { name, .. } => {
                            let callee_str = INTERNER.resolve(name);
                            if Self::is_known_side_effect_function(&callee_str) {
                                is_impure = true;
                            }
                        }
                        ValueExpr::Call { .. } => {
                            // Dynamic indirect function call: conservatively mark impure
                            is_impure = true;
                        }
                        _ => {}
                    }
                }
            }

            if is_impure {
                directly_impure.insert(func.name);
            }
        }

        // Propagate impurity across recursive SCC components:
        // If any member of an SCC is directly impure, all functions in that cycle are impure.
        for scc in &call_graph.sccs {
            if scc.iter().any(|f| directly_impure.contains(f)) {
                directly_impure.extend(scc.iter().copied());
            }
        }

        // Fixed-point worklist propagation across callers
        let mut impure_set = directly_impure;
        let mut worklist: Vec<Symbol> = impure_set.iter().copied().collect();

        while let Some(impure_func) = worklist.pop() {
            if let Some(caller_list) = call_graph.callers.get(&impure_func) {
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

    /// Eliminates redundant calls to proven pure functions within each basic block.
    pub fn eliminate_redundant_pure_calls(
        &mut self,
        module: &mut FirModule,
        pure_funcs: &HashSet<Symbol>,
    ) {
        for func in &mut module.functions {
            let mut func_subst: HashMap<ValueId, ValueId> = HashMap::new();
            let mut eliminated_any = false;

            for block in &mut func.blocks {
                let mut seen_calls: HashMap<(Symbol, Vec<ValueId>), ValueId> = HashMap::new();
                let mut new_instructions = Vec::with_capacity(block.instructions.len());

                for inst in block.instructions.drain(..) {
                    let mut current_inst = inst;
                    SroaPass::substitute_instruction_operands(&mut current_inst, &func_subst);

                    if let (Some(res), ValueExpr::CallDirect { name, args }) =
                        (current_inst.result, &current_inst.expr)
                    {
                        if pure_funcs.contains(name) {
                            let key = (*name, args.clone());
                            if let Some(&prev_res) = seen_calls.get(&key) {
                                // Redundant pure call: reuse previous result
                                func_subst.insert(res, prev_res);
                                self.stats.pure_calls_cse_eliminated += 1;
                                eliminated_any = true;
                                continue;
                            } else {
                                seen_calls.insert(key, res);
                            }
                        }
                    }

                    new_instructions.push(current_inst);
                }

                block.instructions = new_instructions;
            }

            if eliminated_any && !func_subst.is_empty() {
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

    /// Inlines calls to non-recursive pure helper functions located within natural loops.
    fn inline_pure_calls_in_loops(
        &mut self,
        module: &mut FirModule,
        pure_funcs: &HashSet<Symbol>,
        call_graph: &IpoCallGraph,
    ) {
        // Collect single-block non-recursive pure inline candidates (<= 50 instructions, with Return terminator)
        let mut candidates: HashMap<Symbol, FirFunction> = HashMap::new();
        for func in &module.functions {
            if pure_funcs.contains(&func.name)
                && !call_graph.recursive_functions.contains(&func.name)
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

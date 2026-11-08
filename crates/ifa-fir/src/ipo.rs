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
    /// Number of functions proven read-only (observational, no writes).
    pub readonly_functions: usize,
    /// Number of strict external FFI functions elevated to pure.
    pub strict_ffi_pure_functions: usize,
    /// Number of functions participating in direct or mutual recursion.
    pub recursive_functions_detected: usize,
    /// Number of pure helper function calls inlined inside natural loops.
    pub pure_calls_inlined_in_loops: usize,
    /// Number of redundant pure function calls eliminated via inter-procedural CSE.
    pub pure_calls_cse_eliminated: usize,
    /// Number of loops transformed by pure function inlining.
    pub loops_transformed: usize,
    /// Number of direct tail-recursive calls eliminated and transformed into iterative loops.
    pub tail_calls_eliminated: usize,
    /// Number of functions successfully transformed via tail-call elimination.
    pub tail_call_functions_transformed: usize,
    /// Number of mutual tail-recursive calls inlined between pure functions.
    pub mutual_tail_calls_inlined: usize,
    /// Number of colorless coroutines specialized into direct synchronous functions.
    pub coroutines_specialized_sync: usize,
    /// Number of direct call sites retargeted to specialized synchronous coroutine variants.
    pub direct_coroutine_calls_specialized: usize,
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
                    if let ValueExpr::CallDirect { name, .. }
                    | ValueExpr::BlockingCallDirect { name, .. } = &inst.expr
                    {
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

/// Memory effect classification for a function across the whole module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryEffect {
    /// Function performs zero non-local memory accesses and zero observable side-effects.
    Pure,
    /// Function reads memory (global constants or immutable arguments) but performs zero writes.
    ReadOnly,
    /// Function only writes through specific formal arguments (no global state mutations).
    ArgWrite,
    /// Arbitrary side-effects (heap allocation, I/O, concurrency, or unanalyzed external calls).
    Arbitrary,
}

/// Detailed memory access effects for a function parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ParamMemorySummary {
    /// True if the parameter pointer escapes the function frame (stored in escaping alloca,
    /// returned, passed to spawn, or sent across a channel).
    pub escapes: bool,
    /// True if the pointee memory is modified via Store.
    pub written: bool,
    /// True if the pointee memory is read via Load.
    pub read: bool,
}

/// Whole-function inter-procedural memory summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionMemorySummary {
    pub name: Symbol,
    pub effect: MemoryEffect,
    pub params: Vec<ParamMemorySummary>,
}

/// Whole-module repository of inter-procedural memory summaries.
#[derive(Debug, Clone, Default)]
pub struct InterproceduralMemoryMap {
    pub summaries: HashMap<Symbol, FunctionMemorySummary>,
    pub strict_ffi_pures: usize,
}

impl InterproceduralMemoryMap {
    /// Retrieve the inter-procedural memory summary for a function symbol.
    pub fn get_summary(&self, sym: &Symbol) -> Option<&FunctionMemorySummary> {
        self.summaries.get(sym)
    }

    /// Check if a function is proven pure.
    pub fn is_pure(&self, sym: &Symbol) -> bool {
        self.summaries
            .get(sym)
            .is_some_and(|s| s.effect == MemoryEffect::Pure)
    }

    /// Check if a function is proven read-only (observational, no writes).
    pub fn is_readonly(&self, sym: &Symbol) -> bool {
        self.summaries
            .get(sym)
            .is_some_and(|s| s.effect == MemoryEffect::ReadOnly)
    }

    /// Return the set of all symbols proven pure.
    pub fn pure_function_symbols(&self) -> HashSet<Symbol> {
        self.summaries
            .iter()
            .filter(|(_, s)| s.effect == MemoryEffect::Pure)
            .map(|(sym, _)| *sym)
            .collect()
    }

    /// Compute whole-module inter-procedural memory summaries and purity using call graph.
    pub fn compute(module: &FirModule, call_graph: &IpoCallGraph) -> Self {
        let mut summaries: HashMap<Symbol, FunctionMemorySummary> = HashMap::new();
        let mut strict_ffi_pures = 0;

        // Tracks per-function intra-procedural raw information
        struct FuncLocalInfo {
            has_impure_primitives: bool,
            writes_global: bool,
            reads_non_local: bool,
            call_sites: Vec<(Symbol, Vec<ValueId>)>,
            param_derived: Vec<HashSet<ValueId>>,
            param_escapes: Vec<bool>,
            param_written: Vec<bool>,
            param_read: Vec<bool>,
        }

        let mut local_infos: HashMap<Symbol, FuncLocalInfo> = HashMap::new();

        for func in &module.functions {
            let name_str = INTERNER.resolve(&func.name);
            let param_count = func.params.len();

            if func.blocks.is_empty() || func.is_extern.is_some() {
                // External function declaration (FFI)
                let is_intrinsic = IpoPass::is_known_pure_intrinsic(&name_str);
                let is_side_effect = IpoPass::is_known_side_effect_function(&name_str);

                if is_intrinsic {
                    summaries.insert(
                        func.name,
                        FunctionMemorySummary {
                            name: func.name,
                            effect: MemoryEffect::Pure,
                            params: vec![ParamMemorySummary::default(); param_count],
                        },
                    );
                } else if func.is_strict && !is_side_effect {
                    let has_mut_params = func.params.iter().any(|p| {
                        p.mode == ifa_ast::ParamMode::InOut
                            || p.mode == ifa_ast::ParamMode::Mut
                            || p.mode == ifa_ast::ParamMode::Sink
                    });

                    if !has_mut_params {
                        let has_pointers = func.params.iter().any(|p| {
                            matches!(
                                p.ty,
                                crate::types::FirType::Pointer(..)
                                    | crate::types::FirType::Array(..)
                            )
                        });

                        let effect = if has_pointers {
                            MemoryEffect::ReadOnly
                        } else {
                            strict_ffi_pures += 1;
                            MemoryEffect::Pure
                        };

                        let params = func
                            .params
                            .iter()
                            .map(|p| {
                                let is_ptr = matches!(
                                    p.ty,
                                    crate::types::FirType::Pointer(..)
                                        | crate::types::FirType::Array(..)
                                );
                                ParamMemorySummary {
                                    escapes: false,
                                    written: false,
                                    read: is_ptr,
                                }
                            })
                            .collect();

                        summaries.insert(
                            func.name,
                            FunctionMemorySummary {
                                name: func.name,
                                effect,
                                params,
                            },
                        );
                    } else {
                        let params = func
                            .params
                            .iter()
                            .map(|p| {
                                let is_mut = p.mode == ifa_ast::ParamMode::InOut
                                    || p.mode == ifa_ast::ParamMode::Mut;
                                ParamMemorySummary {
                                    escapes: false,
                                    written: is_mut,
                                    read: true,
                                }
                            })
                            .collect();

                        summaries.insert(
                            func.name,
                            FunctionMemorySummary {
                                name: func.name,
                                effect: MemoryEffect::ArgWrite,
                                params,
                            },
                        );
                    }
                } else {
                    // Non-strict or unknown external call: conservative arbitrary side-effects
                    summaries.insert(
                        func.name,
                        FunctionMemorySummary {
                            name: func.name,
                            effect: MemoryEffect::Arbitrary,
                            params: vec![
                                ParamMemorySummary {
                                    escapes: true,
                                    written: true,
                                    read: true,
                                };
                                param_count
                            ],
                        },
                    );
                }
            } else {
                // Function with body: compute intra-procedural aliases and effects
                let mut local_alloca_ptrs = HashSet::new();
                for block in &func.blocks {
                    for inst in &block.instructions {
                        if let Some(res) = inst.result {
                            if matches!(inst.expr, ValueExpr::Alloca { .. }) {
                                local_alloca_ptrs.insert(res);
                            }
                        }
                    }
                }

                // Propagate local alloca pointer projections
                let mut changed = true;
                while changed {
                    changed = false;
                    for block in &func.blocks {
                        for inst in &block.instructions {
                            if let Some(res) = inst.result {
                                if !local_alloca_ptrs.contains(&res) {
                                    match &inst.expr {
                                        ValueExpr::GetFieldPtr { base, .. }
                                        | ValueExpr::GetElementPtr { base, .. }
                                            if local_alloca_ptrs.contains(base) =>
                                        {
                                            local_alloca_ptrs.insert(res);
                                            changed = true;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }

                // Compute parameter projection sets
                let mut param_derived: Vec<HashSet<ValueId>> = Vec::with_capacity(param_count);
                for p in &func.params {
                    let mut s = HashSet::new();
                    s.insert(p.val);
                    param_derived.push(s);
                }

                let mut alloca_param_map: HashMap<ValueId, HashSet<usize>> = HashMap::new();
                let mut p_changed = true;
                while p_changed {
                    p_changed = false;
                    for block in &func.blocks {
                        for inst in &block.instructions {
                            if let Some(res) = inst.result {
                                match &inst.expr {
                                    ValueExpr::GetField { base, .. }
                                    | ValueExpr::GetFieldPtr { base, .. }
                                    | ValueExpr::GetElementPtr { base, .. } => {
                                        for set in &mut param_derived {
                                            if set.contains(base) && set.insert(res) {
                                                p_changed = true;
                                            }
                                        }
                                    }
                                    ValueExpr::StructInit { fields, .. } => {
                                        for set in &mut param_derived {
                                            if fields.iter().any(|f| set.contains(f))
                                                && set.insert(res)
                                            {
                                                p_changed = true;
                                            }
                                        }
                                    }
                                    ValueExpr::Load { ptr } => {
                                        if let Some(indices) = alloca_param_map.get(ptr) {
                                            for &idx in indices {
                                                if param_derived[idx].insert(res) {
                                                    p_changed = true;
                                                }
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            } else if let ValueExpr::Store { ptr, val } = &inst.expr {
                                if local_alloca_ptrs.contains(ptr) {
                                    for (idx, set) in param_derived.iter().enumerate() {
                                        if set.contains(val)
                                            && alloca_param_map.entry(*ptr).or_default().insert(idx)
                                        {
                                            p_changed = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                let mut param_escapes = vec![false; param_count];
                let mut param_written = vec![false; param_count];
                let mut param_read = vec![false; param_count];
                let mut has_impure_primitives = false;
                let mut writes_global = false;
                let mut reads_non_local = false;
                let mut call_sites = Vec::new();

                for block in &func.blocks {
                    for inst in &block.instructions {
                        match &inst.expr {
                            ValueExpr::Yield
                            | ValueExpr::YieldValue { .. }
                            | ValueExpr::Spawn { .. }
                            | ValueExpr::ChanCreate { .. }
                            | ValueExpr::ChanSend { .. }
                            | ValueExpr::ChanRecv { .. }
                            | ValueExpr::ChanTryRecv { .. }
                            | ValueExpr::ChanClose { .. }
                            | ValueExpr::ChanSelect { .. }
                            | ValueExpr::GenFree { .. }
                            | ValueExpr::CoWClone { .. }
                            | ValueExpr::BlockingCallDirect { .. } => {
                                has_impure_primitives = true;
                                for (idx, set) in param_derived.iter().enumerate() {
                                    for u in inst.expr.uses() {
                                        if set.contains(&u) {
                                            param_escapes[idx] = true;
                                        }
                                    }
                                }
                            }
                            ValueExpr::Store { ptr, val } => {
                                let mut is_param_store = false;
                                for (idx, set) in param_derived.iter().enumerate() {
                                    if set.contains(ptr) {
                                        param_written[idx] = true;
                                        is_param_store = true;
                                    }
                                    if set.contains(val) && !local_alloca_ptrs.contains(ptr) {
                                        param_escapes[idx] = true;
                                    }
                                }
                                if !is_param_store && !local_alloca_ptrs.contains(ptr) {
                                    writes_global = true;
                                }
                            }
                            ValueExpr::Load { ptr } => {
                                let mut is_local_alloca = local_alloca_ptrs.contains(ptr);
                                for (idx, set) in param_derived.iter().enumerate() {
                                    if set.contains(ptr) {
                                        param_read[idx] = true;
                                        is_local_alloca = true;
                                    }
                                }
                                if !is_local_alloca {
                                    reads_non_local = true;
                                }
                            }
                            ValueExpr::CallDirect { name, args } => {
                                let callee_name = INTERNER.resolve(name);
                                if IpoPass::is_known_side_effect_function(&callee_name) {
                                    has_impure_primitives = true;
                                }
                                call_sites.push((*name, args.clone()));
                            }
                            ValueExpr::Call { .. } => {
                                // Dynamic indirect call
                                has_impure_primitives = true;
                                for (idx, set) in param_derived.iter().enumerate() {
                                    for u in inst.expr.uses() {
                                        if set.contains(&u) {
                                            param_escapes[idx] = true;
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }

                    if let Some(Terminator::Return(Some(ret_val))) = &block.terminator {
                        for (idx, set) in param_derived.iter().enumerate() {
                            if set.contains(ret_val) {
                                param_escapes[idx] = true;
                            }
                        }
                    }
                }

                local_infos.insert(
                    func.name,
                    FuncLocalInfo {
                        has_impure_primitives,
                        writes_global,
                        reads_non_local,
                        call_sites,
                        param_derived,
                        param_escapes,
                        param_written,
                        param_read,
                    },
                );
            }
        }

        // Initialize summaries for functions with bodies (optimistically Pure, updated via fixed-point)
        for func in &module.functions {
            summaries.entry(func.name).or_insert_with(|| {
                let info = &local_infos[&func.name];
                let mut initial_params = Vec::with_capacity(func.params.len());
                for i in 0..func.params.len() {
                    initial_params.push(ParamMemorySummary {
                        escapes: info.param_escapes[i],
                        written: info.param_written[i],
                        read: info.param_read[i],
                    });
                }
                FunctionMemorySummary {
                    name: func.name,
                    effect: MemoryEffect::Pure,
                    params: initial_params,
                }
            });
        }

        // Fixed-point inter-procedural propagation across call sites
        let mut fp_changed = true;
        let mut iterations = 0;
        while fp_changed && iterations < 32 {
            fp_changed = false;
            iterations += 1;

            for func in &module.functions {
                if let Some(info) = local_infos.get(&func.name) {
                    for (callee_sym, args) in &info.call_sites {
                        if let Some(callee_summary) = summaries.get(callee_sym).cloned() {
                            for (arg_idx, &arg_val) in args.iter().enumerate() {
                                if let Some(callee_param) = callee_summary.params.get(arg_idx) {
                                    for (p_idx, set) in info.param_derived.iter().enumerate() {
                                        if set.contains(&arg_val) {
                                            let current_sum =
                                                summaries.get_mut(&func.name).unwrap();
                                            if callee_param.escapes
                                                && !current_sum.params[p_idx].escapes
                                            {
                                                current_sum.params[p_idx].escapes = true;
                                                fp_changed = true;
                                            }
                                            if callee_param.written
                                                && !current_sum.params[p_idx].written
                                            {
                                                current_sum.params[p_idx].written = true;
                                                fp_changed = true;
                                            }
                                            if callee_param.read && !current_sum.params[p_idx].read
                                            {
                                                current_sum.params[p_idx].read = true;
                                                fp_changed = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Final whole-function memory effect resolution
        // Propagate impurity across recursive SCC components first:
        for scc in &call_graph.sccs {
            let scc_impure = scc.iter().any(|f| {
                if let Some(info) = local_infos.get(f) {
                    info.has_impure_primitives || info.writes_global
                } else if let Some(sum) = summaries.get(f) {
                    sum.effect == MemoryEffect::Arbitrary
                } else {
                    true
                }
            });
            if scc_impure {
                for f in scc {
                    if let Some(sum) = summaries.get_mut(f) {
                        sum.effect = MemoryEffect::Arbitrary;
                    }
                }
            }
        }

        // Propagate effects topologically / iteratively
        let mut effect_changed = true;
        let mut eff_iters = 0;
        while effect_changed && eff_iters < 32 {
            effect_changed = false;
            eff_iters += 1;

            for func in &module.functions {
                if let Some(info) = local_infos.get(&func.name) {
                    let mut max_effect = if info.has_impure_primitives || info.writes_global {
                        MemoryEffect::Arbitrary
                    } else if info.param_written.iter().any(|&w| w) {
                        MemoryEffect::ArgWrite
                    } else if info.param_read.iter().any(|&r| r) || info.reads_non_local {
                        MemoryEffect::ReadOnly
                    } else {
                        MemoryEffect::Pure
                    };

                    for (callee_sym, _) in &info.call_sites {
                        if let Some(callee_sum) = summaries.get(callee_sym) {
                            match callee_sum.effect {
                                MemoryEffect::Arbitrary => max_effect = MemoryEffect::Arbitrary,
                                MemoryEffect::ArgWrite if max_effect != MemoryEffect::Arbitrary => {
                                    max_effect = MemoryEffect::ArgWrite;
                                }
                                MemoryEffect::ReadOnly if max_effect == MemoryEffect::Pure => {
                                    max_effect = MemoryEffect::ReadOnly;
                                }
                                _ => {}
                            }
                        }
                    }

                    let cur_sum = summaries.get_mut(&func.name).unwrap();
                    if cur_sum.effect != max_effect {
                        cur_sum.effect = max_effect;
                        effect_changed = true;
                    }
                }
            }
        }

        Self {
            summaries,
            strict_ffi_pures,
        }
    }
}

/// Inter-Procedural Optimization (IPO) pass for SSA FIR.
///
/// Computes whole-module inter-procedural purity and memory effects via call graph fixed-point analysis,
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

        // 2. Compute whole-module inter-procedural memory access map and purity
        let mem_map = InterproceduralMemoryMap::compute(module, &call_graph);
        self.stats.readonly_functions = mem_map
            .summaries
            .values()
            .filter(|s| s.effect == MemoryEffect::ReadOnly)
            .count();
        self.stats.strict_ffi_pure_functions = mem_map.strict_ffi_pures;

        let pure_functions = mem_map.pure_function_symbols();
        self.stats.pure_functions = pure_functions.len();

        // 3. Eliminate redundant pure function calls within basic blocks (Pure Call CSE)
        self.eliminate_redundant_pure_calls(module, &pure_functions);

        // 4. Inline non-recursive pure leaf helpers inside natural loops for SIMD vectorization
        self.inline_pure_calls_in_loops(module, &pure_functions, &call_graph);

        // 5. Tail-Call Optimization (TCO) for self-recursive and mutually recursive pure functions
        let mut tco_pass = crate::tco::TcoPass::new();
        tco_pass.run_on_module_with_purity(module, &pure_functions, &call_graph);
        let tco_stats = tco_pass.stats();
        self.stats.tail_calls_eliminated = tco_stats.tail_calls_eliminated;
        self.stats.tail_call_functions_transformed = tco_stats.functions_transformed;
        self.stats.mutual_tail_calls_inlined = tco_stats.mutual_tail_calls_inlined;

        // 6. Inter-procedural colorless coroutine specialization for direct synchronous callers
        self.specialize_colorless_coroutines(module);
    }

    /// Analyzes the entire FIR module and computes the set of provably pure function symbols.
    pub fn compute_pure_functions(module: &FirModule) -> HashSet<Symbol> {
        let call_graph = IpoCallGraph::build(module);
        Self::compute_pure_functions_with_graph(module, &call_graph)
    }

    /// Analyzes module functions and computes the set of provably pure symbols using the precomputed call graph.
    pub fn compute_pure_functions_with_graph(
        module: &FirModule,
        call_graph: &IpoCallGraph,
    ) -> HashSet<Symbol> {
        let mem_map = InterproceduralMemoryMap::compute(module, call_graph);
        mem_map.pure_function_symbols()
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

    /// Inter-procedural specialization of colorless coroutines invoked via direct synchronous calls.
    ///
    /// In IFA's colorless concurrency model, functions containing cooperative suspension points (`yield`)
    /// are lowered as stackless coroutines for asynchronous execution (`spawn`). However, when invoked
    /// directly via synchronous call (`CallDirect`), the coroutine can either:
    /// 1. Be specialized in-place into a synchronous direct function when it is never spawned.
    /// 2. Be cloned and specialized into a dedicated synchronous variant (`_direct_sync`) when invoked
    ///    both asynchronously and synchronously, retargeting direct call sites to eliminate coroutine
    ///    state-machine frame allocation overhead.
    pub fn specialize_colorless_coroutines(&mut self, module: &mut FirModule) {
        let coro_symbols: HashSet<Symbol> = module
            .functions
            .iter()
            .filter(|f| f.is_coroutine())
            .map(|f| f.name)
            .collect();

        if coro_symbols.is_empty() {
            return;
        }

        let mut direct_calls: HashMap<Symbol, usize> = HashMap::new();
        let mut spawn_calls: HashMap<Symbol, usize> = HashMap::new();

        for func in &module.functions {
            for block in &func.blocks {
                for inst in &block.instructions {
                    match &inst.expr {
                        ValueExpr::CallDirect { name, .. } if coro_symbols.contains(name) => {
                            *direct_calls.entry(*name).or_default() += 1;
                        }
                        ValueExpr::Spawn { target, .. } if coro_symbols.contains(target) => {
                            *spawn_calls.entry(*target).or_default() += 1;
                        }
                        _ => {}
                    }
                }
            }
        }

        let yield_sym = INTERNER.intern("ifa_rt_fiber_yield");
        let mut specialized_clones: Vec<FirFunction> = Vec::new();
        let mut retarget_map: HashMap<Symbol, Symbol> = HashMap::new();

        for &coro_sym in &coro_symbols {
            let direct_count = direct_calls.get(&coro_sym).copied().unwrap_or(0);
            if direct_count == 0 {
                continue;
            }

            let is_spawned = spawn_calls.get(&coro_sym).copied().unwrap_or(0) > 0;

            if !is_spawned {
                // Case 1: Exclusively direct synchronous callers -> specialize in-place
                if let Some(func) = module.functions.iter_mut().find(|f| f.name == coro_sym) {
                    func.is_coroutine = false;
                    for block in &mut func.blocks {
                        for inst in &mut block.instructions {
                            match &mut inst.expr {
                                ValueExpr::Yield | ValueExpr::YieldValue { .. } => {
                                    inst.expr = ValueExpr::CallDirect {
                                        name: yield_sym,
                                        args: vec![],
                                    };
                                }
                                _ => {}
                            }
                        }
                    }
                    self.stats.coroutines_specialized_sync += 1;
                    self.stats.direct_coroutine_calls_specialized += direct_count;
                }
            } else {
                // Case 2: Inactive both in spawn and direct calls -> generate dedicated synchronous clone
                if let Some(orig_func) = module.functions.iter().find(|f| f.name == coro_sym) {
                    let base_name = INTERNER.resolve(&coro_sym);
                    let sync_name = INTERNER.intern(&format!("{}_direct_sync", base_name));
                    let mut sync_func = orig_func.clone();
                    sync_func.name = sync_name;
                    sync_func.is_coroutine = false;

                    for block in &mut sync_func.blocks {
                        for inst in &mut block.instructions {
                            match &mut inst.expr {
                                ValueExpr::Yield | ValueExpr::YieldValue { .. } => {
                                    inst.expr = ValueExpr::CallDirect {
                                        name: yield_sym,
                                        args: vec![],
                                    };
                                }
                                _ => {}
                            }
                        }
                    }

                    specialized_clones.push(sync_func);
                    retarget_map.insert(coro_sym, sync_name);
                    self.stats.coroutines_specialized_sync += 1;
                    self.stats.direct_coroutine_calls_specialized += direct_count;
                }
            }
        }

        // Add specialized cloned functions to module
        module.functions.extend(specialized_clones);

        // Retarget direct calls to the specialized synchronous clone
        if !retarget_map.is_empty() {
            for func in &mut module.functions {
                for block in &mut func.blocks {
                    for inst in &mut block.instructions {
                        if let ValueExpr::CallDirect { name, .. } = &mut inst.expr {
                            if let Some(&new_name) = retarget_map.get(name) {
                                *name = new_name;
                            }
                        }
                    }
                }
            }
        }
    }
}

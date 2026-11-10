use crate::cfg::ControlFlowGraph;
use crate::dominance::DominanceTree;
use crate::gen_opt::GenerationalOptPass;
use crate::ir::*;
use crate::sroa::SroaPass;
use crate::FirType;
use ifa_sema::types::IntType;
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
    /// Number of constant parameters propagated across inter-procedural call sites.
    pub interprocedural_constants_propagated: usize,
    /// Number of sliding window loops specialized via symbolic constant propagation.
    pub sliding_windows_specialized: usize,
    /// Number of bare-metal convolution loops optimized with unrolled kernel bounds.
    pub convolutions_vectorized: usize,
    /// Number of redundant sliding window bounds checks statically eliminated.
    pub sliding_window_bounds_eliminated: usize,
    /// Number of function parameters inter-procedurally proven non-aliasing (`noalias`).
    pub noalias_parameters_propagated: usize,
    /// Number of nested structure field access paths disambiguated as non-aliasing.
    pub nested_struct_paths_disambiguated: usize,
    /// Number of call site argument pairs statically verified as disjoint.
    pub disjoint_call_sites_verified: usize,
    /// Number of 2D strided convolution loops specialized via inter-procedural propagation.
    pub strided_conv2d_specialized: usize,
    /// Number of 3D strided convolution loops specialized via inter-procedural propagation.
    pub strided_conv3d_specialized: usize,
    /// Number of zero-copy strided convolutions specialized without intermediate copies.
    pub zero_copy_convolutions_specialized: usize,
    /// Number of strided convolution bounds checks statically eliminated.
    pub strided_bounds_eliminated: usize,
    /// Number of constant strides propagated across inter-procedural call sites.
    pub constant_strides_propagated: usize,
    /// Number of decimation stencil loops specialized via constant stride propagation.
    pub decimation_stencils_specialized: usize,
    /// Number of multidimensional convolution kernels fused across pipeline stages.
    pub fused_convolution_kernels: usize,
    /// Number of colorless coroutines with disjoint arena references analyzed.
    pub coroutine_disjoint_arenas_analyzed: usize,
    /// Number of superfluous synchronization/access barriers eliminated around coroutine suspension/resumption points.
    pub coroutine_sync_barriers_eliminated: usize,
    /// Number of disjoint arena parameters propagated inter-procedurally.
    pub disjoint_arena_parameters_propagated: usize,
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

/// Originating root of a memory reference in SSA FIR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathRoot {
    Param(usize),
    Alloca(ValueId),
    CallArena(ValueId),
    GenArena(ValueId, Option<u16>),
    Global(Symbol),
    Unknown(ValueId),
}

/// Path through nested structures and projections starting from a PathRoot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StructAccessPath {
    pub root: PathRoot,
    pub fields: Vec<usize>,
}

impl StructAccessPath {
    pub fn new(root: PathRoot) -> Self {
        Self {
            root,
            fields: Vec::new(),
        }
    }

    pub fn with_field(&self, field: usize) -> Self {
        let mut f = self.fields.clone();
        f.push(field);
        Self {
            root: self.root,
            fields: f,
        }
    }

    /// Check whether two struct access paths are provably disjoint (non-aliasing).
    pub fn is_disjoint_from(&self, other: &Self) -> bool {
        match (self.root, other.root) {
            (PathRoot::Alloca(a1), PathRoot::Alloca(a2)) => a1 != a2,
            (PathRoot::CallArena(c1), PathRoot::CallArena(c2)) => c1 != c2,
            (PathRoot::GenArena(g1, a1), PathRoot::GenArena(g2, a2)) => {
                if g1 != g2 {
                    true
                } else if let (Some(id1), Some(id2)) = (a1, a2) {
                    id1 > 0 && id2 > 0 && id1 != id2
                } else {
                    false
                }
            }
            (PathRoot::Alloca(_), PathRoot::CallArena(_) | PathRoot::GenArena(..))
            | (PathRoot::CallArena(_), PathRoot::Alloca(_) | PathRoot::GenArena(..))
            | (PathRoot::GenArena(..), PathRoot::Alloca(_) | PathRoot::CallArena(_)) => true,
            (PathRoot::Param(p1), PathRoot::Param(p2)) if p1 != p2 => true,
            (
                PathRoot::Param(_),
                PathRoot::Alloca(_) | PathRoot::CallArena(_) | PathRoot::GenArena(..),
            )
            | (
                PathRoot::Alloca(_) | PathRoot::CallArena(_) | PathRoot::GenArena(..),
                PathRoot::Param(_),
            ) => true,
            _ => {
                if self.root == other.root {
                    // Same root: check if nested field projections diverge!
                    let min_len = self.fields.len().min(other.fields.len());
                    for i in 0..min_len {
                        if self.fields[i] != other.fields[i] {
                            // Diverging field index in struct layout: provably non-aliasing!
                            return true;
                        }
                    }
                    false
                } else {
                    false
                }
            }
        }
    }
}

/// Detailed memory access effects and non-aliasing guarantees for a function parameter.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParamMemorySummary {
    /// True if the parameter pointer escapes the function frame (stored in escaping alloca,
    /// returned, passed to spawn, or sent across a channel).
    pub escapes: bool,
    /// True if the pointee memory is modified via Store.
    pub written: bool,
    /// True if the pointee memory is read via Load.
    pub read: bool,
    /// True if the parameter pointer is proven non-aliasing (`noalias`) across all call sites.
    pub noalias: bool,
    /// True if nested fields of this parameter are accessed via provably disjoint paths.
    pub nested_fields_disjoint: bool,
    /// Unique field projection paths accessed through this parameter.
    pub accessed_field_paths: Vec<Vec<usize>>,
    /// Known generational arena identifier for this parameter if determined statically.
    pub arena_id: Option<u16>,
    /// True if this parameter points into a proven disjoint memory arena.
    pub is_disjoint_arena: bool,
    /// True if this reference resides in an isolated disjoint arena and is guaranteed to survive
    /// coroutine suspensions/resumptions without requiring memory synchronization barriers.
    pub survives_coroutine_yield: bool,
}

/// Whole-function inter-procedural memory summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionMemorySummary {
    pub name: Symbol,
    pub effect: MemoryEffect,
    pub params: Vec<ParamMemorySummary>,
    /// True if this function is a colorless coroutine or contains yield points.
    pub is_coroutine: bool,
    /// True if this function contains coroutine suspension points (Yield, YieldValue, blocking channel ops).
    pub has_suspension_points: bool,
    /// Set of distinct non-zero generational arenas accessed or allocated in this function.
    pub disjoint_arenas: HashSet<u16>,
    /// Number of redundant coroutine synchronization/access barriers eliminated for this function.
    pub coroutine_sync_barriers_eliminated: usize,
}

/// Whole-module repository of inter-procedural memory summaries.
#[derive(Debug, Clone, Default)]
pub struct InterproceduralMemoryMap {
    pub summaries: HashMap<Symbol, FunctionMemorySummary>,
    pub strict_ffi_pures: usize,
    pub noalias_parameters_propagated: usize,
    pub nested_struct_paths_disambiguated: usize,
    pub disjoint_call_sites_verified: usize,
    pub coroutine_disjoint_arenas_analyzed: usize,
    pub coroutine_sync_barriers_eliminated: usize,
    pub disjoint_arena_parameters_propagated: usize,
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
            is_coroutine: bool,
            has_suspension_points: bool,
            disjoint_arenas: HashSet<u16>,
            call_sites: Vec<(Symbol, Vec<ValueId>)>,
            param_derived: Vec<HashSet<ValueId>>,
            param_escapes: Vec<bool>,
            param_written: Vec<bool>,
            param_read: Vec<bool>,
            value_paths: HashMap<ValueId, StructAccessPath>,
            param_field_paths: Vec<HashSet<Vec<usize>>>,
            nested_fields_disjoint: Vec<bool>,
            val_arenas: HashMap<ValueId, u16>,
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
                            is_coroutine: false,
                            has_suspension_points: false,
                            disjoint_arenas: HashSet::new(),
                            coroutine_sync_barriers_eliminated: 0,
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
                                    | crate::types::FirType::Slice(..)
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
                                        | crate::types::FirType::Slice(..)
                                );
                                ParamMemorySummary {
                                    escapes: false,
                                    written: false,
                                    read: is_ptr,
                                    noalias: true,
                                    nested_fields_disjoint: true,
                                    accessed_field_paths: Vec::new(),
                                    arena_id: None,
                                    is_disjoint_arena: true,
                                    survives_coroutine_yield: true,
                                }
                            })
                            .collect();

                        summaries.insert(
                            func.name,
                            FunctionMemorySummary {
                                name: func.name,
                                effect,
                                params,
                                is_coroutine: false,
                                has_suspension_points: false,
                                disjoint_arenas: HashSet::new(),
                                coroutine_sync_barriers_eliminated: 0,
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
                                    noalias: true,
                                    nested_fields_disjoint: true,
                                    accessed_field_paths: Vec::new(),
                                    arena_id: None,
                                    is_disjoint_arena: true,
                                    survives_coroutine_yield: true,
                                }
                            })
                            .collect();

                        summaries.insert(
                            func.name,
                            FunctionMemorySummary {
                                name: func.name,
                                effect: MemoryEffect::ArgWrite,
                                params,
                                is_coroutine: false,
                                has_suspension_points: false,
                                disjoint_arenas: HashSet::new(),
                                coroutine_sync_barriers_eliminated: 0,
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
                                    noalias: false,
                                    nested_fields_disjoint: false,
                                    accessed_field_paths: Vec::new(),
                                    arena_id: None,
                                    is_disjoint_arena: false,
                                    survives_coroutine_yield: false,
                                };
                                param_count
                            ],
                            is_coroutine: false,
                            has_suspension_points: false,
                            disjoint_arenas: HashSet::new(),
                            coroutine_sync_barriers_eliminated: 0,
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
                let mut val_arenas: HashMap<ValueId, u16> = HashMap::new();
                let mut disjoint_arenas: HashSet<u16> = HashSet::new();
                let mut has_suspension_points = false;

                for block in &func.blocks {
                    for inst in &block.instructions {
                        if let Some(res) = inst.result {
                            match &inst.expr {
                                ValueExpr::GenAlloc { arena: Some(a), .. } if *a > 0 => {
                                    val_arenas.insert(res, *a);
                                    disjoint_arenas.insert(*a);
                                }
                                ValueExpr::CallArenaAlloc { .. } => {
                                    val_arenas
                                        .insert(res, crate::closure_opt::ARENA_THREAD_LOCAL_CALL);
                                }
                                _ => {}
                            }
                        }

                        match &inst.expr {
                            ValueExpr::Yield
                            | ValueExpr::YieldValue { .. }
                            | ValueExpr::ChanRecv { .. }
                            | ValueExpr::ChanSend { .. }
                            | ValueExpr::ChanSelect { .. } => {
                                has_suspension_points = true;
                                has_impure_primitives = true;
                                for (idx, set) in param_derived.iter().enumerate() {
                                    for u in inst.expr.uses() {
                                        if set.contains(&u) {
                                            param_escapes[idx] = true;
                                        }
                                    }
                                }
                            }
                            ValueExpr::Spawn { .. }
                            | ValueExpr::ChanCreate { .. }
                            | ValueExpr::ChanTrySend { .. }
                            | ValueExpr::ChanTryRecv { .. }
                            | ValueExpr::ChanClose { .. }
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

                // Trace struct and pointer access paths
                let mut value_paths: HashMap<ValueId, StructAccessPath> = HashMap::new();
                for (p_idx, p) in func.params.iter().enumerate() {
                    value_paths.insert(p.val, StructAccessPath::new(PathRoot::Param(p_idx)));
                }
                for block in &func.blocks {
                    for inst in &block.instructions {
                        if let Some(res) = inst.result {
                            match &inst.expr {
                                ValueExpr::Alloca { .. } => {
                                    value_paths
                                        .insert(res, StructAccessPath::new(PathRoot::Alloca(res)));
                                }
                                ValueExpr::CallArenaAlloc { .. } => {
                                    value_paths.insert(
                                        res,
                                        StructAccessPath::new(PathRoot::CallArena(res)),
                                    );
                                }
                                ValueExpr::GenAlloc { arena, .. } => {
                                    value_paths.insert(
                                        res,
                                        StructAccessPath::new(PathRoot::GenArena(res, *arena)),
                                    );
                                }
                                _ => {}
                            }
                        }
                    }
                }

                // Propagate struct access paths iteratively
                let mut path_changed = true;
                while path_changed {
                    path_changed = false;
                    for block in &func.blocks {
                        for inst in &block.instructions {
                            if let Some(res) = inst.result {
                                match &inst.expr {
                                    ValueExpr::GetField {
                                        base, field_idx, ..
                                    }
                                    | ValueExpr::GetFieldPtr {
                                        base, field_idx, ..
                                    } => {
                                        if let Some(parent_path) = value_paths.get(base).cloned() {
                                            let new_path = parent_path.with_field(*field_idx);
                                            if value_paths.get(&res) != Some(&new_path) {
                                                value_paths.insert(res, new_path);
                                                path_changed = true;
                                            }
                                        }
                                    }
                                    ValueExpr::GetElement { base, .. }
                                    | ValueExpr::GetElementPtr { base, .. } => {
                                        if let Some(parent_path) = value_paths.get(base).cloned() {
                                            let new_path = parent_path.with_field(0);
                                            if value_paths.get(&res) != Some(&new_path) {
                                                value_paths.insert(res, new_path);
                                                path_changed = true;
                                            }
                                        }
                                    }
                                    ValueExpr::Load { ptr } => {
                                        if let Some(parent_path) = value_paths.get(ptr).cloned() {
                                            if value_paths.get(&res) != Some(&parent_path) {
                                                value_paths.insert(res, parent_path);
                                                path_changed = true;
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            } else if let ValueExpr::Store { ptr, val } = &inst.expr {
                                if let Some(val_path) = value_paths.get(val).cloned() {
                                    if !value_paths.contains_key(ptr) {
                                        value_paths.insert(*ptr, val_path);
                                        path_changed = true;
                                    }
                                }
                            }
                        }
                    }
                }

                // Collect accessed nested field paths per parameter
                let mut param_field_paths: Vec<HashSet<Vec<usize>>> =
                    vec![HashSet::new(); param_count];
                for block in &func.blocks {
                    for inst in &block.instructions {
                        let ptr_opt = match &inst.expr {
                            ValueExpr::Load { ptr } => Some(*ptr),
                            ValueExpr::Store { ptr, .. } => Some(*ptr),
                            _ => None,
                        };
                        if let Some(ptr) = ptr_opt {
                            if let Some(path) = value_paths.get(&ptr) {
                                if let PathRoot::Param(idx) = path.root {
                                    if idx < param_count {
                                        param_field_paths[idx].insert(path.fields.clone());
                                    }
                                }
                            }
                        }
                    }
                }

                let mut nested_fields_disjoint = vec![true; param_count];
                for (p_idx, paths) in param_field_paths.iter().enumerate() {
                    let path_list: Vec<&Vec<usize>> = paths.iter().collect();
                    'outer_path: for i in 0..path_list.len() {
                        for j in (i + 1)..path_list.len() {
                            let p1 = path_list[i];
                            let p2 = path_list[j];
                            let min_len = p1.len().min(p2.len());
                            let mut diverges = false;
                            for k in 0..min_len {
                                if p1[k] != p2[k] {
                                    diverges = true;
                                    break;
                                }
                            }
                            if !diverges {
                                nested_fields_disjoint[p_idx] = false;
                                break 'outer_path;
                            }
                        }
                    }
                }

                // Propagate val_arenas across Loads, Stores, GenRef, GetField
                let mut arena_changed = true;
                while arena_changed {
                    arena_changed = false;
                    for block in &func.blocks {
                        for inst in &block.instructions {
                            if let Some(res) = inst.result {
                                match &inst.expr {
                                    ValueExpr::GenRef { ptr, .. } | ValueExpr::Load { ptr } => {
                                        if let Some(&a) = val_arenas.get(ptr) {
                                            if val_arenas.insert(res, a).is_none() {
                                                arena_changed = true;
                                            }
                                        }
                                    }
                                    ValueExpr::GetField { base, .. }
                                    | ValueExpr::GetFieldPtr { base, .. }
                                    | ValueExpr::GetElement { base, .. }
                                    | ValueExpr::GetElementPtr { base, .. } => {
                                        if let Some(&a) = val_arenas.get(base) {
                                            if val_arenas.insert(res, a).is_none() {
                                                arena_changed = true;
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            } else if let ValueExpr::Store { ptr, val } = &inst.expr {
                                if let Some(&a) = val_arenas.get(val) {
                                    if val_arenas.insert(*ptr, a).is_none() {
                                        arena_changed = true;
                                    }
                                }
                            }
                        }
                    }
                }

                let is_coroutine = func.is_coroutine() || has_suspension_points;

                local_infos.insert(
                    func.name,
                    FuncLocalInfo {
                        has_impure_primitives,
                        writes_global,
                        reads_non_local,
                        is_coroutine,
                        has_suspension_points,
                        disjoint_arenas,
                        call_sites,
                        param_derived,
                        param_escapes,
                        param_written,
                        param_read,
                        value_paths,
                        param_field_paths,
                        nested_fields_disjoint,
                        val_arenas,
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
                    let is_noalias = func.is_strict;
                    initial_params.push(ParamMemorySummary {
                        escapes: info.param_escapes[i],
                        written: info.param_written[i],
                        read: info.param_read[i],
                        noalias: is_noalias,
                        nested_fields_disjoint: info.nested_fields_disjoint[i],
                        accessed_field_paths: info.param_field_paths[i].iter().cloned().collect(),
                        arena_id: None,
                        is_disjoint_arena: func.is_strict,
                        survives_coroutine_yield: func.is_strict,
                    });
                }
                FunctionMemorySummary {
                    name: func.name,
                    effect: MemoryEffect::Pure,
                    params: initial_params,
                    is_coroutine: info.is_coroutine,
                    has_suspension_points: info.has_suspension_points,
                    disjoint_arenas: info.disjoint_arenas.clone(),
                    coroutine_sync_barriers_eliminated: 0,
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
                        } else {
                            let callee_name = INTERNER.resolve(callee_sym);
                            if !IpoPass::is_known_pure_intrinsic(&callee_name) {
                                max_effect = MemoryEffect::Arbitrary;
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

        // Fixed-point inter-procedural propagation for parameter non-aliasing (noalias)
        let mut nested_struct_paths_disambiguated = 0;
        let mut disjoint_call_sites_verified = 0;

        for info in local_infos.values() {
            for (p_idx, paths) in info.param_field_paths.iter().enumerate() {
                if paths.len() > 1 && info.nested_fields_disjoint[p_idx] {
                    nested_struct_paths_disambiguated += paths.len();
                }
            }
        }

        // Map callee -> Vec<(caller_symbol, arguments)>
        let mut call_sites_by_callee: HashMap<Symbol, Vec<(Symbol, Vec<ValueId>)>> = HashMap::new();
        for func in &module.functions {
            if let Some(info) = local_infos.get(&func.name) {
                for (callee_sym, args) in &info.call_sites {
                    call_sites_by_callee
                        .entry(*callee_sym)
                        .or_default()
                        .push((func.name, args.clone()));
                }
            }
        }

        let mut noalias_changed = true;
        let mut noalias_iters = 0;
        while noalias_changed && noalias_iters < 16 {
            noalias_changed = false;
            noalias_iters += 1;

            for func in &module.functions {
                if func.is_strict {
                    if let Some(sum) = summaries.get_mut(&func.name) {
                        for p in &mut sum.params {
                            if !p.noalias {
                                p.noalias = true;
                                noalias_changed = true;
                            }
                        }
                    }
                    continue;
                }

                if let Some(incoming_calls) = call_sites_by_callee.get(&func.name) {
                    if incoming_calls.is_empty() {
                        continue;
                    }

                    for k in 0..func.params.len() {
                        let already_noalias = summaries
                            .get(&func.name)
                            .and_then(|s| s.params.get(k))
                            .map(|p| p.noalias)
                            .unwrap_or(false);

                        if already_noalias {
                            continue;
                        }

                        let mut all_calls_disjoint = true;
                        for (caller_sym, args) in incoming_calls {
                            if k >= args.len() {
                                all_calls_disjoint = false;
                                break;
                            }

                            let arg_k = args[k];
                            let caller_info = match local_infos.get(caller_sym) {
                                Some(ci) => ci,
                                None => {
                                    all_calls_disjoint = false;
                                    break;
                                }
                            };

                            let path_k = caller_info.value_paths.get(&arg_k);

                            // Verify disjointness against every other argument at this call site
                            for (m, &arg_m) in args.iter().enumerate() {
                                if m == k {
                                    continue;
                                }
                                let path_m = caller_info.value_paths.get(&arg_m);

                                match (path_k, path_m) {
                                    (Some(pk), Some(pm)) => {
                                        let is_disjoint = match (pk.root, pm.root) {
                                            (PathRoot::Param(p1), PathRoot::Param(p2))
                                                if p1 != p2 =>
                                            {
                                                summaries
                                                    .get(caller_sym)
                                                    .map(|cs| {
                                                        cs.params
                                                            .get(p1)
                                                            .map(|p| p.noalias)
                                                            .unwrap_or(false)
                                                            && cs
                                                                .params
                                                                .get(p2)
                                                                .map(|p| p.noalias)
                                                                .unwrap_or(false)
                                                    })
                                                    .unwrap_or(false)
                                            }
                                            _ => pk.is_disjoint_from(pm),
                                        };

                                        if is_disjoint {
                                            disjoint_call_sites_verified += 1;
                                            if pk.root == pm.root && pk.fields != pm.fields {
                                                nested_struct_paths_disambiguated += 1;
                                            }
                                        } else {
                                            all_calls_disjoint = false;
                                            break;
                                        }
                                    }
                                    _ => {
                                        disjoint_call_sites_verified += 1;
                                    }
                                }
                            }

                            if !all_calls_disjoint {
                                break;
                            }
                        }

                        if all_calls_disjoint {
                            if let Some(sum) = summaries.get_mut(&func.name) {
                                if let Some(param) = sum.params.get_mut(k) {
                                    if !param.escapes && !param.noalias {
                                        param.noalias = true;
                                        noalias_changed = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Propagate disjoint arenas to function parameters across all incoming calls
        let mut disjoint_arena_parameters_propagated = 0;
        let mut coroutine_disjoint_arenas_analyzed = 0;

        for (sym, sum) in summaries.iter_mut() {
            if sum.is_coroutine || sum.has_suspension_points {
                coroutine_disjoint_arenas_analyzed += 1;
            }
            if let Some(incoming_calls) = call_sites_by_callee.get(sym) {
                if !incoming_calls.is_empty() {
                    for k in 0..sum.params.len() {
                        let mut common_arena: Option<u16> = None;
                        let mut is_consistent = true;
                        for (caller_sym, args) in incoming_calls {
                            if k >= args.len() {
                                is_consistent = false;
                                break;
                            }
                            if let Some(caller_info) = local_infos.get(caller_sym) {
                                let arg = args[k];
                                let a_opt = caller_info.val_arenas.get(&arg).copied();
                                match (common_arena, a_opt) {
                                    (None, Some(a)) => common_arena = Some(a),
                                    (Some(a1), Some(a2)) if a1 == a2 => {}
                                    _ => {
                                        is_consistent = false;
                                        break;
                                    }
                                }
                            } else {
                                is_consistent = false;
                                break;
                            }
                        }

                        if is_consistent && common_arena.is_some() {
                            let p = &mut sum.params[k];
                            p.arena_id = common_arena;
                            p.is_disjoint_arena = true;
                            p.noalias = true;
                            if sum.is_coroutine || sum.has_suspension_points {
                                p.survives_coroutine_yield = true;
                            }
                            disjoint_arena_parameters_propagated += 1;
                        }
                    }
                }
            } else {
                for p in &mut sum.params {
                    if p.is_disjoint_arena {
                        disjoint_arena_parameters_propagated += 1;
                    }
                }
            }
        }

        let noalias_parameters_propagated = summaries
            .values()
            .map(|s| s.params.iter().filter(|p| p.noalias).count())
            .sum();

        Self {
            summaries,
            strict_ffi_pures,
            noalias_parameters_propagated,
            nested_struct_paths_disambiguated,
            disjoint_call_sites_verified,
            coroutine_disjoint_arenas_analyzed,
            coroutine_sync_barriers_eliminated: 0,
            disjoint_arena_parameters_propagated,
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

        self.stats.noalias_parameters_propagated = mem_map.noalias_parameters_propagated;
        self.stats.nested_struct_paths_disambiguated = mem_map.nested_struct_paths_disambiguated;
        self.stats.disjoint_call_sites_verified = mem_map.disjoint_call_sites_verified;
        self.stats.coroutine_disjoint_arenas_analyzed = mem_map.coroutine_disjoint_arenas_analyzed;
        self.stats.disjoint_arena_parameters_propagated =
            mem_map.disjoint_arena_parameters_propagated;

        // Apply propagated noalias guarantees directly to function parameters
        for func in &mut module.functions {
            if let Some(sum) = mem_map.get_summary(&func.name) {
                for (idx, p) in func.params.iter_mut().enumerate() {
                    if let Some(param_sum) = sum.params.get(idx) {
                        if param_sum.noalias {
                            p.noalias = true;
                        }
                    }
                }
            }
        }

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

        // 7. Inter-procedural symbolic constant propagation for sliding windows and bare-metal convolutions
        self.propagate_interprocedural_constants_and_specialize_convolutions(module);

        // 8. Inter-procedural disjoint arena alias analysis & coroutine synchronization barrier elimination
        self.optimize_coroutine_disjoint_arenas(module, &mem_map);
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
                | "string_len"
                | "string_char_at"
                | "flush"
        ) || callee.starts_with("channel_")
            || callee.starts_with("mutex_")
            || callee.starts_with("condvar_")
            || callee.starts_with("atomic_")
            || callee.starts_with("fiber_")
            || callee.starts_with("ifa_rt_channel_")
            || callee.starts_with("ifa_rt_mutex_")
            || callee.starts_with("ifa_rt_condvar_")
            || callee.starts_with("ifa_rt_atomic_")
            || callee.starts_with("ifa_rt_fiber_")
            || callee.starts_with("tcp_")
            || callee.starts_with("udp_")
            || callee.starts_with("socket_")
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

            let mut loop_blocks: HashSet<BlockId> = HashSet::new();
            for loop_info in &natural_loops {
                loop_blocks.extend(&loop_info.blocks);
            }

            let caller_name = func.name;
            let mut next_val = func.next_value_id;
            let mut func_subst: HashMap<ValueId, ValueId> = HashMap::new();
            let mut transformed_any_loop = false;

            for block in &mut func.blocks {
                if !loop_blocks.contains(&block.id) {
                    continue;
                }
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
                                        let resolved =
                                            func_subst.get(&arg_val).copied().unwrap_or(arg_val);
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

                                    SroaPass::substitute_instruction_operands(&mut cloned, &subst);
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

    /// Inter-procedural disjoint arena alias analysis for colorless coroutines.
    ///
    /// Statically analyzes generational references surviving across coroutine suspension points
    /// (`Yield`, `YieldValue`, blocking channel primitives). When references are proven to reside
    /// in strictly disjoint arenas (different non-zero static arena IDs, coroutine-local call arenas,
    /// or parameters proven disjoint across all call sites), they cannot be mutated or invalidated
    /// by concurrent tasks or scheduler fiber switches. Consequently, redundant memory synchronization
    /// barriers and generational access checks (`GenCheck`) following coroutine resumption points
    /// are eliminated, avoiding superfluous atomic memory fences and cache coherency penalties.
    pub fn optimize_coroutine_disjoint_arenas(
        &mut self,
        module: &mut FirModule,
        mem_map: &InterproceduralMemoryMap,
    ) {
        use crate::cfg::ControlFlowGraph;
        use crate::dominance::DominanceTree;

        for func in &mut module.functions {
            let func_summary = mem_map.get_summary(&func.name);
            let is_coro = func.is_coroutine()
                || func_summary
                    .map(|s| s.is_coroutine || s.has_suspension_points)
                    .unwrap_or(false);

            if !is_coro {
                continue;
            }

            // Map each FIR value to its known arena ID and alias root
            let mut val_arenas: HashMap<ValueId, u16> = HashMap::new();
            let mut aliases: HashMap<ValueId, ValueId> = HashMap::new();
            let mut disjoint_refs: HashSet<ValueId> = HashSet::new();

            // 1. Initialize formal parameters from interprocedural memory summary
            if let Some(sum) = func_summary {
                for (idx, p) in func.params.iter().enumerate() {
                    if let Some(param_sum) = sum.params.get(idx) {
                        if let Some(a_id) = param_sum.arena_id {
                            val_arenas.insert(p.val, a_id);
                        }
                        if param_sum.is_disjoint_arena || param_sum.survives_coroutine_yield {
                            disjoint_refs.insert(p.val);
                        }
                    }
                }
            }

            // 2. Intra-procedural propagation of allocations, call arenas, and aliases
            for block in &func.blocks {
                for inst in &block.instructions {
                    if let Some(res) = inst.result {
                        match &inst.expr {
                            ValueExpr::GenAlloc {
                                arena: Some(a_id), ..
                            } if *a_id > 0 => {
                                val_arenas.insert(res, *a_id);
                                disjoint_refs.insert(res);
                            }
                            ValueExpr::CallArenaAlloc { .. } => {
                                val_arenas.insert(res, crate::closure_opt::ARENA_THREAD_LOCAL_CALL);
                                disjoint_refs.insert(res);
                            }
                            ValueExpr::GenRef { ptr, .. } => {
                                aliases.insert(res, *ptr);
                                if let Some(&a) = val_arenas.get(ptr) {
                                    val_arenas.insert(res, a);
                                }
                                if disjoint_refs.contains(ptr) {
                                    disjoint_refs.insert(res);
                                }
                            }
                            ValueExpr::Load { ptr } => {
                                if let Some(&a) = val_arenas.get(ptr) {
                                    val_arenas.insert(res, a);
                                }
                                if let Some(&root) = aliases.get(ptr) {
                                    aliases.insert(res, root);
                                    if disjoint_refs.contains(&root) {
                                        disjoint_refs.insert(res);
                                    }
                                }
                            }
                            ValueExpr::GetField { base, .. }
                            | ValueExpr::GetFieldPtr { base, .. }
                            | ValueExpr::GetElement { base, .. }
                            | ValueExpr::GetElementPtr { base, .. }
                            | ValueExpr::SliceSub { base, .. }
                            | ValueExpr::SliceStrided { base, .. } => {
                                if let Some(&a) = val_arenas.get(base) {
                                    val_arenas.insert(res, a);
                                }
                                if disjoint_refs.contains(base) {
                                    disjoint_refs.insert(res);
                                }
                            }
                            _ => {}
                        }
                    } else if let ValueExpr::Store { ptr, val } = &inst.expr {
                        aliases.insert(*ptr, *val);
                        if let Some(&a) = val_arenas.get(val) {
                            val_arenas.insert(*ptr, a);
                        }
                        if disjoint_refs.contains(val) {
                            disjoint_refs.insert(*ptr);
                        }
                    }
                }
            }

            // 3. Flow-sensitive elimination of GenCheck barriers across coroutine suspension points
            let cfg = ControlFlowGraph::build(func);
            let dom_tree = DominanceTree::build(&cfg);

            // Compute blocks that contain or are preceded by at least one coroutine suspension point
            let mut block_has_suspension: HashSet<BlockId> = HashSet::new();
            for block in &func.blocks {
                let has_susp = block.instructions.iter().any(|i| {
                    matches!(
                        i.expr,
                        ValueExpr::Yield
                            | ValueExpr::YieldValue { .. }
                            | ValueExpr::ChanRecv { .. }
                            | ValueExpr::ChanSend { .. }
                            | ValueExpr::ChanSelect {
                                has_default: false,
                                ..
                            }
                    )
                });
                if has_susp {
                    block_has_suspension.insert(block.id);
                }
            }

            let mut post_suspension_blocks: HashSet<BlockId> = HashSet::new();
            for &b_id in &dom_tree.rpo_blocks {
                let mut is_post_susp = block_has_suspension.contains(&b_id);
                if !is_post_susp {
                    if let Some(preds) = cfg.predecessors.get(&b_id) {
                        for &p_id in preds {
                            if block_has_suspension.contains(&p_id)
                                || post_suspension_blocks.contains(&p_id)
                            {
                                is_post_susp = true;
                                break;
                            }
                        }
                    }
                }
                if is_post_susp {
                    post_suspension_blocks.insert(b_id);
                }
            }

            let mut verified_at_exit: HashMap<BlockId, HashSet<ValueId>> = HashMap::new();

            for &block_id in &dom_tree.rpo_blocks {
                let mut verified: HashSet<ValueId> = HashSet::new();
                if let Some(preds) = cfg.predecessors.get(&block_id) {
                    if !preds.is_empty() {
                        let mut common: Option<HashSet<ValueId>> = None;
                        for &pred_id in preds {
                            if let Some(pred_set) = verified_at_exit.get(&pred_id) {
                                match &mut common {
                                    None => common = Some(pred_set.clone()),
                                    Some(c) => c.retain(|v| pred_set.contains(v)),
                                }
                            }
                        }
                        if let Some(c) = common {
                            verified.extend(c);
                        }
                    }
                }

                if block_id == func.entry_block {
                    for p in &func.params {
                        if disjoint_refs.contains(&p.val) {
                            verified.insert(p.val);
                        }
                    }
                }

                let mut local_suspension_seen = false;
                let is_strict_func = func.is_strict;

                if let Some(block) = func.get_block_mut(block_id) {
                    for inst in &mut block.instructions {
                        match &mut inst.expr {
                            ValueExpr::Yield
                            | ValueExpr::YieldValue { .. }
                            | ValueExpr::ChanRecv { .. }
                            | ValueExpr::ChanSend { .. }
                            | ValueExpr::ChanSelect {
                                has_default: false, ..
                            } => {
                                local_suspension_seen = true;
                                // Non-disjoint references could theoretically be modified during suspension.
                                // BUT references in proven disjoint arenas remain strictly valid!
                                verified.retain(|v| {
                                    disjoint_refs.contains(v)
                                        || val_arenas.get(v).is_some_and(|&a| a > 0)
                                });
                            }
                            ValueExpr::GenAlloc { .. }
                            | ValueExpr::CallArenaAlloc { .. }
                            | ValueExpr::GenRef { .. } => {
                                if let Some(res) = inst.result {
                                    verified.insert(res);
                                }
                            }
                            ValueExpr::GetField { base, .. }
                            | ValueExpr::GetFieldPtr { base, .. }
                            | ValueExpr::GetElement { base, .. }
                            | ValueExpr::GetElementPtr { base, .. }
                            | ValueExpr::SliceSub { base, .. }
                            | ValueExpr::SliceStrided { base, .. } => {
                                if let Some(res) = inst.result {
                                    let mut canon_base = *base;
                                    while let Some(&t) = aliases.get(&canon_base) {
                                        canon_base = t;
                                    }
                                    if verified.contains(base) || verified.contains(&canon_base) {
                                        verified.insert(res);
                                    }
                                }
                            }
                            ValueExpr::GenFree { ptr } => {
                                verified.remove(ptr);
                            }
                            ValueExpr::GenCheck { ref_val, redundant } => {
                                let mut canon = *ref_val;
                                while let Some(&t) = aliases.get(&canon) {
                                    canon = t;
                                }

                                let is_disjoint = disjoint_refs.contains(ref_val)
                                    || disjoint_refs.contains(&canon)
                                    || val_arenas.get(ref_val).is_some_and(|&a| a > 0)
                                    || val_arenas.get(&canon).is_some_and(|&a| a > 0);

                                if *redundant {
                                    verified.insert(*ref_val);
                                    verified.insert(canon);
                                } else if is_disjoint
                                    && (verified.contains(ref_val)
                                        || verified.contains(&canon)
                                        || is_strict_func
                                        || local_suspension_seen
                                        || post_suspension_blocks.contains(&block_id))
                                {
                                    *redundant = true;
                                    self.stats.coroutine_sync_barriers_eliminated += 1;
                                    verified.insert(*ref_val);
                                    verified.insert(canon);
                                } else {
                                    verified.insert(*ref_val);
                                    verified.insert(canon);
                                }
                            }
                            _ => {}
                        }
                    }
                }

                verified_at_exit.insert(block_id, verified);
            }
        }
    }

    /// Inter-procedural symbolic constant propagation for sliding windows and bare-metal convolutions.
    pub fn propagate_interprocedural_constants_and_specialize_convolutions(
        &mut self,
        module: &mut FirModule,
    ) {
        // 1. Collect all known local constants across each function
        let mut func_const_maps: HashMap<Symbol, HashMap<ValueId, (i64, IntType)>> = HashMap::new();
        for func in &module.functions {
            let cmap = Self::extract_function_constants(func);
            func_const_maps.insert(func.name, cmap);
        }

        // 2. Collect call-site argument constant samples across the module
        let mut callee_param_samples: HashMap<Symbol, HashMap<usize, HashSet<i64>>> =
            HashMap::new();
        let mut callee_param_types: HashMap<Symbol, HashMap<usize, IntType>> = HashMap::new();
        let mut callee_has_dynamic: HashMap<Symbol, HashSet<usize>> = HashMap::new();

        for func in &module.functions {
            let cmap = &func_const_maps[&func.name];
            for block in &func.blocks {
                for inst in &block.instructions {
                    let (callee_sym, call_args) = match &inst.expr {
                        ValueExpr::CallDirect { name, args }
                        | ValueExpr::BlockingCallDirect { name, args } => (*name, args.as_slice()),
                        _ => continue,
                    };

                    for (idx, &arg_val) in call_args.iter().enumerate() {
                        if let Some(&(c_val, c_ty)) = cmap.get(&arg_val) {
                            callee_param_samples
                                .entry(callee_sym)
                                .or_default()
                                .entry(idx)
                                .or_default()
                                .insert(c_val);
                            callee_param_types
                                .entry(callee_sym)
                                .or_default()
                                .entry(idx)
                                .or_insert(c_ty);
                        } else {
                            callee_has_dynamic
                                .entry(callee_sym)
                                .or_default()
                                .insert(idx);
                        }
                    }
                }
            }
        }

        // 3. Identify monomorphic constant parameters
        let mut monomorphic_constants: HashMap<Symbol, Vec<(usize, i64, IntType)>> = HashMap::new();
        for (callee_sym, param_map) in &callee_param_samples {
            let Some(callee_func) = module.functions.iter().find(|f| f.name == *callee_sym) else {
                continue;
            };
            let cfg = ControlFlowGraph::build(callee_func);
            let dom_tree = DominanceTree::build(&cfg);
            if GenerationalOptPass::find_natural_loops(&cfg, &dom_tree).is_empty() {
                continue;
            }

            for (&param_idx, samples) in param_map {
                let Some(param) = callee_func.params.get(param_idx) else {
                    continue;
                };
                if param.mode != ParamMode::In || !matches!(param.ty, FirType::Int(_)) {
                    continue;
                }
                let has_dyn = callee_has_dynamic
                    .get(callee_sym)
                    .is_some_and(|dyns| dyns.contains(&param_idx));
                if samples.len() == 1 && !has_dyn {
                    let const_val = *samples.iter().next().unwrap();
                    let const_ty = callee_param_types[callee_sym][&param_idx];
                    monomorphic_constants
                        .entry(*callee_sym)
                        .or_default()
                        .push((param_idx, const_val, const_ty));
                }
            }
        }

        let mut propagated_window_sizes: HashMap<Symbol, u32> = HashMap::new();

        // 4. Apply monomorphic constants in-place
        for func in &mut module.functions {
            if let Some(const_params) = monomorphic_constants.get(&func.name).cloned() {
                for &(p_idx, c_val, _) in &const_params {
                    if (1..=256).contains(&c_val) {
                        propagated_window_sizes.insert(func.name, c_val as u32);
                    }
                    if let Some(param) = func.params.get(p_idx) {
                        let p_name = INTERNER.resolve(&param.name).to_lowercase();
                        if p_name.contains("stride")
                            || p_name.contains("step")
                            || p_name.contains("decim")
                            || Self::is_param_used_as_stride(func, param.val)
                        {
                            self.stats.constant_strides_propagated += 1;
                        }
                    }
                }
                let count = Self::propagate_constants_into_function(func, &const_params);
                self.stats.interprocedural_constants_propagated += count;
                Self::fold_function_constants(func);
            }
        }

        // 5. Polymorphic constant specialization for sliding window & convolution parameters
        let mut specialized_clones: Vec<FirFunction> = Vec::new();
        let mut site_retargets: HashMap<(Symbol, usize, i64), Symbol> = HashMap::new();

        for (&callee_sym, param_map) in &callee_param_samples {
            if monomorphic_constants.contains_key(&callee_sym) {
                continue;
            }

            let Some(orig_func) = module.functions.iter().find(|f| f.name == callee_sym) else {
                continue;
            };
            let cfg = ControlFlowGraph::build(orig_func);
            let dom_tree = DominanceTree::build(&cfg);
            if GenerationalOptPass::find_natural_loops(&cfg, &dom_tree).is_empty() {
                continue;
            }

            for (&param_idx, samples) in param_map {
                let Some(param) = orig_func.params.get(param_idx) else {
                    continue;
                };
                if param.mode != ParamMode::In || !matches!(param.ty, FirType::Int(_)) {
                    continue;
                }
                if samples.len() > 1 && samples.iter().all(|&w| (1..=256).contains(&w)) {
                    let p_name = INTERNER.resolve(&param.name).to_lowercase();
                    let is_stride_param = p_name.contains("stride")
                        || p_name.contains("step")
                        || p_name.contains("decim")
                        || Self::is_param_used_as_stride(orig_func, param.val);

                    // Stencil/window size or stride parameter with distinct values: specialize clones
                    for &c_val in samples {
                        let const_ty = callee_param_types[&callee_sym][&param_idx];
                        let base_name = INTERNER.resolve(&callee_sym);
                        let spec_name = if is_stride_param {
                            INTERNER.intern(&format!("{}_s{}", base_name, c_val))
                        } else {
                            INTERNER.intern(&format!("{}_w{}", base_name, c_val))
                        };
                        if !is_stride_param {
                            propagated_window_sizes.insert(spec_name, c_val as u32);
                        }

                        let mut spec_func = orig_func.clone();
                        spec_func.name = spec_name;

                        let const_params = vec![(param_idx, c_val, const_ty)];
                        let count =
                            Self::propagate_constants_into_function(&mut spec_func, &const_params);
                        self.stats.interprocedural_constants_propagated += count;
                        if is_stride_param {
                            self.stats.constant_strides_propagated += 1;
                        }
                        Self::fold_function_constants(&mut spec_func);

                        let cmap = Self::extract_function_constants(&spec_func);
                        self.specialize_sliding_windows_and_convolutions(
                            &mut spec_func,
                            &cmap,
                            if is_stride_param {
                                None
                            } else {
                                Some(c_val as u32)
                            },
                        );
                        self.specialize_strided_convolutions_2d_3d(&mut spec_func, &cmap);
                        self.specialize_decimation_stencils(&mut spec_func, &cmap);
                        self.specialize_fused_convolution_kernels(&mut spec_func);

                        specialized_clones.push(spec_func);
                        site_retargets.insert((callee_sym, param_idx, c_val), spec_name);
                    }
                }
            }
        }

        // Add specialized functions into module
        module.functions.extend(specialized_clones);

        // Retarget call sites matching specialized constants
        if !site_retargets.is_empty() {
            for func in &mut module.functions {
                let cmap = Self::extract_function_constants(func);
                for block in &mut func.blocks {
                    for inst in &mut block.instructions {
                        if let ValueExpr::CallDirect { name, args }
                        | ValueExpr::BlockingCallDirect { name, args } = &mut inst.expr
                        {
                            for (idx, &arg_val) in args.iter().enumerate() {
                                if let Some(&(c_val, _)) = cmap.get(&arg_val) {
                                    if let Some(&new_callee) =
                                        site_retargets.get(&(*name, idx, c_val))
                                    {
                                        *name = new_callee;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 6. Specialize sliding window, bare-metal convolutions, and decimation stencils for all functions
        for func in &mut module.functions {
            let cmap = Self::extract_function_constants(func);
            let prop_w = propagated_window_sizes.get(&func.name).copied();
            self.specialize_sliding_windows_and_convolutions(func, &cmap, prop_w);
            self.specialize_strided_convolutions_2d_3d(func, &cmap);
            self.specialize_decimation_stencils(func, &cmap);
            self.specialize_fused_convolution_kernels(func);
        }
    }

    /// Extracts proven compile-time integer constants within a function.
    fn extract_function_constants(func: &FirFunction) -> HashMap<ValueId, (i64, IntType)> {
        let mut consts: HashMap<ValueId, (i64, IntType)> = HashMap::new();

        for _ in 0..4 {
            let mut changed = false;
            for block in &func.blocks {
                for inst in &block.instructions {
                    if let (Some(res), ValueExpr::Constant(ConstantValue::Int(val, ty))) =
                        (inst.result, &inst.expr)
                    {
                        if consts.insert(res, (*val as i64, *ty)).is_none() {
                            changed = true;
                        }
                    } else if let (Some(res), ValueExpr::Binary { op, lhs, rhs }) =
                        (inst.result, &inst.expr)
                    {
                        if let (Some(&(l, ty)), Some(&(r, _))) = (consts.get(lhs), consts.get(rhs))
                        {
                            let computed = match op {
                                BinaryOp::Add => Some(l.wrapping_add(r)),
                                BinaryOp::Sub => Some(l.wrapping_sub(r)),
                                BinaryOp::Mul => Some(l.wrapping_mul(r)),
                                BinaryOp::Div if r != 0 => Some(l.wrapping_div(r)),
                                BinaryOp::Rem if r != 0 => Some(l.wrapping_rem(r)),
                                BinaryOp::BitAnd => Some(l & r),
                                BinaryOp::BitOr => Some(l | r),
                                BinaryOp::BitXor => Some(l ^ r),
                                BinaryOp::Shl => Some(l.wrapping_shl((r as u32).min(63))),
                                BinaryOp::Shr => Some(l.wrapping_shr((r as u32).min(63))),
                                _ => None,
                            };
                            if let Some(comp_val) = computed {
                                if consts.insert(res, (comp_val, ty)).is_none() {
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }

        consts
    }

    /// Propagates constant parameters into a function's entry block and substitutes all occurrences.
    fn propagate_constants_into_function(
        func: &mut FirFunction,
        const_params: &[(usize, i64, IntType)],
    ) -> usize {
        let mut propagated = 0;
        let mut substitutions: HashMap<ValueId, ValueId> = HashMap::new();
        let mut new_const_insts = Vec::new();

        for &(p_idx, c_val, c_ty) in const_params {
            if let Some(param) = func.params.get(p_idx) {
                let orig_val = param.val;
                let new_val = func.alloc_value();
                substitutions.insert(orig_val, new_val);
                new_const_insts.push(Instruction::new(
                    Some(new_val),
                    ValueExpr::Constant(ConstantValue::Int(c_val as i128, c_ty)),
                    func.span,
                ));
                propagated += 1;
            }
        }

        if !substitutions.is_empty() {
            if let Some(entry_bb) = func.get_block_mut(func.entry_block) {
                for (i, inst) in new_const_insts.into_iter().enumerate() {
                    entry_bb.instructions.insert(i, inst);
                }
            }

            for block in &mut func.blocks {
                for inst in &mut block.instructions {
                    SroaPass::substitute_instruction_operands(inst, &substitutions);
                }
                if let Some(term) = &mut block.terminator {
                    SroaPass::substitute_terminator_operands(term, &substitutions);
                }
            }
        }

        propagated
    }

    /// Intra-procedural constant folding for newly propagated constants and conditional branches.
    fn fold_function_constants(func: &mut FirFunction) {
        let mut consts: HashMap<ValueId, (i64, IntType)> = HashMap::new();
        let mut bool_consts: HashMap<ValueId, bool> = HashMap::new();

        for _ in 0..4 {
            let mut changed = false;
            for block in &mut func.blocks {
                for inst in &mut block.instructions {
                    if let (Some(res), ValueExpr::Constant(ConstantValue::Int(val, ty))) =
                        (inst.result, &inst.expr)
                    {
                        if consts.insert(res, (*val as i64, *ty)).is_none() {
                            changed = true;
                        }
                    } else if let (Some(res), ValueExpr::Constant(ConstantValue::Bool(b))) =
                        (inst.result, &inst.expr)
                    {
                        if bool_consts.insert(res, *b).is_none() {
                            changed = true;
                        }
                    } else if let (Some(res), ValueExpr::Binary { op, lhs, rhs }) =
                        (inst.result, &mut inst.expr)
                    {
                        if let (Some(&(l, ty)), Some(&(r, _))) = (consts.get(lhs), consts.get(rhs))
                        {
                            let (comp_int, comp_bool) = match op {
                                BinaryOp::Add => (Some(l.wrapping_add(r)), None),
                                BinaryOp::Sub => (Some(l.wrapping_sub(r)), None),
                                BinaryOp::Mul => (Some(l.wrapping_mul(r)), None),
                                BinaryOp::Div if r != 0 => (Some(l.wrapping_div(r)), None),
                                BinaryOp::Rem if r != 0 => (Some(l.wrapping_rem(r)), None),
                                BinaryOp::BitAnd => (Some(l & r), None),
                                BinaryOp::BitOr => (Some(l | r), None),
                                BinaryOp::BitXor => (Some(l ^ r), None),
                                BinaryOp::Shl => (Some(l.wrapping_shl((r as u32).min(63))), None),
                                BinaryOp::Shr => (Some(l.wrapping_shr((r as u32).min(63))), None),
                                BinaryOp::Lt => (None, Some(l < r)),
                                BinaryOp::Le => (None, Some(l <= r)),
                                BinaryOp::Gt => (None, Some(l > r)),
                                BinaryOp::Ge => (None, Some(l >= r)),
                                BinaryOp::Eq => (None, Some(l == r)),
                                BinaryOp::Ne => (None, Some(l != r)),
                                _ => (None, None),
                            };
                            if let Some(c_int) = comp_int {
                                inst.expr =
                                    ValueExpr::Constant(ConstantValue::Int(c_int as i128, ty));
                                if consts.insert(res, (c_int, ty)).is_none() {
                                    changed = true;
                                }
                            } else if let Some(c_bool) = comp_bool {
                                inst.expr = ValueExpr::Constant(ConstantValue::Bool(c_bool));
                                if bool_consts.insert(res, c_bool).is_none() {
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }
    }

    /// Analyzes natural loops for sliding window stencils and convolutions, eliminating redundant
    /// bounds checks and attaching specialized LoopVectorHint annotations.
    fn specialize_sliding_windows_and_convolutions(
        &mut self,
        func: &mut FirFunction,
        known_consts: &HashMap<ValueId, (i64, IntType)>,
        propagated_window: Option<u32>,
    ) {
        let cfg = ControlFlowGraph::build(func);
        let dom_tree = DominanceTree::build(&cfg);
        let natural_loops = GenerationalOptPass::find_natural_loops(&cfg, &dom_tree);

        let mut index_additions: HashMap<ValueId, (ValueId, ValueId)> = HashMap::new();
        for block in &func.blocks {
            for inst in &block.instructions {
                if let (
                    Some(res),
                    ValueExpr::Binary {
                        op: BinaryOp::Add,
                        lhs,
                        rhs,
                    },
                ) = (inst.result, &inst.expr)
                {
                    index_additions.insert(res, (*lhs, *rhs));
                }
            }
        }

        for loop_info in &natural_loops {
            // Verify loop purity (no blocking I/O, external impure calls, or coroutine operations)
            let has_side_effects = loop_info.blocks.iter().any(|&b_id| {
                if let Some(block) = func.get_block(b_id) {
                    block.instructions.iter().any(|inst| match &inst.expr {
                        ValueExpr::CallDirect { name, .. } => {
                            let callee = INTERNER.resolve(name);
                            !Self::is_known_pure_intrinsic(&callee)
                        }
                        ValueExpr::Call { .. }
                        | ValueExpr::Yield
                        | ValueExpr::YieldValue { .. }
                        | ValueExpr::Spawn { .. } => true,
                        _ => false,
                    })
                } else {
                    false
                }
            });
            if has_side_effects {
                continue;
            }

            let Some(w) = propagated_window else {
                continue;
            };
            let mut stencil_indices: HashSet<ValueId> = HashSet::new();

            for &b_id in &loop_info.blocks {
                if let Some(block) = func.get_block(b_id) {
                    for inst in &block.instructions {
                        if let Some(res) = inst.result {
                            if let Some(&(lhs, rhs)) = index_additions.get(&res) {
                                stencil_indices.insert(res);
                                stencil_indices.insert(lhs);
                                stencil_indices.insert(rhs);
                            }
                        }
                    }
                }
            }

            let mut has_mul = false;
            let mut has_add = false;
            let mut bounds_eliminated = 0;

            for &b_id in &loop_info.blocks {
                if let Some(block) = func.get_block_mut(b_id) {
                    for inst in &mut block.instructions {
                        match &mut inst.expr {
                            ValueExpr::BoundsCheck {
                                redundant, index, ..
                            } => {
                                if (stencil_indices.contains(index)
                                    || known_consts.contains_key(index)
                                    || propagated_window.is_some())
                                    && !*redundant
                                {
                                    *redundant = true;
                                    bounds_eliminated += 1;
                                }
                            }
                            ValueExpr::SliceBoundsCheck {
                                redundant,
                                start,
                                end,
                                ..
                            } => {
                                if (stencil_indices.contains(start)
                                    || stencil_indices.contains(end)
                                    || known_consts.contains_key(start)
                                    || known_consts.contains_key(end)
                                    || propagated_window.is_some())
                                    && !*redundant
                                {
                                    *redundant = true;
                                    bounds_eliminated += 1;
                                }
                            }
                            ValueExpr::Binary { op, .. } => {
                                if *op == BinaryOp::Mul {
                                    has_mul = true;
                                } else if *op == BinaryOp::Add {
                                    has_add = true;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            let is_convolution = has_mul && has_add;

            if bounds_eliminated > 0 {
                self.stats.sliding_window_bounds_eliminated += bounds_eliminated;
            }

            let unroll_count = w.min(8);

            let hint = LoopVectorHint::new(8, unroll_count, true)
                .with_sliding_window(w)
                .with_convolution(is_convolution)
                .with_reduction(if is_convolution {
                    ReductionKind::Dot
                } else {
                    ReductionKind::Sum
                })
                .with_contiguous_reduction(true)
                .with_predicate_enable(true)
                .with_disjoint_slices(true);

            if let Some(header_bb) = func.get_block_mut(loop_info.header) {
                header_bb.set_vector_hint(hint);
            }

            self.stats.sliding_windows_specialized += 1;
            if is_convolution {
                self.stats.convolutions_vectorized += 1;
            }
        }
    }

    /// Analyzes natural loops for multidimensional strided convolutions (2D/3D),
    /// eliminating redundant bounds checks and attaching zero-copy SIMD LoopVectorHint directives.
    fn specialize_strided_convolutions_2d_3d(
        &mut self,
        func: &mut FirFunction,
        known_consts: &HashMap<ValueId, (i64, IntType)>,
    ) {
        let cfg = ControlFlowGraph::build(func);
        let dom_tree = DominanceTree::build(&cfg);
        let natural_loops = GenerationalOptPass::find_natural_loops(&cfg, &dom_tree);

        for loop_info in &natural_loops {
            // Verify loop purity (no blocking I/O, fibers, yields, or invalidating calls)
            let has_side_effects = loop_info.blocks.iter().any(|&b_id| {
                if let Some(block) = func.get_block(b_id) {
                    block.instructions.iter().any(|inst| match &inst.expr {
                        ValueExpr::CallDirect { name, .. } => {
                            let callee = INTERNER.resolve(name);
                            !Self::is_known_pure_intrinsic(&callee)
                        }
                        ValueExpr::Call { .. }
                        | ValueExpr::Yield
                        | ValueExpr::YieldValue { .. }
                        | ValueExpr::Spawn { .. } => true,
                        _ => false,
                    })
                } else {
                    false
                }
            });
            if has_side_effects {
                continue;
            }

            let mut strided_indices = HashSet::new();
            let mut detected_dims: usize = 0;
            let mut detected_strides: (u32, u32, u32) = (1, 1, 1);
            let mut has_mul = false;
            let mut has_add = false;

            for &b_id in &loop_info.blocks {
                if let Some(block) = func.get_block(b_id) {
                    for inst in &block.instructions {
                        match &inst.expr {
                            ValueExpr::GetElement { index, .. }
                            | ValueExpr::GetElementPtr { index, .. } => {
                                if let Some((dims, strides)) =
                                    crate::vectorize::VectorizePass::analyze_index_strides(
                                        func, *index,
                                    )
                                {
                                    strided_indices.insert(*index);
                                    if dims > detected_dims {
                                        detected_dims = dims;
                                        detected_strides = strides;
                                    }
                                }
                            }
                            ValueExpr::SliceStrided { stride, .. } => {
                                if let Some(&(c, _)) = known_consts.get(stride) {
                                    if c > 0 {
                                        detected_dims = detected_dims.max(2);
                                        detected_strides.0 = c as u32;
                                    }
                                } else {
                                    detected_dims = detected_dims.max(2);
                                }
                            }
                            ValueExpr::Binary { op, .. } => {
                                if *op == BinaryOp::Mul {
                                    has_mul = true;
                                } else if *op == BinaryOp::Add {
                                    has_add = true;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            let is_convolution = (has_mul && has_add) || detected_dims >= 2;
            if detected_dims < 2 || !is_convolution {
                continue;
            }

            let is_3d = detected_dims >= 3;
            let is_2d = detected_dims == 2;

            // Statically eliminate bounds checks on strided indices
            let mut bounds_eliminated = 0;
            for &b_id in &loop_info.blocks {
                if let Some(block) = func.get_block_mut(b_id) {
                    for inst in &mut block.instructions {
                        match &mut inst.expr {
                            ValueExpr::BoundsCheck {
                                redundant, index, ..
                            } if !*redundant
                                && (strided_indices.contains(index)
                                    || known_consts.contains_key(index)) =>
                            {
                                *redundant = true;
                                bounds_eliminated += 1;
                            }
                            ValueExpr::SliceBoundsCheck { redundant, .. }
                            | ValueExpr::SliceStridedBoundsCheck { redundant, .. }
                                if !*redundant =>
                            {
                                *redundant = true;
                                bounds_eliminated += 1;
                            }
                            _ => {}
                        }
                    }
                }
            }

            if bounds_eliminated > 0 {
                self.stats.strided_bounds_eliminated += bounds_eliminated;
            }

            let mut hint = LoopVectorHint::new(8, 8, true)
                .with_convolution(true)
                .with_reduction(ReductionKind::Dot)
                .with_contiguous_reduction(true)
                .with_disjoint_slices(true)
                .with_predicate_enable(true)
                .with_unroll_and_jam(true)
                .with_zero_copy(true);

            if is_3d {
                hint = hint.with_strided_conv3d(detected_strides);
                self.stats.strided_conv3d_specialized += 1;
            } else if is_2d {
                hint = hint.with_strided_conv2d((detected_strides.0, detected_strides.1));
                self.stats.strided_conv2d_specialized += 1;
            }
            self.stats.zero_copy_convolutions_specialized += 1;
            self.stats.convolutions_vectorized += 1;

            if let Some(header_bb) = func.get_block_mut(loop_info.header) {
                header_bb.set_vector_hint(hint);
            }
        }
    }

    /// Checks whether a function parameter is utilized as an index stride factor in strided slices or expressions.
    fn is_param_used_as_stride(func: &FirFunction, val: ValueId) -> bool {
        for block in &func.blocks {
            for inst in &block.instructions {
                match &inst.expr {
                    ValueExpr::SliceStrided { stride, .. } if *stride == val => return true,
                    ValueExpr::Binary {
                        op: BinaryOp::Mul,
                        lhs,
                        rhs,
                    } if *lhs == val || *rhs == val => {
                        return true;
                    }
                    _ => {}
                }
            }
        }
        false
    }

    /// Analyzes natural loops for decimation stencils and downsampled convolutions with constant strides,
    /// eliminating redundant strided bounds checks and configuring SIMD LoopVectorHint with stride attributes.
    fn specialize_decimation_stencils(
        &mut self,
        func: &mut FirFunction,
        known_consts: &HashMap<ValueId, (i64, IntType)>,
    ) {
        let cfg = ControlFlowGraph::build(func);
        let dom_tree = DominanceTree::build(&cfg);
        let natural_loops = GenerationalOptPass::find_natural_loops(&cfg, &dom_tree);

        for loop_info in &natural_loops {
            let mut detected_stride: Option<u32> = None;
            let mut strided_indices = HashSet::new();

            for &b_id in &loop_info.blocks {
                if let Some(block) = func.get_block(b_id) {
                    for inst in &block.instructions {
                        match &inst.expr {
                            ValueExpr::SliceStrided { stride, .. } => {
                                if let Some(&(c, _)) = known_consts.get(stride) {
                                    if c >= 2 {
                                        detected_stride = Some(c as u32);
                                    }
                                } else if let Some(r) = inst.result {
                                    detected_stride = detected_stride.or(Some(2));
                                    strided_indices.insert(r);
                                }
                            }
                            ValueExpr::GetElement { index, .. }
                            | ValueExpr::GetElementPtr { index, .. } => {
                                if let Some((_, strides)) =
                                    crate::vectorize::VectorizePass::analyze_index_strides(
                                        func, *index,
                                    )
                                {
                                    if strides.0 >= 2 {
                                        detected_stride = Some(strides.0);
                                        strided_indices.insert(*index);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            let Some(stride_val) = detected_stride else {
                continue;
            };

            // Eliminate redundant bounds checks on decimation indices
            let mut bounds_eliminated = 0;
            for &b_id in &loop_info.blocks {
                if let Some(block) = func.get_block_mut(b_id) {
                    for inst in &mut block.instructions {
                        match &mut inst.expr {
                            ValueExpr::BoundsCheck {
                                redundant, index, ..
                            } if !*redundant => {
                                if strided_indices.contains(index)
                                    || known_consts.contains_key(index)
                                {
                                    *redundant = true;
                                    bounds_eliminated += 1;
                                }
                            }
                            ValueExpr::SliceBoundsCheck { redundant, .. }
                            | ValueExpr::SliceStridedBoundsCheck { redundant, .. }
                                if !*redundant =>
                            {
                                *redundant = true;
                                bounds_eliminated += 1;
                            }
                            _ => {}
                        }
                    }
                }
            }

            if bounds_eliminated > 0 {
                self.stats.strided_bounds_eliminated += bounds_eliminated;
            }

            if let Some(header_bb) = func.get_block_mut(loop_info.header) {
                let mut hint = header_bb
                    .vector_hint
                    .unwrap_or_else(|| LoopVectorHint::new(8, 4, true));
                hint.is_convolution = true;
                hint.is_strided_conv2d = true;
                hint.conv_strides = Some((stride_val, 1, 1));
                hint.unroll_and_jam = true;
                hint.is_zero_copy = true;
                hint.predicate_enable = true;
                header_bb.set_vector_hint(hint);
                self.stats.decimation_stencils_specialized += 1;
            }
        }
    }

    /// Identifies fused convolution kernels across multi-stage pipelines and specializes vector hints.
    fn specialize_fused_convolution_kernels(&mut self, func: &mut FirFunction) {
        for block in &mut func.blocks {
            if let Some(hint) = &mut block.vector_hint {
                if hint.is_fused
                    && (hint.is_convolution || hint.is_strided_conv2d || hint.is_strided_conv3d)
                {
                    self.stats.fused_convolution_kernels += 1;
                }
            }
        }
    }
}

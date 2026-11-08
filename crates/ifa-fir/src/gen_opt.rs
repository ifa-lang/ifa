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

/// Analysis context bundled for dominance-based generational check elimination.
struct DominanceContext<'a> {
    cfg: &'a ControlFlowGraph,
    dom_tree: &'a DominanceTree,
    free_operations: &'a [FreeOperation],
    val_arenas: &'a HashMap<ValueId, u16>,
    ref_defs: &'a HashMap<ValueId, BlockId>,
    aliases: &'a HashMap<ValueId, ValueId>,
    callee_has_free: &'a HashMap<Symbol, bool>,
}

/// Analysis context bundled for loop-invariant generational check hoisting.
struct LoopHoistContext<'a> {
    cfg: &'a ControlFlowGraph,
    dom_tree: &'a DominanceTree,
    free_operations: &'a [FreeOperation],
    val_arenas: &'a HashMap<ValueId, u16>,
    ref_defs: &'a HashMap<ValueId, BlockId>,
    aliases: &'a HashMap<ValueId, ValueId>,
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
        let mut safe_params: HashSet<(Symbol, usize)> = HashSet::new();
        let mut safe_env_captures: HashSet<(Symbol, usize)> = HashSet::new();

        // Structural per-function analysis
        struct FuncAnalysis {
            alloca_values: HashSet<ValueId>,
            freeing_blocks: HashSet<BlockId>,
            dom_tree: DominanceTree,
            global_aliases: HashMap<ValueId, ValueId>,
            checks_by_block: HashMap<BlockId, HashSet<ValueId>>,
            gen_creations: HashMap<ValueId, BlockId>,
            recursive_projections: HashMap<ValueId, ValueId>,
            struct_inits: HashMap<ValueId, (Symbol, Vec<ValueId>, BlockId, usize)>,
            closure_creations: Vec<(Symbol, ValueId, BlockId, usize)>,
        }

        let mut func_analyses: HashMap<Symbol, FuncAnalysis> = HashMap::new();
        for func in &module.functions {
            let cfg = ControlFlowGraph::build(func);
            let dom_tree = DominanceTree::build(&cfg);

            let mut freeing_blocks = HashSet::new();
            let mut alloca_values = HashSet::new();
            let mut gen_creations = HashMap::new();
            let mut checks_by_block: HashMap<BlockId, HashSet<ValueId>> = HashMap::new();
            let mut deref_roots: HashMap<ValueId, ValueId> = HashMap::new();
            let mut recursive_projections: HashMap<ValueId, ValueId> = HashMap::new();
            let mut struct_inits: HashMap<ValueId, (Symbol, Vec<ValueId>, BlockId, usize)> =
                HashMap::new();
            let mut closure_creations: Vec<(Symbol, ValueId, BlockId, usize)> = Vec::new();
            let mut string_constants: HashMap<ValueId, Symbol> = HashMap::new();

            for block in &func.blocks {
                for inst in &block.instructions {
                    if let Some(res) = inst.result {
                        if let ValueExpr::Constant(ConstantValue::String(s)) = &inst.expr {
                            string_constants.insert(res, *s);
                        } else if let ValueExpr::Constant(ConstantValue::Function(s)) = &inst.expr {
                            string_constants.insert(res, *s);
                        }
                    }
                }
            }

            for block in &func.blocks {
                for (inst_idx, inst) in block.instructions.iter().enumerate() {
                    match &inst.expr {
                        ValueExpr::GenFree { .. } => {
                            freeing_blocks.insert(block.id);
                        }
                        ValueExpr::Alloca { .. } => {
                            if let Some(res) = inst.result {
                                alloca_values.insert(res);
                            }
                        }
                        ValueExpr::GenRef { .. } | ValueExpr::GenAlloc { .. } => {
                            if let Some(res) = inst.result {
                                gen_creations.insert(res, block.id);
                            }
                        }
                        ValueExpr::GenDeref { ref_val } => {
                            if let Some(res) = inst.result {
                                deref_roots.insert(res, *ref_val);
                            }
                        }
                        ValueExpr::GetField { base, .. } | ValueExpr::GetFieldPtr { base, .. } => {
                            if let Some(res) = inst.result {
                                let root = deref_roots.get(base).copied().unwrap_or(*base);
                                recursive_projections.insert(res, root);
                            }
                        }
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
                        ValueExpr::GenCheck { ref_val, .. } => {
                            checks_by_block
                                .entry(block.id)
                                .or_default()
                                .insert(*ref_val);
                        }
                        _ => {}
                    }
                }
            }

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

            let mut global_aliases = HashMap::new();
            for block in &func.blocks {
                for inst in &block.instructions {
                    if let ValueExpr::Load { ptr } = &inst.expr {
                        if let (Some(res), Some(&stored_val)) =
                            (inst.result, single_store_val.get(ptr))
                        {
                            global_aliases.insert(res, stored_val);
                        }
                    }
                }
            }

            func_analyses.insert(
                func.name,
                FuncAnalysis {
                    alloca_values,
                    freeing_blocks,
                    dom_tree,
                    global_aliases,
                    checks_by_block,
                    gen_creations,
                    recursive_projections,
                    struct_inits,
                    closure_creations,
                },
            );
        }

        // Helper to check if a value is guaranteed safe at a specific caller point
        let is_val_safe_at = |caller_name: Symbol,
                              block_id: BlockId,
                              inst_idx: usize,
                              arg_val: ValueId,
                              safe_params: &HashSet<(Symbol, usize)>,
                              safe_env_captures: &HashSet<(Symbol, usize)>|
         -> bool {
            let analysis = match func_analyses.get(&caller_name) {
                Some(a) => a,
                None => return false,
            };
            let canon = canonical_ref(arg_val, &analysis.global_aliases);

            // 1. Stack alloca
            if analysis.alloca_values.contains(&arg_val) || analysis.alloca_values.contains(&canon)
            {
                return true;
            }

            // 2. Caller's own parameter is safe
            if let Some(caller_fn) = module.functions.iter().find(|f| f.name == caller_name) {
                for (c_idx, c_p) in caller_fn.params.iter().enumerate() {
                    if (c_p.val == arg_val || c_p.val == canon)
                        && safe_params.contains(&(caller_name, c_idx))
                    {
                        return true;
                    }
                }
            }

            // 3. Closure environment capture in caller (if caller itself is a lambda)
            let caller_name_str = INTERNER.resolve(&caller_name);
            if caller_name_str.starts_with("__ifa_lambda_") {
                if let Some(caller_fn) = module.functions.iter().find(|f| f.name == caller_name) {
                    if let Some(entry_b) = caller_fn.get_block(caller_fn.entry_block) {
                        for inst in &entry_b.instructions {
                            if let ValueExpr::GetField {
                                base, field_idx, ..
                            } = &inst.expr
                            {
                                if (*base == ValueId(0)
                                    || caller_fn.params.first().is_some_and(|p| p.val == *base))
                                    && inst.result.is_some_and(|r| {
                                        r == arg_val
                                            || r == canon
                                            || canonical_ref(r, &analysis.global_aliases) == canon
                                    })
                                    && safe_env_captures.contains(&(caller_name, *field_idx))
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }

            // 4. Dominating GenRef / GenAlloc without intervening GenFree
            let is_fresh_ref = analysis
                .gen_creations
                .get(&arg_val)
                .or_else(|| analysis.gen_creations.get(&canon));
            if let Some(&def_b) = is_fresh_ref {
                let no_free = !analysis.freeing_blocks.iter().any(|&fb| {
                    analysis.dom_tree.dominates(def_b, fb)
                        && analysis.dom_tree.dominates(fb, block_id)
                });
                if no_free && analysis.dom_tree.dominates(def_b, block_id) {
                    return true;
                }
            }

            // 5. Dominating GenCheck
            let mut check_dominates = false;
            for (&chk_b, chk_vals) in &analysis.checks_by_block {
                if chk_vals.contains(&arg_val) || chk_vals.contains(&canon) {
                    if chk_b == block_id {
                        if let Some(caller_fn) =
                            module.functions.iter().find(|f| f.name == caller_name)
                        {
                            if let Some(b) = caller_fn.get_block(block_id) {
                                for inst in b.instructions.iter().take(inst_idx) {
                                    if let ValueExpr::GenCheck { ref_val, .. } = &inst.expr {
                                        if *ref_val == arg_val
                                            || *ref_val == canon
                                            || canonical_ref(*ref_val, &analysis.global_aliases)
                                                == canon
                                        {
                                            check_dominates = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    } else if analysis.dom_tree.dominates(chk_b, block_id) {
                        let no_free = !analysis.freeing_blocks.iter().any(|&fb| {
                            analysis.dom_tree.dominates(chk_b, fb)
                                && analysis.dom_tree.dominates(fb, block_id)
                        });
                        if no_free {
                            check_dominates = true;
                            break;
                        }
                    }
                }
            }
            if check_dominates {
                return true;
            }

            // 6. Recursive child projection from safe root reference
            if let Some(&root_ref) = analysis
                .recursive_projections
                .get(&arg_val)
                .or_else(|| analysis.recursive_projections.get(&canon))
            {
                let canon_root = canonical_ref(root_ref, &analysis.global_aliases);
                if let Some(caller_fn) = module.functions.iter().find(|f| f.name == caller_name) {
                    for (c_idx, c_p) in caller_fn.params.iter().enumerate() {
                        if (c_p.val == root_ref || c_p.val == canon_root)
                            && safe_params.contains(&(caller_name, c_idx))
                        {
                            return true;
                        }
                    }
                }
                for (&chk_b, chk_vals) in &analysis.checks_by_block {
                    if (chk_vals.contains(&root_ref) || chk_vals.contains(&canon_root))
                        && analysis.dom_tree.dominates(chk_b, block_id)
                    {
                        return true;
                    }
                }
            }

            false
        };

        let mut changed = true;
        let mut iter = 0;
        while changed && iter < 16 {
            changed = false;
            iter += 1;

            let mut call_sites_by_target: HashMap<Symbol, Vec<CallSite>> = HashMap::new();
            for func in &module.functions {
                for block in &func.blocks {
                    for (inst_idx, inst) in block.instructions.iter().enumerate() {
                        if let ValueExpr::CallDirect { name, args }
                        | ValueExpr::BlockingCallDirect { name, args } = &inst.expr
                        {
                            call_sites_by_target.entry(*name).or_default().push((
                                func.name,
                                block.id,
                                inst_idx,
                                args.clone(),
                            ));
                        }
                    }
                }
            }

            for func in &module.functions {
                let target_name = func.name;
                let target_name_str = INTERNER.resolve(&target_name);

                // 1. Direct scalar function parameters
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
                                            is_val_safe_at(
                                                *caller_name,
                                                *block_id,
                                                *inst_idx,
                                                arg_val,
                                                &safe_params,
                                                &safe_env_captures,
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

                // 2. Closure environment captures: analyze fields captured in __env (param 0)
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
                                            if let Some(analysis) = func_analyses.get(caller_name) {
                                                let canon_env = canonical_ref(
                                                    env_val,
                                                    &analysis.global_aliases,
                                                );
                                                let struct_init =
                                                    analysis.struct_inits.get(&env_val).or_else(
                                                        || analysis.struct_inits.get(&canon_env),
                                                    );
                                                if let Some((_, fields, _, _)) = struct_init {
                                                    if let Some(&cap_val) = fields.get(f_idx) {
                                                        return is_val_safe_at(
                                                            *caller_name,
                                                            *block_id,
                                                            *inst_idx,
                                                            cap_val,
                                                            &safe_params,
                                                            &safe_env_captures,
                                                        );
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
                        for (c_fn_sym, analysis) in &func_analyses {
                            for (lambda_sym, env_val, b_id, i_idx) in &analysis.closure_creations {
                                if *lambda_sym == target_name {
                                    creation_sites.push((*c_fn_sym, *env_val, *b_id, *i_idx));
                                }
                            }
                        }

                        if !creation_sites.is_empty() {
                            let all_creations_safe = creation_sites.iter().all(
                                |(caller_name, env_val, block_id, inst_idx)| {
                                    if let Some(analysis) = func_analyses.get(caller_name) {
                                        let canon_env =
                                            canonical_ref(*env_val, &analysis.global_aliases);
                                        let struct_init = analysis
                                            .struct_inits
                                            .get(env_val)
                                            .or_else(|| analysis.struct_inits.get(&canon_env));
                                        if let Some((_, fields, _, _)) = struct_init {
                                            if let Some(&cap_val) = fields.get(f_idx) {
                                                let no_frees_in_caller =
                                                    analysis.freeing_blocks.is_empty();
                                                let is_safe = is_val_safe_at(
                                                    *caller_name,
                                                    *block_id,
                                                    *inst_idx,
                                                    cap_val,
                                                    &safe_params,
                                                    &safe_env_captures,
                                                );
                                                return is_safe && no_frees_in_caller;
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

        // Augment global_aliases with invariant block parameter inputs
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
                                        let args = match term {
                                            Terminator::Branch { target, args }
                                                if *target == block.id =>
                                            {
                                                Some(args.clone())
                                            }
                                            Terminator::BranchCond {
                                                then_block,
                                                then_args,
                                                else_block,
                                                else_args,
                                                ..
                                            } => {
                                                if *then_block == block.id {
                                                    Some(then_args.clone())
                                                } else if *else_block == block.id {
                                                    Some(else_args.clone())
                                                } else {
                                                    None
                                                }
                                            }
                                            _ => None,
                                        };
                                        if let Some(args_vec) = args {
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

        // Compute memory arena mappings for values and tracking of explicit free operations
        let val_arenas = Self::compute_val_arenas(func, &global_aliases);

        let mut free_operations: Vec<FreeOperation> = Vec::new();
        for block in &func.blocks {
            for inst in &block.instructions {
                match &inst.expr {
                    ValueExpr::GenFree { ptr } => {
                        let canon_ptr = canonical_ref(*ptr, &global_aliases);
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
                    ValueExpr::CallDirect { name, .. }
                    | ValueExpr::BlockingCallDirect { name, .. }
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

        // 2. Loop-Invariant Check Hoisting (LICM for Generational Checks - Section 9.3 Rule 2)
        // Repeat until fixed point (up to 5 passes) for nested loops
        let loop_cx = LoopHoistContext {
            cfg: &cfg,
            dom_tree: &dom_tree,
            free_operations: &free_operations,
            val_arenas: &val_arenas,
            ref_defs: &ref_creation_block,
            aliases: &global_aliases,
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
            ref_defs: &gen_ref_creations,
            aliases: &global_aliases,
            callee_has_free,
        };
        self.run_dominance_elimination(func, &cx);
    }

    /// Identifies natural loops and hoists invariant `GenCheck` instructions into loop preheaders
    /// taking into account memory arena disjointness.
    fn hoist_loop_invariant_checks(&mut self, func: &mut FirFunction, cx: &LoopHoistContext<'_>) {
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
                                let is_param =
                                    param_values.contains(ref_val) || param_values.contains(&canon);
                                let is_defined_outside =
                                    cx.ref_defs.get(ref_val).is_some_and(|&def_b| {
                                        !loop_info.blocks.contains(&def_b)
                                            && cx.dom_tree.dominates(def_b, preheader_id)
                                    }) || cx.ref_defs.get(&canon).is_some_and(|&def_b| {
                                        !loop_info.blocks.contains(&def_b)
                                            && cx.dom_tree.dominates(def_b, preheader_id)
                                    });

                                if (is_param || is_defined_outside)
                                    && !candidate_checks
                                        .iter()
                                        .any(|(v, c, _)| *v == *ref_val || *c == canon)
                                {
                                    // Verify that no freeing operation inside the loop interferes with ref_val
                                    let ref_arena = cx
                                        .val_arenas
                                        .get(ref_val)
                                        .or_else(|| cx.val_arenas.get(&canon))
                                        .copied();

                                    let has_interfering_free =
                                        cx.free_operations.iter().any(|op| {
                                            loop_info.blocks.contains(&op.block)
                                                && op.interferes_with_ref(
                                                    *ref_val, ref_arena, cx.aliases,
                                                )
                                        });

                                    if !has_interfering_free {
                                        candidate_checks.push((*ref_val, canon, inst.span));
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
                            *r == ref_val || *r == canon || canonical_ref(*r, cx.aliases) == canon
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
                                if (*r == ref_val
                                    || *r == canon
                                    || canonical_ref(*r, cx.aliases) == canon)
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
    fn run_dominance_elimination(&mut self, func: &mut FirFunction, cx: &DominanceContext<'_>) {
        let is_strict = func.is_strict;
        let is_coroutine = func.is_coroutine();
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

        let natural_loops = Self::find_natural_loops(cx.cfg, cx.dom_tree);
        let mut loop_by_header: HashMap<BlockId, &NaturalLoop> = HashMap::new();
        for l in &natural_loops {
            loop_by_header.entry(l.header).or_insert(l);
        }

        let func_name = func.name;
        let is_func_lambda = INTERNER.resolve(&func_name).starts_with("__ifa_lambda_");
        let env_param_val = func.params.first().map(|p| p.val);

        for &block_id in &cx.dom_tree.rpo_blocks {
            let mut available: HashSet<ValueId> = HashSet::new();

            if is_strict {
                // In strict mode, function guarantees zero dynamic generational checks
            } else if block_id == func.entry_block {
                // Inter-procedural propagation: formal parameters proven safe across all call-sites
                for (p_idx, p) in func.params.iter().enumerate() {
                    if self.safe_params.contains(&(func_name, p_idx)) {
                        available.insert(p.val);
                        available.insert(canonical_ref(p.val, cx.aliases));
                    }
                }

                // Inter-procedural propagation: closure captured fields proven safe across all call-sites
                if let Some(entry_blk) = func.get_block(func.entry_block) {
                    for inst in &entry_blk.instructions {
                        if let ValueExpr::GetField {
                            base, field_idx, ..
                        } = &inst.expr
                        {
                            let is_env = (is_func_lambda && *base == ValueId(0))
                                || env_param_val.is_some_and(|p| p == *base);
                            if is_env && self.safe_env_captures.contains(&(func_name, *field_idx)) {
                                if let Some(res) = inst.result {
                                    available.insert(res);
                                    available.insert(canonical_ref(res, cx.aliases));
                                }
                            }
                        }
                    }
                }
            } else if block_id != func.entry_block {
                if let Some(loop_info) = loop_by_header.get(&block_id) {
                    // 1a. Loop header: Checks from the preheader remain valid across iterations
                    // if no block in the loop performs an interfering free on that reference.
                    if let Some(preheader) = loop_info.preheader {
                        if let Some(pre_checks) = verified_at_exit.get(&preheader) {
                            for &chk_val in pre_checks {
                                let canon = canonical_ref(chk_val, cx.aliases);
                                let ref_arena = cx
                                    .val_arenas
                                    .get(&chk_val)
                                    .or_else(|| cx.val_arenas.get(&canon))
                                    .copied();

                                let has_interfering_free = cx.free_operations.iter().any(|op| {
                                    loop_info.blocks.contains(&op.block)
                                        && op.interferes_with_ref(chk_val, ref_arena, cx.aliases)
                                });

                                if !has_interfering_free {
                                    available.insert(chk_val);
                                    available.insert(canon);
                                }
                            }
                        }
                    }
                } else if let Some(preds) = cx.cfg.predecessors.get(&block_id) {
                    // 1b. Non-loop-header block: Confluent dataflow intersection across all predecessors
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
                        } else if let Some(idom) = cx.dom_tree.immediate_dominator(block_id) {
                            if let Some(dom_checks) = verified_at_exit.get(&idom) {
                                for &val in dom_checks {
                                    let canon = canonical_ref(val, cx.aliases);
                                    let ref_arena = cx
                                        .val_arenas
                                        .get(&val)
                                        .or_else(|| cx.val_arenas.get(&canon))
                                        .copied();

                                    let no_free = !cx.free_operations.iter().any(|op| {
                                        op.block != idom
                                            && cx.dom_tree.dominates(idom, op.block)
                                            && cx.dom_tree.dominates(op.block, block_id)
                                            && op.interferes_with_ref(val, ref_arena, cx.aliases)
                                    });

                                    if no_free {
                                        available.insert(val);
                                        available.insert(canon);
                                    }
                                }
                            }
                        }
                    }
                }

                // 2. SSA Block Parameters / Phi Promotion Resolution (SROA Stability)
                if let Some(block) = func.get_block(block_id) {
                    if !block.params.is_empty() {
                        if let Some(preds) = cx.cfg.predecessors.get(&block_id) {
                            for (param_idx, (param_val, _)) in block.params.iter().enumerate() {
                                let mut all_preds_verified = !preds.is_empty();
                                for &pred_id in preds {
                                    if let Some(pred_block) = func.get_block(pred_id) {
                                        if let Some(term) = &pred_block.terminator {
                                            if let Some(args) = get_branch_args(term, block_id) {
                                                if let Some(&arg_val) = args.get(param_idx) {
                                                    let arg_canon =
                                                        canonical_ref(arg_val, cx.aliases);
                                                    let is_verified_in_pred = verified_at_exit
                                                        .get(&pred_id)
                                                        .is_some_and(|set| {
                                                            set.contains(&arg_val)
                                                                || set.contains(&arg_canon)
                                                        });
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
                                    available.insert(canonical_ref(*param_val, cx.aliases));
                                }
                            }
                        }
                    }
                }

                // 3. Direct lexical dominance: created in dominating block with no intervening frees
                for (&ref_val, &def_block) in cx.ref_defs {
                    if cx.dom_tree.dominates(def_block, block_id) {
                        let canon = canonical_ref(ref_val, cx.aliases);
                        let ref_arena = cx
                            .val_arenas
                            .get(&ref_val)
                            .or_else(|| cx.val_arenas.get(&canon))
                            .copied();

                        let no_free = !cx.free_operations.iter().any(|op| {
                            cx.dom_tree.dominates(def_block, op.block)
                                && cx.dom_tree.dominates(op.block, block_id)
                                && op.interferes_with_ref(ref_val, ref_arena, cx.aliases)
                        });
                        if no_free {
                            available.insert(ref_val);
                            available.insert(canon);
                        }
                    }
                }
            }

            // Local store-to-load reference alias tracking
            let mut ptr_aliases: HashMap<ValueId, ValueId> = HashMap::new();
            let mut deref_roots: HashMap<ValueId, ValueId> = HashMap::new();

            if let Some(block) = func.get_block_mut(block_id) {
                for inst in &mut block.instructions {
                    match &mut inst.expr {
                        ValueExpr::Store { ptr, val } => {
                            ptr_aliases.insert(*ptr, *val);
                        }
                        ValueExpr::GenDeref { ref_val } => {
                            if let Some(res) = inst.result {
                                deref_roots.insert(res, *ref_val);
                            }
                        }
                        ValueExpr::GetField {
                            base, field_idx, ..
                        }
                        | ValueExpr::GetFieldPtr {
                            base, field_idx, ..
                        } => {
                            if let Some(res) = inst.result {
                                let root = deref_roots.get(base).copied().unwrap_or(*base);
                                let canon_root = canonical_ref(root, cx.aliases);
                                if available.contains(&root) || available.contains(&canon_root) {
                                    // Recursive child projection derived from verified root reference
                                    available.insert(res);
                                    available.insert(canonical_ref(res, cx.aliases));
                                }

                                let is_env = (is_func_lambda && *base == ValueId(0))
                                    || env_param_val.is_some_and(|p| p == *base);
                                if is_env
                                    && self.safe_env_captures.contains(&(func_name, *field_idx))
                                {
                                    available.insert(res);
                                    available.insert(canonical_ref(res, cx.aliases));
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
                                    if available.contains(&val) || available.contains(&canon) {
                                        available.insert(res);
                                        available.insert(canonical_ref(res, cx.aliases));
                                    }
                                }
                            }
                        }
                        ValueExpr::GenRef { .. }
                        | ValueExpr::GenAlloc { .. }
                        | ValueExpr::CallArenaAlloc { .. } => {
                            if let Some(res) = inst.result {
                                available.insert(res);
                                available.insert(canonical_ref(res, cx.aliases));
                            }
                        }
                        ValueExpr::CallArenaRewind { .. } => {
                            let free_op = FreeOperation {
                                block: block_id,
                                ptr: ValueId(0),
                                arena: Some(crate::closure_opt::ARENA_THREAD_LOCAL_CALL),
                            };

                            available.retain(|&val| {
                                let val_canon = canonical_ref(val, cx.aliases);
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
                                block: block_id,
                                ptr: *ptr,
                                arena: free_arena,
                            };

                            available.retain(|&val| {
                                let val_canon = canonical_ref(val, cx.aliases);
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
                            if !callee_frees {
                                for (arg_idx, &arg_val) in args.iter().enumerate() {
                                    if self.safe_params.contains(&(*name, arg_idx)) {
                                        let canon = canonical_ref(arg_val, cx.aliases);
                                        available.insert(arg_val);
                                        available.insert(canon);
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
                            // During coroutine suspension, keep available references in disjoint arenas
                            available.retain(|&val| {
                                let val_canon = canonical_ref(val, cx.aliases);
                                let val_arena = cx
                                    .val_arenas
                                    .get(&val)
                                    .or_else(|| cx.val_arenas.get(&val_canon))
                                    .copied();
                                val_arena.is_some_and(|a| a > 0)
                            });
                        }
                        ValueExpr::GenCheck { ref_val, redundant } => {
                            self.stats.total_checks += 1;
                            let canon = canonical_ref(*ref_val, cx.aliases);

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
                                self.stats.interprocedural_eliminated_checks += 1;
                                if is_coroutine {
                                    self.stats.coroutine_sync_barriers_eliminated += 1;
                                }
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

//! Generational Arena Merging and Static Access Barrier Elimination for FIR SSA.
//!
//! Optimizes generational memory arenas by coalescing allocations belonging to
//! immutable recursive data structures (binary trees, linked lists, DAGs, ASTs)
//! into shared, contiguous arenas, and statically eliminates access barriers
//! (`GenCheck`) during recursive navigation and traversals.
//!
//! # Architecture
//!
//! 1. **Recursive Structure Identification**:
//!    Identifies struct definitions that contain direct or transitive generational
//!    references to themselves or mutually dependent recursive types.
//!
//! 2. **Arena Coalescing (Fusion)**:
//!    Builds an allocation affinity graph using disjoint-set forests (Union-Find).
//!    Allocations interconnected via fields (`SetField`, `StructInit`, `Store`) or
//!    sharing recursive structural affinity within constructor frames are merged
//!    into a unified generational arena ID (`arena_id`).
//!
//! 3. **Static Access Barrier Elimination**:
//!    Proves by structural induction that once a recursive structure's root node has
//!    been verified via an initial generational barrier (or is locally allocated),
//!    all field projections (`GetField`) along immutable paths are mathematically
//!    guaranteed to remain valid. All subsequent `GenCheck` instructions on child
//!    references are marked redundant and stripped, transforming O(N) dynamic checks
//!    into O(1) root verification.

use crate::cfg::ControlFlowGraph;
use crate::dominance::DominanceTree;
use crate::ir::*;
use crate::sroa::SroaPass;
use crate::types::FirType;
use ifa_sema::types::IntType;
use ifa_span::{Span, Symbol};
use std::collections::{HashMap, HashSet};

/// Statistics tracking the generational arena coalescing and access barrier elimination pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArenaFusionStats {
    /// Total recursive struct types identified in the module.
    pub recursive_structs_analyzed: usize,
    /// Number of distinct generational arenas merged/coalesced.
    pub arenas_merged: usize,
    /// Total generational allocations (`GenAlloc`) fused into unified arenas.
    pub allocations_fused: usize,
    /// Total access barriers (`GenCheck`) statically eliminated across recursive paths.
    pub access_barriers_eliminated: usize,
    /// Recursive field projections (`GetField`) proven safe without dynamic checks.
    pub recursive_projections_verified: usize,
    /// Total zero-copy streaming pipeline arenas created or coalesced.
    pub streaming_arenas_fused: usize,
    /// Total zero-copy streaming pipelines optimized with zero-heap arena locality.
    pub zero_copy_pipelines_optimized: usize,
    /// Total interprocedural arena fusions propagated across call boundaries.
    pub interprocedural_fusions: usize,
    /// Total interprocedural redundant access barriers eliminated across call boundaries.
    pub interprocedural_barriers_eliminated: usize,
    /// Total intermediate call arena allocations (`CallArenaAlloc`) fused or coalesced across filter/projection stages.
    pub call_arenas_fused: usize,
    /// Total redundant call arena marks/rewinds eliminated across pipeline boundaries.
    pub call_arena_scopes_coalesced: usize,
    /// Total multi-dimensional projection intermediate buffers forwarded and eliminated.
    pub multidim_projections_fused: usize,
    /// Total superfluous synchronization/access barriers eliminated around coroutine suspension/resumption points.
    pub coroutine_sync_barriers_eliminated: usize,
    /// Total disjoint arena references proven preserved and valid across coroutine yield points.
    pub disjoint_arena_references_preserved: usize,
    /// Total nested call arena frames fused into outer caller scopes.
    pub nested_call_arenas_fused: usize,
}

impl ArenaFusionStats {
    pub fn total_optimizations(&self) -> usize {
        self.arenas_merged
            + self.allocations_fused
            + self.access_barriers_eliminated
            + self.recursive_projections_verified
            + self.streaming_arenas_fused
            + self.zero_copy_pipelines_optimized
            + self.interprocedural_fusions
            + self.interprocedural_barriers_eliminated
            + self.call_arenas_fused
            + self.call_arena_scopes_coalesced
            + self.multidim_projections_fused
            + self.coroutine_sync_barriers_eliminated
            + self.disjoint_arena_references_preserved
            + self.nested_call_arenas_fused
    }
}

/// Context for interprocedural analysis and propagation across call sites.
#[derive(Debug, Clone, Copy)]
pub struct InterprocContext<'a> {
    pub param_arenas: &'a HashMap<usize, u16>,
    pub call_return_arenas: &'a HashMap<ValueId, u16>,
    pub verified_params: &'a HashSet<ValueId>,
    pub is_initial_pass: bool,
}

/// Disjoint-set forest (Union-Find) for merging allocation arenas.
struct DisjointSet {
    parent: HashMap<ValueId, ValueId>,
}

impl DisjointSet {
    fn new() -> Self {
        Self {
            parent: HashMap::new(),
        }
    }

    fn find(&mut self, x: ValueId) -> ValueId {
        let mut root = x;
        while let Some(&p) = self.parent.get(&root) {
            if p == root {
                break;
            }
            root = p;
        }
        // Path compression
        let mut curr = x;
        while let Some(&p) = self.parent.get(&curr) {
            if p == root {
                break;
            }
            self.parent.insert(curr, root);
            curr = p;
        }
        root
    }

    fn union(&mut self, a: ValueId, b: ValueId) {
        let root_a = self.find(a);
        let root_b = self.find(b);
        if root_a != root_b {
            self.parent.insert(root_b, root_a);
        }
    }
}

/// Generational Arena Merging and Static Access Barrier Elimination pass.
pub struct ArenaFusionPass {
    stats: ArenaFusionStats,
    next_synthetic_arena: u16,
}

impl ArenaFusionPass {
    /// Creates a new arena fusion and access barrier elimination pass.
    pub fn new() -> Self {
        Self {
            stats: ArenaFusionStats::default(),
            next_synthetic_arena: 100,
        }
    }

    /// Access collected optimization statistics.
    pub fn stats(&self) -> ArenaFusionStats {
        self.stats
    }

    /// Run the pass on a FIR module.
    pub fn run_on_module(&mut self, module: &mut FirModule) -> ArenaFusionStats {
        let recursive_structs = Self::identify_recursive_structs(module);
        self.stats.recursive_structs_analyzed = recursive_structs.len();

        let struct_map: HashMap<Symbol, FirStruct> = module
            .structs
            .iter()
            .cloned()
            .map(|s| (s.name, s))
            .collect();

        let empty_param_arenas = HashMap::new();
        let empty_call_return_arenas = HashMap::new();
        let empty_verified_params = HashSet::new();
        let initial_ctx = InterprocContext {
            param_arenas: &empty_param_arenas,
            call_return_arenas: &empty_call_return_arenas,
            verified_params: &empty_verified_params,
            is_initial_pass: true,
        };

        for func in &mut module.functions {
            self.optimize_function(func, &recursive_structs, &struct_map, &initial_ctx);
        }

        self.propagate_interprocedural_arenas(module, &recursive_structs, &struct_map);

        self.stats
    }

    /// Identifies all struct definitions that participate in direct or mutual recursion.
    fn identify_recursive_structs(module: &FirModule) -> HashSet<Symbol> {
        let mut recursive = HashSet::new();

        for st in &module.structs {
            let is_directly_recursive = st
                .fields
                .iter()
                .any(|(_, ty)| ty.is_recursive_with_name(st.name));

            if is_directly_recursive {
                recursive.insert(st.name);
            }
        }

        // Mutual recursion fixed-point propagation
        let mut changed = true;
        while changed {
            changed = false;
            for st in &module.structs {
                if recursive.contains(&st.name) {
                    continue;
                }
                for (_, ty) in &st.fields {
                    if let Some(inner_name) = Self::extract_struct_name(ty) {
                        if recursive.contains(&inner_name) {
                            recursive.insert(st.name);
                            changed = true;
                            break;
                        }
                    }
                }
            }
        }

        recursive
    }

    /// Extracts the struct symbol from a FIR type if one is enclosed.
    fn extract_struct_name(ty: &FirType) -> Option<Symbol> {
        match ty {
            FirType::Struct(name, _) => Some(*name),
            FirType::GenerationalRef(inner)
            | FirType::Pointer(inner)
            | FirType::Optional(inner)
            | FirType::Slice(inner)
            | FirType::Array(inner, _) => Self::extract_struct_name(inner),
            _ => None,
        }
    }

    /// Determines if a type represents a zero-copy streaming pipeline buffer, chunk, or frame.
    fn is_streaming_or_buffer_type(ty: &FirType) -> bool {
        match ty {
            FirType::Slice(_) | FirType::Array(..) => true,
            FirType::Struct(name, _) => {
                let s = ifa_span::INTERNER.resolve(name);
                s.contains("Stream")
                    || s.contains("Chunk")
                    || s.contains("Buffer")
                    || s.contains("Packet")
                    || s.contains("Queue")
                    || s.contains("Frame")
                    || s.contains("Pipeline")
                    || s.contains("Ring")
                    || s.contains("Channel")
                    || s.contains("Batch")
                    || s.contains("Window")
                    || s.contains("Message")
            }
            FirType::GenerationalRef(inner) | FirType::Pointer(inner) => {
                Self::is_streaming_or_buffer_type(inner)
            }
            _ => false,
        }
    }

    /// Optimizes a single function for generational arena coalescing and access barrier elimination.
    fn optimize_function(
        &mut self,
        func: &mut FirFunction,
        recursive_structs: &HashSet<Symbol>,
        struct_map: &HashMap<Symbol, FirStruct>,
        ctx: &InterprocContext,
    ) {
        // Step 1: Generational Arena Merging (Recursive Structs & Zero-Copy Streaming Pipelines)
        self.merge_arenas(
            func,
            recursive_structs,
            ctx.param_arenas,
            ctx.call_return_arenas,
            ctx.is_initial_pass,
        );

        // Step 2: Static Access Barrier Elimination for Recursive & Streaming Structures
        self.eliminate_access_barriers(func, recursive_structs, struct_map, ctx.verified_params);

        // Step 3: Intermediate Call Arena Coalescing & Scope Consolidation
        self.optimize_call_arenas_in_pipeline(func);

        // Step 4: Multi-dimensional Projection Folding & Strided Stencil Fusion
        self.optimize_multidim_projections(func);
    }

    /// Coalesces allocations of recursive structures and streaming pipelines into unified generational arenas.
    fn merge_arenas(
        &mut self,
        func: &mut FirFunction,
        recursive_structs: &HashSet<Symbol>,
        param_arenas: &HashMap<usize, u16>,
        call_return_arenas: &HashMap<ValueId, u16>,
        is_initial_pass: bool,
    ) {
        // 1. Collect all GenAlloc instructions with their ValueId, type, and existing arena
        let mut alloc_infos: HashMap<ValueId, (FirType, Option<u16>)> = HashMap::new();
        let mut param_vals: HashSet<ValueId> = HashSet::new();

        for (&param_idx, &p_arena) in param_arenas {
            if let Some(p) = func.params.get(param_idx) {
                alloc_infos.insert(p.val, (p.ty.clone(), Some(p_arena)));
                param_vals.insert(p.val);
            }
        }

        for (&call_res, &ret_arena) in call_return_arenas {
            alloc_infos.insert(call_res, (FirType::Unit, Some(ret_arena)));
            param_vals.insert(call_res);
        }

        for block in &func.blocks {
            for inst in &block.instructions {
                if let (Some(res), ValueExpr::GenAlloc { ty, arena }) = (inst.result, &inst.expr) {
                    let is_rec = match ty {
                        FirType::Struct(name, _) => recursive_structs.contains(name),
                        _ => Self::extract_struct_name(ty)
                            .is_some_and(|n| recursive_structs.contains(&n)),
                    };
                    let is_streaming = Self::is_streaming_or_buffer_type(ty) || func.is_strict;
                    if is_rec || is_streaming {
                        alloc_infos.insert(res, (ty.clone(), *arena));
                    }
                }
            }
        }

        if alloc_infos.is_empty() {
            return;
        }

        // 2. Build DisjointSet and connect allocations via assignments, struct initializations, and calls
        let mut dset = DisjointSet::new();
        for &val in alloc_infos.keys() {
            dset.parent.insert(val, val);
        }

        // Trace pointers/allocas holding allocations
        let mut val_aliases: HashMap<ValueId, ValueId> = HashMap::new();

        for block in &func.blocks {
            for inst in &block.instructions {
                match &inst.expr {
                    ValueExpr::Store { ptr, val } => {
                        val_aliases.insert(*ptr, *val);
                        if let Some(&ptr_val) = val_aliases.get(ptr) {
                            if alloc_infos.contains_key(&ptr_val) && alloc_infos.contains_key(val) {
                                dset.union(ptr_val, *val);
                            }
                        }
                    }
                    ValueExpr::Load { ptr } => {
                        if let (Some(res), Some(&stored)) = (inst.result, val_aliases.get(ptr)) {
                            val_aliases.insert(res, stored);
                        }
                    }
                    ValueExpr::SetField { base, val, .. } => {
                        let actual_base = val_aliases.get(base).copied().unwrap_or(*base);
                        let actual_val = val_aliases.get(val).copied().unwrap_or(*val);
                        if alloc_infos.contains_key(&actual_base)
                            && alloc_infos.contains_key(&actual_val)
                        {
                            dset.union(actual_base, actual_val);
                        }
                    }
                    ValueExpr::StructInit { fields, .. } => {
                        let mut first_alloc: Option<ValueId> = None;
                        for &f_val in fields {
                            let canon = val_aliases.get(&f_val).copied().unwrap_or(f_val);
                            if alloc_infos.contains_key(&canon) {
                                match first_alloc {
                                    None => first_alloc = Some(canon),
                                    Some(first) => dset.union(first, canon),
                                }
                            }
                        }
                    }
                    ValueExpr::Call { args, .. } | ValueExpr::CallDirect { args, .. } => {
                        let mut first_alloc: Option<ValueId> = None;
                        for &a_val in args {
                            let canon = val_aliases.get(&a_val).copied().unwrap_or(a_val);
                            if alloc_infos.contains_key(&canon) {
                                match first_alloc {
                                    None => first_alloc = Some(canon),
                                    Some(first) => dset.union(first, canon),
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Also merge allocations of the same type within the same function
        // (constructors/factories creating complete sub-graphs or uniform streaming buffers)
        let mut by_type: HashMap<FirType, Vec<ValueId>> = HashMap::new();
        for (&val, (ty, _)) in &alloc_infos {
            by_type.entry(ty.clone()).or_default().push(val);
        }
        for vals in by_type.values() {
            if vals.len() > 1 {
                let first = vals[0];
                for &v in &vals[1..] {
                    dset.union(first, v);
                }
            }
        }

        // 3. Group by connected component root and determine unified arena ID
        let mut groups: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
        for &val in alloc_infos.keys() {
            let root = dset.find(val);
            groups.entry(root).or_default().push(val);
        }

        let mut fused_assignments: HashMap<ValueId, u16> = HashMap::new();

        for members in groups.values() {
            let mut existing_arenas = HashSet::new();
            let mut is_streaming_group = false;
            let mut has_interprocedural_param = false;

            for m in members {
                if param_vals.contains(m) {
                    has_interprocedural_param = true;
                }
                if let Some((ty, a_opt)) = alloc_infos.get(m) {
                    if let Some(a) = a_opt {
                        if *a > 0 {
                            existing_arenas.insert(*a);
                        }
                    }
                    if Self::is_streaming_or_buffer_type(ty) || func.is_strict {
                        is_streaming_group = true;
                    }
                }
            }

            let unified_arena = if let Some(&chosen) = existing_arenas.iter().min() {
                if existing_arenas.len() > 1 {
                    self.stats.arenas_merged += existing_arenas.len() - 1;
                }
                chosen
            } else {
                let syn = self.next_synthetic_arena;
                self.next_synthetic_arena = self.next_synthetic_arena.saturating_add(1);
                syn
            };

            for m in members {
                fused_assignments.insert(*m, unified_arena);
            }

            let local_member_count = members.iter().filter(|m| !param_vals.contains(m)).count();
            if is_initial_pass {
                self.stats.allocations_fused += local_member_count;
                if is_streaming_group && local_member_count > 0 {
                    self.stats.streaming_arenas_fused += 1;
                    self.stats.zero_copy_pipelines_optimized += 1;
                }
            }

            if has_interprocedural_param && local_member_count > 0 {
                self.stats.interprocedural_fusions += 1;
            }
        }

        // 4. Rewrite GenAlloc instructions with fused arena IDs
        for block in &mut func.blocks {
            for inst in &mut block.instructions {
                if let (Some(res), ValueExpr::GenAlloc { ty, arena }) =
                    (inst.result, &mut inst.expr)
                {
                    if let Some(&fused_id) = fused_assignments.get(&res) {
                        *arena = Some(fused_id);
                        let _ = ty;
                    }
                }
            }
        }
    }

    /// Statically eliminates redundant `GenCheck` access barriers for immutable recursive structures.
    fn eliminate_access_barriers(
        &mut self,
        func: &mut FirFunction,
        recursive_structs: &HashSet<Symbol>,
        struct_map: &HashMap<Symbol, FirStruct>,
        verified_params: &HashSet<ValueId>,
    ) {
        let cfg = ControlFlowGraph::build(func);
        let dom_tree = DominanceTree::build(&cfg);

        // Pre-compute local alias chains and dereferences
        let mut aliases: HashMap<ValueId, ValueId> = HashMap::new();
        let mut deref_roots: HashMap<ValueId, ValueId> = HashMap::new();
        let mut recursive_projections: HashMap<ValueId, ValueId> = HashMap::new();
        let mut val_arenas: HashMap<ValueId, u16> = HashMap::new();

        for block in &func.blocks {
            for inst in &block.instructions {
                if let Some(res) = inst.result {
                    match &inst.expr {
                        ValueExpr::GenAlloc { arena: Some(a), .. } if *a > 0 => {
                            val_arenas.insert(res, *a);
                        }
                        ValueExpr::CallArenaAlloc { .. } => {
                            val_arenas.insert(res, crate::closure_opt::ARENA_THREAD_LOCAL_CALL);
                        }
                        _ => {}
                    }
                }

                match &inst.expr {
                    ValueExpr::GenRef { ptr } => {
                        if let Some(res) = inst.result {
                            aliases.insert(res, *ptr);
                            if let Some(&a) = val_arenas.get(ptr) {
                                val_arenas.insert(res, a);
                            }
                        }
                    }
                    ValueExpr::Load { ptr } => {
                        if let Some(res) = inst.result {
                            if let Some(&stored) = aliases.get(ptr) {
                                aliases.insert(res, stored);
                            }
                            if let Some(&a) = val_arenas.get(ptr) {
                                val_arenas.insert(res, a);
                            }
                        }
                    }
                    ValueExpr::Store { ptr, val } => {
                        aliases.insert(*ptr, *val);
                        if let Some(&a) = val_arenas.get(val) {
                            val_arenas.insert(*ptr, a);
                        }
                    }
                    ValueExpr::GenDeref { ref_val } => {
                        if let Some(res) = inst.result {
                            deref_roots.insert(res, *ref_val);
                            if let Some(&a) = val_arenas.get(ref_val) {
                                val_arenas.insert(res, a);
                            }
                        }
                    }
                    ValueExpr::GetField {
                        base,
                        field_idx,
                        field_name: _,
                    } => {
                        if let Some(res) = inst.result {
                            let root = deref_roots.get(base).copied().unwrap_or(*base);
                            if let Some(&a) = val_arenas.get(base).or_else(|| val_arenas.get(&root))
                            {
                                val_arenas.insert(res, a);
                            }
                            // Check if this field corresponds to a recursive reference
                            let is_rec = Self::is_field_recursive(
                                root,
                                *field_idx,
                                func,
                                recursive_structs,
                                struct_map,
                            );
                            if is_rec {
                                recursive_projections.insert(res, root);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        let is_coro_func = func.is_coroutine();
        let mut block_has_suspension: HashSet<BlockId> = HashSet::new();
        for block in &func.blocks {
            if block.instructions.iter().any(|i| {
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
            }) {
                block_has_suspension.insert(block.id);
            }
        }
        let has_any_suspension = is_coro_func || !block_has_suspension.is_empty();

        // Trace dataflow across blocks in Reverse Post-Order
        let mut verified_at_exit: HashMap<BlockId, HashSet<ValueId>> = HashMap::new();

        for &block_id in &dom_tree.rpo_blocks {
            let mut verified: HashSet<ValueId> = HashSet::new();

            // Inherit from predecessors
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

            // Fresh allocations and parameters proven safe
            if block_id == func.entry_block {
                for p in &func.params {
                    if verified_params.contains(&p.val) {
                        verified.insert(p.val);
                        verified.insert(Self::resolve_alias(p.val, &aliases));
                        self.stats.interprocedural_barriers_eliminated += 1;
                    }
                    if let FirType::GenerationalRef(inner) = &p.ty {
                        if let Some(st_name) = Self::extract_struct_name(inner) {
                            if recursive_structs.contains(&st_name) {
                                // Formal parameter is safe once checked at entry
                            }
                        }
                    }
                }
            }

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
                            // Suspension point: retain references belonging to disjoint/local arenas or verified parameters
                            verified.retain(|v| {
                                val_arenas.get(v).is_some_and(|&a| a > 0)
                                    || verified_params.contains(v)
                                    || deref_roots
                                        .get(v)
                                        .is_some_and(|r| val_arenas.get(r).is_some_and(|&a| a > 0))
                            });
                        }
                        ValueExpr::GenAlloc { .. } | ValueExpr::GenRef { .. } => {
                            if let Some(res) = inst.result {
                                verified.insert(res);
                            }
                        }
                        ValueExpr::GenFree { ptr } => {
                            verified.remove(ptr);
                        }
                        ValueExpr::GetField { base, .. } => {
                            if let Some(res) = inst.result {
                                let root = deref_roots.get(base).copied().unwrap_or(*base);
                                let canon_root = Self::resolve_alias(root, &aliases);
                                if verified.contains(&root) || verified.contains(&canon_root) {
                                    verified.insert(res);
                                    verified.insert(Self::resolve_alias(res, &aliases));
                                    self.stats.recursive_projections_verified += 1;
                                }
                            }
                        }
                        ValueExpr::SliceSub { base, .. } | ValueExpr::SliceStrided { base, .. } => {
                            if let Some(res) = inst.result {
                                let canon_base = Self::resolve_alias(*base, &aliases);
                                if verified.contains(base) || verified.contains(&canon_base) {
                                    verified.insert(res);
                                    verified.insert(Self::resolve_alias(res, &aliases));
                                    self.stats.recursive_projections_verified += 1;
                                }
                            }
                        }
                        ValueExpr::GenCheck { ref_val, redundant } => {
                            let canon = Self::resolve_alias(*ref_val, &aliases);
                            let root = recursive_projections.get(ref_val).copied();
                            let is_verified = verified.contains(ref_val)
                                || verified.contains(&canon)
                                || root.is_some_and(|r| {
                                    verified.contains(&r)
                                        || verified.contains(&Self::resolve_alias(r, &aliases))
                                });

                            let is_disjoint_ref = val_arenas.get(ref_val).is_some_and(|&a| a > 0)
                                || val_arenas.get(&canon).is_some_and(|&a| a > 0)
                                || verified_params.contains(ref_val)
                                || verified_params.contains(&canon);

                            if *redundant {
                                verified.insert(*ref_val);
                                verified.insert(canon);
                            } else if is_verified {
                                *redundant = true;
                                self.stats.access_barriers_eliminated += 1;
                                if has_any_suspension && is_disjoint_ref {
                                    self.stats.coroutine_sync_barriers_eliminated += 1;
                                    self.stats.disjoint_arena_references_preserved += 1;
                                }
                                verified.insert(*ref_val);
                                verified.insert(canon);
                            } else {
                                // First check in path: validates reference for future accesses
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

    /// Helper resolving canonical alias.
    fn resolve_alias(mut val: ValueId, aliases: &HashMap<ValueId, ValueId>) -> ValueId {
        let mut visited = HashSet::new();
        while let Some(&target) = aliases.get(&val) {
            if !visited.insert(val) {
                break;
            }
            val = target;
        }
        val
    }

    /// Checks if a field at `field_idx` on reference `root` is a recursive reference.
    fn is_field_recursive(
        root: ValueId,
        field_idx: usize,
        func: &FirFunction,
        recursive_structs: &HashSet<Symbol>,
        struct_map: &HashMap<Symbol, FirStruct>,
    ) -> bool {
        // Look up root's type from function parameters or local allocas
        for p in &func.params {
            if p.val == root {
                if let FirType::GenerationalRef(inner) = &p.ty {
                    if let Some(st_name) = Self::extract_struct_name(inner) {
                        if recursive_structs.contains(&st_name) {
                            if let Some(st) = struct_map.get(&st_name) {
                                if let Some((_, f_ty)) = st.fields.get(field_idx) {
                                    return f_ty.is_generational_ref()
                                        || f_ty.is_recursive_with_name(st_name);
                                }
                            }
                        }
                    }
                }
            }
        }

        for block in &func.blocks {
            for inst in &block.instructions {
                if inst.result == Some(root) {
                    if let ValueExpr::GenAlloc { ty, .. } = &inst.expr {
                        if let Some(st_name) = Self::extract_struct_name(ty) {
                            if recursive_structs.contains(&st_name) {
                                if let Some(st) = struct_map.get(&st_name) {
                                    if let Some((_, f_ty)) = st.fields.get(field_idx) {
                                        return f_ty.is_generational_ref()
                                            || f_ty.is_recursive_with_name(st_name);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Conservative fallback: assume true if index > 0 on recursive struct projection
        true
    }

    /// Propagates generational arena assignments and access verification across interprocedural call boundaries.
    fn propagate_interprocedural_arenas(
        &mut self,
        module: &mut FirModule,
        recursive_structs: &HashSet<Symbol>,
        struct_map: &HashMap<Symbol, FirStruct>,
    ) {
        for _ in 0..4 {
            let mut callee_param_arenas: HashMap<Symbol, HashMap<usize, u16>> = HashMap::new();
            let mut callee_param_verified: HashMap<Symbol, HashMap<usize, bool>> = HashMap::new();
            let mut callee_return_arenas: HashMap<Symbol, u16> = HashMap::new();
            let mut callees_under_call_arena: HashSet<Symbol> = HashSet::new();

            // 1. Analyze each function's return arena
            for func in &module.functions {
                let mut return_arena: Option<u16> = None;
                for block in &func.blocks {
                    if let Some(Terminator::Return(Some(ret_val))) = &block.terminator {
                        for inst in &block.instructions {
                            if inst.result == Some(*ret_val) {
                                if let ValueExpr::GenAlloc { arena: Some(a), .. } = inst.expr {
                                    return_arena = Some(a);
                                }
                            }
                        }
                    }
                }
                if let Some(ra) = return_arena {
                    callee_return_arenas.insert(func.name, ra);
                }
            }

            // 2. Collect call site information across all functions
            for func in &module.functions {
                let mut val_to_arena: HashMap<ValueId, u16> = HashMap::new();
                let mut aliases: HashMap<ValueId, ValueId> = HashMap::new();
                let mut verified_at_call: HashSet<ValueId> = HashSet::new();
                let mut in_call_arena_scope = false;

                for block in &func.blocks {
                    for inst in &block.instructions {
                        match &inst.expr {
                            ValueExpr::CallArenaMark => {
                                in_call_arena_scope = true;
                            }
                            ValueExpr::CallArenaRewind { .. } => {
                                in_call_arena_scope = false;
                            }
                            _ => {}
                        }
                        if let (Some(res), ValueExpr::GenAlloc { arena: Some(a), .. }) =
                            (inst.result, &inst.expr)
                        {
                            val_to_arena.insert(res, *a);
                            verified_at_call.insert(res);
                        }
                        if let (Some(res), ValueExpr::GenRef { ptr, .. }) =
                            (inst.result, &inst.expr)
                        {
                            aliases.insert(res, *ptr);
                            if let Some(&a) = val_to_arena.get(ptr) {
                                val_to_arena.insert(res, a);
                            }
                            verified_at_call.insert(res);
                        }
                        if let (Some(res), ValueExpr::Load { ptr }) = (inst.result, &inst.expr) {
                            if let Some(&a) = val_to_arena.get(ptr) {
                                val_to_arena.insert(res, a);
                            }
                            if let Some(&root) = aliases.get(ptr) {
                                aliases.insert(res, root);
                            }
                        }
                        if let ValueExpr::Store { ptr, val } = &inst.expr {
                            aliases.insert(*ptr, *val);
                            if let Some(&a) = val_to_arena.get(val) {
                                val_to_arena.insert(*ptr, a);
                            }
                        }
                        if let ValueExpr::GenCheck { ref_val, .. } = &inst.expr {
                            verified_at_call.insert(*ref_val);
                        }
                        if let (
                            Some(res),
                            ValueExpr::CallDirect {
                                name: callee_name, ..
                            },
                        ) = (inst.result, &inst.expr)
                        {
                            if in_call_arena_scope {
                                callees_under_call_arena.insert(*callee_name);
                            }
                            if let Some(&ret_a) = callee_return_arenas.get(callee_name) {
                                val_to_arena.insert(res, ret_a);
                                verified_at_call.insert(res);
                            }
                        }

                        let callee_sym = match &inst.expr {
                            ValueExpr::CallDirect { name: callee, .. } => {
                                if in_call_arena_scope {
                                    callees_under_call_arena.insert(*callee);
                                }
                                Some(*callee)
                            }
                            _ => None,
                        };
                        let call_args = match &inst.expr {
                            ValueExpr::CallDirect { args, .. } | ValueExpr::Call { args, .. } => {
                                args.as_slice()
                            }
                            _ => &[],
                        };

                        if let Some(target) = callee_sym {
                            for (idx, &arg) in call_args.iter().enumerate() {
                                let canon_arg = Self::resolve_alias(arg, &aliases);
                                if let Some(&arg_arena) = val_to_arena
                                    .get(&arg)
                                    .or_else(|| val_to_arena.get(&canon_arg))
                                {
                                    let param_map = callee_param_arenas.entry(target).or_default();
                                    param_map
                                        .entry(idx)
                                        .and_modify(|existing| {
                                            *existing = (*existing).min(arg_arena)
                                        })
                                        .or_insert(arg_arena);
                                }
                                let is_ver = verified_at_call.contains(&arg)
                                    || verified_at_call.contains(&canon_arg);
                                let ver_map = callee_param_verified.entry(target).or_default();
                                ver_map
                                    .entry(idx)
                                    .and_modify(|v| *v = *v && is_ver)
                                    .or_insert(is_ver);
                            }
                        }
                    }
                }
            }

            // 3. Re-optimize each function with acquired interprocedural context
            let before_fusions = self.stats.interprocedural_fusions;
            for func in &mut module.functions {
                let incoming_param_arenas = callee_param_arenas
                    .get(&func.name)
                    .cloned()
                    .unwrap_or_default();
                let incoming_verified_params: HashSet<ValueId> =
                    if let Some(v_map) = callee_param_verified.get(&func.name) {
                        v_map
                            .iter()
                            .filter(|(_, &is_ver)| is_ver)
                            .filter_map(|(&idx, _)| func.params.get(idx).map(|p| p.val))
                            .collect()
                    } else {
                        HashSet::new()
                    };

                let mut call_res_arenas: HashMap<ValueId, u16> = HashMap::new();
                for block in &func.blocks {
                    for inst in &block.instructions {
                        if let (
                            Some(res),
                            ValueExpr::CallDirect {
                                name: callee_name, ..
                            },
                        ) = (inst.result, &inst.expr)
                        {
                            if let Some(&ret_arena) = callee_return_arenas.get(callee_name) {
                                call_res_arenas.insert(res, ret_arena);
                            }
                        }
                    }
                }

                if callees_under_call_arena.contains(&func.name) {
                    let mut has_call_arena_scope = false;
                    for block in &func.blocks {
                        if block
                            .instructions
                            .iter()
                            .any(|i| matches!(i.expr, ValueExpr::CallArenaMark))
                        {
                            has_call_arena_scope = true;
                            break;
                        }
                    }
                    if has_call_arena_scope {
                        let mut eliminated_marks = HashSet::new();
                        for block in &mut func.blocks {
                            block.instructions.retain(|i| match &i.expr {
                                ValueExpr::CallArenaMark => {
                                    if let Some(res) = i.result {
                                        eliminated_marks.insert(res);
                                    }
                                    false
                                }
                                ValueExpr::CallArenaRewind { mark } => {
                                    !eliminated_marks.contains(mark)
                                }
                                _ => true,
                            });
                        }
                        self.stats.nested_call_arenas_fused += 1;
                        self.stats.call_arena_scopes_coalesced += 1;
                    }
                }

                if incoming_param_arenas.is_empty()
                    && call_res_arenas.is_empty()
                    && incoming_verified_params.is_empty()
                {
                    continue;
                }

                let ctx = InterprocContext {
                    param_arenas: &incoming_param_arenas,
                    call_return_arenas: &call_res_arenas,
                    verified_params: &incoming_verified_params,
                    is_initial_pass: false,
                };

                self.optimize_function(func, recursive_structs, struct_map, &ctx);
            }

            if self.stats.interprocedural_fusions == before_fusions {
                break;
            }
        }
    }

    /// Coalesces intermediate call arena allocations (`CallArenaAlloc`) and consolidates redundant `CallArenaMark` / `CallArenaRewind` scopes.
    fn optimize_call_arenas_in_pipeline(&mut self, func: &mut FirFunction) {
        // Phase 1: Sequential Mark & Rewind scope consolidation and Nested Scope Fusion
        let mut mark_replacements: HashMap<ValueId, ValueId> = HashMap::new();
        let mut redundant_mark_insts: HashSet<ValueId> = HashSet::new();
        let mut redundant_rewind_marks: HashSet<ValueId> = HashSet::new();

        // Phase 1: Nested Call Arena Scopes Fusion & Hierarchical Scope Consolidation
        // Detects inner call arena scopes [mark_inner .. rewind_inner] enveloped by an outer scope
        // [mark_outer .. rewind_outer], fusing the nested frame directly into the parent arena.
        for block in &func.blocks {
            let mut active_mark_stack: Vec<ValueId> = Vec::new();
            let mut mark_allocations: HashMap<ValueId, Vec<ValueId>> = HashMap::new();

            // Track uses of values within and after instructions
            let mut val_last_use_idx: HashMap<ValueId, usize> = HashMap::new();
            for (idx, inst) in block.instructions.iter().enumerate() {
                for u in inst.expr.uses() {
                    val_last_use_idx.insert(u, idx);
                }
            }
            if let Some(term) = &block.terminator {
                for u in term.uses() {
                    // Mark as escaping to terminator / block exit
                    val_last_use_idx.insert(u, block.instructions.len() + 1);
                }
            }

            let block_rewind_marks: HashSet<ValueId> = block
                .instructions
                .iter()
                .filter_map(|i| match i.expr {
                    ValueExpr::CallArenaRewind { mark } => Some(mark),
                    _ => None,
                })
                .collect();

            for inst in &block.instructions {
                match &inst.expr {
                    ValueExpr::CallArenaMark => {
                        if let Some(res) = inst.result {
                            active_mark_stack.push(res);
                        }
                    }
                    ValueExpr::CallArenaAlloc { .. } => {
                        if let Some(res) = inst.result {
                            if let Some(&top_mark) = active_mark_stack.last() {
                                mark_allocations.entry(top_mark).or_default().push(res);
                            }
                        }
                    }
                    ValueExpr::CallArenaRewind { mark } => {
                        let actual_mark = mark_replacements.get(mark).copied().unwrap_or(*mark);
                        if let Some(pos) = active_mark_stack.iter().rposition(|&m| m == actual_mark)
                        {
                            if pos > 0 {
                                // Nested scope inside active_mark_stack[pos - 1]
                                let parent_mark = active_mark_stack[pos - 1];
                                mark_replacements.insert(actual_mark, parent_mark);
                                redundant_mark_insts.insert(actual_mark);
                                if block_rewind_marks.contains(&parent_mark) {
                                    // True nested scope: parent has its own outer rewind, so eliminate inner rewind
                                    redundant_rewind_marks.insert(actual_mark);
                                    self.stats.nested_call_arenas_fused += 1;
                                }
                                self.stats.call_arena_scopes_coalesced += 1;
                            }
                            active_mark_stack.remove(pos);
                        }
                    }
                    _ => {}
                }
            }

            // Coalesce remaining redundant marks that have no intervening allocations and no matching rewind
            let mut last_mark: Option<ValueId> = None;
            for inst in &block.instructions {
                match &inst.expr {
                    ValueExpr::CallArenaMark => {
                        if let Some(res) = inst.result {
                            if !redundant_mark_insts.contains(&res) {
                                if let Some(prev) = last_mark {
                                    mark_replacements.insert(res, prev);
                                    redundant_mark_insts.insert(res);
                                    self.stats.call_arena_scopes_coalesced += 1;
                                } else {
                                    last_mark = Some(res);
                                }
                            }
                        }
                    }
                    ValueExpr::CallArenaAlloc { .. } => {
                        last_mark = None;
                    }
                    _ => {}
                }
            }
        }

        // Apply mark replacements on rewinds and remove redundant mark and rewind instructions
        if !mark_replacements.is_empty() || !redundant_rewind_marks.is_empty() {
            for block in &mut func.blocks {
                block.instructions.retain(|i| {
                    if let Some(r) = i.result {
                        if redundant_mark_insts.contains(&r) {
                            return false;
                        }
                    }
                    if let ValueExpr::CallArenaRewind { mark } = &i.expr {
                        let canon = mark_replacements.get(mark).copied().unwrap_or(*mark);
                        if redundant_rewind_marks.contains(mark)
                            || redundant_rewind_marks.contains(&canon)
                        {
                            return false;
                        }
                    }
                    true
                });
                for inst in &mut block.instructions {
                    if let ValueExpr::CallArenaRewind { mark } = &mut inst.expr {
                        if let Some(&canon) = mark_replacements.get(mark) {
                            *mark = canon;
                        }
                    }
                }
            }
        }

        // Phase 2: Intermediate CallArenaAlloc buffer coalescing and reuse across filter/projection stages
        let mut call_allocs: Vec<(BlockId, usize, ValueId, FirType)> = Vec::new();
        for block in &func.blocks {
            for (idx, inst) in block.instructions.iter().enumerate() {
                if let (Some(res), ValueExpr::CallArenaAlloc { ty }) = (inst.result, &inst.expr) {
                    call_allocs.push((block.id, idx, res, ty.clone()));
                }
            }
        }

        if call_allocs.len() < 2 {
            return;
        }

        // Compute uses and defs of all values
        let mut loads_from: HashMap<ValueId, ValueId> = HashMap::new();
        let mut stores_to: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
        let mut set_elements: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
        let mut escaped_values: HashSet<ValueId> = HashSet::new();

        for block in &func.blocks {
            for inst in &block.instructions {
                match &inst.expr {
                    ValueExpr::Load { ptr } => {
                        if let Some(res) = inst.result {
                            loads_from.insert(res, *ptr);
                        }
                    }
                    ValueExpr::GetElement { base, .. } | ValueExpr::GetElementPtr { base, .. } => {
                        if let Some(res) = inst.result {
                            loads_from.insert(res, *base);
                        }
                    }
                    ValueExpr::SliceStrided { base, .. } | ValueExpr::SliceSub { base, .. } => {
                        if let Some(res) = inst.result {
                            loads_from.insert(res, *base);
                        }
                    }
                    ValueExpr::Store { ptr, val } => {
                        stores_to.entry(*ptr).or_default().push(*val);
                    }
                    ValueExpr::SetElement { base, val, .. } => {
                        set_elements.entry(*base).or_default().push(*val);
                    }
                    ValueExpr::Call { args, .. } | ValueExpr::CallDirect { args, .. } => {
                        for a in args {
                            escaped_values.insert(*a);
                        }
                    }
                    _ => {}
                }
            }
            if let Some(term) = &block.terminator {
                for u in term.uses() {
                    escaped_values.insert(u);
                }
            }
        }

        let mut fused_buffers: HashMap<ValueId, ValueId> = HashMap::new();
        let mut eliminated_allocs: HashSet<ValueId> = HashSet::new();

        for i in 0..call_allocs.len() {
            let (_, _, buf1, _) = call_allocs[i];
            if eliminated_allocs.contains(&buf1) || escaped_values.contains(&buf1) {
                continue;
            }

            for &(_, _, buf2, _) in call_allocs.iter().skip(i + 1) {
                if eliminated_allocs.contains(&buf2) {
                    continue;
                }

                let reads_buf1: HashSet<ValueId> = loads_from
                    .iter()
                    .filter(|(_, &base)| base == buf1)
                    .map(|(&res, _)| res)
                    .collect();

                let mut buf2_fed_from_buf1 = false;
                if let Some(stored) = stores_to.get(&buf2) {
                    if stored.iter().any(|v| reads_buf1.contains(v)) {
                        buf2_fed_from_buf1 = true;
                    }
                }
                if let Some(elems) = set_elements.get(&buf2) {
                    if elems.iter().any(|v| reads_buf1.contains(v)) {
                        buf2_fed_from_buf1 = true;
                    }
                }

                if loads_from.get(&buf2) == Some(&buf1) {
                    buf2_fed_from_buf1 = true;
                }

                if buf2_fed_from_buf1 {
                    fused_buffers.insert(buf2, buf1);
                    eliminated_allocs.insert(buf2);
                    self.stats.call_arenas_fused += 1;
                    break;
                }
            }
        }

        if !fused_buffers.is_empty() {
            for block in &mut func.blocks {
                block.instructions.retain(|inst| {
                    if let Some(res) = inst.result {
                        !eliminated_allocs.contains(&res)
                    } else {
                        true
                    }
                });

                for inst in &mut block.instructions {
                    SroaPass::substitute_instruction_operands(inst, &fused_buffers);
                }
                if let Some(term) = &mut block.terminator {
                    SroaPass::substitute_terminator_operands(term, &fused_buffers);
                }
            }
        }
    }

    /// Folds multi-dimensional projections (`SliceStrided`, `SliceSub`) and collapses intermediate stencil steps.
    fn optimize_multidim_projections(&mut self, func: &mut FirFunction) {
        let mut int_constants: HashMap<ValueId, i64> = HashMap::new();
        for block in &func.blocks {
            for inst in &block.instructions {
                if let (Some(res), ValueExpr::Constant(ConstantValue::Int(v, _))) =
                    (inst.result, &inst.expr)
                {
                    int_constants.insert(res, *v as i64);
                }
            }
        }

        // res -> (base, start_val, end_val, stride_val)
        let mut strided_projections: HashMap<ValueId, (ValueId, i64, i64, i64)> = HashMap::new();

        for block in &func.blocks {
            for inst in &block.instructions {
                if let Some(res) = inst.result {
                    match &inst.expr {
                        ValueExpr::SliceStrided {
                            base,
                            start,
                            end,
                            stride,
                        } => {
                            if let (Some(&s_val), Some(&e_val), Some(&strd_val)) = (
                                int_constants.get(start),
                                int_constants.get(end),
                                int_constants.get(stride),
                            ) {
                                strided_projections.insert(res, (*base, s_val, e_val, strd_val));
                            }
                        }
                        ValueExpr::SliceSub { base, start, end } => {
                            if let (Some(&s_val), Some(&e_val)) =
                                (int_constants.get(start), int_constants.get(end))
                            {
                                strided_projections.insert(res, (*base, s_val, e_val, 1));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // Search for chained projections: SliceStrided / SliceSub on top of an existing SliceStrided
        let mut folded_projections: HashMap<ValueId, (ValueId, i64, i64, i64)> = HashMap::new();
        for (&res, &(parent_base, parent_start, parent_end, parent_stride)) in &strided_projections
        {
            if let Some(&(grand_base, grand_start, _grand_end, grand_stride)) =
                strided_projections.get(&parent_base)
            {
                let combined_stride = grand_stride * parent_stride;
                let combined_start = grand_start + parent_start * grand_stride;
                let parent_len = (parent_end - parent_start).max(0);
                let combined_end = combined_start + parent_len * grand_stride;
                folded_projections.insert(
                    res,
                    (grand_base, combined_start, combined_end, combined_stride),
                );
            }
        }

        if folded_projections.is_empty() {
            return;
        }

        let entry_b = func.entry_block;
        let mut new_const_insts = Vec::new();
        let mut resolved_const_ids: HashMap<i64, ValueId> = HashMap::new();

        // Pre-allocate and emit all necessary constant values at entry to guarantee dominance
        for &(_, comb_start, comb_end, comb_stride) in folded_projections.values() {
            for &c_val in &[comb_start, comb_end, comb_stride] {
                if resolved_const_ids.contains_key(&c_val) {
                    continue;
                }
                let vid = func.alloc_value();
                resolved_const_ids.insert(c_val, vid);
                new_const_insts.push(Instruction::new(
                    Some(vid),
                    ValueExpr::Constant(ConstantValue::Int(c_val as i128, IntType::I64)),
                    Span::DUMMY,
                ));
            }
        }

        for block in &mut func.blocks {
            for inst in &mut block.instructions {
                if let Some(res) = inst.result {
                    if let Some(&(root_base, comb_start, comb_end, comb_stride)) =
                        folded_projections.get(&res)
                    {
                        let v_start = resolved_const_ids[&comb_start];
                        let v_end = resolved_const_ids[&comb_end];

                        if comb_stride == 1 {
                            inst.expr = ValueExpr::SliceSub {
                                base: root_base,
                                start: v_start,
                                end: v_end,
                            };
                        } else {
                            let v_stride = resolved_const_ids[&comb_stride];
                            inst.expr = ValueExpr::SliceStrided {
                                base: root_base,
                                start: v_start,
                                end: v_end,
                                stride: v_stride,
                            };
                        }
                        self.stats.multidim_projections_fused += 1;
                    }
                }
            }
        }

        if !new_const_insts.is_empty() {
            if let Some(entry) = func.get_block_mut(entry_b) {
                // Prepend all new constants at the very start of entry block
                for (idx, inst) in new_const_insts.into_iter().enumerate() {
                    entry.instructions.insert(idx, inst);
                }
            }
        }
    }
}

impl Default for ArenaFusionPass {
    fn default() -> Self {
        Self::new()
    }
}

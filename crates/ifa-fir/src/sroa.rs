use crate::cfg::ControlFlowGraph;
use crate::dominance::DominanceTree;
use crate::ir::*;
use crate::types::{FirType, IntType};
use ifa_span::{Span, Symbol, INTERNER};
use std::collections::{HashMap, HashSet};

/// Statistics collected by the SROA and non-escaping allocation elimination pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SroaStats {
    /// Number of aggregate structures decomposed into scalar fields.
    pub decomposed_aggregates: usize,
    /// Number of non-escaping stack allocations completely eliminated.
    pub eliminated_allocas: usize,
    pub eliminated_stores: usize,
    pub promoted_loads: usize,
    pub eliminated_dead_insts: usize,
    /// Number of tagged union discriminant queries folded to constants.
    pub folded_discriminants: usize,
    /// Number of tagged union payloads forwarded directly.
    pub forwarded_payloads: usize,
}

/// Optimizes SSA FIR by decomposing non-escaping aggregate structures into scalar fields (SROA)
/// and promoting non-escaping stack allocations into direct SSA values (Mem2Reg), eliminating
/// redundant stores, loads, and stack frame allocations.
pub struct SroaPass {
    stats: SroaStats,
}

impl SroaPass {
    pub fn new() -> Self {
        Self {
            stats: SroaStats::default(),
        }
    }

    pub fn stats(&self) -> SroaStats {
        self.stats
    }

    /// Run SROA and allocation elimination on an entire FIR module leveraging whole-module inter-procedural memory analysis.
    pub fn run_on_module(&mut self, module: &mut FirModule) {
        let call_graph = crate::ipo::IpoCallGraph::build(module);
        let mem_map = crate::ipo::InterproceduralMemoryMap::compute(module, &call_graph);
        for func in &mut module.functions {
            self.run_on_function_with_mem_map(func, Some(&mem_map));
        }
    }

    /// Run SROA and allocation elimination on a single FIR function.
    pub fn run_on_function(&mut self, func: &mut FirFunction) {
        self.run_on_function_with_mem_map(func, None);
    }

    /// Run SROA and allocation elimination on a single FIR function with optional inter-procedural memory access summary.
    pub fn run_on_function_with_mem_map(
        &mut self,
        func: &mut FirFunction,
        mem_map: Option<&crate::ipo::InterproceduralMemoryMap>,
    ) {
        if func.blocks.is_empty() {
            return;
        }

        // Step 1: Collect all local Alloca instructions
        let mut alloca_info: HashMap<ValueId, (FirType, Option<Symbol>, Span, BlockId)> =
            HashMap::new();

        for block in &func.blocks {
            for inst in &block.instructions {
                if let (Some(res), ValueExpr::Alloca { ty, name }) = (inst.result, &inst.expr) {
                    alloca_info.insert(res, (ty.clone(), *name, inst.span, block.id));
                }
            }
        }

        if !alloca_info.is_empty() {
            // Step 2: Escape analysis across all instructions and terminators
            let escaping = self.analyze_escapes_with_mem(func, &alloca_info, mem_map);
            let non_escaping: HashSet<ValueId> = alloca_info
                .keys()
                .copied()
                .filter(|ptr| !escaping.contains(ptr))
                .collect();

            if !non_escaping.is_empty() {
                // Step 3: Decompose non-escaping aggregate structures (SROA)
                let decomposed_fields =
                    self.decompose_aggregates(func, &non_escaping, &alloca_info);

                // Update alloca info with newly created field allocas
                for (field_id, field_ty, field_name, field_span, block_id) in &decomposed_fields {
                    alloca_info.insert(
                        *field_id,
                        (field_ty.clone(), *field_name, *field_span, *block_id),
                    );
                }

                // Re-analyze non-escaping allocas now that aggregates are decomposed
                let escaping_after_sroa =
                    self.analyze_escapes_with_mem(func, &alloca_info, mem_map);
                let candidates: HashSet<ValueId> = alloca_info
                    .keys()
                    .copied()
                    .filter(|ptr| !escaping_after_sroa.contains(ptr))
                    .collect();

                // Step 4: Promote non-escaping allocations to SSA values (Store-to-Load forwarding)
                self.promote_allocations_to_registers_with_mem(func, &candidates, mem_map);
            }
        }

        // Step 5: Optimize tagged unions (fold discriminants, forward payloads, fold branch conds)
        self.optimize_tagged_unions(func);
        self.optimize_aggregate_projections(func);

        // Step 6: Clean up dead pure instructions
        self.eliminate_dead_instructions(func);
    }

    /// Identifies all ValueIds that escape their local stack frame.
    pub fn analyze_escapes(
        func: &FirFunction,
        alloca_info: &HashMap<ValueId, (FirType, Option<Symbol>, Span, BlockId)>,
    ) -> HashSet<ValueId> {
        let mut pass = Self::new();
        pass.analyze_escapes_with_mem(func, alloca_info, None)
    }

    /// Identifies all ValueIds that escape their local stack frame using optional inter-procedural memory analysis.
    fn analyze_escapes_with_mem(
        &mut self,
        func: &FirFunction,
        alloca_info: &HashMap<ValueId, (FirType, Option<Symbol>, Span, BlockId)>,
        _mem_map: Option<&crate::ipo::InterproceduralMemoryMap>,
    ) -> HashSet<ValueId> {
        let mut escaping = HashSet::new();

        for block in &func.blocks {
            for inst in &block.instructions {
                match &inst.expr {
                    // Safe uses: only pointer operand
                    ValueExpr::Store { ptr, val } => {
                        if alloca_info.contains_key(val) {
                            escaping.insert(*val);
                        }
                        if !alloca_info.contains_key(ptr) && alloca_info.contains_key(val) {
                            escaping.insert(*val);
                        }
                    }
                    ValueExpr::Load { ptr: _ } => {
                        // Safe: load from ptr does not escape ptr
                    }
                    ValueExpr::GetField { base, .. } => {
                        let _ = base;
                    }
                    ValueExpr::GetFieldPtr { base, .. } => {
                        if alloca_info.contains_key(base) {
                            escaping.insert(*base);
                        }
                    }
                    ValueExpr::GetElementPtr { base, index } => {
                        if alloca_info.contains_key(base) {
                            escaping.insert(*base);
                        }
                        if alloca_info.contains_key(index) {
                            escaping.insert(*index);
                        }
                    }
                    ValueExpr::SetField { base: _, val, .. } => {
                        if alloca_info.contains_key(val) {
                            escaping.insert(*val);
                        }
                    }
                    ValueExpr::GetElement { base: _, index } => {
                        if alloca_info.contains_key(index) {
                            escaping.insert(*index);
                        }
                    }
                    ValueExpr::SetElement {
                        base: _,
                        index,
                        val,
                    } => {
                        if alloca_info.contains_key(index) {
                            escaping.insert(*index);
                        }
                        if alloca_info.contains_key(val) {
                            escaping.insert(*val);
                        }
                    }
                    ValueExpr::BoundsCheck { base: _, index, .. } => {
                        if alloca_info.contains_key(index) {
                            escaping.insert(*index);
                        }
                    }
                    ValueExpr::SliceBoundsCheck {
                        base: _,
                        start,
                        end,
                        ..
                    } => {
                        if alloca_info.contains_key(start) {
                            escaping.insert(*start);
                        }
                        if alloca_info.contains_key(end) {
                            escaping.insert(*end);
                        }
                    }
                    // Escaping operations: taking generational reference, passing to calls, returning, etc.
                    ValueExpr::GenRef { ptr } | ValueExpr::GenFree { ptr } => {
                        if alloca_info.contains_key(ptr) {
                            escaping.insert(*ptr);
                        }
                    }
                    ValueExpr::Call { callee, args } => {
                        if alloca_info.contains_key(callee) {
                            escaping.insert(*callee);
                        }
                        for arg in args {
                            if alloca_info.contains_key(arg) {
                                escaping.insert(*arg);
                            }
                        }
                    }
                    ValueExpr::CallDirect { args, .. }
                    | ValueExpr::BlockingCallDirect { args, .. } => {
                        for arg in args {
                            if alloca_info.contains_key(arg) {
                                escaping.insert(*arg);
                            }
                        }
                    }
                    ValueExpr::Spawn { args, .. } => {
                        for arg in args {
                            if alloca_info.contains_key(arg) {
                                escaping.insert(*arg);
                            }
                        }
                    }
                    ValueExpr::StructInit { fields, .. } | ValueExpr::TupleInit(fields) => {
                        for f in fields {
                            if alloca_info.contains_key(f) {
                                escaping.insert(*f);
                            }
                        }
                    }
                    ValueExpr::ArrayInit(elements) => {
                        for elem in elements {
                            if alloca_info.contains_key(elem) {
                                escaping.insert(*elem);
                            }
                        }
                    }
                    ValueExpr::ArrayPush { array: _, val } => {
                        if alloca_info.contains_key(val) {
                            escaping.insert(*val);
                        }
                    }
                    // Any other expression using an alloca value escapes it
                    _ => {
                        for u in inst.expr.uses() {
                            if alloca_info.contains_key(&u) {
                                escaping.insert(u);
                            }
                        }
                    }
                }
            }

            // Check terminators
            if let Some(term) = &block.terminator {
                match term {
                    Terminator::Return(Some(ret_val)) => {
                        if alloca_info.contains_key(ret_val) {
                            escaping.insert(*ret_val);
                        }
                    }
                    Terminator::Fail(fail_val) => {
                        if alloca_info.contains_key(fail_val) {
                            escaping.insert(*fail_val);
                        }
                    }
                    Terminator::Branch { args, .. } => {
                        for arg in args {
                            if alloca_info.contains_key(arg) {
                                escaping.insert(*arg);
                            }
                        }
                    }
                    Terminator::BranchCond {
                        cond,
                        then_args,
                        else_args,
                        ..
                    } => {
                        if alloca_info.contains_key(cond) {
                            escaping.insert(*cond);
                        }
                        for arg in then_args.iter().chain(else_args) {
                            if alloca_info.contains_key(arg) {
                                escaping.insert(*arg);
                            }
                        }
                    }
                    Terminator::Switch {
                        val,
                        cases,
                        default_args,
                        ..
                    } => {
                        if alloca_info.contains_key(val) {
                            escaping.insert(*val);
                        }
                        for (_, _, args) in cases {
                            for arg in args {
                                if alloca_info.contains_key(arg) {
                                    escaping.insert(*arg);
                                }
                            }
                        }
                        for arg in default_args {
                            if alloca_info.contains_key(arg) {
                                escaping.insert(*arg);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        escaping
    }

    /// Decomposes non-escaping aggregate struct/tuple allocas into individual scalar allocas.
    fn decompose_aggregates(
        &mut self,
        func: &mut FirFunction,
        non_escaping: &HashSet<ValueId>,
        alloca_info: &HashMap<ValueId, (FirType, Option<Symbol>, Span, BlockId)>,
    ) -> Vec<(ValueId, FirType, Option<Symbol>, Span, BlockId)> {
        let mut new_field_allocas = Vec::new();
        let mut struct_to_fields: HashMap<ValueId, Vec<ValueId>> = HashMap::new();

        // 1. Collect aggregate initializations and constant integer values
        let mut aggregate_inits: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
        let mut const_ints: HashMap<ValueId, usize> = HashMap::new();
        for block in &func.blocks {
            for inst in &block.instructions {
                if let Some(res) = inst.result {
                    match &inst.expr {
                        ValueExpr::StructInit { fields, .. } | ValueExpr::TupleInit(fields) => {
                            aggregate_inits.insert(res, fields.clone());
                        }
                        ValueExpr::ArrayInit(elements) => {
                            aggregate_inits.insert(res, elements.clone());
                        }
                        ValueExpr::Constant(ConstantValue::Int(v, _)) if *v >= 0 => {
                            const_ints.insert(res, *v as usize);
                        }
                        _ => {}
                    }
                }
            }
        }

        // 2. Identify which non-escaping allocas are eligible aggregates for decomposition
        for &ptr in non_escaping {
            if let Some((ty, name, span, block_id)) = alloca_info.get(&ptr) {
                let (is_array, field_types): (bool, Vec<FirType>) = match ty {
                    FirType::Struct(_, fields) => {
                        (false, fields.iter().map(|(_, t)| t.clone()).collect())
                    }
                    FirType::Array(elem_ty, count) if *count <= 16 => {
                        (true, vec![(**elem_ty).clone(); *count as usize])
                    }
                    _ => (false, Vec::new()),
                };

                if field_types.is_empty() {
                    continue;
                }

                // Check eligibility:
                // A) All stores to `ptr` must store a known aggregate init of matching length
                // B) All indexed operations on `ptr` or loaded values must use in-bounds constant indices
                let mut is_eligible = true;
                let mut loaded_values = HashSet::new();

                for block in &func.blocks {
                    for inst in &block.instructions {
                        match &inst.expr {
                            ValueExpr::Store { ptr: p, val } if *p == ptr => {
                                if let Some(inits) = aggregate_inits.get(val) {
                                    if inits.len() != field_types.len() {
                                        is_eligible = false;
                                        break;
                                    }
                                } else {
                                    is_eligible = false;
                                    break;
                                }
                            }
                            ValueExpr::SetElement { base: p, index, .. }
                                if is_array && *p == ptr =>
                            {
                                match const_ints.get(index) {
                                    Some(&k) if k < field_types.len() => {}
                                    _ => {
                                        is_eligible = false;
                                        break;
                                    }
                                }
                            }
                            ValueExpr::GetElement { base: p, index }
                            | ValueExpr::BoundsCheck { base: p, index, .. }
                                if is_array && *p == ptr =>
                            {
                                match const_ints.get(index) {
                                    Some(&k) if k < field_types.len() => {}
                                    _ => {
                                        is_eligible = false;
                                        break;
                                    }
                                }
                            }
                            ValueExpr::Load { ptr: p } if *p == ptr => {
                                if let Some(res) = inst.result {
                                    loaded_values.insert(res);
                                }
                            }
                            _ => {}
                        }
                    }
                    if !is_eligible {
                        break;
                    }
                }

                if !is_eligible {
                    continue;
                }

                // Verify that loaded aggregate values are ONLY used as base in GetField (struct) or GetElement / BoundsCheck (array)
                for block in &func.blocks {
                    for inst in &block.instructions {
                        for u in inst.expr.uses() {
                            if loaded_values.contains(&u) {
                                if is_array {
                                    match &inst.expr {
                                        ValueExpr::GetElement { base, index }
                                        | ValueExpr::BoundsCheck { base, index, .. }
                                            if *base == u =>
                                        {
                                            match const_ints.get(index) {
                                                Some(&k) if k < field_types.len() => {}
                                                _ => {
                                                    is_eligible = false;
                                                    break;
                                                }
                                            }
                                        }
                                        _ => {
                                            is_eligible = false;
                                            break;
                                        }
                                    }
                                } else {
                                    match &inst.expr {
                                        ValueExpr::GetField { base, .. } if *base == u => {}
                                        _ => {
                                            is_eligible = false;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        if !is_eligible {
                            break;
                        }
                    }
                    if let Some(term) = &block.terminator {
                        for u in term.uses() {
                            if loaded_values.contains(&u) {
                                is_eligible = false;
                                break;
                            }
                        }
                    }
                    if !is_eligible {
                        break;
                    }
                }

                if !is_eligible {
                    continue;
                }

                // Eligible for full scalar replacement
                let mut field_ids = Vec::with_capacity(field_types.len());
                for (i, f_ty) in field_types.into_iter().enumerate() {
                    let field_val = func.alloc_value();
                    let field_name =
                        name.map(|sym| INTERNER.intern(&format!("{}.{}", sym.as_str(), i)));
                    new_field_allocas.push((field_val, f_ty, field_name, *span, *block_id));
                    field_ids.push(field_val);
                }
                struct_to_fields.insert(ptr, field_ids);
                self.stats.decomposed_aggregates += 1;
            }
        }

        if struct_to_fields.is_empty() {
            return new_field_allocas;
        }

        // Track loads of decomposed structs: loaded_struct_res -> aggregate_ptr
        let mut struct_loads: HashMap<ValueId, ValueId> = HashMap::new();
        for block in &func.blocks {
            for inst in &block.instructions {
                if let (Some(res), ValueExpr::Load { ptr }) = (inst.result, &inst.expr) {
                    if struct_to_fields.contains_key(ptr) {
                        struct_loads.insert(res, *ptr);
                    }
                }
            }
        }

        // 3. Transform instructions in all blocks
        for block in &mut func.blocks {
            let mut rewritten_instructions = Vec::with_capacity(block.instructions.len());

            for inst in block.instructions.drain(..) {
                // If this is the original aggregate alloca, insert decomposed scalar allocas instead
                if let (Some(res), ValueExpr::Alloca { .. }) = (inst.result, &inst.expr) {
                    if let Some(fields) = struct_to_fields.get(&res) {
                        for &f_id in fields {
                            let (_, f_ty, f_name, span, _) = new_field_allocas
                                .iter()
                                .find(|(id, ..)| *id == f_id)
                                .unwrap();
                            rewritten_instructions.push(Instruction::new(
                                Some(f_id),
                                ValueExpr::Alloca {
                                    ty: f_ty.clone(),
                                    name: *f_name,
                                },
                                *span,
                            ));
                        }
                        continue;
                    }
                }

                // If storing into a decomposed aggregate struct or array
                if let ValueExpr::Store { ptr, val } = &inst.expr {
                    if let Some(fields) = struct_to_fields.get(ptr) {
                        if let Some(init_fields) = aggregate_inits.get(val) {
                            for (f_ptr, f_val) in fields.iter().zip(init_fields) {
                                rewritten_instructions.push(Instruction::new(
                                    None,
                                    ValueExpr::Store {
                                        ptr: *f_ptr,
                                        val: *f_val,
                                    },
                                    inst.span,
                                ));
                            }
                            continue;
                        }
                    }
                }

                // If setting a field of a decomposed aggregate struct
                if let ValueExpr::SetField {
                    base,
                    field_idx,
                    val,
                } = &inst.expr
                {
                    if let Some(fields) = struct_to_fields.get(base) {
                        if let Some(&f_ptr) = fields.get(*field_idx) {
                            rewritten_instructions.push(Instruction::new(
                                None,
                                ValueExpr::Store {
                                    ptr: f_ptr,
                                    val: *val,
                                },
                                inst.span,
                            ));
                            continue;
                        }
                    }
                }

                // If setting an element of a decomposed aggregate array
                if let ValueExpr::SetElement { base, index, val } = &inst.expr {
                    if let Some(fields) = struct_to_fields.get(base) {
                        if let Some(&k) = const_ints.get(index) {
                            if let Some(&f_ptr) = fields.get(k) {
                                rewritten_instructions.push(Instruction::new(
                                    None,
                                    ValueExpr::Store {
                                        ptr: f_ptr,
                                        val: *val,
                                    },
                                    inst.span,
                                ));
                                continue;
                            }
                        }
                    }
                }

                // If getting a field from a loaded struct or directly from an alloca base
                if let ValueExpr::GetField {
                    base, field_idx, ..
                } = &inst.expr
                {
                    // Case A: GetField directly on the aggregate pointer
                    if let Some(fields) = struct_to_fields.get(base) {
                        if let Some(&f_ptr) = fields.get(*field_idx) {
                            rewritten_instructions.push(Instruction::new(
                                inst.result,
                                ValueExpr::Load { ptr: f_ptr },
                                inst.span,
                            ));
                            continue;
                        }
                    }
                    // Case B: GetField on a value loaded from the aggregate pointer
                    if let Some(struct_ptr) = struct_loads.get(base) {
                        if let Some(fields) = struct_to_fields.get(struct_ptr) {
                            if let Some(&f_ptr) = fields.get(*field_idx) {
                                rewritten_instructions.push(Instruction::new(
                                    inst.result,
                                    ValueExpr::Load { ptr: f_ptr },
                                    inst.span,
                                ));
                                continue;
                            }
                        }
                    }
                }

                // If getting an element from a loaded array or directly from an alloca base
                if let ValueExpr::GetElement { base, index } = &inst.expr {
                    // Case A: GetElement directly on the aggregate pointer
                    if let Some(fields) = struct_to_fields.get(base) {
                        if let Some(&k) = const_ints.get(index) {
                            if let Some(&f_ptr) = fields.get(k) {
                                rewritten_instructions.push(Instruction::new(
                                    inst.result,
                                    ValueExpr::Load { ptr: f_ptr },
                                    inst.span,
                                ));
                                continue;
                            }
                        }
                    }
                    // Case B: GetElement on a value loaded from the aggregate pointer
                    if let Some(struct_ptr) = struct_loads.get(base) {
                        if let Some(fields) = struct_to_fields.get(struct_ptr) {
                            if let Some(&k) = const_ints.get(index) {
                                if let Some(&f_ptr) = fields.get(k) {
                                    rewritten_instructions.push(Instruction::new(
                                        inst.result,
                                        ValueExpr::Load { ptr: f_ptr },
                                        inst.span,
                                    ));
                                    continue;
                                }
                            }
                        }
                    }
                }

                // If checking bounds on a decomposed aggregate array (already proven safe):
                if let ValueExpr::BoundsCheck { base, .. } = &inst.expr {
                    if struct_to_fields.contains_key(base)
                        || struct_loads
                            .get(base)
                            .is_some_and(|p| struct_to_fields.contains_key(p))
                    {
                        self.stats.eliminated_dead_insts += 1;
                        continue;
                    }
                }

                // If this is a whole-struct load of a decomposed struct that had only GetField uses:
                // It has been completely replaced by field loads, so drop this load
                if let (Some(res), ValueExpr::Load { ptr }) = (inst.result, &inst.expr) {
                    if struct_to_fields.contains_key(ptr) && struct_loads.contains_key(&res) {
                        continue;
                    }
                }

                rewritten_instructions.push(inst);
            }

            block.instructions = rewritten_instructions;
        }

        new_field_allocas
    }

    /// Promotes non-escaping stack allocations into SSA values via dominance and store-to-load forwarding.
    pub fn promote_allocations_to_registers(
        &mut self,
        func: &mut FirFunction,
        candidates: &HashSet<ValueId>,
    ) {
        self.promote_allocations_to_registers_with_mem(func, candidates, None);
    }

    /// Promotes non-escaping stack allocations into SSA values via dominance and store-to-load forwarding
    /// using optional whole-module inter-procedural memory effect summaries.
    fn promote_allocations_to_registers_with_mem(
        &mut self,
        func: &mut FirFunction,
        candidates: &HashSet<ValueId>,
        mem_map: Option<&crate::ipo::InterproceduralMemoryMap>,
    ) {
        if candidates.is_empty() {
            return;
        }

        let cfg = ControlFlowGraph::build(func);
        let dom_tree = DominanceTree::build(&cfg);

        // Track stores, loads, and mutations for each candidate alloca
        let mut stores: HashMap<ValueId, Vec<(BlockId, usize, ValueId)>> = HashMap::new();
        let mut loads: HashMap<ValueId, Vec<(BlockId, usize, ValueId)>> = HashMap::new();
        let mut has_other_mutations: HashSet<ValueId> = HashSet::new();

        for block in &func.blocks {
            for (idx, inst) in block.instructions.iter().enumerate() {
                match &inst.expr {
                    ValueExpr::Store { ptr, val } => {
                        if candidates.contains(ptr) {
                            stores.entry(*ptr).or_default().push((block.id, idx, *val));
                        }
                    }
                    ValueExpr::Load { ptr } => {
                        if candidates.contains(ptr) {
                            if let Some(res) = inst.result {
                                loads.entry(*ptr).or_default().push((block.id, idx, res));
                            }
                        }
                    }
                    ValueExpr::SetField { base, .. }
                    | ValueExpr::SetElement { base, .. }
                    | ValueExpr::ArrayPush { array: base, .. }
                    | ValueExpr::StructPushField { base, .. }
                        if candidates.contains(base) =>
                    {
                        has_other_mutations.insert(*base);
                    }
                    _ => {}
                }
            }
        }

        let mut substitutions: HashMap<ValueId, ValueId> = HashMap::new();
        let mut dead_loads: HashSet<ValueId> = HashSet::new();
        let mut dead_allocas: HashSet<ValueId> = HashSet::new();
        let mut dead_stores: HashSet<(BlockId, usize)> = HashSet::new();

        for &ptr in candidates {
            let empty_stores = Vec::new();
            let empty_loads = Vec::new();
            let ptr_stores = stores.get(&ptr).unwrap_or(&empty_stores);
            let ptr_loads = loads.get(&ptr).unwrap_or(&empty_loads);
            let is_mutated = has_other_mutations.contains(&ptr);

            // Subcase 1: Single store in the entire function and no other mutations (dominates all reads)
            if ptr_stores.len() == 1 && !is_mutated {
                let (store_block, store_idx, stored_val) = ptr_stores[0];
                let mut can_promote_all = true;

                for &(load_block, load_idx, _) in ptr_loads {
                    if load_block == store_block {
                        if load_idx <= store_idx {
                            can_promote_all = false;
                            break;
                        }
                    } else if !dom_tree.dominates(store_block, load_block) {
                        can_promote_all = false;
                        break;
                    }
                }

                if can_promote_all {
                    for &(_, _, load_res) in ptr_loads {
                        substitutions.insert(load_res, stored_val);
                        dead_loads.insert(load_res);
                        self.stats.promoted_loads += 1;
                    }
                    dead_stores.insert((store_block, store_idx));
                    dead_allocas.insert(ptr);
                    self.stats.eliminated_allocas += 1;
                    self.stats.eliminated_stores += 1;
                    continue;
                }
            }

            // Subcase 2: Intra-block store-to-load forwarding (only if not mutated by SetField/SetElement)
            if !is_mutated {
                for block in &func.blocks {
                    let mut current_val: Option<ValueId> = None;
                    for inst in &block.instructions {
                        match &inst.expr {
                            ValueExpr::Store { ptr: p, val } if *p == ptr => {
                                current_val = Some(*val);
                            }
                            ValueExpr::Load { ptr: p } if *p == ptr => {
                                if let (Some(cur), Some(res)) = (current_val, inst.result) {
                                    substitutions.insert(res, cur);
                                    dead_loads.insert(res);
                                    self.stats.promoted_loads += 1;
                                }
                            }
                            ValueExpr::CallDirect { name, args } => {
                                if let Some(map) = mem_map {
                                    if let Some(callee_sum) = map.summaries.get(name) {
                                        for (idx, arg) in args.iter().enumerate() {
                                            if arg == &ptr
                                                && callee_sum
                                                    .params
                                                    .get(idx)
                                                    .map(|p| p.written)
                                                    .unwrap_or(true)
                                            {
                                                current_val = None;
                                            }
                                        }
                                    } else if args.contains(&ptr) {
                                        current_val = None;
                                    }
                                } else if args.contains(&ptr) {
                                    current_val = None;
                                }
                            }
                            ValueExpr::BlockingCallDirect { args, .. } if args.contains(&ptr) => {
                                current_val = None;
                            }
                            _ => {}
                        }
                    }
                }

                // Check if all loads of this alloca were promoted
                let all_loads_eliminated = ptr_loads.iter().all(|(_, _, r)| dead_loads.contains(r));
                if all_loads_eliminated && !ptr_loads.is_empty() {
                    dead_allocas.insert(ptr);
                    self.stats.eliminated_allocas += 1;
                    for &(s_b, s_i, _) in ptr_stores {
                        dead_stores.insert((s_b, s_i));
                        self.stats.eliminated_stores += 1;
                    }
                }
            }
        }

        // Resolve transitive substitutions: if v2 -> v1 and v3 -> v2, then v3 -> v1
        Self::resolve_substitution_chains(&mut substitutions);

        // Apply substitutions across all instructions and terminators, and remove dead instructions
        for block in &mut func.blocks {
            let block_id = block.id;
            let mut surviving_instructions = Vec::with_capacity(block.instructions.len());

            for (idx, mut inst) in block.instructions.drain(..).enumerate() {
                // Remove eliminated alloca
                if let (Some(res), ValueExpr::Alloca { .. }) = (inst.result, &inst.expr) {
                    if dead_allocas.contains(&res) {
                        continue;
                    }
                }

                // Remove promoted load
                if let (Some(res), ValueExpr::Load { .. }) = (inst.result, &inst.expr) {
                    if dead_loads.contains(&res) {
                        continue;
                    }
                }

                // Remove dead store
                if let ValueExpr::Store { .. } = &inst.expr {
                    if dead_stores.contains(&(block_id, idx)) {
                        continue;
                    }
                }

                // Substitute operands
                Self::substitute_instruction_operands(&mut inst, &substitutions);
                surviving_instructions.push(inst);
            }

            block.instructions = surviving_instructions;

            // Substitute terminator operands
            if let Some(term) = &mut block.terminator {
                Self::substitute_terminator_operands(term, &substitutions);
            }
        }
    }

    /// Resolves substitution chains transitively until a fixpoint is reached.
    pub(crate) fn resolve_substitution_chains(substitutions: &mut HashMap<ValueId, ValueId>) {
        let keys: Vec<ValueId> = substitutions.keys().copied().collect();
        for k in keys {
            let mut target = substitutions[&k];
            let mut visited = HashSet::new();
            visited.insert(k);

            while let Some(&next) = substitutions.get(&target) {
                if !visited.insert(target) {
                    break;
                }
                target = next;
            }
            substitutions.insert(k, target);
        }
    }

    /// Substitutes all input operands in an instruction according to the substitution map.
    pub(crate) fn substitute_instruction_operands(
        inst: &mut Instruction,
        substitutions: &HashMap<ValueId, ValueId>,
    ) {
        let replace = |val: &mut ValueId| {
            if let Some(&new_val) = substitutions.get(val) {
                *val = new_val;
            }
        };

        match &mut inst.expr {
            ValueExpr::Constant(_) | ValueExpr::Alloca { .. } | ValueExpr::Yield => {}
            ValueExpr::YieldValue { val } => replace(val),
            ValueExpr::Load { ptr } => replace(ptr),
            ValueExpr::Store { ptr, val } => {
                replace(ptr);
                replace(val);
            }
            ValueExpr::Binary { lhs, rhs, .. } => {
                replace(lhs);
                replace(rhs);
            }
            ValueExpr::Unary { val, .. } => replace(val),
            ValueExpr::GetField { base, .. } | ValueExpr::GetFieldPtr { base, .. } => replace(base),
            ValueExpr::SetField { base, val, .. } => {
                replace(base);
                replace(val);
            }
            ValueExpr::GetElement { base, index } | ValueExpr::GetElementPtr { base, index } => {
                replace(base);
                replace(index);
            }
            ValueExpr::SetElement { base, index, val } => {
                replace(base);
                replace(index);
                replace(val);
            }
            ValueExpr::Call { callee, args } => {
                replace(callee);
                for a in args {
                    replace(a);
                }
            }
            ValueExpr::CallDirect { args, .. } | ValueExpr::BlockingCallDirect { args, .. } => {
                for a in args {
                    replace(a);
                }
            }
            ValueExpr::StructInit { fields, .. } | ValueExpr::TupleInit(fields) => {
                for f in fields {
                    replace(f);
                }
            }
            ValueExpr::ArrayInit(elements) => {
                for e in elements {
                    replace(e);
                }
            }
            ValueExpr::ArrayPush { array, val } => {
                replace(array);
                replace(val);
            }
            ValueExpr::ArrayLen { array } => replace(array),
            ValueExpr::StructPushField { base, val, .. } => {
                replace(base);
                replace(val);
            }
            ValueExpr::CoWMakeUnique { val }
            | ValueExpr::CoWCheckShared { val }
            | ValueExpr::CoWClone { val } => replace(val),
            ValueExpr::GenAlloc { .. } => {}
            ValueExpr::GenFree { ptr } => replace(ptr),
            ValueExpr::GenRef { ptr } => replace(ptr),
            ValueExpr::GenCheck { ref_val, .. } => replace(ref_val),
            ValueExpr::GenDeref { ref_val } => replace(ref_val),
            ValueExpr::CallArenaAlloc { .. } | ValueExpr::CallArenaMark => {}
            ValueExpr::CallArenaRewind { mark } => replace(mark),
            ValueExpr::Spawn { args, .. } => {
                for a in args {
                    replace(a);
                }
            }
            ValueExpr::ChanCreate { capacity, .. } => {
                if let Some(cap) = capacity {
                    replace(cap);
                }
            }
            ValueExpr::ChanSend { chan, val } => {
                replace(chan);
                replace(val);
            }
            ValueExpr::ChanRecv { chan }
            | ValueExpr::ChanTryRecv { chan }
            | ValueExpr::ChanClose { chan } => {
                replace(chan);
            }
            ValueExpr::ChanSelect { channels, .. } => {
                for c in channels {
                    replace(c);
                }
            }
            ValueExpr::EnumInit { payload, .. } => {
                if let Some(p) = payload {
                    replace(p);
                }
            }
            ValueExpr::EnumGetDiscriminant { base } => {
                replace(base);
            }
            ValueExpr::EnumGetPayload { base, .. } => {
                replace(base);
            }
            ValueExpr::SliceSub { base, start, end } => {
                replace(base);
                replace(start);
                replace(end);
            }
            ValueExpr::SliceStrided {
                base,
                start,
                end,
                stride,
            } => {
                replace(base);
                replace(start);
                replace(end);
                replace(stride);
            }
            ValueExpr::BoundsCheck { base, index, .. } => {
                replace(base);
                replace(index);
            }
            ValueExpr::SliceBoundsCheck {
                base, start, end, ..
            } => {
                replace(base);
                replace(start);
                replace(end);
            }
            ValueExpr::SliceStridedBoundsCheck {
                base,
                start,
                end,
                stride,
                ..
            } => {
                replace(base);
                replace(start);
                replace(end);
                replace(stride);
            }
            ValueExpr::FormatString(parts) => {
                for p in parts {
                    replace(p);
                }
            }
        }
    }

    /// Substitutes operands in terminators.
    pub(crate) fn substitute_terminator_operands(
        term: &mut Terminator,
        substitutions: &HashMap<ValueId, ValueId>,
    ) {
        let replace = |val: &mut ValueId| {
            if let Some(&new_val) = substitutions.get(val) {
                *val = new_val;
            }
        };

        match term {
            Terminator::Branch { args, .. } => {
                for a in args {
                    replace(a);
                }
            }
            Terminator::BranchCond {
                cond,
                then_args,
                else_args,
                ..
            } => {
                replace(cond);
                for a in then_args.iter_mut().chain(else_args) {
                    replace(a);
                }
            }
            Terminator::Switch {
                val,
                cases,
                default_args,
                ..
            } => {
                replace(val);
                for (_, _, args) in cases {
                    for a in args {
                        replace(a);
                    }
                }
                for a in default_args {
                    replace(a);
                }
            }
            Terminator::Return(Some(val)) => replace(val),
            Terminator::Return(None) => {}
            Terminator::Fail(val) => replace(val),
            Terminator::Unreachable => {}
        }
    }

    /// Optimizes tagged union operations when the variant discriminant or payload is statically known.
    ///
    /// Folds `EnumGetDiscriminant` to constant integers and forwards `EnumGetPayload` directly
    /// to the initialized payload SSA value.
    fn optimize_tagged_unions(&mut self, func: &mut FirFunction) {
        let mut enum_inits: HashMap<ValueId, (u32, Option<ValueId>)> = HashMap::new();
        let mut substitutions: HashMap<ValueId, ValueId> = HashMap::new();

        for block in &func.blocks {
            for inst in &block.instructions {
                if let Some(res) = inst.result {
                    if let ValueExpr::EnumInit {
                        discriminant,
                        payload,
                        ..
                    } = &inst.expr
                    {
                        enum_inits.insert(res, (*discriminant, *payload));
                    }
                }
            }
        }

        if enum_inits.is_empty() {
            return;
        }

        // Fold EnumGetDiscriminant and forward EnumGetPayload
        for block in &mut func.blocks {
            for inst in &mut block.instructions {
                if let Some(res) = inst.result {
                    match &inst.expr {
                        ValueExpr::EnumGetDiscriminant { base } => {
                            let actual_base = substitutions.get(base).copied().unwrap_or(*base);
                            if let Some(&(disc, _)) = enum_inits.get(&actual_base) {
                                inst.expr = ValueExpr::Constant(ConstantValue::Int(
                                    disc as i128,
                                    IntType::I64,
                                ));
                                self.stats.folded_discriminants += 1;
                            }
                        }
                        ValueExpr::EnumGetPayload { base, .. } => {
                            let actual_base = substitutions.get(base).copied().unwrap_or(*base);
                            if let Some(&(_, Some(payload_val))) = enum_inits.get(&actual_base) {
                                let actual_payload = substitutions
                                    .get(&payload_val)
                                    .copied()
                                    .unwrap_or(payload_val);
                                substitutions.insert(res, actual_payload);
                                self.stats.forwarded_payloads += 1;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // Apply payload substitutions across instructions and terminators
        if !substitutions.is_empty() {
            Self::resolve_substitution_chains(&mut substitutions);
            for block in &mut func.blocks {
                for inst in &mut block.instructions {
                    Self::substitute_instruction_operands(inst, &substitutions);
                }
                if let Some(term) = &mut block.terminator {
                    Self::substitute_terminator_operands(term, &substitutions);
                }
            }
        }
    }

    /// Directly folds field projections (`GetField`), element lookups (`GetElement`), and length queries (`ArrayLen`)
    /// on known SSA aggregates (`StructInit`, `TupleInit`, `ArrayInit`, and `SliceSub`).
    fn optimize_aggregate_projections(&mut self, func: &mut FirFunction) {
        let mut loop_count = 0;
        loop {
            loop_count += 1;
            if loop_count > 16 {
                break;
            }

            let mut aggregate_inits: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
            let mut array_inits: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
            let mut slice_subs: HashMap<ValueId, (ValueId, ValueId, ValueId)> = HashMap::new();
            let mut const_ints: HashMap<ValueId, i128> = HashMap::new();
            let mut substitutions: HashMap<ValueId, ValueId> = HashMap::new();

            for block in &func.blocks {
                for inst in &block.instructions {
                    if let Some(res) = inst.result {
                        match &inst.expr {
                            ValueExpr::StructInit { fields, .. } | ValueExpr::TupleInit(fields) => {
                                aggregate_inits.insert(res, fields.clone());
                            }
                            ValueExpr::ArrayInit(elements) => {
                                array_inits.insert(res, elements.clone());
                            }
                            ValueExpr::SliceSub { base, start, end } => {
                                slice_subs.insert(res, (*base, *start, *end));
                            }
                            ValueExpr::Constant(ConstantValue::Int(v, _)) => {
                                const_ints.insert(res, *v);
                            }
                            _ => {}
                        }
                    }
                }
            }

            if aggregate_inits.is_empty() && array_inits.is_empty() && slice_subs.is_empty() {
                break;
            }

            let mut changed = false;
            for block in &mut func.blocks {
                for inst in &mut block.instructions {
                    if let Some(res) = inst.result {
                        match &mut inst.expr {
                            ValueExpr::GetField {
                                base, field_idx, ..
                            } => {
                                let actual_base = substitutions.get(base).copied().unwrap_or(*base);
                                if let Some(fields) = aggregate_inits.get(&actual_base) {
                                    if let Some(&field_val) = fields.get(*field_idx) {
                                        let actual_val = substitutions
                                            .get(&field_val)
                                            .copied()
                                            .unwrap_or(field_val);
                                        substitutions.insert(res, actual_val);
                                        self.stats.forwarded_payloads += 1;
                                        changed = true;
                                    }
                                }
                            }
                            ValueExpr::GetElement { base, index } => {
                                let actual_base = substitutions.get(base).copied().unwrap_or(*base);
                                let actual_idx =
                                    substitutions.get(index).copied().unwrap_or(*index);
                                if let Some(&idx_val) = const_ints.get(&actual_idx) {
                                    // 1. Direct array indexing
                                    if let Some(elements) = array_inits.get(&actual_base) {
                                        if idx_val >= 0 && (idx_val as usize) < elements.len() {
                                            let elem_val = elements[idx_val as usize];
                                            let actual_val = substitutions
                                                .get(&elem_val)
                                                .copied()
                                                .unwrap_or(elem_val);
                                            substitutions.insert(res, actual_val);
                                            self.stats.forwarded_payloads += 1;
                                            changed = true;
                                        }
                                    } else {
                                        // 2. Indexing through one or more SliceSub layers
                                        let mut curr = actual_base;
                                        let mut offset = idx_val;
                                        let mut resolved = None;
                                        while let Some(&(sub_base, start_v, _end_v)) =
                                            slice_subs.get(&curr)
                                        {
                                            let actual_start = substitutions
                                                .get(&start_v)
                                                .copied()
                                                .unwrap_or(start_v);
                                            if let Some(&s_val) = const_ints.get(&actual_start) {
                                                offset += s_val;
                                                curr = substitutions
                                                    .get(&sub_base)
                                                    .copied()
                                                    .unwrap_or(sub_base);
                                            } else {
                                                break;
                                            }
                                        }
                                        if let Some(elements) = array_inits.get(&curr) {
                                            if offset >= 0 && (offset as usize) < elements.len() {
                                                resolved = Some(elements[offset as usize]);
                                            }
                                        }
                                        if let Some(elem_val) = resolved {
                                            let actual_val = substitutions
                                                .get(&elem_val)
                                                .copied()
                                                .unwrap_or(elem_val);
                                            substitutions.insert(res, actual_val);
                                            self.stats.forwarded_payloads += 1;
                                            changed = true;
                                        }
                                    }
                                }
                            }
                            ValueExpr::ArrayLen { array } => {
                                let actual_arr =
                                    substitutions.get(array).copied().unwrap_or(*array);
                                let mut resolved_len: Option<i128> = None;
                                if let Some(elements) = array_inits.get(&actual_arr) {
                                    resolved_len = Some(elements.len() as i128);
                                } else if let Some(&(_base, start_v, end_v)) =
                                    slice_subs.get(&actual_arr)
                                {
                                    let actual_start =
                                        substitutions.get(&start_v).copied().unwrap_or(start_v);
                                    let actual_end =
                                        substitutions.get(&end_v).copied().unwrap_or(end_v);
                                    if let (Some(&s_val), Some(&e_val)) =
                                        (const_ints.get(&actual_start), const_ints.get(&actual_end))
                                    {
                                        resolved_len = Some((e_val - s_val).max(0));
                                    }
                                }
                                if let Some(len) = resolved_len {
                                    inst.expr =
                                        ValueExpr::Constant(ConstantValue::Int(len, IntType::I64));
                                    const_ints.insert(res, len);
                                    self.stats.forwarded_payloads += 1;
                                    changed = true;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            if !substitutions.is_empty() {
                Self::resolve_substitution_chains(&mut substitutions);
                for block in &mut func.blocks {
                    for inst in &mut block.instructions {
                        Self::substitute_instruction_operands(inst, &substitutions);
                    }
                    if let Some(term) = &mut block.terminator {
                        Self::substitute_terminator_operands(term, &substitutions);
                    }
                }
            }

            if !changed {
                break;
            }
        }
    }

    /// Removes pure SSA instructions whose result is never referenced.
    fn eliminate_dead_instructions(&mut self, func: &mut FirFunction) {
        let mut changed = true;

        while changed {
            changed = false;

            // 1. Count uses of all ValueIds
            let mut use_counts: HashMap<ValueId, usize> = HashMap::new();
            for block in &func.blocks {
                for inst in &block.instructions {
                    for u in inst.expr.uses() {
                        *use_counts.entry(u).or_insert(0) += 1;
                    }
                }
                if let Some(term) = &block.terminator {
                    for u in term.uses() {
                        *use_counts.entry(u).or_insert(0) += 1;
                    }
                }
            }

            // 2. Filter instructions with 0 uses that have no side effects
            for block in &mut func.blocks {
                let mut retained = Vec::with_capacity(block.instructions.len());

                for inst in block.instructions.drain(..) {
                    if let Some(res) = inst.result {
                        let is_unused = use_counts.get(&res).copied().unwrap_or(0) == 0;
                        let is_pure = matches!(
                            &inst.expr,
                            ValueExpr::Constant(_)
                                | ValueExpr::Binary { .. }
                                | ValueExpr::Unary { .. }
                                | ValueExpr::StructInit { .. }
                                | ValueExpr::TupleInit(_)
                                | ValueExpr::ArrayInit(_)
                                | ValueExpr::GetField { .. }
                                | ValueExpr::GetFieldPtr { .. }
                                | ValueExpr::GetElement { .. }
                                | ValueExpr::GetElementPtr { .. }
                                | ValueExpr::ArrayLen { .. }
                                | ValueExpr::SliceSub { .. }
                                | ValueExpr::SliceStrided { .. }
                                | ValueExpr::Alloca { .. }
                        );

                        if is_unused && is_pure {
                            self.stats.eliminated_dead_insts += 1;
                            changed = true;
                            continue;
                        }
                    }

                    retained.push(inst);
                }

                block.instructions = retained;
            }
        }
    }
}

impl Default for SroaPass {
    fn default() -> Self {
        Self::new()
    }
}

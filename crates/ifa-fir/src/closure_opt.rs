use crate::cfg::ControlFlowGraph;
use crate::ir::*;
use crate::sroa::SroaPass;
use crate::types::FirType;
use ifa_span::{Symbol, INTERNER};
use std::collections::{HashMap, HashSet};

/// Memory allocation classification for a closure's captured environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosureAllocationKind {
    /// Environment does not escape its calling frame: allocated purely on stack
    /// or scalarized directly into SSA registers (zero heap allocation overhead).
    Stack,
    /// Environment escapes local frame only into bounded callee invocations (e.g. higher-order iterators):
    /// allocated in a pre-allocated request/scoped arena (O(1) bump allocation, zero fragmentation).
    Arena(u16),
    /// Environment escapes unboundedly (returned from caller, stored in global or spawned across threads):
    /// requires heap allocation with generational safety.
    Heap,
}

/// Information collected about a single closure instantiation in SSA FIR.
#[derive(Debug, Clone)]
pub struct ClosureInstance {
    /// Function where the closure was instantiated.
    pub func_name: Symbol,
    /// SSA ValueId holding the closure aggregate `{ __ifa_fn, __ifa_env }`.
    pub closure_val: ValueId,
    /// Lifted function symbol (e.g. `__ifa_lambda_0`).
    pub lambda_sym: Symbol,
    /// SSA ValueId holding the environment struct.
    pub env_val: ValueId,
    /// Escape classification determined by interprocedural analysis.
    pub allocation: ClosureAllocationKind,
}

/// Statistics collected by the interprocedural closure optimizer pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClosureEscapeStats {
    /// Total closure instantiations discovered in the module.
    pub total_closures: usize,
    /// Closures whose environments are guaranteed to reside on the stack or in registers.
    pub stack_allocated_closures: usize,
    /// Closures whose environments are placed in pre-allocated scoped arenas.
    pub arena_allocated_closures: usize,
    /// Closures whose environments escape and require heap storage.
    pub heap_allocated_closures: usize,
    /// Indirect closure calls devirtualized into direct SSA function calls (`CallDirect`).
    pub devirtualized_calls: usize,
    /// Captured environment fields forwarded directly to scalar registers (SROA).
    pub forwarded_capture_fields: usize,
    /// Higher-order function call sites inlined to enable zero-cost capture elimination.
    pub inlined_higher_order_calls: usize,
    /// Intermediate closure/environment allocations eliminated.
    pub eliminated_allocations: usize,
    /// Thunk adapters inlined directly to underlying top-level functions.
    pub inlined_thunk_adapters: usize,
    /// Monomorphic higher-order function calls specialized for static callees.
    pub specialized_higher_order_calls: usize,
    /// Environments successfully placed into pre-allocated memory arenas.
    pub arena_placed_closures: usize,
}

/// Interprocedural closure escape analysis and capture optimizer.
///
/// Analyzes closure instantiations across all module functions, proves non-escape
/// of closure environments, devirtualizes indirect closure dispatches, and eliminates
/// aggregate environment packing through scalar replacement.
pub struct ClosureOptPass {
    stats: ClosureEscapeStats,
}

impl ClosureOptPass {
    /// Create a new closure optimization pass.
    pub fn new() -> Self {
        Self {
            stats: ClosureEscapeStats::default(),
        }
    }

    /// Return statistics from the optimization run.
    pub fn stats(&self) -> ClosureEscapeStats {
        self.stats
    }

    /// Run closure escape analysis, devirtualization, and capture SROA on a FIR module.
    pub fn run_on_module(&mut self, module: &mut FirModule) {
        // Step 1: Detect all closure instantiations across all functions
        let mut closures = self.collect_closure_instances(module);
        self.stats.total_closures = closures.len();

        // Step 2: Inline small higher-order helper functions at known closure call sites
        self.inline_higher_order_call_sites(module, &closures);

        // Step 3: Specialize monomorphic higher-order calls (multi-block or loops)
        self.specialize_higher_order_calls(module, &mut closures);

        // Step 4: Refresh closure instances and run Interprocedural Escape Analysis
        let mut closures = self.collect_closure_instances(module);
        self.analyze_escapes(module, &mut closures);

        for c in &closures {
            match c.allocation {
                ClosureAllocationKind::Stack => self.stats.stack_allocated_closures += 1,
                ClosureAllocationKind::Arena(_) => self.stats.arena_allocated_closures += 1,
                ClosureAllocationKind::Heap => self.stats.heap_allocated_closures += 1,
            }
        }

        // Step 5: Devirtualize closure calls, forward captured fields, and optimize bounded arena placement
        let thunk_adapters = self.collect_thunk_adapters(module);
        for func in &mut module.functions {
            self.optimize_function(func, &closures, &thunk_adapters);
        }

        // Step 6: Inline remaining direct thunk adapter calls
        self.inline_thunk_adapter_calls(module, &thunk_adapters);

        // Step 7: Clean up dead aggregate instructions resulting from capture forwarding
        self.eliminate_dead_closure_instructions(module);

        // Step 8: Prune unreferenced thunk adapter functions completely inlined
        self.prune_unused_thunk_adapters(module, &thunk_adapters);
    }

    /// Collects all closure aggregate initializations across all functions.
    fn collect_closure_instances(&self, module: &FirModule) -> Vec<ClosureInstance> {
        let mut instances = Vec::new();

        for func in &module.functions {
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
                for inst in &block.instructions {
                    if let Some(res) = inst.result {
                        if let ValueExpr::StructInit { name, fields } = &inst.expr {
                            let name_str = INTERNER.resolve(name);
                            if (name_str.starts_with("__ifa_closure_")
                                || name_str.starts_with("__ifa_fnref_"))
                                && fields.len() >= 2
                            {
                                let fn_val = fields[0];
                                let env_val = fields[1];
                                if let Some(&lambda_sym) = string_constants.get(&fn_val) {
                                    instances.push(ClosureInstance {
                                        func_name: func.name,
                                        closure_val: res,
                                        lambda_sym,
                                        env_val,
                                        allocation: ClosureAllocationKind::Stack,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        instances
    }

    /// Interprocedural dataflow escape analysis.
    fn analyze_escapes(&self, module: &FirModule, closures: &mut [ClosureInstance]) {
        // Collect functions that escape any higher-order function parameters
        let escaping_params = self.find_escaping_function_parameters(module);

        for closure in closures.iter_mut() {
            if let Some(func) = module
                .functions
                .iter()
                .find(|f| f.name == closure.func_name)
            {
                closure.allocation =
                    Self::classify_closure_escape(func, closure.closure_val, &escaping_params);
            }
        }
    }

    /// Identifies which function parameters of type `FirType::Function` escape their callee.
    fn find_escaping_function_parameters(&self, module: &FirModule) -> HashSet<(Symbol, usize)> {
        let mut escaping = HashSet::new();

        for func in &module.functions {
            for (idx, p) in func.params.iter().enumerate() {
                if matches!(p.ty, FirType::Function { .. }) {
                    let param_val = p.val;
                    if Self::value_escapes_function(func, param_val) {
                        escaping.insert((func.name, idx));
                    }
                }
            }
        }

        escaping
    }

    /// Check if a value escapes the local function through return, heap store, or concurrency spawn.
    fn value_escapes_function(func: &FirFunction, target_val: ValueId) -> bool {
        let local_allocas: HashSet<ValueId> = func
            .blocks
            .iter()
            .flat_map(|b| &b.instructions)
            .filter_map(|i| match (i.result, &i.expr) {
                (Some(r), ValueExpr::Alloca { .. }) => Some(r),
                _ => None,
            })
            .collect();

        let mut visited = HashSet::new();
        let mut queue = vec![target_val];

        while let Some(v) = queue.pop() {
            if !visited.insert(v) {
                continue;
            }

            for block in &func.blocks {
                if let Some(term) = &block.terminator {
                    match term {
                        Terminator::Return(Some(ret_val)) if *ret_val == v => return true,
                        Terminator::Fail(fail_val) if *fail_val == v => return true,
                        Terminator::Branch { args, .. } => {
                            for a in args {
                                if *a == v {
                                    queue.push(*a);
                                }
                            }
                        }
                        Terminator::BranchCond {
                            then_args,
                            else_args,
                            ..
                        } => {
                            for a in then_args.iter().chain(else_args.iter()) {
                                if *a == v {
                                    queue.push(*a);
                                }
                            }
                        }
                        _ => {}
                    }
                }

                for inst in &block.instructions {
                    match &inst.expr {
                        ValueExpr::Store { ptr, val } if *val == v => {
                            if !local_allocas.contains(ptr) {
                                return true;
                            }
                        }
                        ValueExpr::Spawn { args, .. } => {
                            if args.contains(&v) {
                                return true;
                            }
                        }
                        ValueExpr::GenRef { ptr } if *ptr == v => return true,
                        ValueExpr::ArrayPush { val, .. } if *val == v => return true,
                        _ => {}
                    }
                }
            }
        }

        false
    }

    /// Classify whether a closure value remains strictly on stack, can be placed into a scoped arena (bounded call),
    /// or escapes globally to the generational heap.
    fn classify_closure_escape(
        func: &FirFunction,
        closure_val: ValueId,
        escaping_params: &HashSet<(Symbol, usize)>,
    ) -> ClosureAllocationKind {
        let local_allocas: HashSet<ValueId> = func
            .blocks
            .iter()
            .flat_map(|b| &b.instructions)
            .filter_map(|i| match (i.result, &i.expr) {
                (Some(r), ValueExpr::Alloca { .. }) => Some(r),
                _ => None,
            })
            .collect();

        let mut visited = HashSet::new();
        let mut worklist = vec![closure_val];

        // Also track alloca aliases where the closure was stored
        let mut tracked_ptrs = HashSet::new();
        for block in &func.blocks {
            for inst in &block.instructions {
                if let ValueExpr::Store { ptr, val } = &inst.expr {
                    if *val == closure_val {
                        tracked_ptrs.insert(*ptr);
                    }
                }
            }
        }

        // Add values loaded from those allocas
        for block in &func.blocks {
            for inst in &block.instructions {
                if let (Some(res), ValueExpr::Load { ptr }) = (inst.result, &inst.expr) {
                    if tracked_ptrs.contains(ptr) {
                        worklist.push(res);
                    }
                }
            }
        }

        let mut passed_to_bounded_call = false;

        while let Some(v) = worklist.pop() {
            if !visited.insert(v) {
                continue;
            }

            for block in &func.blocks {
                if let Some(term) = &block.terminator {
                    match term {
                        Terminator::Return(Some(ret_val)) if *ret_val == v => {
                            return ClosureAllocationKind::Heap;
                        }
                        Terminator::Fail(fail_val) if *fail_val == v => {
                            return ClosureAllocationKind::Heap;
                        }
                        _ => {}
                    }
                }

                for inst in &block.instructions {
                    match &inst.expr {
                        ValueExpr::Store { ptr, val } if *val == v => {
                            if !local_allocas.contains(ptr) {
                                return ClosureAllocationKind::Heap;
                            }
                        }
                        ValueExpr::Spawn { args, .. } if args.contains(&v) => {
                            return ClosureAllocationKind::Heap;
                        }
                        ValueExpr::CallDirect { name, args } => {
                            for (idx, arg) in args.iter().enumerate() {
                                if *arg == v {
                                    if escaping_params.contains(&(*name, idx)) {
                                        return ClosureAllocationKind::Heap;
                                    } else {
                                        passed_to_bounded_call = true;
                                    }
                                }
                            }
                        }
                        ValueExpr::ArrayPush { val, .. } if *val == v => {
                            return ClosureAllocationKind::Heap;
                        }
                        _ => {}
                    }
                }
            }
        }

        if passed_to_bounded_call {
            ClosureAllocationKind::Arena(1)
        } else {
            ClosureAllocationKind::Stack
        }
    }

    /// Inlines small higher-order helper functions at call sites where a known closure is passed.
    fn inline_higher_order_call_sites(
        &mut self,
        module: &mut FirModule,
        closures: &[ClosureInstance],
    ) {
        let candidates: HashMap<Symbol, FirFunction> = module
            .functions
            .iter()
            .filter(|f| {
                !INTERNER.resolve(&f.name).starts_with("__ifa_lambda_")
                    && f.params
                        .iter()
                        .any(|p| matches!(p.ty, FirType::Function { .. }))
                    && f.blocks.len() == 1
                    && f.blocks[0].instructions.len() <= 16
            })
            .map(|f| (f.name, f.clone()))
            .collect();

        if candidates.is_empty() {
            return;
        }

        let closure_val_to_lambda: HashMap<ValueId, Symbol> = closures
            .iter()
            .map(|c| (c.closure_val, c.lambda_sym))
            .collect();

        for func in &mut module.functions {
            let mut func_subst: HashMap<ValueId, ValueId> = HashMap::new();
            let mut inlined_anything = false;

            // Track local single-store alloca loads to resolve closure argument values
            let mut local_aliases: HashMap<ValueId, ValueId> = HashMap::new();
            let mut store_counts: HashMap<ValueId, usize> = HashMap::new();
            let mut store_map: HashMap<ValueId, ValueId> = HashMap::new();
            for block in &func.blocks {
                for inst in &block.instructions {
                    if let ValueExpr::Store { ptr, val } = &inst.expr {
                        *store_counts.entry(*ptr).or_insert(0) += 1;
                        store_map.insert(*ptr, *val);
                    }
                }
            }
            for block in &func.blocks {
                for inst in &block.instructions {
                    if let (Some(res), ValueExpr::Load { ptr }) = (inst.result, &inst.expr) {
                        if store_counts.get(ptr) == Some(&1) {
                            if let Some(&val) = store_map.get(ptr) {
                                local_aliases.insert(res, val);
                            }
                        }
                    }
                }
            }

            for block in &mut func.blocks {
                let mut new_instructions = Vec::with_capacity(block.instructions.len());

                for inst in block.instructions.drain(..) {
                    if let (Some(res), ValueExpr::CallDirect { name, args }) =
                        (inst.result, &inst.expr)
                    {
                        if let Some(target_func) = candidates.get(name) {
                            let has_known_closure_arg = args.iter().any(|a| {
                                let resolved = local_aliases.get(a).copied().unwrap_or(*a);
                                closure_val_to_lambda.contains_key(&resolved)
                            });

                            if has_known_closure_arg && target_func.blocks.len() == 1 {
                                let mut subst: HashMap<ValueId, ValueId> = HashMap::new();
                                for (p_idx, param) in target_func.params.iter().enumerate() {
                                    if let Some(&arg_val) = args.get(p_idx) {
                                        let resolved_arg =
                                            local_aliases.get(&arg_val).copied().unwrap_or(arg_val);
                                        let resolved_arg = func_subst
                                            .get(&resolved_arg)
                                            .copied()
                                            .unwrap_or(resolved_arg);
                                        subst.insert(param.val, resolved_arg);
                                    }
                                }

                                let inline_block = &target_func.blocks[0];
                                for inline_inst in &inline_block.instructions {
                                    let mut cloned_inst = inline_inst.clone();
                                    let new_val_id = ValueId(func.next_value_id);
                                    func.next_value_id += 1;
                                    if let Some(orig_res) = cloned_inst.result {
                                        subst.insert(orig_res, new_val_id);
                                        cloned_inst.result = Some(new_val_id);
                                    }
                                    SroaPass::substitute_instruction_operands(
                                        &mut cloned_inst,
                                        &subst,
                                    );
                                    new_instructions.push(cloned_inst);
                                }

                                if let Some(Terminator::Return(Some(ret_val))) =
                                    &inline_block.terminator
                                {
                                    let actual_ret =
                                        subst.get(ret_val).copied().unwrap_or(*ret_val);
                                    func_subst.insert(res, actual_ret);
                                }

                                self.stats.inlined_higher_order_calls += 1;
                                inlined_anything = true;
                                continue;
                            }
                        }
                    }

                    new_instructions.push(inst);
                }

                block.instructions = new_instructions;
            }

            if inlined_anything && !func_subst.is_empty() {
                SroaPass::resolve_substitution_chains(&mut func_subst);
                for block in &mut func.blocks {
                    for inst in &mut block.instructions {
                        SroaPass::substitute_instruction_operands(inst, &func_subst);
                    }
                    if let Some(term) = &mut block.terminator {
                        SroaPass::substitute_terminator_operands(term, &func_subst);
                    }
                }
                let _ = ControlFlowGraph::build(func);
            }
        }
    }

    /// Collects all thunk adapter functions that adapt a direct function to the uniform closure ABI.
    fn collect_thunk_adapters(&self, module: &FirModule) -> HashMap<Symbol, Symbol> {
        let mut map = HashMap::new();
        for func in &module.functions {
            let name_str = INTERNER.resolve(&func.name);
            if name_str.starts_with("__ifa_thunk_") && func.blocks.len() == 1 {
                let block = &func.blocks[0];
                for inst in &block.instructions {
                    if let ValueExpr::CallDirect { name: target, args } = &inst.expr {
                        if func.params.len() == args.len() + 1 {
                            let matches = args
                                .iter()
                                .enumerate()
                                .all(|(idx, &arg_val)| func.params[idx + 1].val == arg_val);
                            if matches {
                                map.insert(func.name, *target);
                                break;
                            }
                        }
                    }
                }
            }
        }
        map
    }

    /// Resolves an SSA argument value to its static closure or function pointer identity if known.
    fn resolve_closure_arg(
        func: &FirFunction,
        arg_val: ValueId,
        closures: &[ClosureInstance],
    ) -> Option<(Symbol, ValueId)> {
        // 1. Direct match in closure instances for this function
        if let Some(c) = closures
            .iter()
            .find(|c| c.func_name == func.name && c.closure_val == arg_val)
        {
            return Some((c.lambda_sym, c.env_val));
        }

        // 2. Track alloca aliases if arg was loaded from an alloca
        let mut load_source: Option<ValueId> = None;
        for block in &func.blocks {
            for inst in &block.instructions {
                if inst.result == Some(arg_val) {
                    if let ValueExpr::Load { ptr } = &inst.expr {
                        load_source = Some(*ptr);
                        break;
                    }
                }
            }
        }

        if let Some(alloca_ptr) = load_source {
            let mut store_count = 0;
            let mut single_store_val = None;
            for block in &func.blocks {
                for inst in &block.instructions {
                    if let ValueExpr::Store { ptr, val } = &inst.expr {
                        if *ptr == alloca_ptr {
                            store_count += 1;
                            single_store_val = Some(*val);
                        }
                    }
                }
            }

            if store_count == 1 {
                if let Some(val) = single_store_val {
                    if val != arg_val {
                        if let Some(res) = Self::resolve_closure_arg(func, val, closures) {
                            return Some(res);
                        }
                    }
                }
            }
        }

        // 3. Check if arg_val was defined directly by Constant(Function) or StructInit
        for block in &func.blocks {
            for inst in &block.instructions {
                if inst.result == Some(arg_val) {
                    match &inst.expr {
                        ValueExpr::Constant(ConstantValue::Function(sym)) => {
                            return Some((*sym, ValueId(0)));
                        }
                        ValueExpr::StructInit { fields, .. } if !fields.is_empty() => {
                            let fn_vid = fields[0];
                            let env_vid = if fields.len() > 1 {
                                fields[1]
                            } else {
                                ValueId(0)
                            };
                            for b2 in &func.blocks {
                                for i2 in &b2.instructions {
                                    if i2.result == Some(fn_vid) {
                                        if let ValueExpr::Constant(ConstantValue::Function(sym)) =
                                            &i2.expr
                                        {
                                            return Some((*sym, env_vid));
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        None
    }

    /// Specializes higher-order functions for statically monomorphic closure or function pointer call sites.
    fn specialize_higher_order_calls(
        &mut self,
        module: &mut FirModule,
        closures: &mut Vec<ClosureInstance>,
    ) {
        let mut specialized_cache: HashMap<(Symbol, usize, Symbol), Symbol> = HashMap::new();

        // Perform specialization up to 4 iterations (handles pipelines and transitive higher-order calls)
        for _iteration in 0..4 {
            let mut specializations_to_apply = Vec::new();

            // Collect function parameter signatures
            let func_signatures: HashMap<Symbol, Vec<FirType>> = module
                .functions
                .iter()
                .map(|f| (f.name, f.params.iter().map(|p| p.ty.clone()).collect()))
                .collect();

            for func in &module.functions {
                let func_name_str = INTERNER.resolve(&func.name);
                if func_name_str.starts_with("__ifa_thunk_")
                    || func_name_str.starts_with("__ifa_lambda_")
                {
                    continue;
                }

                for (b_idx, block) in func.blocks.iter().enumerate() {
                    for (i_idx, inst) in block.instructions.iter().enumerate() {
                        if let ValueExpr::CallDirect {
                            name: callee_name,
                            args,
                        } = &inst.expr
                        {
                            let callee_name_str = INTERNER.resolve(callee_name);
                            if callee_name_str.starts_with("__ifa_thunk_")
                                || callee_name_str.starts_with("__ifa_lambda_")
                            {
                                continue;
                            }

                            if let Some(param_tys) = func_signatures.get(callee_name) {
                                for (p_idx, p_ty) in param_tys.iter().enumerate() {
                                    let is_hof_param = matches!(p_ty, FirType::Function { .. })
                                        || matches!(
                                            p_ty,
                                            FirType::Struct(name, _)
                                                if INTERNER.resolve(name).starts_with("__ifa_closure_")
                                        );

                                    if is_hof_param {
                                        if let Some(&arg_val) = args.get(p_idx) {
                                            if let Some((target_sym, env_val)) =
                                                Self::resolve_closure_arg(func, arg_val, closures)
                                            {
                                                specializations_to_apply.push((
                                                    func.name,
                                                    b_idx,
                                                    i_idx,
                                                    *callee_name,
                                                    p_idx,
                                                    target_sym,
                                                    env_val,
                                                ));
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if specializations_to_apply.is_empty() {
                break;
            }

            let mut new_specialized_funcs = Vec::new();

            for (caller_name, b_idx, i_idx, callee_name, p_idx, target_sym, env_val) in
                specializations_to_apply
            {
                let spec_name = *specialized_cache
                    .entry((callee_name, p_idx, target_sym))
                    .or_insert_with(|| {
                        let base_callee = INTERNER.resolve(&callee_name);
                        let target_clean = INTERNER.resolve(&target_sym);
                        let clean_suffix = target_clean
                            .trim_start_matches("__ifa_thunk_")
                            .trim_start_matches("__ifa_lambda_");
                        let new_sym =
                            INTERNER.intern(&format!("{}$spec_{}", base_callee, clean_suffix));

                        if let Some(orig_func) =
                            module.functions.iter().find(|f| f.name == callee_name)
                        {
                            let mut spec_func = orig_func.clone();
                            spec_func.name = new_sym;
                            let param_val = spec_func.params[p_idx].val;

                            // Register closure instance in the new specialized function
                            closures.push(ClosureInstance {
                                func_name: new_sym,
                                closure_val: param_val,
                                lambda_sym: target_sym,
                                env_val,
                                allocation: ClosureAllocationKind::Stack,
                            });

                            new_specialized_funcs.push(spec_func);
                            self.stats.specialized_higher_order_calls += 1;
                        }

                        new_sym
                    });

                // Update call site in caller
                if let Some(caller_func) =
                    module.functions.iter_mut().find(|f| f.name == caller_name)
                {
                    if let Some(inst) = caller_func
                        .blocks
                        .get_mut(b_idx)
                        .and_then(|b| b.instructions.get_mut(i_idx))
                    {
                        if let ValueExpr::CallDirect { name, .. } = &mut inst.expr {
                            *name = spec_name;
                        }
                    }
                }
            }

            module.functions.extend(new_specialized_funcs);
        }
    }

    /// Inlines calls to thunk adapters directly to the underlying function, dropping dummy env arg.
    fn inline_thunk_adapter_calls(
        &mut self,
        module: &mut FirModule,
        thunk_adapters: &HashMap<Symbol, Symbol>,
    ) {
        if thunk_adapters.is_empty() {
            return;
        }

        for func in &mut module.functions {
            if thunk_adapters.contains_key(&func.name) {
                continue;
            }

            for block in &mut func.blocks {
                for inst in &mut block.instructions {
                    if let ValueExpr::CallDirect { name, args } = &mut inst.expr {
                        if let Some(&underlying_fn) = thunk_adapters.get(name) {
                            *name = underlying_fn;
                            if !args.is_empty() {
                                args.remove(0);
                            }
                            self.stats.inlined_thunk_adapters += 1;
                        }
                    }
                }
            }
        }
    }

    /// Prune unreferenced thunk adapter functions that were completely inlined.
    fn prune_unused_thunk_adapters(
        &mut self,
        module: &mut FirModule,
        thunk_adapters: &HashMap<Symbol, Symbol>,
    ) {
        if thunk_adapters.is_empty() {
            return;
        }

        let mut referenced = HashSet::new();
        for func in &module.functions {
            if thunk_adapters.contains_key(&func.name) {
                continue;
            }
            for block in &func.blocks {
                for inst in &block.instructions {
                    match &inst.expr {
                        ValueExpr::CallDirect { name, .. } => {
                            referenced.insert(*name);
                        }
                        ValueExpr::Constant(ConstantValue::Function(sym)) => {
                            referenced.insert(*sym);
                        }
                        ValueExpr::Constant(ConstantValue::String(sym)) => {
                            referenced.insert(*sym);
                        }
                        _ => {}
                    }
                }
            }
        }

        module
            .functions
            .retain(|f| !thunk_adapters.contains_key(&f.name) || referenced.contains(&f.name));
    }

    /// Optimizes a single FIR function: devirtualizes calls and forwards capture projections.
    fn optimize_function(
        &mut self,
        func: &mut FirFunction,
        closures: &[ClosureInstance],
        thunk_adapters: &HashMap<Symbol, Symbol>,
    ) {
        // Build map of closure SSA values to their lambda symbol and env SSA value
        let mut closure_map: HashMap<ValueId, (Symbol, ValueId)> = HashMap::new();
        let mut arena_assigned_envs: HashMap<ValueId, u16> = HashMap::new();
        for c in closures {
            if c.func_name == func.name {
                closure_map.insert(c.closure_val, (c.lambda_sym, c.env_val));
                if let ClosureAllocationKind::Arena(arena_id) = c.allocation {
                    arena_assigned_envs.insert(c.env_val, arena_id);
                    arena_assigned_envs.insert(c.closure_val, arena_id);
                }
            }
        }

        // Apply arena placement for bounded closure environments
        if !arena_assigned_envs.is_empty() {
            for block in &mut func.blocks {
                for inst in &mut block.instructions {
                    if let Some(res) = inst.result {
                        if let Some(&arena_id) = arena_assigned_envs.get(&res) {
                            if let ValueExpr::GenAlloc { arena, .. } = &mut inst.expr {
                                if arena.is_none() || *arena == Some(0) {
                                    *arena = Some(arena_id);
                                    self.stats.arena_placed_closures += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Track field projections: GetField on closure values
        let mut fn_sym_values: HashMap<ValueId, Symbol> = HashMap::new();
        let mut env_inst_values: HashMap<ValueId, ValueId> = HashMap::new();
        let mut env_struct_inits: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
        let mut substitutions: HashMap<ValueId, ValueId> = HashMap::new();

        // Track local single-store alloca loads for closures so un-promoted closures and parameters are resolved
        let mut store_counts: HashMap<ValueId, usize> = HashMap::new();
        let mut store_map: HashMap<ValueId, ValueId> = HashMap::new();
        for block in &func.blocks {
            for inst in &block.instructions {
                if let ValueExpr::Store { ptr, val } = &inst.expr {
                    *store_counts.entry(*ptr).or_insert(0) += 1;
                    store_map.insert(*ptr, *val);
                }
            }
        }
        for block in &func.blocks {
            for inst in &block.instructions {
                if let (Some(res), ValueExpr::Load { ptr }) = (inst.result, &inst.expr) {
                    if store_counts.get(ptr) == Some(&1) {
                        if let Some(&val) = store_map.get(ptr) {
                            if closure_map.contains_key(&val) {
                                substitutions.insert(res, val);
                            }
                        }
                    }
                }
            }
        }

        for block in &func.blocks {
            for inst in &block.instructions {
                if let Some(res) = inst.result {
                    match &inst.expr {
                        ValueExpr::StructInit { name, fields } => {
                            let name_str = INTERNER.resolve(name);
                            if name_str.starts_with("__ifa_closure_env_") {
                                env_struct_inits.insert(res, fields.clone());
                            }
                        }
                        ValueExpr::GetField {
                            base, field_idx, ..
                        } => {
                            let actual_base = substitutions.get(base).copied().unwrap_or(*base);
                            if let Some(&(lambda_sym, env_val)) = closure_map.get(&actual_base) {
                                if *field_idx == 0 {
                                    fn_sym_values.insert(res, lambda_sym);
                                } else if *field_idx == 1 {
                                    env_inst_values.insert(res, env_val);
                                    substitutions.insert(res, env_val);
                                    self.stats.forwarded_capture_fields += 1;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // Devirtualize indirect Call to CallDirect when callee resolves to a known lambda or thunk
        for block in &mut func.blocks {
            for inst in &mut block.instructions {
                if let ValueExpr::Call { callee, args } = &inst.expr {
                    let actual_callee = substitutions.get(callee).copied().unwrap_or(*callee);
                    if let Some(&lambda_sym) = fn_sym_values.get(&actual_callee) {
                        let mut rewritten_args = Vec::with_capacity(args.len());
                        for a in args {
                            let sub_a = substitutions.get(a).copied().unwrap_or(*a);
                            rewritten_args.push(sub_a);
                        }

                        if let Some(&underlying_fn) = thunk_adapters.get(&lambda_sym) {
                            let actual_args = if rewritten_args.is_empty() {
                                Vec::new()
                            } else {
                                rewritten_args[1..].to_vec()
                            };
                            inst.expr = ValueExpr::CallDirect {
                                name: underlying_fn,
                                args: actual_args,
                            };
                            self.stats.devirtualized_calls += 1;
                            self.stats.inlined_thunk_adapters += 1;
                        } else {
                            inst.expr = ValueExpr::CallDirect {
                                name: lambda_sym,
                                args: rewritten_args,
                            };
                            self.stats.devirtualized_calls += 1;
                        }
                    }
                }
            }
        }

        // Substitute operands across all instructions
        if !substitutions.is_empty() {
            SroaPass::resolve_substitution_chains(&mut substitutions);
            for block in &mut func.blocks {
                for inst in &mut block.instructions {
                    SroaPass::substitute_instruction_operands(inst, &substitutions);
                }
                if let Some(term) = &mut block.terminator {
                    SroaPass::substitute_terminator_operands(term, &substitutions);
                }
            }
        }
    }

    /// Removes unreferenced pure instructions created during closure capture forwarding.
    fn eliminate_dead_closure_instructions(&mut self, module: &mut FirModule) {
        for func in &mut module.functions {
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

            for block in &mut func.blocks {
                let mut retained = Vec::with_capacity(block.instructions.len());
                for inst in block.instructions.drain(..) {
                    if let Some(res) = inst.result {
                        let is_unused = use_counts.get(&res).copied().unwrap_or(0) == 0;
                        let is_closure_struct = matches!(
                            &inst.expr,
                            ValueExpr::StructInit { name, .. }
                                if INTERNER.resolve(name).starts_with("__ifa_closure")
                        );
                        let is_closure_getfield = matches!(
                            &inst.expr,
                            ValueExpr::GetField { field_name, .. }
                                if INTERNER.resolve(field_name).starts_with("__ifa_")
                        );

                        if is_unused && (is_closure_struct || is_closure_getfield) {
                            self.stats.eliminated_allocations += 1;
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

impl Default for ClosureOptPass {
    fn default() -> Self {
        Self::new()
    }
}

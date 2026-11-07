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
    /// Environment escapes its creating stack frame (e.g., returned or stored
    /// in generational/heap structures): requires heap allocation.
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

        // Step 2: Interprocedural Escape Analysis
        self.analyze_escapes(module, &mut closures);

        for c in &closures {
            match c.allocation {
                ClosureAllocationKind::Stack => self.stats.stack_allocated_closures += 1,
                ClosureAllocationKind::Heap => self.stats.heap_allocated_closures += 1,
            }
        }

        // Step 3: Inline small higher-order helper functions at known closure call sites
        self.inline_higher_order_call_sites(module, &closures);

        // Step 4: Devirtualize closure calls and forward captured fields in all functions
        for func in &mut module.functions {
            self.optimize_function(func, &closures);
        }

        // Step 5: Clean up dead aggregate instructions resulting from capture forwarding
        self.eliminate_dead_closure_instructions(module);
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
                        }
                    }
                }
            }

            for block in &func.blocks {
                for inst in &block.instructions {
                    if let Some(res) = inst.result {
                        if let ValueExpr::StructInit { name, fields } = &inst.expr {
                            let name_str = INTERNER.resolve(name);
                            if name_str.starts_with("__ifa_closure_") && fields.len() >= 2 {
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
                if Self::is_closure_escaping_in_func(func, closure.closure_val, &escaping_params) {
                    closure.allocation = ClosureAllocationKind::Heap;
                }
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

    /// Checks if a closure value escapes from its creating function.
    fn is_closure_escaping_in_func(
        func: &FirFunction,
        closure_val: ValueId,
        escaping_params: &HashSet<(Symbol, usize)>,
    ) -> bool {
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

        while let Some(v) = worklist.pop() {
            if !visited.insert(v) {
                continue;
            }

            for block in &func.blocks {
                if let Some(term) = &block.terminator {
                    match term {
                        Terminator::Return(Some(ret_val)) if *ret_val == v => return true,
                        Terminator::Fail(fail_val) if *fail_val == v => return true,
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
                        ValueExpr::Spawn { args, .. } if args.contains(&v) => return true,
                        ValueExpr::CallDirect { name, args } => {
                            for (idx, arg) in args.iter().enumerate() {
                                if *arg == v && escaping_params.contains(&(*name, idx)) {
                                    return true;
                                }
                            }
                        }
                        ValueExpr::ArrayPush { val, .. } if *val == v => return true,
                        _ => {}
                    }
                }
            }
        }

        false
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

            for block in &mut func.blocks {
                let mut new_instructions = Vec::with_capacity(block.instructions.len());

                for inst in block.instructions.drain(..) {
                    if let (Some(res), ValueExpr::CallDirect { name, args }) =
                        (inst.result, &inst.expr)
                    {
                        if let Some(target_func) = candidates.get(name) {
                            let has_known_closure_arg =
                                args.iter().any(|a| closure_val_to_lambda.contains_key(a));

                            if has_known_closure_arg && target_func.blocks.len() == 1 {
                                let mut subst: HashMap<ValueId, ValueId> = HashMap::new();
                                for (p_idx, param) in target_func.params.iter().enumerate() {
                                    if let Some(&arg_val) = args.get(p_idx) {
                                        let resolved_arg =
                                            func_subst.get(&arg_val).copied().unwrap_or(arg_val);
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

    /// Optimizes a single FIR function: devirtualizes calls and forwards capture projections.
    fn optimize_function(&mut self, func: &mut FirFunction, closures: &[ClosureInstance]) {
        // Build map of closure SSA values to their lambda symbol and env SSA value
        let mut closure_map: HashMap<ValueId, (Symbol, ValueId)> = HashMap::new();
        for c in closures {
            if c.func_name == func.name {
                closure_map.insert(c.closure_val, (c.lambda_sym, c.env_val));
            }
        }

        // Track field projections: GetField on closure values
        let mut fn_sym_values: HashMap<ValueId, Symbol> = HashMap::new();
        let mut env_inst_values: HashMap<ValueId, ValueId> = HashMap::new();
        let mut env_struct_inits: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
        let mut substitutions: HashMap<ValueId, ValueId> = HashMap::new();

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

        // Devirtualize indirect Call to CallDirect when callee resolves to a known lambda
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
                        inst.expr = ValueExpr::CallDirect {
                            name: lambda_sym,
                            args: rewritten_args,
                        };
                        self.stats.devirtualized_calls += 1;
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

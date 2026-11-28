use crate::cfg::ControlFlowGraph;
use crate::dominance::DominanceTree;
use crate::ir::{BlockId, FirFunction, FirModule, Terminator, ValueId};
use ifa_diagnostics::Diagnostic;
use ifa_span::Span;
use std::collections::{HashMap, HashSet};

/// Verification errors found during FIR SSA verification.
#[derive(Debug, Clone)]
pub struct FirVerifyError {
    pub message: String,
    pub span: Span,
    pub code: Option<String>,
}

impl FirVerifyError {
    pub fn new(message: impl Into<String>, span: Span) -> Self {
        Self {
            message: message.into(),
            span,
            code: None,
        }
    }

    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }

    pub fn to_diagnostic(&self) -> Diagnostic {
        let code = self.code.as_deref().unwrap_or("E0600");
        Diagnostic::error(format!("FIR verification error: {}", self.message))
            .with_code(code)
            .with_primary_label(self.span, self.message.clone())
    }
}

/// Verifies SSA invariants, CFG consistency, and typing constraints on a FIR module.
pub struct FirVerifier;

impl FirVerifier {
    /// Verify an entire FIR module.
    pub fn verify_module(module: &FirModule) -> Result<(), Vec<FirVerifyError>> {
        let mut errors = Vec::new();
        for func in &module.functions {
            if let Err(mut func_errors) = Self::verify_function(func) {
                errors.append(&mut func_errors);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Verify a single FIR function.
    pub fn verify_function(func: &FirFunction) -> Result<(), Vec<FirVerifyError>> {
        if func.blocks.is_empty() {
            return Ok(());
        }

        let mut errors = Vec::new();

        // 1. Check all blocks have valid terminators
        for block in &func.blocks {
            if block.terminator.is_none() {
                errors.push(FirVerifyError::new(
                    format!("Block {} does not have a terminator", block.id),
                    func.span,
                ));
            }
        }

        let cfg = ControlFlowGraph::build(func);
        let dom_tree = DominanceTree::build(&cfg);

        // 2. Track definitions: ValueId -> (defining BlockId, is_param)
        let mut def_block: HashMap<ValueId, BlockId> = HashMap::new();
        let mut defined_values: HashSet<ValueId> = HashSet::new();

        // Function parameters defined in entry block
        for param in &func.params {
            def_block.insert(param.val, func.entry_block);
            defined_values.insert(param.val);
        }

        // Block parameters defined at block entry
        for block in &func.blocks {
            for (val, _) in &block.params {
                if !defined_values.insert(*val) {
                    errors.push(FirVerifyError::new(
                        format!("SSA violation: value {} is defined multiple times", val),
                        func.span,
                    ));
                }
                def_block.insert(*val, block.id);
            }

            // Instruction results defined in block
            for inst in &block.instructions {
                if let Some(res) = inst.result {
                    if !defined_values.insert(res) {
                        errors.push(FirVerifyError::new(
                            format!(
                                "SSA violation: value {} is defined multiple times",
                                res
                            ),
                            inst.span,
                        ));
                    }
                    def_block.insert(res, block.id);
                }

                // Strict function constraint check: zero-heap determinism mandates NO GenAlloc or CoWMakeUnique
                if func.is_strict {
                    match &inst.expr {
                        crate::ir::ValueExpr::GenAlloc { .. } => {
                            errors.push(FirVerifyError::new(
                                format!(
                                    "Strict function '{}' contains prohibited heap generational allocation (zero-heap violation)",
                                    func.name.as_str()
                                ),
                                inst.span,
                            ));
                        }
                        crate::ir::ValueExpr::CoWMakeUnique { .. } => {
                            errors.push(FirVerifyError::new(
                                format!(
                                    "Strict function '{}' contains prohibited implicit Copy-on-Write clone (zero-heap determinism violation)",
                                    func.name.as_str()
                                ),
                                inst.span,
                            ));
                        }
                        _ => {}
                    }
                }
            }
        }

        // 3. Verify all uses are dominated by definitions
        let block_map: HashMap<BlockId, &crate::ir::BasicBlock> =
            func.blocks.iter().map(|b| (b.id, b)).collect();

        for block in &func.blocks {
            // Check instruction uses
            for inst in &block.instructions {
                for used in inst.expr.uses() {
                    if !defined_values.contains(&used) {
                        errors.push(FirVerifyError::new(
                            format!(
                                "Use of undefined value {} in block {}",
                                used, block.id
                            ),
                            inst.span,
                        ));
                    } else if let Some(&d_block) = def_block.get(&used) {
                        // In SSA, definition must dominate use. If in the same block, definition must precede use.
                        if d_block != block.id && !dom_tree.dominates(d_block, block.id) {
                            errors.push(FirVerifyError::new(
                                format!(
                                    "SSA dominance violation: definition in {} does not dominate use in {}",
                                    d_block, block.id
                                ),
                                inst.span,
                            ));
                        }
                    }
                }
            }

            // Check terminator uses and branch argument arities
            if let Some(term) = &block.terminator {
                for used in term.uses() {
                    if !defined_values.contains(&used) {
                        errors.push(FirVerifyError::new(
                            format!(
                                "Use of undefined value {} in terminator of block {}",
                                used, block.id
                            ),
                            func.span,
                        ));
                    }
                }

                match term {
                    Terminator::Branch { target, args } => {
                        Self::check_branch_args(
                            *target,
                            args.len(),
                            &block_map,
                            &mut errors,
                            func.span,
                        );
                    }
                    Terminator::BranchCond {
                        then_block,
                        then_args,
                        else_block,
                        else_args,
                        ..
                    } => {
                        Self::check_branch_args(
                            *then_block,
                            then_args.len(),
                            &block_map,
                            &mut errors,
                            func.span,
                        );
                        Self::check_branch_args(
                            *else_block,
                            else_args.len(),
                            &block_map,
                            &mut errors,
                            func.span,
                        );
                    }
                    Terminator::Switch {
                        cases,
                        default_block,
                        default_args,
                        ..
                    } => {
                        for (_, b, args) in cases {
                            Self::check_branch_args(
                                *b,
                                args.len(),
                                &block_map,
                                &mut errors,
                                func.span,
                            );
                        }
                        Self::check_branch_args(
                            *default_block,
                            default_args.len(),
                            &block_map,
                            &mut errors,
                            func.span,
                        );
                    }
                    Terminator::Return(_) | Terminator::Fail(_) | Terminator::Unreachable => {}
                }
            }
        }

        // 4. Verify escape invariants
        Self::verify_escape_invariants(func, &mut errors);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn check_branch_args(
        target: BlockId,
        arg_count: usize,
        block_map: &HashMap<BlockId, &crate::ir::BasicBlock>,
        errors: &mut Vec<FirVerifyError>,
        span: Span,
    ) {
        if let Some(target_block) = block_map.get(&target) {
            if target_block.params.len() != arg_count {
                errors.push(FirVerifyError::new(
                    format!(
                        "Branch to block {} passes {} arguments, but block expects {}",
                        target,
                        arg_count,
                        target_block.params.len()
                    ),
                    span,
                ));
            }
        } else {
            errors.push(FirVerifyError::new(
                format!("Branch targets non-existent block {}", target),
                span,
            ));
        }
    }

    /// Verifies that no local stack allocations, local references, or thread-local call-arena buffers
    /// escape their valid lifetimes through function return, concurrent spawn boundaries, channel communication,
    /// or non-local memory stores.
    pub fn verify_escape_invariants(func: &FirFunction, errors: &mut Vec<FirVerifyError>) {
        if func.blocks.is_empty() {
            return;
        }

        // 1. Collect all local stack allocas
        let mut alloca_info: HashMap<ValueId, (crate::types::FirType, Option<ifa_span::Symbol>, Span)> = HashMap::new();
        for block in &func.blocks {
            for inst in &block.instructions {
                if let (Some(res), crate::ir::ValueExpr::Alloca { ty, name }) = (inst.result, &inst.expr) {
                    alloca_info.insert(res, (ty.clone(), *name, inst.span));
                }
            }
        }

        // Check if there are CallArenaAlloc or Alloca to verify
        let mut has_call_arena = false;
        for block in &func.blocks {
            for inst in &block.instructions {
                if matches!(inst.expr, crate::ir::ValueExpr::CallArenaAlloc { .. }) {
                    has_call_arena = true;
                    break;
                }
            }
            if has_call_arena {
                break;
            }
        }

        if alloca_info.is_empty() && !has_call_arena {
            return;
        }

        // 2. Map pointer / reference values to their root local allocation
        let mut local_pointers: HashMap<ValueId, ValueId> = HashMap::new();
        for alloca_val in alloca_info.keys() {
            local_pointers.insert(*alloca_val, *alloca_val);
        }

        let mut call_arena_allocs: HashMap<ValueId, Span> = HashMap::new();
        let mut local_alloca_stores: HashMap<ValueId, ValueId> = HashMap::new();
        let mut aggregates_with_local_ptrs: HashMap<ValueId, ValueId> = HashMap::new();

        // 3. Forward flow analysis across instructions to track derived pointers, references, and aggregates
        for block in &func.blocks {
            for inst in &block.instructions {
                if let Some(res) = inst.result {
                    match &inst.expr {
                        crate::ir::ValueExpr::CallArenaAlloc { .. } => {
                            call_arena_allocs.insert(res, inst.span);
                            local_pointers.insert(res, res);
                        }
                        crate::ir::ValueExpr::GetFieldPtr { base, .. }
                        | crate::ir::ValueExpr::GetElementPtr { base, .. } => {
                            if let Some(&root) = local_pointers.get(base) {
                                local_pointers.insert(res, root);
                            }
                        }
                        crate::ir::ValueExpr::GenRef { ptr } => {
                            if let Some(&root) = local_pointers.get(ptr) {
                                local_pointers.insert(res, root);
                            }
                        }
                        crate::ir::ValueExpr::Store { ptr, val } => {
                            if let Some(&root) = local_pointers.get(val) {
                                if alloca_info.contains_key(ptr) {
                                    local_alloca_stores.insert(*ptr, root);
                                }
                            }
                        }
                        crate::ir::ValueExpr::Load { ptr } => {
                            if let Some(&root) = local_alloca_stores.get(ptr) {
                                local_pointers.insert(res, root);
                            }
                        }
                        crate::ir::ValueExpr::StructInit { fields, .. }
                        | crate::ir::ValueExpr::TupleInit(fields)
                        | crate::ir::ValueExpr::ArrayInit(fields) => {
                            for f in fields {
                                if let Some(&root) = local_pointers.get(f) {
                                    aggregates_with_local_ptrs.insert(res, root);
                                    break;
                                } else if let Some(&root) = aggregates_with_local_ptrs.get(f) {
                                    aggregates_with_local_ptrs.insert(res, root);
                                    break;
                                }
                            }
                        }
                        crate::ir::ValueExpr::EnumInit { payload: Some(p), .. } => {
                            if let Some(&root) = local_pointers.get(p) {
                                aggregates_with_local_ptrs.insert(res, root);
                            } else if let Some(&root) = aggregates_with_local_ptrs.get(p) {
                                aggregates_with_local_ptrs.insert(res, root);
                            }
                        }
                        _ => {}
                    }
                }

                // Check escape operations on instructions
                match &inst.expr {
                    crate::ir::ValueExpr::Spawn { target, args } => {
                        for arg in args {
                            if let Some(&root) = local_pointers.get(arg) {
                                if call_arena_allocs.contains_key(&root) {
                                    errors.push(
                                        FirVerifyError::new(
                                            format!(
                                                "Thread-local call-arena allocation {} escapes across concurrent spawn boundary into task '{}'",
                                                root,
                                                target.as_str()
                                            ),
                                            inst.span,
                                        )
                                        .with_code("E0029"),
                                    );
                                } else if let Some((_, name, _)) = alloca_info.get(&root) {
                                    let name_str = name.map(|s| format!(" ('{}')", s.as_str())).unwrap_or_default();
                                    errors.push(
                                        FirVerifyError::new(
                                            format!(
                                                "Local stack allocation {}{} escapes across concurrent spawn boundary into task '{}'",
                                                root,
                                                name_str,
                                                target.as_str()
                                            ),
                                            inst.span,
                                        )
                                        .with_code("E0029"),
                                    );
                                }
                            } else if let Some(&root) = aggregates_with_local_ptrs.get(arg) {
                                if call_arena_allocs.contains_key(&root) {
                                    errors.push(
                                        FirVerifyError::new(
                                            format!(
                                                "Aggregate value escaping into concurrent task '{}' contains thread-local call-arena allocation {}",
                                                target.as_str(),
                                                root
                                            ),
                                            inst.span,
                                        )
                                        .with_code("E0029"),
                                    );
                                } else if let Some((_, name, _)) = alloca_info.get(&root) {
                                    let name_str = name.map(|s| format!(" ('{}')", s.as_str())).unwrap_or_default();
                                    errors.push(
                                        FirVerifyError::new(
                                            format!(
                                                "Aggregate value escaping into concurrent task '{}' contains local stack allocation {}{}",
                                                target.as_str(),
                                                root,
                                                name_str
                                            ),
                                            inst.span,
                                        )
                                        .with_code("E0029"),
                                    );
                                }
                            }
                        }
                    }
                    crate::ir::ValueExpr::ChanSend { chan: _, val }
                    | crate::ir::ValueExpr::ChanTrySend { chan: _, val } => {
                        if let Some(&root) = local_pointers.get(val) {
                            if call_arena_allocs.contains_key(&root) {
                                errors.push(
                                    FirVerifyError::new(
                                        format!(
                                            "Thread-local call-arena allocation {} escapes across channel boundary",
                                            root
                                        ),
                                        inst.span,
                                    )
                                    .with_code("E0072"),
                                );
                            } else if let Some((_, name, _)) = alloca_info.get(&root) {
                                let name_str = name.map(|s| format!(" ('{}')", s.as_str())).unwrap_or_default();
                                errors.push(
                                    FirVerifyError::new(
                                        format!(
                                            "Local stack allocation {}{} escapes across channel boundary",
                                            root,
                                            name_str
                                        ),
                                        inst.span,
                                    )
                                    .with_code("E0072"),
                                );
                            }
                        } else if let Some(&root) = aggregates_with_local_ptrs.get(val) {
                            if call_arena_allocs.contains_key(&root) {
                                errors.push(
                                    FirVerifyError::new(
                                        format!(
                                            "Aggregate payload sent over channel contains thread-local call-arena allocation {}",
                                            root
                                        ),
                                        inst.span,
                                    )
                                    .with_code("E0072"),
                                );
                            } else if let Some((_, name, _)) = alloca_info.get(&root) {
                                let name_str = name.map(|s| format!(" ('{}')", s.as_str())).unwrap_or_default();
                                errors.push(
                                    FirVerifyError::new(
                                        format!(
                                            "Aggregate payload sent over channel contains local stack allocation {}{}",
                                            root,
                                            name_str
                                        ),
                                        inst.span,
                                    )
                                    .with_code("E0072"),
                                );
                            }
                        }
                    }
                    crate::ir::ValueExpr::Store { ptr, val } => {
                        // If storing a local pointer into a non-local pointer (e.g. parameter or heap location)
                        if !alloca_info.contains_key(ptr) && !local_pointers.contains_key(ptr) {
                            if let Some(&root) = local_pointers.get(val) {
                                if let Some((_, name, _)) = alloca_info.get(&root) {
                                    let name_str = name.map(|s| format!(" ('{}')", s.as_str())).unwrap_or_default();
                                    errors.push(
                                        FirVerifyError::new(
                                            format!(
                                                "Local stack allocation {}{} escapes into non-local memory location",
                                                root,
                                                name_str
                                            ),
                                            inst.span,
                                        )
                                        .with_code("E0020"),
                                    );
                                } else if call_arena_allocs.contains_key(&root) {
                                    errors.push(
                                        FirVerifyError::new(
                                            format!(
                                                "Thread-local call-arena allocation {} escapes into non-local memory location",
                                                root
                                            ),
                                            inst.span,
                                        )
                                        .with_code("E0020"),
                                    );
                                }
                            } else if let Some(&root) = aggregates_with_local_ptrs.get(val) {
                                if let Some((_, name, _)) = alloca_info.get(&root) {
                                    let name_str = name.map(|s| format!(" ('{}')", s.as_str())).unwrap_or_default();
                                    errors.push(
                                        FirVerifyError::new(
                                            format!(
                                                "Aggregate containing local stack allocation {}{} escapes into non-local memory location",
                                                root,
                                                name_str
                                            ),
                                            inst.span,
                                        )
                                        .with_code("E0020"),
                                    );
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Check terminators for escaping local allocations
            if let Some(Terminator::Return(Some(ret_val)) | Terminator::Fail(ret_val)) = &block.terminator {
                if let Some(&root) = local_pointers.get(ret_val) {
                    if call_arena_allocs.contains_key(&root) {
                        errors.push(
                            FirVerifyError::new(
                                format!(
                                    "Thread-local call-arena allocation {} escapes function frame through return",
                                    root
                                ),
                                func.span,
                            )
                            .with_code("E0025"),
                        );
                    } else if let Some((_, name, _)) = alloca_info.get(&root) {
                        let name_str = name.map(|s| format!(" ('{}')", s.as_str())).unwrap_or_default();
                        errors.push(
                            FirVerifyError::new(
                                format!(
                                    "Local stack allocation {}{} escapes function frame through return",
                                    root,
                                    name_str
                                ),
                                func.span,
                            )
                            .with_code("E0025"),
                        );
                    }
                } else if let Some(&root) = aggregates_with_local_ptrs.get(ret_val) {
                    if call_arena_allocs.contains_key(&root) {
                        errors.push(
                            FirVerifyError::new(
                                format!(
                                    "Aggregate value escaping through return contains thread-local call-arena allocation {}",
                                    root
                                ),
                                func.span,
                            )
                            .with_code("E0025"),
                        );
                    } else if let Some((_, name, _)) = alloca_info.get(&root) {
                        let name_str = name.map(|s| format!(" ('{}')", s.as_str())).unwrap_or_default();
                        errors.push(
                            FirVerifyError::new(
                                format!(
                                    "Aggregate value escaping through return contains local stack allocation {}{}",
                                    root,
                                    name_str
                                ),
                                func.span,
                            )
                            .with_code("E0025"),
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ConstantValue, FirFunction, FirParam, Instruction, Terminator, ValueExpr};
    use crate::types::FirType;
    use ifa_ast::ParamMode;
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    fn make_test_func(name: &str, params: Vec<FirParam>, ret_ty: FirType, is_strict: bool) -> FirFunction {
        FirFunction::new(
            INTERNER.intern(name),
            params,
            ret_ty,
            is_strict,
            false,
            false,
            None,
            Span::DUMMY,
        )
    }

    #[test]
    fn test_safe_stack_alloca_value_load_and_return() {
        let mut func = make_test_func("safe_fn", Vec::new(), FirType::Int(IntType::I32), false);
        let entry = func.get_block_mut(func.entry_block).unwrap();

        let v_alloca = ValueId(1);
        let v_const = ValueId(2);
        let v_loaded = ValueId(3);

        entry.push_instruction(Instruction::new(
            Some(v_alloca),
            ValueExpr::Alloca {
                ty: FirType::Int(IntType::I32),
                name: Some(INTERNER.intern("x")),
            },
            Span::DUMMY,
        ));
        entry.push_instruction(Instruction::new(
            Some(v_const),
            ValueExpr::Constant(ConstantValue::Int(42, IntType::I32)),
            Span::DUMMY,
        ));
        entry.push_instruction(Instruction::new(
            None,
            ValueExpr::Store {
                ptr: v_alloca,
                val: v_const,
            },
            Span::DUMMY,
        ));
        entry.push_instruction(Instruction::new(
            Some(v_loaded),
            ValueExpr::Load { ptr: v_alloca },
            Span::DUMMY,
        ));
        entry.set_terminator(Terminator::Return(Some(v_loaded)));

        let res = FirVerifier::verify_function(&func);
        assert!(res.is_ok(), "Expected verification to pass, got: {:?}", res);
    }

    #[test]
    fn test_escaping_alloca_direct_return() {
        let mut func = make_test_func("escape_ret", Vec::new(), FirType::Pointer(Box::new(FirType::Int(IntType::I32))), false);
        let entry = func.get_block_mut(func.entry_block).unwrap();

        let v_alloca = ValueId(1);
        entry.push_instruction(Instruction::new(
            Some(v_alloca),
            ValueExpr::Alloca {
                ty: FirType::Int(IntType::I32),
                name: Some(INTERNER.intern("local_var")),
            },
            Span::DUMMY,
        ));
        entry.set_terminator(Terminator::Return(Some(v_alloca)));

        let res = FirVerifier::verify_function(&func);
        assert!(res.is_err(), "Expected E0025 error for escaping alloca return");
        let errs = res.unwrap_err();
        assert!(
            errs.iter().any(|e| e.code.as_deref() == Some("E0025")),
            "Expected E0025 diagnostic, got: {:?}",
            errs
        );
    }

    #[test]
    fn test_escaping_alloca_via_gen_ref_return() {
        let mut func = make_test_func("escape_gen_ref", Vec::new(), FirType::GenerationalRef(Box::new(FirType::Int(IntType::I32))), false);
        let entry = func.get_block_mut(func.entry_block).unwrap();

        let v_alloca = ValueId(1);
        let v_ref = ValueId(2);

        entry.push_instruction(Instruction::new(
            Some(v_alloca),
            ValueExpr::Alloca {
                ty: FirType::Int(IntType::I32),
                name: Some(INTERNER.intern("data")),
            },
            Span::DUMMY,
        ));
        entry.push_instruction(Instruction::new(
            Some(v_ref),
            ValueExpr::GenRef { ptr: v_alloca },
            Span::DUMMY,
        ));
        entry.set_terminator(Terminator::Return(Some(v_ref)));

        let res = FirVerifier::verify_function(&func);
        assert!(res.is_err(), "Expected E0025 error for escaping gen ref");
        let errs = res.unwrap_err();
        assert!(
            errs.iter().any(|e| e.code.as_deref() == Some("E0025")),
            "Expected E0025 diagnostic, got: {:?}",
            errs
        );
    }

    #[test]
    fn test_escaping_alloca_via_struct_return() {
        let mut func = make_test_func("escape_struct", Vec::new(), FirType::Struct(INTERNER.intern("View"), Vec::new()), false);
        let entry = func.get_block_mut(func.entry_block).unwrap();

        let v_alloca = ValueId(1);
        let v_ref = ValueId(2);
        let v_struct = ValueId(3);

        entry.push_instruction(Instruction::new(
            Some(v_alloca),
            ValueExpr::Alloca {
                ty: FirType::Int(IntType::I32),
                name: Some(INTERNER.intern("elem")),
            },
            Span::DUMMY,
        ));
        entry.push_instruction(Instruction::new(
            Some(v_ref),
            ValueExpr::GenRef { ptr: v_alloca },
            Span::DUMMY,
        ));
        entry.push_instruction(Instruction::new(
            Some(v_struct),
            ValueExpr::StructInit {
                name: INTERNER.intern("View"),
                fields: vec![v_ref],
            },
            Span::DUMMY,
        ));
        entry.set_terminator(Terminator::Return(Some(v_struct)));

        let res = FirVerifier::verify_function(&func);
        assert!(res.is_err(), "Expected E0025 error for aggregate containing escaping ref");
        let errs = res.unwrap_err();
        assert!(
            errs.iter().any(|e| e.code.as_deref() == Some("E0025")),
            "Expected E0025 diagnostic, got: {:?}",
            errs
        );
    }

    #[test]
    fn test_escaping_alloca_spawn() {
        let mut func = make_test_func("escape_spawn", Vec::new(), FirType::Unit, false);
        let entry = func.get_block_mut(func.entry_block).unwrap();

        let v_alloca = ValueId(1);
        let v_ref = ValueId(2);
        let v_spawn = ValueId(3);

        entry.push_instruction(Instruction::new(
            Some(v_alloca),
            ValueExpr::Alloca {
                ty: FirType::Int(IntType::I32),
                name: Some(INTERNER.intern("shared_data")),
            },
            Span::DUMMY,
        ));
        entry.push_instruction(Instruction::new(
            Some(v_ref),
            ValueExpr::GenRef { ptr: v_alloca },
            Span::DUMMY,
        ));
        entry.push_instruction(Instruction::new(
            Some(v_spawn),
            ValueExpr::Spawn {
                target: INTERNER.intern("worker_fiber"),
                args: vec![v_ref],
            },
            Span::DUMMY,
        ));
        entry.set_terminator(Terminator::Return(None));

        let res = FirVerifier::verify_function(&func);
        assert!(res.is_err(), "Expected E0029 error for stack ref passed to spawn");
        let errs = res.unwrap_err();
        assert!(
            errs.iter().any(|e| e.code.as_deref() == Some("E0029")),
            "Expected E0029 diagnostic, got: {:?}",
            errs
        );
    }

    #[test]
    fn test_escaping_alloca_chan_send() {
        let mut func = make_test_func("escape_chan", Vec::new(), FirType::Unit, false);
        let entry = func.get_block_mut(func.entry_block).unwrap();

        let v_chan = ValueId(1);
        let v_alloca = ValueId(2);
        let v_ref = ValueId(3);

        entry.push_instruction(Instruction::new(
            Some(v_chan),
            ValueExpr::ChanCreate {
                elem_ty: FirType::GenerationalRef(Box::new(FirType::Int(IntType::I32))),
                capacity: None,
            },
            Span::DUMMY,
        ));
        entry.push_instruction(Instruction::new(
            Some(v_alloca),
            ValueExpr::Alloca {
                ty: FirType::Int(IntType::I32),
                name: Some(INTERNER.intern("msg_payload")),
            },
            Span::DUMMY,
        ));
        entry.push_instruction(Instruction::new(
            Some(v_ref),
            ValueExpr::GenRef { ptr: v_alloca },
            Span::DUMMY,
        ));
        entry.push_instruction(Instruction::new(
            None,
            ValueExpr::ChanSend {
                chan: v_chan,
                val: v_ref,
            },
            Span::DUMMY,
        ));
        entry.set_terminator(Terminator::Return(None));

        let res = FirVerifier::verify_function(&func);
        assert!(res.is_err(), "Expected E0072 error for stack ref sent over channel");
        let errs = res.unwrap_err();
        assert!(
            errs.iter().any(|e| e.code.as_deref() == Some("E0072")),
            "Expected E0072 diagnostic, got: {:?}",
            errs
        );
    }

    #[test]
    fn test_escaping_call_arena_return() {
        let mut func = make_test_func("escape_call_arena", Vec::new(), FirType::Pointer(Box::new(FirType::Int(IntType::I32))), false);
        let entry = func.get_block_mut(func.entry_block).unwrap();

        let v_arena = ValueId(1);
        entry.push_instruction(Instruction::new(
            Some(v_arena),
            ValueExpr::CallArenaAlloc {
                ty: FirType::Int(IntType::I32),
            },
            Span::DUMMY,
        ));
        entry.set_terminator(Terminator::Return(Some(v_arena)));

        let res = FirVerifier::verify_function(&func);
        assert!(res.is_err(), "Expected E0025 error for call arena alloc escaping return");
        let errs = res.unwrap_err();
        assert!(
            errs.iter().any(|e| e.code.as_deref() == Some("E0025")),
            "Expected E0025 diagnostic, got: {:?}",
            errs
        );
    }

    #[test]
    fn test_escaping_alloca_non_local_store() {
        let param = FirParam {
            name: INTERNER.intern("out_ptr"),
            val: ValueId(0),
            ty: FirType::Pointer(Box::new(FirType::Pointer(Box::new(FirType::Int(IntType::I32))))),
            mode: ParamMode::InOut,
            noalias: true,
        };
        let mut func = make_test_func("escape_store", vec![param], FirType::Unit, false);
        let entry = func.get_block_mut(func.entry_block).unwrap();

        let v_alloca = ValueId(1);
        entry.push_instruction(Instruction::new(
            Some(v_alloca),
            ValueExpr::Alloca {
                ty: FirType::Int(IntType::I32),
                name: Some(INTERNER.intern("local_val")),
            },
            Span::DUMMY,
        ));
        entry.push_instruction(Instruction::new(
            None,
            ValueExpr::Store {
                ptr: ValueId(0),
                val: v_alloca,
            },
            Span::DUMMY,
        ));
        entry.set_terminator(Terminator::Return(None));

        let res = FirVerifier::verify_function(&func);
        assert!(res.is_err(), "Expected E0020 error for local alloca stored to param");
        let errs = res.unwrap_err();
        assert!(
            errs.iter().any(|e| e.code.as_deref() == Some("E0020")),
            "Expected E0020 diagnostic, got: {:?}",
            errs
        );
    }
}

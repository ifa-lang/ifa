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
}

impl FirVerifyError {
    pub fn to_diagnostic(&self) -> Diagnostic {
        Diagnostic::error(format!("FIR verification error: {}", self.message))
            .with_code("E0600")
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
                errors.push(FirVerifyError {
                    message: format!("Block {} does not have a terminator", block.id),
                    span: func.span,
                });
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
                    errors.push(FirVerifyError {
                        message: format!("SSA violation: value {} is defined multiple times", val),
                        span: func.span,
                    });
                }
                def_block.insert(*val, block.id);
            }

            // Instruction results defined in block
            for inst in &block.instructions {
                if let Some(res) = inst.result {
                    if !defined_values.insert(res) {
                        errors.push(FirVerifyError {
                            message: format!(
                                "SSA violation: value {} is defined multiple times",
                                res
                            ),
                            span: inst.span,
                        });
                    }
                    def_block.insert(res, block.id);
                }

                // Strict function constraint check: zero-heap determinism mandates NO GenAlloc or CoWMakeUnique
                if func.is_strict {
                    match &inst.expr {
                        crate::ir::ValueExpr::GenAlloc { .. } => {
                            errors.push(FirVerifyError {
                                message: format!(
                                    "Strict function '{}' contains prohibited heap generational allocation (zero-heap violation)",
                                    func.name.as_str()
                                ),
                                span: inst.span,
                            });
                        }
                        crate::ir::ValueExpr::CoWMakeUnique { .. } => {
                            errors.push(FirVerifyError {
                                message: format!(
                                    "Strict function '{}' contains prohibited implicit Copy-on-Write clone (zero-heap determinism violation)",
                                    func.name.as_str()
                                ),
                                span: inst.span,
                            });
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
                        errors.push(FirVerifyError {
                            message: format!(
                                "Use of undefined value {} in block {}",
                                used, block.id
                            ),
                            span: inst.span,
                        });
                    } else if let Some(&d_block) = def_block.get(&used) {
                        // In SSA, definition must dominate use. If in the same block, definition must precede use.
                        if d_block != block.id && !dom_tree.dominates(d_block, block.id) {
                            errors.push(FirVerifyError {
                                message: format!(
                                    "SSA dominance violation: definition in {} does not dominate use in {}",
                                    d_block, block.id
                                ),
                                span: inst.span,
                            });
                        }
                    }
                }
            }

            // Check terminator uses and branch argument arities
            if let Some(term) = &block.terminator {
                for used in term.uses() {
                    if !defined_values.contains(&used) {
                        errors.push(FirVerifyError {
                            message: format!(
                                "Use of undefined value {} in terminator of block {}",
                                used, block.id
                            ),
                            span: func.span,
                        });
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
                errors.push(FirVerifyError {
                    message: format!(
                        "Branch to block {} passes {} arguments, but block expects {}",
                        target,
                        arg_count,
                        target_block.params.len()
                    ),
                    span,
                });
            }
        } else {
            errors.push(FirVerifyError {
                message: format!("Branch targets non-existent block {}", target),
                span,
            });
        }
    }
}

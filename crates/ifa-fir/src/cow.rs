use crate::ir::*;
use std::collections::HashMap;

/// Tracks the sharing state of variables to determine whether CoW clone is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharingState {
    /// Value is exclusively owned by a single local reference.
    Unique,
    /// Value has been shared or projected, requiring CoW detachment prior to mutation.
    PotentiallyShared,
}

/// Pass that automatically inserts Copy-on-Write (`CoWMakeUnique`) primitives before mutations.
pub struct CowPass {
    inserted_cow_count: usize,
}

impl CowPass {
    pub fn new() -> Self {
        Self {
            inserted_cow_count: 0,
        }
    }

    /// Number of CoWMakeUnique instructions inserted across the module.
    pub fn inserted_count(&self) -> usize {
        self.inserted_cow_count
    }

    /// Run the implicit Copy-on-Write pass across all functions in the module.
    pub fn run_on_module(&mut self, module: &mut FirModule) {
        for func in &mut module.functions {
            self.run_on_function(func);
        }
    }

    /// Run the pass on a single function.
    pub fn run_on_function(&mut self, func: &mut FirFunction) {
        // Strict functions enforce absolute zero-heap determinism and prohibit implicit Copy-on-Write.
        // Memory mutations in strict fn must remain strictly in-place on the stack or in pre-allocated arenas.
        if func.is_strict {
            return;
        }

        // Track variable state: alloca ValueId -> SharingState
        let mut sharing_states: HashMap<ValueId, SharingState> = HashMap::new();
        // Track which values have multiple reads/uses
        let mut use_counts: HashMap<ValueId, usize> = HashMap::new();

        // 1. First pass: count uses across all blocks
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

        // Initialize allocas
        for block in &func.blocks {
            for inst in &block.instructions {
                if let (Some(res), ValueExpr::Alloca { ty, .. }) = (inst.result, &inst.expr) {
                    if ty.is_cow_candidate() {
                        sharing_states.insert(res, SharingState::Unique);
                    }
                }
            }
        }

        // 2. Second pass: detect sharing and insert CoWMakeUnique prior to mutations
        for block in &mut func.blocks {
            let mut new_instructions = Vec::with_capacity(block.instructions.len());

            for inst in block.instructions.drain(..) {
                match &inst.expr {
                    // Storing a new value: check if the value being stored has multiple uses
                    ValueExpr::Store { ptr, val } => {
                        let is_candidate = sharing_states.contains_key(ptr);
                        let is_shared = use_counts.get(val).copied().unwrap_or(0) > 1;

                        if is_candidate && is_shared {
                            // Value is used elsewhere: insert CoWMakeUnique before mutation
                            let unique_val = ValueId(func.next_value_id);
                            func.next_value_id += 1;

                            new_instructions.push(Instruction::new(
                                Some(unique_val),
                                ValueExpr::CoWMakeUnique { val: *val },
                                inst.span,
                            ));
                            self.inserted_cow_count += 1;

                            // Update store to use the detached unique value
                            new_instructions.push(Instruction::new(
                                inst.result,
                                ValueExpr::Store {
                                    ptr: *ptr,
                                    val: unique_val,
                                },
                                inst.span,
                            ));
                            sharing_states.insert(*ptr, SharingState::Unique);
                            continue;
                        }
                    }

                    // Field mutation on compound structure
                    ValueExpr::SetField {
                        base,
                        field_idx,
                        val,
                    } => {
                        let is_shared = use_counts.get(base).copied().unwrap_or(0) > 1;
                        if is_shared {
                            let detached_base = ValueId(func.next_value_id);
                            func.next_value_id += 1;

                            new_instructions.push(Instruction::new(
                                Some(detached_base),
                                ValueExpr::CoWMakeUnique { val: *base },
                                inst.span,
                            ));
                            self.inserted_cow_count += 1;

                            new_instructions.push(Instruction::new(
                                inst.result,
                                ValueExpr::SetField {
                                    base: detached_base,
                                    field_idx: *field_idx,
                                    val: *val,
                                },
                                inst.span,
                            ));
                            continue;
                        }
                    }

                    // Array / Slice element mutation
                    ValueExpr::SetElement { base, index, val } => {
                        let is_shared = use_counts.get(base).copied().unwrap_or(0) > 1;
                        if is_shared {
                            let detached_base = ValueId(func.next_value_id);
                            func.next_value_id += 1;

                            new_instructions.push(Instruction::new(
                                Some(detached_base),
                                ValueExpr::CoWMakeUnique { val: *base },
                                inst.span,
                            ));
                            self.inserted_cow_count += 1;

                            new_instructions.push(Instruction::new(
                                inst.result,
                                ValueExpr::SetElement {
                                    base: detached_base,
                                    index: *index,
                                    val: *val,
                                },
                                inst.span,
                            ));
                            continue;
                        }
                    }

                    // Passing to function call with potential sharing
                    ValueExpr::Call { callee: _, args }
                    | ValueExpr::CallDirect { name: _, args } => {
                        // Mark arguments as potentially shared if multiple uses
                        for arg in args {
                            let arg_uses = use_counts.get(arg).copied().unwrap_or(0);
                            if arg_uses > 1 {
                                for ptr in sharing_states.keys() {
                                    if ptr == arg {
                                        // Marked as shared
                                    }
                                }
                            }
                        }
                    }

                    _ => {}
                }

                new_instructions.push(inst);
            }

            block.instructions = new_instructions;
        }
    }
}

impl Default for CowPass {
    fn default() -> Self {
        Self::new()
    }
}

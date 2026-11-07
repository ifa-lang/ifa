use crate::ir::*;
use ifa_span::INTERNER;
use std::collections::HashMap;

/// Statistics collected by the StringFoldPass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StringFoldStats {
    /// Number of FormatString expressions completely folded into static constant string literals.
    pub folded_format_strings: usize,
    /// Number of contiguous string constant segments merged into fewer segments.
    pub merged_string_segments: usize,
    /// Number of nested FormatString expressions flattened.
    pub flattened_concats: usize,
}

/// Optimizes SSA FIR by flattening nested string concatenations, fusing contiguous static
/// string segments, and constant folding pure format strings into interned literals.
pub struct StringFoldPass {
    stats: StringFoldStats,
}

impl StringFoldPass {
    /// Create a new string constant folding pass.
    pub fn new() -> Self {
        Self {
            stats: StringFoldStats::default(),
        }
    }

    /// Return statistics collected across all optimization passes.
    pub fn stats(&self) -> StringFoldStats {
        self.stats
    }

    /// Run the string constant folding pass on all functions in the module.
    pub fn run_on_module(&mut self, module: &mut FirModule) {
        for func in &mut module.functions {
            self.run_on_function(func);
        }
    }

    /// Run the string constant folding pass on a single FIR function.
    pub fn run_on_function(&mut self, func: &mut FirFunction) {
        let mut known_constants: HashMap<ValueId, ConstantValue> = HashMap::new();
        let mut known_format_strings: HashMap<ValueId, Vec<ValueId>> = HashMap::new();

        // 1. Initial collection of defined constants and format strings
        for block in &func.blocks {
            for inst in &block.instructions {
                if let Some(res) = inst.result {
                    match &inst.expr {
                        ValueExpr::Constant(c) => {
                            known_constants.insert(res, c.clone());
                        }
                        ValueExpr::FormatString(parts) => {
                            known_format_strings.insert(res, parts.clone());
                        }
                        _ => {}
                    }
                }
            }
        }

        let mut next_val_id = func.next_value_id;

        // 2. Iterate through blocks and fold/merge format strings
        for block in &mut func.blocks {
            let mut surviving_instructions = Vec::with_capacity(block.instructions.len());

            for mut inst in block.instructions.drain(..) {
                match &mut inst.expr {
                    ValueExpr::Constant(c) => {
                        if let Some(r) = inst.result {
                            known_constants.insert(r, c.clone());
                        }
                        surviving_instructions.push(inst);
                    }

                    ValueExpr::Binary {
                        op: BinaryOp::Add,
                        lhs,
                        rhs,
                    } => {
                        let c_lhs = known_constants.get(lhs);
                        let c_rhs = known_constants.get(rhs);

                        let is_string_add = matches!(c_lhs, Some(ConstantValue::String(_)))
                            || matches!(c_rhs, Some(ConstantValue::String(_)));

                        if is_string_add {
                            let str_lhs = c_lhs.and_then(Self::const_to_str);
                            let str_rhs = c_rhs.and_then(Self::const_to_str);

                            if let (Some(s1), Some(s2)) = (str_lhs, str_rhs) {
                                let merged = format!("{}{}", s1, s2);
                                let sym = INTERNER.intern(&merged);
                                inst.expr = ValueExpr::Constant(ConstantValue::String(sym));
                                if let Some(r) = inst.result {
                                    known_constants.insert(r, ConstantValue::String(sym));
                                }
                                self.stats.folded_format_strings += 1;
                            }
                        } else if let (
                            Some(ConstantValue::Int(i1, ty1)),
                            Some(ConstantValue::Int(i2, _)),
                        ) = (c_lhs, c_rhs)
                        {
                            let folded = i1.wrapping_add(*i2);
                            inst.expr = ValueExpr::Constant(ConstantValue::Int(folded, *ty1));
                            if let Some(r) = inst.result {
                                known_constants.insert(r, ConstantValue::Int(folded, *ty1));
                            }
                        }
                        surviving_instructions.push(inst);
                    }

                    ValueExpr::FormatString(parts) => {
                        // A. Flatten nested format string parts
                        let mut flat_parts = Vec::with_capacity(parts.len());
                        Self::flatten_parts(
                            parts,
                            &known_format_strings,
                            &mut flat_parts,
                            &mut self.stats,
                        );

                        // B. Merge contiguous static string segments
                        let mut reduced_parts = Vec::new();
                        let mut current_buf = String::new();
                        let mut segments_in_buf = 0;

                        for &p in &flat_parts {
                            if let Some(c) = known_constants.get(&p).and_then(Self::const_to_str) {
                                current_buf.push_str(&c);
                                segments_in_buf += 1;
                            } else {
                                if !current_buf.is_empty() {
                                    if segments_in_buf > 1 {
                                        self.stats.merged_string_segments += segments_in_buf - 1;
                                    }
                                    let sym = INTERNER.intern(&current_buf);
                                    let new_vid = ValueId(next_val_id);
                                    next_val_id += 1;
                                    surviving_instructions.push(Instruction::new(
                                        Some(new_vid),
                                        ValueExpr::Constant(ConstantValue::String(sym)),
                                        inst.span,
                                    ));
                                    known_constants.insert(new_vid, ConstantValue::String(sym));
                                    reduced_parts.push(new_vid);
                                    current_buf.clear();
                                    segments_in_buf = 0;
                                }
                                reduced_parts.push(p);
                            }
                        }

                        if !current_buf.is_empty() {
                            if segments_in_buf > 1 {
                                self.stats.merged_string_segments += segments_in_buf - 1;
                            }
                            let sym = INTERNER.intern(&current_buf);
                            let new_vid = ValueId(next_val_id);
                            next_val_id += 1;
                            surviving_instructions.push(Instruction::new(
                                Some(new_vid),
                                ValueExpr::Constant(ConstantValue::String(sym)),
                                inst.span,
                            ));
                            known_constants.insert(new_vid, ConstantValue::String(sym));
                            reduced_parts.push(new_vid);
                            current_buf.clear();
                        }

                        // C. Analyze resulting parts: full fold vs partial merge
                        if reduced_parts.is_empty() {
                            let sym = INTERNER.intern("");
                            inst.expr = ValueExpr::Constant(ConstantValue::String(sym));
                            if let Some(r) = inst.result {
                                known_constants.insert(r, ConstantValue::String(sym));
                            }
                            self.stats.folded_format_strings += 1;
                            surviving_instructions.push(inst);
                        } else if reduced_parts.len() == 1
                            && known_constants.contains_key(&reduced_parts[0])
                        {
                            let const_val = known_constants[&reduced_parts[0]].clone();
                            inst.expr = ValueExpr::Constant(const_val.clone());
                            if let Some(r) = inst.result {
                                known_constants.insert(r, const_val);
                            }
                            self.stats.folded_format_strings += 1;
                            surviving_instructions.push(inst);
                        } else {
                            inst.expr = ValueExpr::FormatString(reduced_parts.clone());
                            if let Some(r) = inst.result {
                                known_format_strings.insert(r, reduced_parts);
                            }
                            surviving_instructions.push(inst);
                        }
                    }

                    _ => {
                        surviving_instructions.push(inst);
                    }
                }
            }

            block.instructions = surviving_instructions;
        }

        func.next_value_id = next_val_id;
    }

    fn flatten_parts(
        parts: &[ValueId],
        known_format_strings: &HashMap<ValueId, Vec<ValueId>>,
        out: &mut Vec<ValueId>,
        stats: &mut StringFoldStats,
    ) {
        for &p in parts {
            if let Some(sub_parts) = known_format_strings.get(&p) {
                stats.flattened_concats += 1;
                Self::flatten_parts(sub_parts, known_format_strings, out, stats);
            } else {
                out.push(p);
            }
        }
    }

    fn const_to_str(c: &ConstantValue) -> Option<String> {
        match c {
            ConstantValue::String(s) => Some(INTERNER.resolve(s)),
            ConstantValue::Int(i, _) => Some(i.to_string()),
            ConstantValue::Float(f, _) => Some(f.to_string()),
            ConstantValue::Bool(b) => Some(b.to_string()),
            ConstantValue::Char(c) => Some(c.to_string()),
            _ => None,
        }
    }
}

impl Default for StringFoldPass {
    fn default() -> Self {
        Self::new()
    }
}

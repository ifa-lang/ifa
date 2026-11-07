use crate::ir::*;
use std::fmt::{self, Write};

/// Pretty printer for FIR modules and functions.
pub struct FirPrinter<'a> {
    indent_level: usize,
    output: &'a mut String,
}

impl<'a> FirPrinter<'a> {
    pub fn new(output: &'a mut String) -> Self {
        Self {
            indent_level: 0,
            output,
        }
    }

    fn indent(&mut self) {
        for _ in 0..self.indent_level {
            self.output.push_str("  ");
        }
    }

    pub fn print_module(&mut self, module: &FirModule) -> fmt::Result {
        writeln!(self.output, "fir.module @{} {{", module.name.as_str())?;
        self.indent_level += 1;

        for st in &module.structs {
            self.indent();
            writeln!(self.output, "struct @{} {{", st.name.as_str())?;
            self.indent_level += 1;
            for (fname, fty) in &st.fields {
                self.indent();
                writeln!(self.output, "{}: {},", fname.as_str(), fty)?;
            }
            self.indent_level -= 1;
            self.indent();
            writeln!(self.output, "}}\n")?;
        }

        for func in &module.functions {
            self.print_function(func)?;
            writeln!(self.output)?;
        }

        self.indent_level -= 1;
        writeln!(self.output, "}}")?;
        Ok(())
    }

    pub fn print_function(&mut self, func: &FirFunction) -> fmt::Result {
        self.indent();
        if func.is_strict {
            write!(self.output, "strict ")?;
        }
        if func.is_pub {
            write!(self.output, "pub ")?;
        }
        write!(self.output, "fir.func @{}(", func.name.as_str())?;
        for (i, p) in func.params.iter().enumerate() {
            if i > 0 {
                write!(self.output, ", ")?;
            }
            if p.mode != ifa_ast::ParamMode::In {
                write!(self.output, "{} ", p.mode)?;
            }
            write!(self.output, "{}: {}", p.val, p.ty)?;
        }
        writeln!(self.output, ") -> {} {{", func.ret_ty)?;

        self.indent_level += 1;
        for block in &func.blocks {
            self.print_block(block)?;
        }
        self.indent_level -= 1;

        self.indent();
        writeln!(self.output, "}}")?;
        Ok(())
    }

    pub fn print_block(&mut self, block: &BasicBlock) -> fmt::Result {
        self.indent();
        write!(self.output, "{}(", block.id)?;
        for (i, (val, ty)) in block.params.iter().enumerate() {
            if i > 0 {
                write!(self.output, ", ")?;
            }
            write!(self.output, "{}: {}", val, ty)?;
        }
        writeln!(self.output, "):")?;

        self.indent_level += 1;
        if let Some(hint) = &block.vector_hint {
            self.indent();
            writeln!(
                self.output,
                "// [vector_hint: width={}, interleave={}]",
                hint.vector_width, hint.interleave_count
            )?;
        }
        for inst in &block.instructions {
            self.indent();
            self.print_instruction(inst)?;
            writeln!(self.output)?;
        }

        if let Some(term) = &block.terminator {
            self.indent();
            self.print_terminator(term)?;
            writeln!(self.output)?;
        }
        self.indent_level -= 1;
        Ok(())
    }

    fn print_instruction(&mut self, inst: &Instruction) -> fmt::Result {
        if let Some(res) = inst.result {
            write!(self.output, "{} = ", res)?;
        }

        match &inst.expr {
            ValueExpr::Constant(c) => write!(self.output, "const {}", c),
            ValueExpr::Alloca { ty, name } => {
                if let Some(sym) = name {
                    write!(self.output, "alloca {} \"{}\"", ty, sym.as_str())
                } else {
                    write!(self.output, "alloca {}", ty)
                }
            }
            ValueExpr::Load { ptr } => write!(self.output, "load {}", ptr),
            ValueExpr::Store { ptr, val } => write!(self.output, "store {}, {}", ptr, val),
            ValueExpr::Binary { op, lhs, rhs } => write!(self.output, "{} {}, {}", op, lhs, rhs),
            ValueExpr::Unary { op, val } => write!(self.output, "{} {}", op, val),
            ValueExpr::GetField {
                base,
                field_idx,
                field_name,
            } => write!(
                self.output,
                "getfield {}.{} (#{})",
                base,
                field_name.as_str(),
                field_idx
            ),
            ValueExpr::SetField {
                base,
                field_idx,
                val,
            } => write!(self.output, "setfield {}.#{}, {}", base, field_idx, val),
            ValueExpr::GetElement { base, index } => {
                write!(self.output, "getelem {}[{}]", base, index)
            }
            ValueExpr::SetElement { base, index, val } => {
                write!(self.output, "setelem {}[{}], {}", base, index, val)
            }
            ValueExpr::Call { callee, args } => {
                write!(self.output, "call {}(", callee)?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        write!(self.output, ", ")?;
                    }
                    write!(self.output, "{}", a)?;
                }
                write!(self.output, ")")
            }
            ValueExpr::CallDirect { name, args } => {
                write!(self.output, "call @{}(", name.as_str())?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        write!(self.output, ", ")?;
                    }
                    write!(self.output, "{}", a)?;
                }
                write!(self.output, ")")
            }
            ValueExpr::StructInit { name, fields } => {
                write!(self.output, "struct @{}(", name.as_str())?;
                for (i, f) in fields.iter().enumerate() {
                    if i > 0 {
                        write!(self.output, ", ")?;
                    }
                    write!(self.output, "{}", f)?;
                }
                write!(self.output, ")")
            }
            ValueExpr::TupleInit(fields) => {
                write!(self.output, "tuple(")?;
                for (i, f) in fields.iter().enumerate() {
                    if i > 0 {
                        write!(self.output, ", ")?;
                    }
                    write!(self.output, "{}", f)?;
                }
                write!(self.output, ")")
            }
            ValueExpr::ArrayInit(elements) => {
                write!(self.output, "array(")?;
                for (i, e) in elements.iter().enumerate() {
                    if i > 0 {
                        write!(self.output, ", ")?;
                    }
                    write!(self.output, "{}", e)?;
                }
                write!(self.output, ")")
            }
            ValueExpr::ArrayPush { array, val } => {
                write!(self.output, "array.push {}, {}", array, val)
            }
            ValueExpr::ArrayLen { array } => {
                write!(self.output, "array.len {}", array)
            }
            ValueExpr::SliceSub { base, start, end } => {
                write!(self.output, "slicesub {}, {}, {}", base, start, end)
            }
            ValueExpr::StructPushField {
                base,
                field_idx,
                val,
            } => {
                write!(
                    self.output,
                    "struct.push_field {}.#{}, {}",
                    base, field_idx, val
                )
            }
            ValueExpr::CoWMakeUnique { val } => write!(self.output, "cow.make_unique {}", val),
            ValueExpr::CoWCheckShared { val } => write!(self.output, "cow.is_shared {}", val),
            ValueExpr::CoWClone { val } => write!(self.output, "cow.clone {}", val),
            ValueExpr::GenAlloc { ty, arena } => {
                if let Some(a) = arena {
                    write!(self.output, "gen.alloc {} in arena {}", ty, a)
                } else {
                    write!(self.output, "gen.alloc {}", ty)
                }
            }
            ValueExpr::GenFree { ptr } => write!(self.output, "gen.free {}", ptr),
            ValueExpr::GenRef { ptr } => write!(self.output, "gen.ref {}", ptr),
            ValueExpr::GenCheck { ref_val, redundant } => {
                if *redundant {
                    write!(self.output, "gen.check {} [eliminated]", ref_val)
                } else {
                    write!(self.output, "gen.check {}", ref_val)
                }
            }
            ValueExpr::GenDeref { ref_val } => write!(self.output, "gen.deref {}", ref_val),
            ValueExpr::Yield => write!(self.output, "yield"),
            ValueExpr::Spawn { target, args } => {
                write!(self.output, "spawn @{}(", target.as_str())?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        write!(self.output, ", ")?;
                    }
                    write!(self.output, "{}", a)?;
                }
                write!(self.output, ")")
            }
            ValueExpr::ChanCreate { elem_ty, capacity } => {
                if let Some(cap) = capacity {
                    write!(self.output, "chan.create <{}>, cap: {}", elem_ty, cap)
                } else {
                    write!(self.output, "chan.create <{}>", elem_ty)
                }
            }
            ValueExpr::ChanSend { chan, val } => {
                write!(self.output, "chan.send {}, {}", chan, val)
            }
            ValueExpr::ChanRecv { chan } => write!(self.output, "chan.recv {}", chan),
            ValueExpr::ChanTryRecv { chan } => write!(self.output, "chan.try_recv {}", chan),
            ValueExpr::ChanClose { chan } => write!(self.output, "chan.close {}", chan),
            ValueExpr::ChanSelect {
                channels,
                has_default,
            } => {
                write!(self.output, "chan.select [")?;
                for (i, c) in channels.iter().enumerate() {
                    if i > 0 {
                        write!(self.output, ", ")?;
                    }
                    write!(self.output, "{}", c)?;
                }
                write!(
                    self.output,
                    "]{}",
                    if *has_default { " (default)" } else { "" }
                )
            }
            ValueExpr::EnumInit {
                enum_name,
                variant,
                discriminant,
                payload,
            } => {
                if let Some(p) = payload {
                    write!(
                        self.output,
                        "enum.init {}::{} (disc: {}, payload: {})",
                        enum_name.as_str(),
                        variant.as_str(),
                        discriminant,
                        p
                    )
                } else {
                    write!(
                        self.output,
                        "enum.init {}::{} (disc: {})",
                        enum_name.as_str(),
                        variant.as_str(),
                        discriminant
                    )
                }
            }
            ValueExpr::EnumGetDiscriminant { base } => {
                write!(self.output, "enum.get_disc {}", base)
            }
            ValueExpr::EnumGetPayload { base, payload_ty } => {
                write!(self.output, "enum.get_payload {} as {}", base, payload_ty)
            }
        }
    }

    fn print_terminator(&mut self, term: &Terminator) -> fmt::Result {
        match term {
            Terminator::Branch { target, args } => {
                write!(self.output, "br {}(", target)?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        write!(self.output, ", ")?;
                    }
                    write!(self.output, "{}", a)?;
                }
                write!(self.output, ")")
            }
            Terminator::BranchCond {
                cond,
                then_block,
                then_args,
                else_block,
                else_args,
            } => {
                write!(self.output, "br_cond {}, {}(", cond, then_block)?;
                for (i, a) in then_args.iter().enumerate() {
                    if i > 0 {
                        write!(self.output, ", ")?;
                    }
                    write!(self.output, "{}", a)?;
                }
                write!(self.output, "), {}(", else_block)?;
                for (i, a) in else_args.iter().enumerate() {
                    if i > 0 {
                        write!(self.output, ", ")?;
                    }
                    write!(self.output, "{}", a)?;
                }
                write!(self.output, ")")
            }
            Terminator::Switch {
                val,
                cases,
                default_block,
                default_args,
            } => {
                writeln!(self.output, "switch {} [", val)?;
                self.indent_level += 1;
                for (c, b, args) in cases {
                    self.indent();
                    write!(self.output, "{}: {}(", c, b)?;
                    for (i, a) in args.iter().enumerate() {
                        if i > 0 {
                            write!(self.output, ", ")?;
                        }
                        write!(self.output, "{}", a)?;
                    }
                    writeln!(self.output, "),")?;
                }
                self.indent();
                write!(self.output, "default: {}(", default_block)?;
                for (i, a) in default_args.iter().enumerate() {
                    if i > 0 {
                        write!(self.output, ", ")?;
                    }
                    write!(self.output, "{}", a)?;
                }
                writeln!(self.output, ")")?;
                self.indent_level -= 1;
                self.indent();
                write!(self.output, "]")
            }
            Terminator::Return(Some(val)) => write!(self.output, "ret {}", val),
            Terminator::Return(None) => write!(self.output, "ret"),
            Terminator::Fail(val) => write!(self.output, "fail {}", val),
            Terminator::Unreachable => write!(self.output, "unreachable"),
        }
    }
}

/// Helper function to format a FIR module as a String.
pub fn format_module(module: &FirModule) -> String {
    let mut out = String::new();
    let mut printer = FirPrinter::new(&mut out);
    let _ = printer.print_module(module);
    out
}

/// Helper function to format a FIR function as a String.
pub fn format_function(func: &FirFunction) -> String {
    let mut out = String::new();
    let mut printer = FirPrinter::new(&mut out);
    let _ = printer.print_function(func);
    out
}

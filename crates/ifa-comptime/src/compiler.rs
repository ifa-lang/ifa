use crate::error::{ComptimeError, ComptimeErrorKind};
use crate::op::{Chunk, OpCode};
use crate::value::Value;
use ifa_ast::{BinOp, Block, Expr, ExprKind, Function, Lit, Pattern, Stmt, UnaryOp};
use ifa_span::{sym, Span, Symbol, INTERNER};

/// Compiled bytecode function ready for execution by `ComptimeVM`.
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionBytecode {
    pub name: Symbol,
    pub is_comptime: bool,
    pub params: Vec<Symbol>,
    pub chunk: Chunk,
    pub num_locals: usize,
    pub span: Span,
}

#[derive(Debug, Clone)]
struct LocalScope {
    locals: Vec<(Symbol, u32)>,
}

/// AST-to-Bytecode compiler for IFA compile-time expressions and functions.
pub struct Compiler {
    scopes: Vec<LocalScope>,
    next_slot: u32,
    chunk: Chunk,
}

impl Default for Compiler {
    fn default() -> Self {
        Self::new()
    }
}

impl Compiler {
    pub fn new() -> Self {
        Self {
            scopes: vec![LocalScope { locals: Vec::new() }],
            next_slot: 0,
            chunk: Chunk::new(),
        }
    }

    fn push_scope(&mut self) {
        self.scopes.push(LocalScope { locals: Vec::new() });
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }

    fn define_local(&mut self, name: Symbol) -> u32 {
        let slot = self.next_slot;
        self.next_slot += 1;
        if let Some(scope) = self.scopes.last_mut() {
            scope.locals.push((name, slot));
        }
        slot
    }

    fn resolve_local(&self, name: &Symbol) -> Option<u32> {
        for scope in self.scopes.iter().rev() {
            for (var_name, slot) in scope.locals.iter().rev() {
                if var_name == name {
                    return Some(*slot);
                }
            }
        }
        None
    }

    /// Compiles a single expression into a self-contained chunk.
    pub fn compile_expr_to_chunk(expr: &Expr) -> Result<Chunk, ComptimeError> {
        let mut compiler = Compiler::new();
        compiler.compile_expr(expr)?;
        compiler.chunk.emit(OpCode::Return, expr.span);
        Ok(compiler.chunk)
    }

    /// Compiles an IFA function into a `FunctionBytecode`.
    pub fn compile_function(func: &Function) -> Result<FunctionBytecode, ComptimeError> {
        let mut compiler = Compiler::new();
        let mut param_symbols = Vec::new();

        // Parameters occupy slots 0..params.len()
        for p in &func.params {
            compiler.define_local(p.name);
            param_symbols.push(p.name);
        }

        if let Some(body) = &func.body {
            compiler.compile_block(body)?;
            // If block has a trailing expr, it leaves the return value on stack.
            // If not, push Unit.
            if body.expr.is_none() {
                compiler.chunk.emit(OpCode::Unit, body.span);
            }
            compiler.chunk.emit(OpCode::Return, body.span);
        } else {
            compiler.chunk.emit(OpCode::Unit, func.span);
            compiler.chunk.emit(OpCode::Return, func.span);
        }

        Ok(FunctionBytecode {
            name: func.name,
            is_comptime: func.is_comptime,
            params: param_symbols,
            chunk: compiler.chunk,
            num_locals: compiler.next_slot as usize,
            span: func.span,
        })
    }

    pub fn compile_block(&mut self, block: &Block) -> Result<(), ComptimeError> {
        self.push_scope();

        for stmt in &block.stmts {
            self.compile_stmt(stmt)?;
        }

        if let Some(expr) = &block.expr {
            self.compile_expr(expr)?;
        }

        self.pop_scope();
        Ok(())
    }

    pub fn compile_stmt(&mut self, stmt: &Stmt) -> Result<(), ComptimeError> {
        match stmt {
            Stmt::Let {
                pattern,
                init,
                span,
                ..
            } => {
                if let Some(val_expr) = init {
                    self.compile_expr(val_expr)?;
                } else {
                    self.chunk.emit(OpCode::Unit, *span);
                }
                if let Pattern::Ident(name, _) = pattern {
                    let slot = self.define_local(*name);
                    self.chunk.emit(OpCode::StoreLocal(slot), *span);
                } else {
                    for (sym, _) in pattern.bound_variables() {
                        let slot = self.define_local(sym);
                        self.chunk.emit(OpCode::StoreLocal(slot), *span);
                    }
                }
            }
            Stmt::Assign {
                target, val, span, ..
            } => match &target.kind {
                ExprKind::Ident(sym) => {
                    self.compile_expr(val)?;
                    if let Some(slot) = self.resolve_local(sym) {
                        self.chunk.emit(OpCode::StoreLocal(slot), *span);
                    } else {
                        self.chunk.emit(OpCode::StoreGlobal(*sym), *span);
                    }
                }
                ExprKind::Index { receiver, index } => {
                    if let ExprKind::Ident(target_sym) = &receiver.kind {
                        if let Some(slot) = self.resolve_local(target_sym) {
                            self.chunk.emit(OpCode::LoadLocal(slot), receiver.span);
                            self.compile_expr(index)?;
                            self.compile_expr(val)?;
                            self.chunk.emit(OpCode::SetIndex, *span);
                            self.chunk.emit(OpCode::StoreLocal(slot), *span);
                        } else {
                            self.chunk
                                .emit(OpCode::LoadGlobal(*target_sym), receiver.span);
                            self.compile_expr(index)?;
                            self.compile_expr(val)?;
                            self.chunk.emit(OpCode::SetIndex, *span);
                            self.chunk.emit(OpCode::StoreGlobal(*target_sym), *span);
                        }
                    } else {
                        return Err(ComptimeError::new(
                            ComptimeErrorKind::InvalidAssignmentTarget,
                            *span,
                        ));
                    }
                }
                ExprKind::FieldAccess {
                    receiver, field, ..
                } => {
                    if let ExprKind::Ident(target_sym) = &receiver.kind {
                        if let Some(slot) = self.resolve_local(target_sym) {
                            self.chunk.emit(OpCode::LoadLocal(slot), receiver.span);
                            self.compile_expr(val)?;
                            self.chunk.emit(OpCode::SetField(*field), *span);
                            self.chunk.emit(OpCode::StoreLocal(slot), *span);
                        } else {
                            self.chunk
                                .emit(OpCode::LoadGlobal(*target_sym), receiver.span);
                            self.compile_expr(val)?;
                            self.chunk.emit(OpCode::SetField(*field), *span);
                            self.chunk.emit(OpCode::StoreGlobal(*target_sym), *span);
                        }
                    } else {
                        return Err(ComptimeError::new(
                            ComptimeErrorKind::InvalidAssignmentTarget,
                            *span,
                        ));
                    }
                }
                _ => {
                    return Err(ComptimeError::new(
                        ComptimeErrorKind::InvalidAssignmentTarget,
                        *span,
                    ));
                }
            },
            Stmt::While { cond, body, span } => {
                let loop_start = self.chunk.code.len();
                self.compile_expr(cond)?;
                let exit_jump = self.chunk.emit_jump(OpCode::JumpIfFalse(0), cond.span);

                self.compile_block(body)?;
                // Discard trailing expression of loop block if any
                if body.expr.is_some() {
                    self.chunk.emit(OpCode::Pop, body.span);
                }

                self.chunk.emit_jump(OpCode::Jump(loop_start), *span);
                self.chunk.patch_jump(exit_jump);
            }
            Stmt::For {
                var,
                iterable,
                body,
                span,
            } => {
                // Compile iterator expression: leaves array on stack
                self.compile_expr(iterable)?;
                let arr_slot = self.define_local(sym("__comptime_for_arr"));
                self.chunk.emit(OpCode::StoreLocal(arr_slot), iterable.span);

                let idx_slot = self.define_local(sym("__comptime_for_idx"));
                self.chunk.emit(OpCode::ConstInt(0), *span);
                self.chunk.emit(OpCode::StoreLocal(idx_slot), *span);

                let loop_start = self.chunk.code.len();
                // Check idx < len(arr)
                self.chunk.emit(OpCode::LoadLocal(idx_slot), *span);
                self.chunk.emit(OpCode::LoadLocal(arr_slot), *span);
                self.chunk.emit(OpCode::ArrayLen, *span);
                self.chunk.emit(OpCode::Lt, *span);
                let exit_jump = self.chunk.emit_jump(OpCode::JumpIfFalse(0), *span);

                // var = arr[idx]
                self.push_scope();
                let var_slot = self.define_local(*var);
                self.chunk.emit(OpCode::LoadLocal(arr_slot), *span);
                self.chunk.emit(OpCode::LoadLocal(idx_slot), *span);
                self.chunk.emit(OpCode::GetIndex, *span);
                self.chunk.emit(OpCode::StoreLocal(var_slot), *span);

                self.compile_block(body)?;
                if body.expr.is_some() {
                    self.chunk.emit(OpCode::Pop, body.span);
                }
                self.pop_scope();

                // idx += 1
                self.chunk.emit(OpCode::LoadLocal(idx_slot), *span);
                self.chunk.emit(OpCode::ConstInt(1), *span);
                self.chunk.emit(OpCode::Add, *span);
                self.chunk.emit(OpCode::StoreLocal(idx_slot), *span);

                self.chunk.emit_jump(OpCode::Jump(loop_start), *span);
                self.chunk.patch_jump(exit_jump);
            }
            Stmt::Loop(body, span) => {
                let loop_start = self.chunk.code.len();
                self.compile_block(body)?;
                if body.expr.is_some() {
                    self.chunk.emit(OpCode::Pop, body.span);
                }
                self.chunk.emit_jump(OpCode::Jump(loop_start), *span);
            }
            Stmt::Return(opt_expr, span) => {
                if let Some(expr) = opt_expr {
                    self.compile_expr(expr)?;
                } else {
                    self.chunk.emit(OpCode::Unit, *span);
                }
                self.chunk.emit(OpCode::Return, *span);
            }
            Stmt::Expr(expr) => {
                self.compile_expr(expr)?;
                self.chunk.emit(OpCode::Pop, expr.span);
            }
            Stmt::Break(span) | Stmt::Continue(span) => {
                return Err(ComptimeError::new(
                    ComptimeErrorKind::CompileError(
                        "break/continue direct non encore branché dans cette version du compilateur comptime"
                            .to_string(),
                    ),
                    *span,
                ));
            }
            Stmt::Fail(expr, _span) => {
                self.compile_expr(expr)?;
                self.chunk.emit(OpCode::CompileError, expr.span);
            }
            Stmt::Defer(_, _) => {
                // Defer is evaluated at runtime function exit, ignored in strict pure comptime
            }
            Stmt::WhileLet { span, .. } => {
                return Err(ComptimeError::new(
                    ComptimeErrorKind::CompileError(
                        "boucle 'while let' non encore supportée en contexte comptime".to_string(),
                    ),
                    *span,
                ));
            }
        }
        Ok(())
    }

    pub fn compile_expr(&mut self, expr: &Expr) -> Result<(), ComptimeError> {
        match &expr.kind {
            ExprKind::Lit(lit) => match lit {
                Lit::Int(sym) => {
                    let text = INTERNER.resolve(sym);
                    let val = parse_int_literal(&text);
                    self.chunk.emit(OpCode::ConstInt(val), expr.span);
                }
                Lit::Float(sym) => {
                    let text = INTERNER.resolve(sym);
                    let val = parse_float_literal(&text);
                    let idx = self.chunk.add_constant(Value::Float(val));
                    self.chunk.emit(OpCode::Const(idx), expr.span);
                }
                Lit::Bool(b) => {
                    self.chunk.emit(OpCode::ConstBool(*b), expr.span);
                }
                Lit::Char(c) => {
                    let idx = self.chunk.add_constant(Value::Char(*c));
                    self.chunk.emit(OpCode::Const(idx), expr.span);
                }
                Lit::String(sym) => {
                    let text = INTERNER.resolve(sym);
                    let unescaped = unescape_string(&text);
                    let idx = self.chunk.add_constant(Value::String(unescaped));
                    self.chunk.emit(OpCode::Const(idx), expr.span);
                }
                Lit::Null => {
                    let idx = self.chunk.add_constant(Value::Option(None));
                    self.chunk.emit(OpCode::Const(idx), expr.span);
                }
            },
            ExprKind::Ident(sym) => {
                if let Some(slot) = self.resolve_local(sym) {
                    self.chunk.emit(OpCode::LoadLocal(slot), expr.span);
                } else {
                    self.chunk.emit(OpCode::LoadGlobal(*sym), expr.span);
                }
            }
            ExprKind::Path(path) => {
                if let Some(last) = path.last() {
                    self.chunk.emit(OpCode::LoadGlobal(*last), expr.span);
                } else {
                    self.chunk.emit(OpCode::Unit, expr.span);
                }
            }
            ExprKind::Binary { op, left, right } => match op {
                BinOp::And => {
                    // Short-circuiting AND: if left is false, skip right
                    self.compile_expr(left)?;
                    self.chunk.emit(OpCode::Dup, expr.span);
                    let jump = self.chunk.emit_jump(OpCode::JumpIfFalse(0), expr.span);
                    self.chunk.emit(OpCode::Pop, expr.span);
                    self.compile_expr(right)?;
                    self.chunk.patch_jump(jump);
                }
                BinOp::Or | BinOp::Coalesce => {
                    // Short-circuiting OR / COALESCE: if left is true/some, skip right
                    self.compile_expr(left)?;
                    self.chunk.emit(OpCode::Dup, expr.span);
                    let jump = self.chunk.emit_jump(OpCode::JumpIfTrue(0), expr.span);
                    self.chunk.emit(OpCode::Pop, expr.span);
                    self.compile_expr(right)?;
                    self.chunk.patch_jump(jump);
                }
                _ => {
                    self.compile_expr(left)?;
                    self.compile_expr(right)?;
                    let opcode = match op {
                        BinOp::Add => OpCode::Add,
                        BinOp::Sub => OpCode::Sub,
                        BinOp::Mul => OpCode::Mul,
                        BinOp::Div => OpCode::Div,
                        BinOp::Rem => OpCode::Mod,
                        BinOp::Eq => OpCode::Eq,
                        BinOp::NotEq => OpCode::NotEq,
                        BinOp::Lt => OpCode::Lt,
                        BinOp::LtEq => OpCode::LtEq,
                        BinOp::Gt => OpCode::Gt,
                        BinOp::GtEq => OpCode::GtEq,
                        BinOp::BitAnd => OpCode::BitAnd,
                        BinOp::BitOr => OpCode::BitOr,
                        BinOp::BitXor => OpCode::BitXor,
                        BinOp::Shl => OpCode::Shl,
                        BinOp::Shr => OpCode::Shr,
                        BinOp::And | BinOp::Or | BinOp::Coalesce => unreachable!(),
                    };
                    self.chunk.emit(opcode, expr.span);
                }
            },
            ExprKind::Unary { op, expr: inner } => {
                self.compile_expr(inner)?;
                match op {
                    UnaryOp::Neg => {
                        self.chunk.emit(OpCode::Neg, expr.span);
                    }
                    UnaryOp::Not => {
                        self.chunk.emit(OpCode::Not, expr.span);
                    }
                    UnaryOp::Try | UnaryOp::InOut | UnaryOp::Ref | UnaryOp::Sink => {
                        // In comptime, value passes through directly
                    }
                }
            }
            ExprKind::If {
                cond,
                then_branch,
                else_branch,
            } => {
                self.compile_expr(cond)?;
                let false_jump = self.chunk.emit_jump(OpCode::JumpIfFalse(0), cond.span);

                self.compile_block(then_branch)?;
                if then_branch.expr.is_none() {
                    self.chunk.emit(OpCode::Unit, then_branch.span);
                }

                let end_jump = self.chunk.emit_jump(OpCode::Jump(0), expr.span);
                self.chunk.patch_jump(false_jump);

                if let Some(else_expr) = else_branch {
                    self.compile_expr(else_expr)?;
                } else {
                    self.chunk.emit(OpCode::Unit, expr.span);
                }

                self.chunk.patch_jump(end_jump);
            }
            ExprKind::Array(elems) => {
                for elem in elems {
                    self.compile_expr(elem)?;
                }
                self.chunk
                    .emit(OpCode::MakeArray(elems.len() as u32), expr.span);
            }
            ExprKind::ArrayRepeat(val, count) => {
                self.compile_expr(val)?;
                self.compile_expr(count)?;
                self.chunk.emit(OpCode::MakeArrayRepeat, expr.span);
            }
            ExprKind::Index { receiver, index } => {
                self.compile_expr(receiver)?;
                self.compile_expr(index)?;
                self.chunk.emit(OpCode::GetIndex, expr.span);
            }
            ExprKind::FieldAccess {
                receiver, field, ..
            } => {
                self.compile_expr(receiver)?;
                self.chunk.emit(OpCode::GetField(*field), expr.span);
            }
            ExprKind::StructInit { name, fields } => {
                let struct_name = *name.last().unwrap_or(&sym("__comptime_anon"));
                let mut field_names = Vec::new();
                for (fname, fexpr) in fields {
                    self.compile_expr(fexpr)?;
                    field_names.push(*fname);
                }
                self.chunk
                    .emit(OpCode::MakeStruct(struct_name, field_names), expr.span);
            }
            ExprKind::Tuple(items) => {
                for item in items {
                    self.compile_expr(item)?;
                }
                self.chunk
                    .emit(OpCode::MakeTuple(items.len() as u32), expr.span);
            }
            ExprKind::Call { callee, args } => {
                let func_name = match &callee.kind {
                    ExprKind::Ident(sym) => *sym,
                    ExprKind::Path(path) => *path.last().unwrap(),
                    _ => {
                        return Err(ComptimeError::new(
                            ComptimeErrorKind::CompileError(
                                "appel indirect non supporté en comptime".to_string(),
                            ),
                            callee.span,
                        ));
                    }
                };

                for arg in args {
                    self.compile_expr(&arg.value)?;
                }

                let name_str = INTERNER.resolve(&func_name);
                match name_str.as_str() {
                    "assert" | "compile_error" | "len" | "type_of" | "crc32" | "hex_encode"
                    | "json_validate" => {
                        self.chunk.emit(
                            OpCode::CallIntrinsic {
                                name: func_name,
                                arg_count: args.len() as u32,
                            },
                            expr.span,
                        );
                    }
                    _ => {
                        self.chunk.emit(
                            OpCode::Call {
                                func_name,
                                arg_count: args.len() as u32,
                            },
                            expr.span,
                        );
                    }
                }
            }
            ExprKind::Block(b) => {
                self.compile_block(b)?;
                if b.expr.is_none() {
                    self.chunk.emit(OpCode::Unit, b.span);
                }
            }
            ExprKind::Comptime(inner) => {
                self.compile_expr(inner)?;
            }
            ExprKind::Unit => {
                self.chunk.emit(OpCode::Unit, expr.span);
            }
            ExprKind::Catch { expr: inner, .. } => {
                self.compile_expr(inner)?;
            }
            ExprKind::Spawn(inner) => {
                self.compile_expr(inner)?;
            }
            _ => {
                return Err(ComptimeError::new(
                    ComptimeErrorKind::CompileError(format!(
                        "expression non supportée à la compilation: {:?}",
                        expr.kind
                    )),
                    expr.span,
                ));
            }
        }
        Ok(())
    }
}

fn strip_type_suffix(s: &str) -> &str {
    for suffix in [
        "u128", "i128", "u64", "i64", "u32", "i32", "u16", "i16", "u8", "i8", "f64", "f32",
        "usize", "isize",
    ] {
        if let Some(stripped) = s.strip_suffix(suffix) {
            return stripped;
        }
    }
    s
}

fn unescape_string(s: &str) -> String {
    let mut res = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                match next {
                    'n' => res.push('\n'),
                    't' => res.push('\t'),
                    'r' => res.push('\r'),
                    '\\' => res.push('\\'),
                    '"' => res.push('"'),
                    '\'' => res.push('\''),
                    _ => {
                        res.push('\\');
                        res.push(next);
                    }
                }
            } else {
                res.push('\\');
            }
        } else {
            res.push(c);
        }
    }
    res
}

fn parse_int_literal(text: &str) -> i64 {
    let clean = text.trim();
    let stripped = strip_type_suffix(clean).replace('_', "");
    if stripped.starts_with("0x") || stripped.starts_with("0X") {
        i64::from_str_radix(&stripped[2..], 16)
            .unwrap_or_else(|_| u64::from_str_radix(&stripped[2..], 16).unwrap_or(0) as i64)
    } else if stripped.starts_with("0b") || stripped.starts_with("0B") {
        i64::from_str_radix(&stripped[2..], 2).unwrap_or(0)
    } else if stripped.starts_with("0o") || stripped.starts_with("0O") {
        i64::from_str_radix(&stripped[2..], 8).unwrap_or(0)
    } else {
        stripped
            .parse::<i64>()
            .unwrap_or_else(|_| stripped.parse::<u64>().unwrap_or(0) as i64)
    }
}

fn parse_float_literal(text: &str) -> f64 {
    let clean = text.trim();
    let stripped = strip_type_suffix(clean).replace('_', "");
    stripped.parse::<f64>().unwrap_or(0.0)
}

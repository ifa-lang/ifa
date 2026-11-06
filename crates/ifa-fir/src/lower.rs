use crate::ir::*;
use crate::types::FirType;
use ifa_ast::{BinOp, Expr, ExprKind, Item, Lit, Program, Stmt, UnaryOp};
use ifa_sema::types::{FloatType, IntType};
use ifa_sema::SymbolTable;
use ifa_span::{Span, Symbol, INTERNER};
use std::collections::HashMap;

/// Loop control flow contexts for break and continue statements.
#[derive(Debug, Clone)]
struct LoopContext {
    continue_block: BlockId,
    break_block: BlockId,
}

/// Context for lowering a single function AST into FIR SSA.
struct FunctionLoweringContext<'a> {
    func: FirFunction,
    current_block: BlockId,
    /// Maps source variables to their alloca pointer in SSA FIR
    var_allocas: HashMap<Symbol, ValueId>,
    /// Maps source variables to their FIR type
    var_types: HashMap<Symbol, FirType>,
    symbols: &'a SymbolTable,
    constants: &'a HashMap<Symbol, &'a Expr>,
    loop_stack: Vec<LoopContext>,
}

impl<'a> FunctionLoweringContext<'a> {
    fn new(
        func_ast: &ifa_ast::Function,
        symbols: &'a SymbolTable,
        constants: &'a HashMap<Symbol, &'a Expr>,
    ) -> Self {
        let ret_ty = func_ast
            .ret_ty
            .as_ref()
            .map(|_t| {
                if let Some(sema_ty) = symbols.lookup_function(&func_ast.name) {
                    FirType::from_sema_type(&sema_ty.ret_ty)
                } else {
                    FirType::Unit
                }
            })
            .unwrap_or(FirType::Unit);

        let mut next_val = 0;
        let mut params = Vec::new();

        for p in &func_ast.params {
            let val = ValueId(next_val);
            next_val += 1;
            let ty = if let Some(sym_fn) = symbols.lookup_function(&func_ast.name) {
                sym_fn
                    .params
                    .iter()
                    .find(|ps| ps.name == p.name)
                    .map(|ps| FirType::from_sema_type(&ps.ty))
                    .unwrap_or(FirType::Unit)
            } else {
                FirType::Unit
            };
            params.push(FirParam {
                name: p.name,
                val,
                ty,
                mode: p.mode,
            });
        }

        let mut func = FirFunction::new(
            func_ast.name,
            params,
            ret_ty,
            func_ast.is_strict,
            func_ast.is_pub,
            func_ast.is_comptime,
            func_ast.is_extern.clone(),
            func_ast.span,
        );
        func.next_value_id = next_val;

        let entry = func.entry_block;

        Self {
            func,
            current_block: entry,
            var_allocas: HashMap::new(),
            var_types: HashMap::new(),
            symbols,
            constants,
            loop_stack: Vec::new(),
        }
    }

    fn alloc_value(&mut self) -> ValueId {
        self.func.alloc_value()
    }

    fn alloc_block(&mut self) -> BlockId {
        self.func.alloc_block()
    }

    fn emit(&mut self, res: Option<ValueId>, expr: ValueExpr, span: Span) -> Option<ValueId> {
        let inst = Instruction::new(res, expr, span);
        if let Some(block) = self.func.get_block_mut(self.current_block) {
            block.push_instruction(inst);
        }
        res
    }

    fn set_terminator(&mut self, term: Terminator) {
        if let Some(block) = self.func.get_block_mut(self.current_block) {
            if !block.is_terminated() {
                block.set_terminator(term);
            }
        }
    }

    fn extract_field_index_from_fir_type(&self, ty: &FirType, field: Symbol) -> Option<usize> {
        match ty {
            FirType::Struct(name, fields) => {
                if let Some(pos) = fields.iter().position(|(f_name, _)| *f_name == field) {
                    Some(pos)
                } else if let Some(st) = self.symbols.lookup_struct(name) {
                    st.field_indices.get(&field).copied()
                } else {
                    None
                }
            }
            FirType::GenerationalRef(inner)
            | FirType::Pointer(inner)
            | FirType::Optional(inner) => self.extract_field_index_from_fir_type(inner, field),
            _ => None,
        }
    }

    fn infer_expr_fir_type(&self, expr: &Expr) -> Option<FirType> {
        match &expr.kind {
            ExprKind::Ident(sym) => {
                if let Some(ty) = self.var_types.get(sym) {
                    return Some(ty.clone());
                }
                if let Some(var) = self.symbols.lookup_variable(sym) {
                    return Some(FirType::from_sema_type(&var.ty));
                }
                None
            }
            ExprKind::FieldAccess { receiver, field } => {
                let rec_ty = self.infer_expr_fir_type(receiver)?;
                let mut current = &rec_ty;
                while let FirType::GenerationalRef(inner)
                | FirType::Pointer(inner)
                | FirType::Optional(inner) = current
                {
                    current = inner;
                }
                let st_name = match current {
                    FirType::Struct(name, _) => *name,
                    _ => return None,
                };
                if let Some(st) = self.symbols.lookup_struct(&st_name) {
                    if let Some(f) = st.fields.iter().find(|f| f.name == *field) {
                        return Some(FirType::from_sema_type(&f.ty));
                    }
                }
                None
            }
            ExprKind::Lit(lit) => match lit {
                Lit::Int(_) => Some(FirType::Int(IntType::I64)),
                Lit::Float(_) => Some(FirType::Float(FloatType::F64)),
                Lit::Bool(_) => Some(FirType::Bool),
                Lit::String(_) => Some(FirType::String),
                Lit::Char(_) => Some(FirType::Int(IntType::U32)),
            },
            ExprKind::Unary {
                op: UnaryOp::Ref,
                expr,
            } => {
                let inner = self.infer_expr_fir_type(expr)?;
                Some(FirType::GenerationalRef(Box::new(inner)))
            }
            ExprKind::StructInit { name, .. } => {
                let sym = name.last().copied()?;
                if let Some(st) = self.symbols.lookup_struct(&sym) {
                    let fields = st
                        .fields
                        .iter()
                        .map(|f| (f.name, FirType::from_sema_type(&f.ty)))
                        .collect();
                    Some(FirType::Struct(sym, fields))
                } else {
                    Some(FirType::Struct(sym, Vec::new()))
                }
            }
            ExprKind::Call { callee, .. } => {
                if let ExprKind::Ident(fn_name) = &callee.kind {
                    self.symbols
                        .lookup_function(fn_name)
                        .map(|func| FirType::from_sema_type(&func.ret_ty))
                } else {
                    None
                }
            }
            ExprKind::Binary { op, left, .. } => match op {
                BinOp::Eq
                | BinOp::NotEq
                | BinOp::Lt
                | BinOp::LtEq
                | BinOp::Gt
                | BinOp::GtEq
                | BinOp::And
                | BinOp::Or => Some(FirType::Bool),
                _ => self.infer_expr_fir_type(left),
            },
            ExprKind::Index { receiver, .. } => {
                let rec_ty = self.infer_expr_fir_type(receiver)?;
                match rec_ty {
                    FirType::Array(elem, _) | FirType::Slice(elem) => Some(*elem),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn find_field_index(&self, receiver_expr: &Expr, field: Symbol) -> usize {
        // 1. Try to infer receiver type directly
        if let Some(fir_ty) = self.infer_expr_fir_type(receiver_expr) {
            if let Some(idx) = self.extract_field_index_from_fir_type(&fir_ty, field) {
                return idx;
            }
        }
        // 2. Check receiver variable type in local scope
        if let ExprKind::Ident(rec_sym) = &receiver_expr.kind {
            if let Some(fir_ty) = self.var_types.get(rec_sym) {
                if let Some(idx) = self.extract_field_index_from_fir_type(fir_ty, field) {
                    return idx;
                }
            }
            if let Some(var_sym) = self.symbols.lookup_variable(rec_sym) {
                let fir_ty = FirType::from_sema_type(&var_sym.ty);
                if let Some(idx) = self.extract_field_index_from_fir_type(&fir_ty, field) {
                    return idx;
                }
            }
        }
        // 3. Fallback: Lookup in struct definitions in symbol table
        for st in self.symbols.structs.values() {
            if let Some(&idx) = st.field_indices.get(&field) {
                return idx;
            }
        }
        0
    }

    fn lower(mut self, body: &ifa_ast::Block) -> FirFunction {
        // 1. In entry block, create allocas for parameters and store incoming values
        let entry_params = self.func.params.clone();
        for p in entry_params {
            if p.mode == ifa_ast::ParamMode::InOut {
                // InOut parameter is an l-value pointer projection passed directly by the caller
                self.var_allocas.insert(p.name, p.val);
                self.var_types.insert(p.name, p.ty);
            } else {
                let ptr_val = self.alloc_value();
                self.emit(
                    Some(ptr_val),
                    ValueExpr::Alloca {
                        ty: p.ty.clone(),
                        name: Some(p.name),
                    },
                    self.func.span,
                );
                self.emit(
                    None,
                    ValueExpr::Store {
                        ptr: ptr_val,
                        val: p.val,
                    },
                    self.func.span,
                );
                self.var_allocas.insert(p.name, ptr_val);
                self.var_types.insert(p.name, p.ty);
            }
        }

        // 2. Lower all statements in the body
        for stmt in &body.stmts {
            self.lower_stmt(stmt);
        }

        // 3. Lower optional trailing expression as return
        if let Some(trailing_expr) = &body.expr {
            let ret_val = self.lower_expr(trailing_expr);
            self.set_terminator(Terminator::Return(Some(ret_val)));
        } else if let Some(block) = self.func.get_block(self.current_block) {
            if !block.is_terminated() {
                self.set_terminator(Terminator::Return(None));
            }
        }

        self.func
    }

    fn lower_stmt(&mut self, stmt: &Stmt) {
        if let Some(block) = self.func.get_block(self.current_block) {
            if block.is_terminated() {
                return;
            }
        }

        match stmt {
            Stmt::Let {
                name, init, span, ..
            } => {
                let init_val = init.as_ref().map(|e| self.lower_expr(e));
                let ty = if let Some(init_expr) = init {
                    if let Some(inferred) = self.infer_expr_fir_type(init_expr) {
                        inferred
                    } else if let Some(var_sym) = self.symbols.lookup_variable(name) {
                        FirType::from_sema_type(&var_sym.ty)
                    } else {
                        init_val
                            .map(|_| FirType::Int(IntType::I64))
                            .unwrap_or(FirType::Unit)
                    }
                } else if let Some(var_sym) = self.symbols.lookup_variable(name) {
                    FirType::from_sema_type(&var_sym.ty)
                } else {
                    FirType::Unit
                };

                let ptr = self.alloc_value();
                self.emit(
                    Some(ptr),
                    ValueExpr::Alloca {
                        ty: ty.clone(),
                        name: Some(*name),
                    },
                    *span,
                );

                if let Some(val) = init_val {
                    self.emit(None, ValueExpr::Store { ptr, val }, *span);
                }

                self.var_allocas.insert(*name, ptr);
                self.var_types.insert(*name, ty);
            }

            Stmt::Assign {
                target, val, span, ..
            } => {
                let val_id = self.lower_expr(val);
                match &target.kind {
                    ExprKind::Ident(sym) => {
                        if let Some(&ptr) = self.var_allocas.get(sym) {
                            self.emit(None, ValueExpr::Store { ptr, val: val_id }, *span);
                        }
                    }
                    ExprKind::FieldAccess { receiver, field } => {
                        let field_idx = self.find_field_index(receiver, *field);
                        let base_id = match &receiver.kind {
                            ExprKind::Ident(sym) => self
                                .var_allocas
                                .get(sym)
                                .copied()
                                .unwrap_or_else(|| self.lower_expr(receiver)),
                            _ => self.lower_expr(receiver),
                        };
                        self.emit(
                            None,
                            ValueExpr::SetField {
                                base: base_id,
                                field_idx,
                                val: val_id,
                            },
                            *span,
                        );
                    }
                    ExprKind::Index { receiver, index } => {
                        let base_id = match &receiver.kind {
                            ExprKind::Ident(sym) => self
                                .var_allocas
                                .get(sym)
                                .copied()
                                .unwrap_or_else(|| self.lower_expr(receiver)),
                            _ => self.lower_expr(receiver),
                        };
                        let idx_id = self.lower_expr(index);
                        self.emit(
                            None,
                            ValueExpr::SetElement {
                                base: base_id,
                                index: idx_id,
                                val: val_id,
                            },
                            *span,
                        );
                    }
                    _ => {}
                }
            }

            Stmt::Expr(expr) => {
                let _ = self.lower_expr(expr);
            }

            Stmt::Return(opt_expr, _) => {
                let ret_val = opt_expr.as_ref().map(|e| self.lower_expr(e));
                self.set_terminator(Terminator::Return(ret_val));
            }

            Stmt::Fail(expr, _) => {
                let fail_val = self.lower_expr(expr);
                self.set_terminator(Terminator::Fail(fail_val));
            }

            Stmt::While {
                cond,
                body,
                span: _,
            } => {
                let cond_block = self.alloc_block();
                let body_block = self.alloc_block();
                let exit_block = self.alloc_block();

                self.set_terminator(Terminator::Branch {
                    target: cond_block,
                    args: Vec::new(),
                });

                // Condition block
                self.current_block = cond_block;
                let cond_val = self.lower_expr(cond);
                self.set_terminator(Terminator::BranchCond {
                    cond: cond_val,
                    then_block: body_block,
                    then_args: Vec::new(),
                    else_block: exit_block,
                    else_args: Vec::new(),
                });

                // Body block
                self.current_block = body_block;
                self.loop_stack.push(LoopContext {
                    continue_block: cond_block,
                    break_block: exit_block,
                });

                for s in &body.stmts {
                    self.lower_stmt(s);
                }
                if let Some(trailing) = &body.expr {
                    let _ = self.lower_expr(trailing);
                }

                if let Some(b) = self.func.get_block(self.current_block) {
                    if !b.is_terminated() {
                        self.set_terminator(Terminator::Branch {
                            target: cond_block,
                            args: Vec::new(),
                        });
                    }
                }
                self.loop_stack.pop();

                // Exit block
                self.current_block = exit_block;
            }

            Stmt::Loop(body, _) => {
                let body_block = self.alloc_block();
                let exit_block = self.alloc_block();

                self.set_terminator(Terminator::Branch {
                    target: body_block,
                    args: Vec::new(),
                });

                self.current_block = body_block;
                self.loop_stack.push(LoopContext {
                    continue_block: body_block,
                    break_block: exit_block,
                });

                for s in &body.stmts {
                    self.lower_stmt(s);
                }

                if let Some(b) = self.func.get_block(self.current_block) {
                    if !b.is_terminated() {
                        self.set_terminator(Terminator::Branch {
                            target: body_block,
                            args: Vec::new(),
                        });
                    }
                }
                self.loop_stack.pop();
                self.current_block = exit_block;
            }

            Stmt::Break(_) => {
                if let Some(ctx) = self.loop_stack.last().cloned() {
                    self.set_terminator(Terminator::Branch {
                        target: ctx.break_block,
                        args: Vec::new(),
                    });
                }
            }

            Stmt::Continue(_) => {
                if let Some(ctx) = self.loop_stack.last().cloned() {
                    self.set_terminator(Terminator::Branch {
                        target: ctx.continue_block,
                        args: Vec::new(),
                    });
                }
            }

            Stmt::Defer(_, _) => {
                // Defers are lowered at block exit in reverse order
            }

            Stmt::For { .. } => {}
        }
    }

    fn lower_expr(&mut self, expr: &Expr) -> ValueId {
        let span = expr.span;
        match &expr.kind {
            ExprKind::Lit(lit) => {
                let res = self.alloc_value();
                let c = match lit {
                    Lit::Int(s) => {
                        let val: i128 = s.as_str().parse().unwrap_or(0);
                        ConstantValue::Int(val, IntType::I64)
                    }
                    Lit::Float(s) => {
                        let val: f64 = s.as_str().parse().unwrap_or(0.0);
                        ConstantValue::Float(val, FloatType::F64)
                    }
                    Lit::Bool(b) => ConstantValue::Bool(*b),
                    Lit::Char(c) => ConstantValue::Char(*c),
                    Lit::String(s) => ConstantValue::String(*s),
                };
                self.emit(Some(res), ValueExpr::Constant(c), span);
                res
            }

            ExprKind::Ident(sym) => {
                if let Some(&ptr) = self.var_allocas.get(sym) {
                    let res = self.alloc_value();
                    self.emit(Some(res), ValueExpr::Load { ptr }, span);
                    res
                } else if let Some(c_expr) = self.constants.get(sym) {
                    self.lower_expr(c_expr)
                } else {
                    let res = self.alloc_value();
                    self.emit(Some(res), ValueExpr::Constant(ConstantValue::Unit), span);
                    res
                }
            }

            ExprKind::Binary { op, left, right } => {
                let lhs = self.lower_expr(left);
                let rhs = self.lower_expr(right);
                let fir_op = match op {
                    BinOp::Add => BinaryOp::Add,
                    BinOp::Sub => BinaryOp::Sub,
                    BinOp::Mul => BinaryOp::Mul,
                    BinOp::Div => BinaryOp::Div,
                    BinOp::Rem => BinaryOp::Rem,
                    BinOp::Eq => BinaryOp::Eq,
                    BinOp::NotEq => BinaryOp::Ne,
                    BinOp::Lt => BinaryOp::Lt,
                    BinOp::LtEq => BinaryOp::Le,
                    BinOp::Gt => BinaryOp::Gt,
                    BinOp::GtEq => BinaryOp::Ge,
                    BinOp::And => BinaryOp::And,
                    BinOp::Or => BinaryOp::Or,
                    BinOp::BitAnd => BinaryOp::BitAnd,
                    BinOp::BitOr => BinaryOp::BitOr,
                    BinOp::BitXor => BinaryOp::BitXor,
                    BinOp::Shl => BinaryOp::Shl,
                    BinOp::Shr => BinaryOp::Shr,
                    BinOp::Coalesce => BinaryOp::Or,
                };
                let res = self.alloc_value();
                self.emit(
                    Some(res),
                    ValueExpr::Binary {
                        op: fir_op,
                        lhs,
                        rhs,
                    },
                    span,
                );
                res
            }

            ExprKind::Unary { op, expr } => {
                match op {
                    UnaryOp::Neg => {
                        let val = self.lower_expr(expr);
                        let res = self.alloc_value();
                        self.emit(
                            Some(res),
                            ValueExpr::Unary {
                                op: crate::ir::UnaryOp::Neg,
                                val,
                            },
                            span,
                        );
                        res
                    }
                    UnaryOp::Not => {
                        let val = self.lower_expr(expr);
                        let res = self.alloc_value();
                        self.emit(
                            Some(res),
                            ValueExpr::Unary {
                                op: crate::ir::UnaryOp::Not,
                                val,
                            },
                            span,
                        );
                        res
                    }
                    // Mot-clé `ref`: Création d'une référence générationnelle sûre (Section 9.2)
                    UnaryOp::Ref => {
                        let ptr = if let ExprKind::Ident(sym) = &expr.kind {
                            self.var_allocas
                                .get(sym)
                                .copied()
                                .unwrap_or_else(|| self.lower_expr(expr))
                        } else {
                            self.lower_expr(expr)
                        };
                        let res = self.alloc_value();
                        self.emit(Some(res), ValueExpr::GenRef { ptr }, span);
                        res
                    }
                    UnaryOp::InOut => {
                        // Inout projection passes l-value pointer
                        if let ExprKind::Ident(sym) = &expr.kind {
                            self.var_allocas
                                .get(sym)
                                .copied()
                                .unwrap_or_else(|| self.lower_expr(expr))
                        } else {
                            self.lower_expr(expr)
                        }
                    }
                    UnaryOp::Sink => self.lower_expr(expr),
                    UnaryOp::Try => self.lower_expr(expr),
                }
            }

            ExprKind::Call { callee, args } => {
                // Check if this is a List::new call
                if let ExprKind::Path(path) = &callee.kind {
                    if path.len() >= 2
                        && INTERNER.resolve(&path[0]) == "List"
                        && INTERNER.resolve(&path[1]) == "new"
                    {
                        let res = self.alloc_value();
                        self.emit(Some(res), ValueExpr::ArrayInit(Vec::new()), span);
                        return res;
                    }
                }

                let direct_name = match &callee.kind {
                    ExprKind::Ident(fn_name) => Some(*fn_name),
                    ExprKind::Path(path) => path.last().copied(),
                    ExprKind::FieldAccess { field, .. } => Some(*field),
                    _ => None,
                };

                // Check if calling a Struct constructor directly (e.g. WindowNode(id: ..., parent: ...))
                if let Some(struct_name) = direct_name {
                    if let Some(st) = self.symbols.lookup_struct(&struct_name) {
                        let mut ordered_fields = Vec::new();
                        for field_sym in &st.fields {
                            if let Some(arg) = args.iter().find(|a| a.name == Some(field_sym.name))
                            {
                                ordered_fields.push(self.lower_expr(&arg.value));
                            } else if let Some(idx) = st.field_indices.get(&field_sym.name) {
                                if let Some(arg) = args.get(*idx) {
                                    ordered_fields.push(self.lower_expr(&arg.value));
                                } else {
                                    let unit_val = self.alloc_value();
                                    self.emit(
                                        Some(unit_val),
                                        ValueExpr::Constant(ConstantValue::Unit),
                                        span,
                                    );
                                    ordered_fields.push(unit_val);
                                }
                            } else {
                                let unit_val = self.alloc_value();
                                self.emit(
                                    Some(unit_val),
                                    ValueExpr::Constant(ConstantValue::Unit),
                                    span,
                                );
                                ordered_fields.push(unit_val);
                            }
                        }
                        let res = self.alloc_value();
                        self.emit(
                            Some(res),
                            ValueExpr::StructInit {
                                name: struct_name,
                                fields: ordered_fields,
                            },
                            span,
                        );
                        return res;
                    }
                }

                let mut arg_vals = Vec::new();
                for a in args {
                    arg_vals.push(self.lower_expr(&a.value));
                }

                if let Some(fn_name) = direct_name {
                    let res = self.alloc_value();
                    self.emit(
                        Some(res),
                        ValueExpr::CallDirect {
                            name: fn_name,
                            args: arg_vals,
                        },
                        span,
                    );
                    res
                } else {
                    let callee_val = self.lower_expr(callee);
                    let res = self.alloc_value();
                    self.emit(
                        Some(res),
                        ValueExpr::Call {
                            callee: callee_val,
                            args: arg_vals,
                        },
                        span,
                    );
                    res
                }
            }

            ExprKind::MethodCall {
                receiver,
                method,
                args,
            } => {
                let m_name = INTERNER.resolve(method);
                if m_name == "push" && !args.is_empty() {
                    let val_to_push = self.lower_expr(&args[0].value);
                    let res = self.alloc_value();

                    match &receiver.kind {
                        ExprKind::FieldAccess {
                            receiver: inner_rec,
                            field: field_sym,
                        } => {
                            let field_idx = self.find_field_index(inner_rec, *field_sym);
                            let base_id = match &inner_rec.kind {
                                ExprKind::Ident(sym) => self
                                    .var_allocas
                                    .get(sym)
                                    .copied()
                                    .unwrap_or_else(|| self.lower_expr(inner_rec)),
                                _ => self.lower_expr(inner_rec),
                            };
                            self.emit(
                                Some(res),
                                ValueExpr::StructPushField {
                                    base: base_id,
                                    field_idx,
                                    val: val_to_push,
                                },
                                span,
                            );
                        }
                        ExprKind::Ident(sym) => {
                            let base_id = self
                                .var_allocas
                                .get(sym)
                                .copied()
                                .unwrap_or_else(|| self.lower_expr(receiver));
                            self.emit(
                                Some(res),
                                ValueExpr::ArrayPush {
                                    array: base_id,
                                    val: val_to_push,
                                },
                                span,
                            );
                        }
                        _ => {
                            let base_id = self.lower_expr(receiver);
                            self.emit(
                                Some(res),
                                ValueExpr::ArrayPush {
                                    array: base_id,
                                    val: val_to_push,
                                },
                                span,
                            );
                        }
                    }
                    res
                } else if m_name == "len" {
                    let base_id = self.lower_expr(receiver);
                    let res = self.alloc_value();
                    self.emit(Some(res), ValueExpr::ArrayLen { array: base_id }, span);
                    res
                } else {
                    let mut arg_vals = vec![self.lower_expr(receiver)];
                    for a in args {
                        arg_vals.push(self.lower_expr(&a.value));
                    }
                    let res = self.alloc_value();
                    self.emit(
                        Some(res),
                        ValueExpr::CallDirect {
                            name: *method,
                            args: arg_vals,
                        },
                        span,
                    );
                    res
                }
            }

            ExprKind::FieldAccess { receiver, field } => {
                let base_val = self.lower_expr(receiver);
                // Si le récepteur est une référence ref, émettre GenCheck et GenDeref
                let checked_base = if let ExprKind::Unary {
                    op: UnaryOp::Ref, ..
                } = &receiver.kind
                {
                    self.emit(
                        None,
                        ValueExpr::GenCheck {
                            ref_val: base_val,
                            redundant: false,
                        },
                        span,
                    );
                    let deref_res = self.alloc_value();
                    self.emit(
                        Some(deref_res),
                        ValueExpr::GenDeref { ref_val: base_val },
                        span,
                    );
                    deref_res
                } else {
                    base_val
                };

                let field_idx = self.find_field_index(receiver, *field);

                let res = self.alloc_value();
                self.emit(
                    Some(res),
                    ValueExpr::GetField {
                        base: checked_base,
                        field_idx,
                        field_name: *field,
                    },
                    span,
                );
                res
            }

            ExprKind::Index { receiver, index } => {
                let base = self.lower_expr(receiver);
                let idx = self.lower_expr(index);
                let res = self.alloc_value();
                self.emit(Some(res), ValueExpr::GetElement { base, index: idx }, span);
                res
            }

            ExprKind::If {
                cond,
                then_branch,
                else_branch,
            } => {
                let cond_val = self.lower_expr(cond);
                let then_block = self.alloc_block();
                let else_block = self.alloc_block();
                let merge_block = self.alloc_block();

                self.set_terminator(Terminator::BranchCond {
                    cond: cond_val,
                    then_block,
                    then_args: Vec::new(),
                    else_block,
                    else_args: Vec::new(),
                });

                // Then branch
                self.current_block = then_block;
                for s in &then_branch.stmts {
                    self.lower_stmt(s);
                }
                let then_val = then_branch.expr.as_ref().map(|e| self.lower_expr(e));
                let then_end_block = self.current_block;
                let then_reaches_merge = self
                    .func
                    .get_block(then_end_block)
                    .is_some_and(|b| !b.is_terminated());

                // Else branch
                self.current_block = else_block;
                let else_val = else_branch
                    .as_ref()
                    .map(|else_expr| self.lower_expr(else_expr));
                let else_end_block = self.current_block;
                let else_reaches_merge = self
                    .func
                    .get_block(else_end_block)
                    .is_some_and(|b| !b.is_terminated());

                let has_phi = else_branch.is_some()
                    && then_val.is_some()
                    && else_val.is_some()
                    && then_reaches_merge
                    && else_reaches_merge;

                let res = self.alloc_value();

                // Branch from then_end_block if not terminated
                if then_reaches_merge {
                    let args = if has_phi {
                        vec![then_val.unwrap()]
                    } else {
                        Vec::new()
                    };
                    self.current_block = then_end_block;
                    self.set_terminator(Terminator::Branch {
                        target: merge_block,
                        args,
                    });
                }

                // Branch from else_end_block if not terminated
                if else_reaches_merge {
                    let args = if has_phi {
                        vec![else_val.unwrap()]
                    } else {
                        Vec::new()
                    };
                    self.current_block = else_end_block;
                    self.set_terminator(Terminator::Branch {
                        target: merge_block,
                        args,
                    });
                }

                // Merge block
                self.current_block = merge_block;
                if let Some(mb) = self.func.get_block_mut(merge_block) {
                    if has_phi {
                        mb.push_param(res, FirType::Int(IntType::I64));
                    }
                }
                if !has_phi {
                    self.emit(Some(res), ValueExpr::Constant(ConstantValue::Unit), span);
                }
                res
            }

            ExprKind::Block(b) => {
                for s in &b.stmts {
                    self.lower_stmt(s);
                }
                if let Some(e) = &b.expr {
                    self.lower_expr(e)
                } else {
                    let res = self.alloc_value();
                    self.emit(Some(res), ValueExpr::Constant(ConstantValue::Unit), span);
                    res
                }
            }

            ExprKind::StructInit { name, fields } => {
                let mut field_vals = Vec::new();
                for (_, f_expr) in fields {
                    field_vals.push(self.lower_expr(f_expr));
                }
                let sym_name = name
                    .last()
                    .copied()
                    .unwrap_or_else(|| INTERNER.intern("Struct"));
                let res = self.alloc_value();
                self.emit(
                    Some(res),
                    ValueExpr::StructInit {
                        name: sym_name,
                        fields: field_vals,
                    },
                    span,
                );
                res
            }

            ExprKind::Array(elements) => {
                let mut elem_vals = Vec::new();
                for e in elements {
                    elem_vals.push(self.lower_expr(e));
                }
                let res = self.alloc_value();
                self.emit(Some(res), ValueExpr::ArrayInit(elem_vals), span);
                res
            }

            ExprKind::ArrayRepeat(val_expr, count_expr) => {
                let count: usize = if let ExprKind::Lit(Lit::Int(s)) = &count_expr.kind {
                    s.as_str().parse().unwrap_or(0)
                } else {
                    0
                };
                let mut elem_vals = Vec::with_capacity(count);
                for _ in 0..count {
                    elem_vals.push(self.lower_expr(val_expr));
                }
                let res = self.alloc_value();
                self.emit(Some(res), ValueExpr::ArrayInit(elem_vals), span);
                res
            }

            ExprKind::Tuple(elements) => {
                let mut elem_vals = Vec::new();
                for e in elements {
                    elem_vals.push(self.lower_expr(e));
                }
                let res = self.alloc_value();
                self.emit(Some(res), ValueExpr::TupleInit(elem_vals), span);
                res
            }

            ExprKind::Spawn(e) => {
                let _ = self.lower_expr(e);
                let res = self.alloc_value();
                let sym = INTERNER.intern("task");
                self.emit(
                    Some(res),
                    ValueExpr::Spawn {
                        target: sym,
                        args: Vec::new(),
                    },
                    span,
                );
                res
            }

            ExprKind::Comptime(inner) => self.lower_expr(inner),

            ExprKind::Unit => {
                let res = self.alloc_value();
                self.emit(Some(res), ValueExpr::Constant(ConstantValue::Unit), span);
                res
            }

            _ => {
                let res = self.alloc_value();
                self.emit(Some(res), ValueExpr::Constant(ConstantValue::Unit), span);
                res
            }
        }
    }
}

/// Lowers an entire parsed and semantically analyzed IFA program into a FIR module.
pub fn lower_program(program: &Program, symbols: &SymbolTable) -> FirModule {
    let module_name = INTERNER.intern("main");
    let mut module = FirModule::new(module_name);

    let mut constants = HashMap::new();
    for item in &program.items {
        if let Item::Const(c) = item {
            constants.insert(c.name, &c.value);
        }
    }

    for item in &program.items {
        match item {
            Item::Function(func_ast) => {
                if let Some(body) = &func_ast.body {
                    let ctx = FunctionLoweringContext::new(func_ast, symbols, &constants);
                    let fir_func = ctx.lower(body);
                    module.functions.push(fir_func);
                }
            }
            Item::Struct(s_ast) => {
                let struct_sym = symbols.lookup_struct(&s_ast.name);
                let fields = if let Some(st) = struct_sym {
                    st.fields
                        .iter()
                        .map(|f| (f.name, FirType::from_sema_type(&f.ty)))
                        .collect()
                } else {
                    s_ast
                        .fields
                        .iter()
                        .map(|f| (f.name, FirType::Int(IntType::I64)))
                        .collect()
                };
                module.structs.push(FirStruct {
                    name: s_ast.name,
                    fields,
                    is_pub: s_ast.is_pub,
                    span: s_ast.span,
                });
            }
            Item::Enum(e_ast) => {
                let variants = e_ast.variants.iter().map(|v| (v.name, None)).collect();
                module.enums.push(FirEnum {
                    name: e_ast.name,
                    variants,
                    is_pub: e_ast.is_pub,
                    span: e_ast.span,
                });
            }
            _ => {}
        }
    }

    module
}

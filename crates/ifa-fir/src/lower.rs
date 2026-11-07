use crate::ir::*;
use crate::types::FirType;
use ifa_ast::{
    BinOp, Block, Expr, ExprKind, Item, Lit, Pattern, Program, SelectArm, Stmt, UnaryOp,
};
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
    type_subst: HashMap<Symbol, ifa_sema::types::Type>,
    module_structs: &'a [FirStruct],
    module_enums: &'a [FirEnum],
    defer_stack: Vec<Block>,
}

impl<'a> FunctionLoweringContext<'a> {
    fn new(
        func_ast: &ifa_ast::Function,
        symbols: &'a SymbolTable,
        constants: &'a HashMap<Symbol, &'a Expr>,
        func_name_override: Option<Symbol>,
        type_subst: HashMap<Symbol, ifa_sema::types::Type>,
        module_structs: &'a [FirStruct],
        module_enums: &'a [FirEnum],
    ) -> Self {
        let ret_ty = func_ast
            .ret_ty
            .as_ref()
            .map(|_t| {
                if let Some(sema_ty) = symbols.lookup_function(&func_ast.name) {
                    let substituted = sema_ty.ret_ty.substitute(&type_subst);
                    FirType::from_sema_type(&substituted)
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
                    .map(|ps| {
                        let substituted = ps.ty.substitute(&type_subst);
                        FirType::from_sema_type(&substituted)
                    })
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

        let name = func_name_override.unwrap_or(func_ast.name);

        let mut func = FirFunction::new(
            name,
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
            type_subst,
            module_structs,
            module_enums,
            defer_stack: Vec::new(),
        }
    }

    fn emit_all_defers(&mut self) {
        let defers = self.defer_stack.clone();
        for block in defers.iter().rev() {
            for s in &block.stmts {
                self.lower_stmt(s);
            }
        }
    }

    fn lookup_variant_discriminant(&self, variant_name: Symbol) -> Option<usize> {
        for e in self.module_enums {
            for (idx, (v_name, _)) in e.variants.iter().enumerate() {
                if *v_name == variant_name {
                    return Some(idx);
                }
            }
        }
        None
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
                } else if let Some(st) = self.module_structs.iter().find(|s| s.name == *name) {
                    st.fields.iter().position(|(f_name, _)| *f_name == field)
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
        if let Some(sema_ty) = self.symbols.expr_types.get(&expr.span) {
            let substituted = sema_ty.substitute(&self.type_subst);
            if !matches!(substituted, ifa_sema::types::Type::Unknown) {
                return Some(FirType::from_sema_type(&substituted));
            }
        }

        match &expr.kind {
            ExprKind::Ident(sym) => {
                if let Some(ty) = self.var_types.get(sym) {
                    return Some(ty.clone());
                }
                if let Some(var) = self.symbols.lookup_variable(sym) {
                    let substituted = var.ty.substitute(&self.type_subst);
                    return Some(FirType::from_sema_type(&substituted));
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
                    if let Some(func) = self.symbols.lookup_function(fn_name) {
                        Some(FirType::from_sema_type(&func.ret_ty))
                    } else if let Some(st) = self.symbols.lookup_struct(fn_name) {
                        let fields = st
                            .fields
                            .iter()
                            .map(|f| (f.name, FirType::from_sema_type(&f.ty)))
                            .collect();
                        Some(FirType::Struct(*fn_name, fields))
                    } else {
                        None
                    }
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
            ExprKind::MethodCall { method, .. } => self
                .symbols
                .lookup_function(method)
                .map(|func| FirType::from_sema_type(&func.ret_ty)),
            ExprKind::Select { arms } => {
                arms.first().and_then(|a| self.infer_expr_fir_type(&a.body))
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
                let substituted = var_sym.ty.substitute(&self.type_subst);
                let fir_ty = FirType::from_sema_type(&substituted);
                if let Some(idx) = self.extract_field_index_from_fir_type(&fir_ty, field) {
                    return idx;
                }
            }
        }
        // 3. Fallback: Lookup in module structs
        for st in self.module_structs {
            if let Some(pos) = st.fields.iter().position(|(f_name, _)| *f_name == field) {
                return pos;
            }
        }
        // 4. Fallback: Lookup in struct definitions in symbol table
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
            let val = self.lower_expr(trailing_expr);
            let ret_val = if matches!(self.func.ret_ty, FirType::ErrorUnion { .. }) {
                let e_ty = self.infer_expr_fir_type(trailing_expr);
                if !matches!(e_ty, Some(FirType::ErrorUnion { .. })) {
                    let zero = self.alloc_value();
                    self.emit(
                        Some(zero),
                        ValueExpr::Constant(ConstantValue::Int(0, IntType::I64)),
                        trailing_expr.span,
                    );
                    let union_val = self.alloc_value();
                    self.emit(
                        Some(union_val),
                        ValueExpr::TupleInit(vec![zero, val]),
                        trailing_expr.span,
                    );
                    union_val
                } else {
                    val
                }
            } else {
                val
            };
            self.emit_all_defers();
            self.set_terminator(Terminator::Return(Some(ret_val)));
        } else if let Some(block) = self.func.get_block(self.current_block) {
            if !block.is_terminated() {
                self.emit_all_defers();
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
                        let substituted = var_sym.ty.substitute(&self.type_subst);
                        FirType::from_sema_type(&substituted)
                    } else {
                        init_val
                            .map(|_| FirType::Int(IntType::I64))
                            .unwrap_or(FirType::Unit)
                    }
                } else if let Some(var_sym) = self.symbols.lookup_variable(name) {
                    let substituted = var_sym.ty.substitute(&self.type_subst);
                    FirType::from_sema_type(&substituted)
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

            Stmt::Return(opt_expr, span) => {
                let ret_val = if let Some(e) = opt_expr {
                    let val = self.lower_expr(e);
                    if matches!(self.func.ret_ty, FirType::ErrorUnion { .. }) {
                        let e_ty = self.infer_expr_fir_type(e);
                        if !matches!(e_ty, Some(FirType::ErrorUnion { .. })) {
                            let zero = self.alloc_value();
                            self.emit(
                                Some(zero),
                                ValueExpr::Constant(ConstantValue::Int(0, IntType::I64)),
                                *span,
                            );
                            let union_val = self.alloc_value();
                            self.emit(
                                Some(union_val),
                                ValueExpr::TupleInit(vec![zero, val]),
                                *span,
                            );
                            Some(union_val)
                        } else {
                            Some(val)
                        }
                    } else {
                        Some(val)
                    }
                } else if matches!(self.func.ret_ty, FirType::ErrorUnion { .. }) {
                    let zero = self.alloc_value();
                    self.emit(
                        Some(zero),
                        ValueExpr::Constant(ConstantValue::Int(0, IntType::I64)),
                        *span,
                    );
                    let unit_val = self.alloc_value();
                    self.emit(
                        Some(unit_val),
                        ValueExpr::Constant(ConstantValue::Unit),
                        *span,
                    );
                    let union_val = self.alloc_value();
                    self.emit(
                        Some(union_val),
                        ValueExpr::TupleInit(vec![zero, unit_val]),
                        *span,
                    );
                    Some(union_val)
                } else {
                    None
                };
                self.emit_all_defers();
                self.set_terminator(Terminator::Return(ret_val));
            }

            Stmt::Fail(expr, span) => {
                let fail_val = self.lower_expr(expr);
                let err_union_val = if matches!(self.func.ret_ty, FirType::ErrorUnion { .. }) {
                    let status_one = self.alloc_value();
                    self.emit(
                        Some(status_one),
                        ValueExpr::Constant(ConstantValue::Int(1, IntType::I64)),
                        *span,
                    );
                    let union_val = self.alloc_value();
                    self.emit(
                        Some(union_val),
                        ValueExpr::TupleInit(vec![status_one, fail_val]),
                        *span,
                    );
                    union_val
                } else {
                    fail_val
                };
                self.emit_all_defers();
                self.set_terminator(Terminator::Return(Some(err_union_val)));
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

            Stmt::Defer(body, _) => {
                self.defer_stack.push(body.clone());
            }

            Stmt::For {
                var,
                iterable,
                body,
                span,
            } => {
                let iter_val = self.lower_expr(iterable);
                let iter_ty = self.infer_expr_fir_type(iterable);

                let limit_val = if let Some(FirType::Array(_, len)) = iter_ty {
                    let lim = self.alloc_value();
                    self.emit(
                        Some(lim),
                        ValueExpr::Constant(ConstantValue::Int(len as i128, IntType::I64)),
                        *span,
                    );
                    lim
                } else {
                    let lim = self.alloc_value();
                    self.emit(Some(lim), ValueExpr::ArrayLen { array: iter_val }, *span);
                    lim
                };

                let elem_ty = match &iter_ty {
                    Some(FirType::Array(inner, _)) => (**inner).clone(),
                    Some(FirType::Slice(inner)) => (**inner).clone(),
                    _ => FirType::Int(IntType::I64),
                };

                // Allocate loop index counter
                let idx_ptr = self.alloc_value();
                self.emit(
                    Some(idx_ptr),
                    ValueExpr::Alloca {
                        ty: FirType::Int(IntType::I64),
                        name: Some(
                            INTERNER.intern(&format!("__for_idx_{}", self.func.next_value_id)),
                        ),
                    },
                    *span,
                );
                let zero_val = self.alloc_value();
                self.emit(
                    Some(zero_val),
                    ValueExpr::Constant(ConstantValue::Int(0, IntType::I64)),
                    *span,
                );
                self.emit(
                    None,
                    ValueExpr::Store {
                        ptr: idx_ptr,
                        val: zero_val,
                    },
                    *span,
                );

                // Allocate loop element variable
                let var_ptr = self.alloc_value();
                self.emit(
                    Some(var_ptr),
                    ValueExpr::Alloca {
                        ty: elem_ty.clone(),
                        name: Some(*var),
                    },
                    *span,
                );
                self.var_allocas.insert(*var, var_ptr);
                self.var_types.insert(*var, elem_ty);

                let cond_block = self.alloc_block();
                let body_block = self.alloc_block();
                let step_block = self.alloc_block();
                let exit_block = self.alloc_block();

                self.set_terminator(Terminator::Branch {
                    target: cond_block,
                    args: Vec::new(),
                });

                // Condition block
                self.current_block = cond_block;
                let cur_idx = self.alloc_value();
                self.emit(Some(cur_idx), ValueExpr::Load { ptr: idx_ptr }, *span);
                let cond_val = self.alloc_value();
                self.emit(
                    Some(cond_val),
                    ValueExpr::Binary {
                        op: BinaryOp::Lt,
                        lhs: cur_idx,
                        rhs: limit_val,
                    },
                    *span,
                );
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
                    continue_block: step_block,
                    break_block: exit_block,
                });

                let elem_val = self.alloc_value();
                self.emit(
                    Some(elem_val),
                    ValueExpr::GetElement {
                        base: iter_val,
                        index: cur_idx,
                    },
                    *span,
                );
                self.emit(
                    None,
                    ValueExpr::Store {
                        ptr: var_ptr,
                        val: elem_val,
                    },
                    *span,
                );

                for s in &body.stmts {
                    self.lower_stmt(s);
                }
                if let Some(trailing) = &body.expr {
                    let _ = self.lower_expr(trailing);
                }

                if let Some(b) = self.func.get_block(self.current_block) {
                    if !b.is_terminated() {
                        self.set_terminator(Terminator::Branch {
                            target: step_block,
                            args: Vec::new(),
                        });
                    }
                }
                self.loop_stack.pop();

                // Step block
                self.current_block = step_block;
                let idx_before = self.alloc_value();
                self.emit(Some(idx_before), ValueExpr::Load { ptr: idx_ptr }, *span);
                let one_val = self.alloc_value();
                self.emit(
                    Some(one_val),
                    ValueExpr::Constant(ConstantValue::Int(1, IntType::I64)),
                    *span,
                );
                let idx_after = self.alloc_value();
                self.emit(
                    Some(idx_after),
                    ValueExpr::Binary {
                        op: BinaryOp::Add,
                        lhs: idx_before,
                        rhs: one_val,
                    },
                    *span,
                );
                self.emit(
                    None,
                    ValueExpr::Store {
                        ptr: idx_ptr,
                        val: idx_after,
                    },
                    *span,
                );
                self.set_terminator(Terminator::Branch {
                    target: cond_block,
                    args: Vec::new(),
                });

                // Exit block
                self.current_block = exit_block;
            }
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
                } else if let Some(disc) = self.lookup_variant_discriminant(*sym) {
                    let res = self.alloc_value();
                    self.emit(
                        Some(res),
                        ValueExpr::Constant(ConstantValue::Int(disc as i128, IntType::I64)),
                        span,
                    );
                    res
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
                    UnaryOp::Try => {
                        let inner_val = self.lower_expr(expr);
                        let inner_fir_ty = self.infer_expr_fir_type(expr);
                        let is_fallible = inner_fir_ty
                            .as_ref()
                            .is_none_or(|t| matches!(t, FirType::ErrorUnion { .. }));

                        if !is_fallible {
                            inner_val
                        } else {
                            let err_status = self.alloc_value();
                            self.emit(
                                Some(err_status),
                                ValueExpr::GetField {
                                    base: inner_val,
                                    field_idx: 0,
                                    field_name: INTERNER.intern("status"),
                                },
                                span,
                            );
                            let zero_const = self.alloc_value();
                            self.emit(
                                Some(zero_const),
                                ValueExpr::Constant(ConstantValue::Int(0, IntType::I64)),
                                span,
                            );
                            let is_err_val = self.alloc_value();
                            self.emit(
                                Some(is_err_val),
                                ValueExpr::Binary {
                                    op: BinaryOp::Ne,
                                    lhs: err_status,
                                    rhs: zero_const,
                                },
                                span,
                            );

                            let ok_block = self.alloc_block();
                            let err_block = self.alloc_block();

                            self.set_terminator(Terminator::BranchCond {
                                cond: is_err_val,
                                then_block: err_block,
                                then_args: Vec::new(),
                                else_block: ok_block,
                                else_args: Vec::new(),
                            });

                            // err_block: propagate error immediately to caller
                            self.current_block = err_block;
                            self.emit_all_defers();
                            if matches!(self.func.ret_ty, FirType::ErrorUnion { .. }) {
                                self.set_terminator(Terminator::Return(Some(inner_val)));
                            } else {
                                self.set_terminator(Terminator::Fail(inner_val));
                            }

                            // ok_block: unpack success value
                            self.current_block = ok_block;
                            let ok_val = self.alloc_value();
                            self.emit(
                                Some(ok_val),
                                ValueExpr::GetField {
                                    base: inner_val,
                                    field_idx: 1,
                                    field_name: INTERNER.intern("value"),
                                },
                                span,
                            );
                            ok_val
                        }
                    }
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
                        let target_struct_name = if !st.generics.is_empty() {
                            if let Some(call_args) = self.symbols.call_instantiations.get(&span) {
                                let concrete_args: Vec<_> = call_args
                                    .iter()
                                    .map(|t| t.substitute(&self.type_subst))
                                    .collect();
                                crate::types::mangle_instantiation_symbol(
                                    &INTERNER.resolve(&struct_name),
                                    &concrete_args,
                                )
                            } else {
                                struct_name
                            }
                        } else {
                            struct_name
                        };

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
                                name: target_struct_name,
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
                    let target_fn_name = if let Some(fn_sym) =
                        self.symbols.lookup_function(&fn_name)
                    {
                        if !fn_sym.generics.is_empty() {
                            if let Some(call_args) = self.symbols.call_instantiations.get(&span) {
                                let concrete_args: Vec<_> = call_args
                                    .iter()
                                    .map(|t| t.substitute(&self.type_subst))
                                    .collect();
                                crate::types::mangle_instantiation_symbol(
                                    &INTERNER.resolve(&fn_name),
                                    &concrete_args,
                                )
                            } else {
                                fn_name
                            }
                        } else {
                            fn_name
                        }
                    } else {
                        fn_name
                    };

                    let res = self.alloc_value();
                    self.emit(
                        Some(res),
                        ValueExpr::CallDirect {
                            name: target_fn_name,
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
                    let target_fn_name = if let Some(fn_sym) = self.symbols.lookup_function(method)
                    {
                        if !fn_sym.generics.is_empty() {
                            if let Some(call_args) = self.symbols.call_instantiations.get(&span) {
                                let concrete_args: Vec<_> = call_args
                                    .iter()
                                    .map(|t| t.substitute(&self.type_subst))
                                    .collect();
                                crate::types::mangle_instantiation_symbol(
                                    &INTERNER.resolve(method),
                                    &concrete_args,
                                )
                            } else {
                                *method
                            }
                        } else {
                            *method
                        }
                    } else {
                        *method
                    };

                    let res = self.alloc_value();
                    self.emit(
                        Some(res),
                        ValueExpr::CallDirect {
                            name: target_fn_name,
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
                let defer_checkpoint = self.defer_stack.len();
                for s in &b.stmts {
                    self.lower_stmt(s);
                }
                let res = if let Some(e) = &b.expr {
                    self.lower_expr(e)
                } else {
                    let res = self.alloc_value();
                    self.emit(Some(res), ValueExpr::Constant(ConstantValue::Unit), span);
                    res
                };
                while self.defer_stack.len() > defer_checkpoint {
                    if let Some(def) = self.defer_stack.pop() {
                        for s in &def.stmts {
                            self.lower_stmt(s);
                        }
                    }
                }
                res
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
                let target_struct_name = if let Some(st) = self.symbols.lookup_struct(&sym_name) {
                    if !st.generics.is_empty() {
                        if let Some(call_args) = self.symbols.call_instantiations.get(&span) {
                            let concrete_args: Vec<_> = call_args
                                .iter()
                                .map(|t| t.substitute(&self.type_subst))
                                .collect();
                            crate::types::mangle_instantiation_symbol(
                                &INTERNER.resolve(&sym_name),
                                &concrete_args,
                            )
                        } else {
                            sym_name
                        }
                    } else {
                        sym_name
                    }
                } else {
                    sym_name
                };

                let res = self.alloc_value();
                self.emit(
                    Some(res),
                    ValueExpr::StructInit {
                        name: target_struct_name,
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

            ExprKind::Catch {
                expr: inner_expr,
                err_var,
                body,
            } => {
                let inner_val = self.lower_expr(inner_expr);
                let inner_fir_ty = self.infer_expr_fir_type(inner_expr);
                let is_fallible = matches!(inner_fir_ty, Some(FirType::ErrorUnion { .. }));

                if !is_fallible {
                    return inner_val;
                }

                let res_ptr = self.alloc_value();
                let res_ty = inner_fir_ty
                    .as_ref()
                    .map(|t| match t {
                        FirType::ErrorUnion { ok, .. } => (**ok).clone(),
                        other => other.clone(),
                    })
                    .unwrap_or(FirType::Int(IntType::I64));

                self.emit(
                    Some(res_ptr),
                    ValueExpr::Alloca {
                        ty: res_ty.clone(),
                        name: Some(
                            INTERNER.intern(&format!("__catch_res_{}", self.func.next_value_id)),
                        ),
                    },
                    span,
                );

                let ok_block = self.alloc_block();
                let err_block = self.alloc_block();
                let exit_block = self.alloc_block();

                // Extract error status (field 0)
                let err_status = self.alloc_value();
                self.emit(
                    Some(err_status),
                    ValueExpr::GetField {
                        base: inner_val,
                        field_idx: 0,
                        field_name: INTERNER.intern("status"),
                    },
                    span,
                );
                let zero_const = self.alloc_value();
                self.emit(
                    Some(zero_const),
                    ValueExpr::Constant(ConstantValue::Int(0, IntType::I64)),
                    span,
                );
                let is_err_val = self.alloc_value();
                self.emit(
                    Some(is_err_val),
                    ValueExpr::Binary {
                        op: BinaryOp::Ne,
                        lhs: err_status,
                        rhs: zero_const,
                    },
                    span,
                );
                self.set_terminator(Terminator::BranchCond {
                    cond: is_err_val,
                    then_block: err_block,
                    then_args: Vec::new(),
                    else_block: ok_block,
                    else_args: Vec::new(),
                });

                // ok_block: unpack success value (field 1)
                self.current_block = ok_block;
                let ok_val = self.alloc_value();
                self.emit(
                    Some(ok_val),
                    ValueExpr::GetField {
                        base: inner_val,
                        field_idx: 1,
                        field_name: INTERNER.intern("value"),
                    },
                    span,
                );
                self.emit(
                    None,
                    ValueExpr::Store {
                        ptr: res_ptr,
                        val: ok_val,
                    },
                    span,
                );
                self.set_terminator(Terminator::Branch {
                    target: exit_block,
                    args: Vec::new(),
                });

                // err_block: catch fallback branch
                self.current_block = err_block;
                if let Some(err_name) = err_var {
                    let err_payload = self.alloc_value();
                    self.emit(
                        Some(err_payload),
                        ValueExpr::GetField {
                            base: inner_val,
                            field_idx: 1,
                            field_name: INTERNER.intern("error"),
                        },
                        span,
                    );
                    let err_ptr = self.alloc_value();
                    self.emit(
                        Some(err_ptr),
                        ValueExpr::Alloca {
                            ty: FirType::Int(IntType::I64),
                            name: Some(*err_name),
                        },
                        span,
                    );
                    self.emit(
                        None,
                        ValueExpr::Store {
                            ptr: err_ptr,
                            val: err_payload,
                        },
                        span,
                    );
                    self.var_allocas.insert(*err_name, err_ptr);
                    self.var_types.insert(*err_name, FirType::Int(IntType::I64));
                }

                for s in &body.stmts {
                    self.lower_stmt(s);
                }
                let body_res = if let Some(e) = &body.expr {
                    self.lower_expr(e)
                } else {
                    let u = self.alloc_value();
                    self.emit(Some(u), ValueExpr::Constant(ConstantValue::Unit), span);
                    u
                };
                self.emit(
                    None,
                    ValueExpr::Store {
                        ptr: res_ptr,
                        val: body_res,
                    },
                    span,
                );
                if let Some(b) = self.func.get_block(self.current_block) {
                    if !b.is_terminated() {
                        self.set_terminator(Terminator::Branch {
                            target: exit_block,
                            args: Vec::new(),
                        });
                    }
                }

                // exit_block
                self.current_block = exit_block;
                let final_res = self.alloc_value();
                self.emit(Some(final_res), ValueExpr::Load { ptr: res_ptr }, span);
                final_res
            }

            ExprKind::Match {
                expr: target_expr,
                arms,
            } => {
                let target_val = self.lower_expr(target_expr);
                let exit_block = self.alloc_block();

                let res_ptr = self.alloc_value();
                let res_ty = self
                    .infer_expr_fir_type(expr)
                    .unwrap_or(FirType::Int(IntType::I64));
                self.emit(
                    Some(res_ptr),
                    ValueExpr::Alloca {
                        ty: res_ty.clone(),
                        name: Some(
                            INTERNER.intern(&format!("__match_res_{}", self.func.next_value_id)),
                        ),
                    },
                    span,
                );

                let mut next_arm_block = self.alloc_block();
                let total_arms = arms.len();

                for (arm_idx, arm) in arms.iter().enumerate() {
                    let is_last = arm_idx + 1 == total_arms;
                    let arm_check_block = next_arm_block;
                    let arm_body_block = self.alloc_block();
                    next_arm_block = if is_last {
                        exit_block
                    } else {
                        self.alloc_block()
                    };

                    self.set_terminator(Terminator::Branch {
                        target: arm_check_block,
                        args: Vec::new(),
                    });

                    self.current_block = arm_check_block;

                    match &arm.pattern {
                        Pattern::Wildcard(_) => {
                            self.set_terminator(Terminator::Branch {
                                target: arm_body_block,
                                args: Vec::new(),
                            });
                        }
                        Pattern::Lit(lit, _) => {
                            let lit_const = match lit {
                                Lit::Int(s) => {
                                    let v: i128 = s.as_str().replace('_', "").parse().unwrap_or(0);
                                    ConstantValue::Int(v, IntType::I64)
                                }
                                Lit::Float(s) => {
                                    let v: f64 = s.as_str().parse().unwrap_or(0.0);
                                    ConstantValue::Float(v, FloatType::F64)
                                }
                                Lit::Bool(b) => ConstantValue::Bool(*b),
                                Lit::Char(c) => ConstantValue::Char(*c),
                                Lit::String(s) => ConstantValue::String(*s),
                            };
                            let lit_val = self.alloc_value();
                            self.emit(Some(lit_val), ValueExpr::Constant(lit_const), arm.span);
                            let matches_cond = self.alloc_value();
                            self.emit(
                                Some(matches_cond),
                                ValueExpr::Binary {
                                    op: BinaryOp::Eq,
                                    lhs: target_val,
                                    rhs: lit_val,
                                },
                                arm.span,
                            );
                            self.set_terminator(Terminator::BranchCond {
                                cond: matches_cond,
                                then_block: arm_body_block,
                                then_args: Vec::new(),
                                else_block: next_arm_block,
                                else_args: Vec::new(),
                            });
                        }
                        Pattern::Ident(sym, p_span) => {
                            let var_ptr = self.alloc_value();
                            let var_ty = self
                                .infer_expr_fir_type(target_expr)
                                .unwrap_or(FirType::Int(IntType::I64));
                            self.emit(
                                Some(var_ptr),
                                ValueExpr::Alloca {
                                    ty: var_ty.clone(),
                                    name: Some(*sym),
                                },
                                *p_span,
                            );
                            self.emit(
                                None,
                                ValueExpr::Store {
                                    ptr: var_ptr,
                                    val: target_val,
                                },
                                *p_span,
                            );
                            self.var_allocas.insert(*sym, var_ptr);
                            self.var_types.insert(*sym, var_ty);

                            self.set_terminator(Terminator::Branch {
                                target: arm_body_block,
                                args: Vec::new(),
                            });
                        }
                        Pattern::Variant {
                            variant,
                            span: v_span,
                            ..
                        } => {
                            let disc = self.lookup_variant_discriminant(*variant).unwrap_or(0);
                            let disc_val = self.alloc_value();
                            self.emit(
                                Some(disc_val),
                                ValueExpr::Constant(ConstantValue::Int(disc as i128, IntType::I64)),
                                *v_span,
                            );
                            let matches_cond = self.alloc_value();
                            self.emit(
                                Some(matches_cond),
                                ValueExpr::Binary {
                                    op: BinaryOp::Eq,
                                    lhs: target_val,
                                    rhs: disc_val,
                                },
                                *v_span,
                            );
                            self.set_terminator(Terminator::BranchCond {
                                cond: matches_cond,
                                then_block: arm_body_block,
                                then_args: Vec::new(),
                                else_block: next_arm_block,
                                else_args: Vec::new(),
                            });
                        }
                    }

                    // Arm Body
                    self.current_block = arm_body_block;
                    let arm_res = self.lower_expr(&arm.body);
                    self.emit(
                        None,
                        ValueExpr::Store {
                            ptr: res_ptr,
                            val: arm_res,
                        },
                        arm.span,
                    );
                    if let Some(b) = self.func.get_block(self.current_block) {
                        if !b.is_terminated() {
                            self.set_terminator(Terminator::Branch {
                                target: exit_block,
                                args: Vec::new(),
                            });
                        }
                    }
                }

                self.current_block = exit_block;
                let final_res = self.alloc_value();
                self.emit(Some(final_res), ValueExpr::Load { ptr: res_ptr }, span);
                final_res
            }

            ExprKind::Select { arms } => {
                let exit_block = self.alloc_block();
                let res_ptr = self.alloc_value();
                let res_ty = self.infer_expr_fir_type(expr).unwrap_or(FirType::Unit);
                self.emit(
                    Some(res_ptr),
                    ValueExpr::Alloca {
                        ty: res_ty.clone(),
                        name: Some(
                            INTERNER.intern(&format!("__select_res_{}", self.func.next_value_id)),
                        ),
                    },
                    span,
                );

                let mut chan_arms = Vec::new();
                let mut default_arm: Option<&SelectArm> = None;

                for arm in arms {
                    if arm.is_default {
                        default_arm = Some(arm);
                    } else if let Some(chan_expr) = &arm.channel {
                        let chan_val = self.lower_expr(chan_expr);
                        chan_arms.push((arm, chan_val));
                    }
                }

                let has_default = default_arm.is_some();
                let channel_vals: Vec<ValueId> = chan_arms.iter().map(|(_, c)| *c).collect();

                let select_idx = self.alloc_value();
                self.emit(
                    Some(select_idx),
                    ValueExpr::ChanSelect {
                        channels: channel_vals,
                        has_default,
                    },
                    span,
                );

                let mut next_arm_check = self.alloc_block();
                self.set_terminator(Terminator::Branch {
                    target: next_arm_check,
                    args: Vec::new(),
                });

                for (idx, (arm, chan_val)) in chan_arms.iter().enumerate() {
                    let cur_check_block = next_arm_check;
                    let arm_body_block = self.alloc_block();
                    next_arm_check = self.alloc_block();

                    self.current_block = cur_check_block;
                    let idx_val = self.alloc_value();
                    self.emit(
                        Some(idx_val),
                        ValueExpr::Constant(ConstantValue::Int(idx as i128, IntType::I64)),
                        arm.span,
                    );
                    let is_match = self.alloc_value();
                    self.emit(
                        Some(is_match),
                        ValueExpr::Binary {
                            op: BinaryOp::Eq,
                            lhs: select_idx,
                            rhs: idx_val,
                        },
                        arm.span,
                    );
                    self.set_terminator(Terminator::BranchCond {
                        cond: is_match,
                        then_block: arm_body_block,
                        then_args: Vec::new(),
                        else_block: next_arm_check,
                        else_args: Vec::new(),
                    });

                    // Arm Body
                    self.current_block = arm_body_block;

                    if let Some(Pattern::Ident(var_sym, p_span)) = &arm.pattern {
                        let recv_val = self.alloc_value();
                        self.emit(
                            Some(recv_val),
                            ValueExpr::ChanRecv { chan: *chan_val },
                            *p_span,
                        );
                        let var_ptr = self.alloc_value();
                        let elem_ty = FirType::Int(IntType::I64);
                        self.emit(
                            Some(var_ptr),
                            ValueExpr::Alloca {
                                ty: elem_ty.clone(),
                                name: Some(*var_sym),
                            },
                            *p_span,
                        );
                        self.emit(
                            None,
                            ValueExpr::Store {
                                ptr: var_ptr,
                                val: recv_val,
                            },
                            *p_span,
                        );
                        self.var_allocas.insert(*var_sym, var_ptr);
                        self.var_types.insert(*var_sym, elem_ty);
                    }

                    let arm_res = self.lower_expr(&arm.body);
                    self.emit(
                        None,
                        ValueExpr::Store {
                            ptr: res_ptr,
                            val: arm_res,
                        },
                        arm.span,
                    );
                    if let Some(b) = self.func.get_block(self.current_block) {
                        if !b.is_terminated() {
                            self.set_terminator(Terminator::Branch {
                                target: exit_block,
                                args: Vec::new(),
                            });
                        }
                    }
                }

                // Default arm or fallthrough
                self.current_block = next_arm_check;
                if let Some(def_arm) = default_arm {
                    let def_res = self.lower_expr(&def_arm.body);
                    self.emit(
                        None,
                        ValueExpr::Store {
                            ptr: res_ptr,
                            val: def_res,
                        },
                        def_arm.span,
                    );
                }
                if let Some(b) = self.func.get_block(self.current_block) {
                    if !b.is_terminated() {
                        self.set_terminator(Terminator::Branch {
                            target: exit_block,
                            args: Vec::new(),
                        });
                    }
                }

                self.current_block = exit_block;
                let final_res = self.alloc_value();
                self.emit(Some(final_res), ValueExpr::Load { ptr: res_ptr }, span);
                final_res
            }

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

    // 1. Lower all enums
    for item in &program.items {
        if let Item::Enum(e_ast) = item {
            let variants = e_ast.variants.iter().map(|v| (v.name, None)).collect();
            module.enums.push(FirEnum {
                name: e_ast.name,
                variants,
                is_pub: e_ast.is_pub,
                span: e_ast.span,
            });
        }
    }

    // 2. Lower non-generic structs and monomorphize generic structs
    for item in &program.items {
        if let Item::Struct(s_ast) = item {
            if s_ast.generics.is_empty() {
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
            } else if let Some(instances) = symbols.generic_struct_instances.get(&s_ast.name) {
                for type_args in instances {
                    let mut type_subst = HashMap::new();
                    for (g, concrete) in s_ast.generics.iter().zip(type_args.iter()) {
                        type_subst.insert(g.name, concrete.clone());
                    }
                    let mangled_name = crate::types::mangle_instantiation_symbol(
                        &INTERNER.resolve(&s_ast.name),
                        type_args,
                    );
                    let struct_sym = symbols.lookup_struct(&s_ast.name);
                    let fields = if let Some(st) = struct_sym {
                        st.fields
                            .iter()
                            .map(|f| {
                                let sub = f.ty.substitute(&type_subst);
                                (f.name, FirType::from_sema_type(&sub))
                            })
                            .collect()
                    } else {
                        s_ast
                            .fields
                            .iter()
                            .map(|f| (f.name, FirType::Int(IntType::I64)))
                            .collect()
                    };
                    module.structs.push(FirStruct {
                        name: mangled_name,
                        fields,
                        is_pub: s_ast.is_pub,
                        span: s_ast.span,
                    });
                }
            }
        }
    }

    // 3. Collect all functions (free functions and methods in impl blocks)
    let mut all_functions: HashMap<Symbol, &ifa_ast::Function> = HashMap::new();
    for item in &program.items {
        match item {
            Item::Function(f) => {
                all_functions.insert(f.name, f);
            }
            Item::Impl(im) => {
                for f in &im.methods {
                    all_functions.insert(f.name, f);
                }
            }
            _ => {}
        }
    }

    // 4. Lower non-generic functions
    for func_ast in all_functions.values() {
        if func_ast.generics.is_empty() {
            if let Some(body) = &func_ast.body {
                let ctx = FunctionLoweringContext::new(
                    func_ast,
                    symbols,
                    &constants,
                    None,
                    HashMap::new(),
                    &module.structs,
                    &module.enums,
                );
                let fir_func = ctx.lower(body);
                module.functions.push(fir_func);
            }
        }
    }

    // 5. Monomorphize all generic function instances
    let mut worklist: Vec<(Symbol, Vec<ifa_sema::types::Type>)> = Vec::new();
    for (fn_name, instances) in &symbols.generic_function_instances {
        for type_args in instances {
            worklist.push((*fn_name, type_args.clone()));
        }
    }

    let mut generated_instances = std::collections::HashSet::new();
    while let Some((orig_name, type_args)) = worklist.pop() {
        let mangled_name =
            crate::types::mangle_instantiation_symbol(&INTERNER.resolve(&orig_name), &type_args);
        if !generated_instances.insert(mangled_name) {
            continue;
        }

        if let Some(func_ast) = all_functions.get(&orig_name) {
            if let Some(body) = &func_ast.body {
                let mut type_subst = HashMap::new();
                for (g, concrete) in func_ast.generics.iter().zip(type_args.iter()) {
                    type_subst.insert(g.name, concrete.clone());
                }
                let ctx = FunctionLoweringContext::new(
                    func_ast,
                    symbols,
                    &constants,
                    Some(mangled_name),
                    type_subst,
                    &module.structs,
                    &module.enums,
                );
                let fir_func = ctx.lower(body);
                module.functions.push(fir_func);
            }
        }
    }

    module
}

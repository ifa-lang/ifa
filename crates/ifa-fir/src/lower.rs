use crate::ir::*;
use crate::types::FirType;
use ifa_ast::{
    BinOp, Block, Expr, ExprKind, Item, Lit, Pattern, Program, SelectArm, Stmt, UnaryOp,
};
use ifa_sema::types::{FloatType, IntType};
use ifa_sema::SymbolTable;
use ifa_span::{Span, Symbol, INTERNER};
use std::collections::{HashMap, HashSet};

fn comptime_val_to_constant(val: &ifa_comptime::Value) -> Option<ConstantValue> {
    match val {
        ifa_comptime::Value::Unit => Some(ConstantValue::Unit),
        ifa_comptime::Value::Bool(b) => Some(ConstantValue::Bool(*b)),
        ifa_comptime::Value::Int(i) => Some(ConstantValue::Int(*i as i128, IntType::I64)),
        ifa_comptime::Value::UInt(u) => Some(ConstantValue::Int(*u as i128, IntType::U64)),
        ifa_comptime::Value::Float(f) => Some(ConstantValue::Float(*f, FloatType::F64)),
        ifa_comptime::Value::Char(c) => Some(ConstantValue::Char(*c)),
        ifa_comptime::Value::String(s) => Some(ConstantValue::String(INTERNER.intern(s))),
        _ => None,
    }
}

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
    known_null_vars: HashSet<Symbol>,
    known_non_null_vars: HashSet<Symbol>,
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
        let effective_name = func_name_override.unwrap_or(func_ast.name);

        let sema_fn = symbols
            .lookup_function(&effective_name)
            .or_else(|| symbols.lookup_function(&func_ast.name));

        let ret_ty = func_ast
            .ret_ty
            .as_ref()
            .map(|_t| {
                if let Some(sema_ty) = sema_fn {
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
            let ty = if let Some(sym_fn) = sema_fn {
                sym_fn
                    .params
                    .iter()
                    .find(|ps| ps.name == p.name)
                    .map(|ps| {
                        let substituted = ps.ty.substitute(&type_subst);
                        FirType::from_sema_type(&substituted)
                    })
                    .unwrap_or_else(|| {
                        let known_structs = HashMap::new();
                        let known_enums = HashMap::new();
                        ifa_sema::types::Type::from_ast(&p.ty, &known_structs, &known_enums)
                            .map(|t| FirType::from_sema_type(&t.substitute(&type_subst)))
                            .unwrap_or(FirType::Unit)
                    })
            } else {
                let known_structs = HashMap::new();
                let known_enums = HashMap::new();
                ifa_sema::types::Type::from_ast(&p.ty, &known_structs, &known_enums)
                    .map(|t| FirType::from_sema_type(&t.substitute(&type_subst)))
                    .unwrap_or(FirType::Unit)
            };
            params.push(FirParam {
                name: p.name,
                val,
                ty,
                mode: p.mode,
            });
        }

        let name = effective_name;

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
            known_null_vars: HashSet::new(),
            known_non_null_vars: HashSet::new(),
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

    fn lookup_variant_info(
        &self,
        variant_name: Symbol,
    ) -> Option<(Symbol, usize, Option<FirType>)> {
        for e in self.module_enums {
            for (idx, (v_name, payload)) in e.variants.iter().enumerate() {
                if *v_name == variant_name {
                    return Some((e.name, idx, payload.clone()));
                }
            }
        }
        None
    }

    fn lookup_qualified_variant_info(
        &self,
        enum_name: Symbol,
        variant_name: Symbol,
    ) -> Option<(Symbol, usize, Option<FirType>)> {
        for e in self.module_enums {
            if e.name == enum_name {
                for (idx, (v_name, payload)) in e.variants.iter().enumerate() {
                    if *v_name == variant_name {
                        return Some((e.name, idx, payload.clone()));
                    }
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
            ExprKind::FieldAccess {
                receiver,
                field,
                safe,
            } => {
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
                        let f_ty = FirType::from_sema_type(&f.ty);
                        return if *safe {
                            match f_ty {
                                FirType::Optional(_) => Some(f_ty),
                                other => Some(FirType::Optional(Box::new(other))),
                            }
                        } else {
                            Some(f_ty)
                        };
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
                Lit::Null => Some(FirType::Int(IntType::I64)),
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
                    } else if let Some((en_name, _, _)) = self.lookup_variant_info(*fn_name) {
                        let variants = self
                            .module_enums
                            .iter()
                            .find(|e| e.name == en_name)
                            .map(|e| e.variants.clone())
                            .unwrap_or_default();
                        Some(FirType::Enum(en_name, variants))
                    } else {
                        None
                    }
                } else if let ExprKind::Path(path) = &callee.kind {
                    if path.len() >= 2 {
                        if let Some((en_name, _, _)) = self.lookup_qualified_variant_info(
                            path[path.len() - 2],
                            path[path.len() - 1],
                        ) {
                            let variants = self
                                .module_enums
                                .iter()
                                .find(|e| e.name == en_name)
                                .map(|e| e.variants.clone())
                                .unwrap_or_default();
                            return Some(FirType::Enum(en_name, variants));
                        }
                    }
                    if let Some(last) = path.last() {
                        if let Some((en_name, _, _)) = self.lookup_variant_info(*last) {
                            let variants = self
                                .module_enums
                                .iter()
                                .find(|e| e.name == en_name)
                                .map(|e| e.variants.clone())
                                .unwrap_or_default();
                            return Some(FirType::Enum(en_name, variants));
                        }
                    }
                    None
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
            ExprKind::MethodCall {
                receiver, method, ..
            } => {
                if let Some(&resolved) = self.symbols.method_resolutions.get(&expr.span) {
                    if let Some(func) = self.symbols.lookup_function(&resolved) {
                        return Some(FirType::from_sema_type(&func.ret_ty));
                    }
                }
                let rec_fir_ty = self.infer_expr_fir_type(receiver);
                if let Some(mut cur) = rec_fir_ty.as_ref() {
                    while let FirType::GenerationalRef(inner)
                    | FirType::Pointer(inner)
                    | FirType::Optional(inner) = cur
                    {
                        cur = inner;
                    }
                    if let FirType::Struct(name, _) = cur {
                        let specialized = INTERNER.intern(&format!(
                            "{}__{}",
                            INTERNER.resolve(name),
                            INTERNER.resolve(method)
                        ));
                        if let Some(f) = self.symbols.lookup_function(&specialized) {
                            return Some(FirType::from_sema_type(&f.ret_ty));
                        }
                        if let Some(f) = self.symbols.lookup_type_method(name, method) {
                            return Some(FirType::from_sema_type(&f.ret_ty));
                        }
                    }
                }
                self.symbols
                    .lookup_function(method)
                    .map(|func| FirType::from_sema_type(&func.ret_ty))
            }
            ExprKind::Select { arms } => {
                arms.first().and_then(|a| self.infer_expr_fir_type(&a.body))
            }
            ExprKind::Match { arms, .. } => {
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

    /// Resolves the concrete monomorphic method target, devirtualizing trait and interface calls AOT.
    fn resolve_method_call_target(&self, receiver: &Expr, method: Symbol, span: Span) -> Symbol {
        if let Some(&resolved) = self.symbols.method_resolutions.get(&span) {
            return resolved;
        }

        // Monomorphic Devirtualization: Check concrete receiver FIR type
        let rec_fir_ty = self.infer_expr_fir_type(receiver);
        let mut rec_struct_name = None;
        if let Some(mut cur) = rec_fir_ty.as_ref() {
            while let FirType::GenerationalRef(inner)
            | FirType::Pointer(inner)
            | FirType::Optional(inner) = cur
            {
                cur = inner;
            }
            if let FirType::Struct(name, _) = cur {
                rec_struct_name = Some(*name);
            }
        }

        if let Some(st_name) = rec_struct_name {
            let specialized = INTERNER.intern(&format!(
                "{}__{}",
                INTERNER.resolve(&st_name),
                INTERNER.resolve(&method)
            ));
            if self.symbols.lookup_function(&specialized).is_some()
                || self.symbols.lookup_type_method(&st_name, &method).is_some()
            {
                return specialized;
            }
        }

        if let Some(fn_sym) = self.symbols.lookup_function(&method) {
            if !fn_sym.generics.is_empty() {
                if let Some(call_args) = self.symbols.call_instantiations.get(&span) {
                    let concrete_args: Vec<_> = call_args
                        .iter()
                        .map(|t| t.substitute(&self.type_subst))
                        .collect();
                    crate::types::mangle_instantiation_symbol(
                        &INTERNER.resolve(&method),
                        &concrete_args,
                    )
                } else {
                    method
                }
            } else {
                method
            }
        } else {
            method
        }
    }

    fn is_expr_null(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Lit(Lit::Null) => true,
            ExprKind::Ident(sym) => {
                INTERNER.resolve(sym) == "null" || self.known_null_vars.contains(sym)
            }
            _ => false,
        }
    }

    fn is_expr_non_null(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Lit(lit) => !matches!(lit, Lit::Null),
            ExprKind::StructInit { .. }
            | ExprKind::Array(_)
            | ExprKind::ArrayRepeat(..)
            | ExprKind::Tuple(_) => true,
            ExprKind::Unary {
                op: UnaryOp::Ref, ..
            } => true,
            ExprKind::Ident(sym) => self.known_non_null_vars.contains(sym),
            _ => false,
        }
    }

    fn is_generational_ref_expr(&self, expr: &Expr) -> bool {
        if matches!(
            &expr.kind,
            ExprKind::Unary {
                op: UnaryOp::Ref,
                ..
            }
        ) {
            return true;
        }
        if let Some(fir_ty) = self.infer_expr_fir_type(expr) {
            match fir_ty {
                FirType::GenerationalRef(_) => return true,
                FirType::Optional(inner) => {
                    if matches!(*inner, FirType::GenerationalRef(_)) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn eval_static_bool(&self, expr: &Expr) -> Option<bool> {
        if let Some(ifa_comptime::Value::Bool(b)) =
            self.symbols.comptime_expr_values.get(&expr.span)
        {
            return Some(*b);
        }

        match &expr.kind {
            ExprKind::Lit(Lit::Bool(b)) => Some(*b),
            ExprKind::Lit(Lit::Null) => Some(false),
            ExprKind::Unary {
                op: UnaryOp::Not,
                expr: inner,
            } => self.eval_static_bool(inner).map(|b| !b),
            ExprKind::Binary { op, left, right } => match op {
                BinOp::Eq => {
                    if self.is_expr_null(left) && self.is_expr_null(right) {
                        Some(true)
                    } else if (self.is_expr_null(left) && self.is_expr_non_null(right))
                        || (self.is_expr_non_null(left) && self.is_expr_null(right))
                    {
                        Some(false)
                    } else {
                        None
                    }
                }
                BinOp::NotEq => {
                    if self.is_expr_null(left) && self.is_expr_null(right) {
                        Some(false)
                    } else if (self.is_expr_null(left) && self.is_expr_non_null(right))
                        || (self.is_expr_non_null(left) && self.is_expr_null(right))
                    {
                        Some(true)
                    } else {
                        None
                    }
                }
                BinOp::And => match (self.eval_static_bool(left), self.eval_static_bool(right)) {
                    (Some(false), _) | (_, Some(false)) => Some(false),
                    (Some(true), Some(true)) => Some(true),
                    _ => None,
                },
                BinOp::Or => match (self.eval_static_bool(left), self.eval_static_bool(right)) {
                    (Some(true), _) | (_, Some(true)) => Some(true),
                    (Some(false), Some(false)) => Some(false),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        }
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

                if let Some(init_expr) = init {
                    if self.is_expr_null(init_expr) {
                        self.known_null_vars.insert(*name);
                        self.known_non_null_vars.remove(name);
                    } else if self.is_expr_non_null(init_expr) {
                        self.known_non_null_vars.insert(*name);
                        self.known_null_vars.remove(name);
                    }
                }

                self.var_allocas.insert(*name, ptr);
                self.var_types.insert(*name, ty);
            }

            Stmt::Assign {
                target, val, span, ..
            } => {
                let val_id = self.lower_expr(val);

                if let ExprKind::Ident(target_sym) = &target.kind {
                    if self.is_expr_null(val) {
                        self.known_null_vars.insert(*target_sym);
                        self.known_non_null_vars.remove(target_sym);
                    } else if self.is_expr_non_null(val) {
                        self.known_non_null_vars.insert(*target_sym);
                        self.known_null_vars.remove(target_sym);
                    } else {
                        self.known_null_vars.remove(target_sym);
                        self.known_non_null_vars.remove(target_sym);
                    }
                }
                match &target.kind {
                    ExprKind::Ident(sym) => {
                        if let Some(&ptr) = self.var_allocas.get(sym) {
                            self.emit(None, ValueExpr::Store { ptr, val: val_id }, *span);
                        }
                    }
                    ExprKind::FieldAccess {
                        receiver, field, ..
                    } => {
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
                    Lit::Null => ConstantValue::Null,
                };
                self.emit(Some(res), ValueExpr::Constant(c), span);
                res
            }

            ExprKind::Ident(sym) => {
                if sym.as_str() == "null" || sym.as_str() == "None" {
                    let res = self.alloc_value();
                    self.emit(Some(res), ValueExpr::Constant(ConstantValue::Null), span);
                    res
                } else if let Some(&ptr) = self.var_allocas.get(sym) {
                    let res = self.alloc_value();
                    self.emit(Some(res), ValueExpr::Load { ptr }, span);
                    res
                } else if let Some(val) = self.symbols.comptime_values.get(sym) {
                    if let Some(c) = comptime_val_to_constant(val) {
                        let res = self.alloc_value();
                        self.emit(Some(res), ValueExpr::Constant(c), span);
                        res
                    } else if let Some(c_expr) = self.constants.get(sym) {
                        self.lower_expr(c_expr)
                    } else {
                        let res = self.alloc_value();
                        self.emit(Some(res), ValueExpr::Constant(ConstantValue::Unit), span);
                        res
                    }
                } else if let Some(c_expr) = self.constants.get(sym) {
                    self.lower_expr(c_expr)
                } else if let Some((en_name, disc, _)) = self.lookup_variant_info(*sym) {
                    let res = self.alloc_value();
                    self.emit(
                        Some(res),
                        ValueExpr::EnumInit {
                            enum_name: en_name,
                            variant: *sym,
                            discriminant: disc as u32,
                            payload: None,
                        },
                        span,
                    );
                    res
                } else {
                    let res = self.alloc_value();
                    self.emit(Some(res), ValueExpr::Constant(ConstantValue::Unit), span);
                    res
                }
            }

            ExprKind::Binary {
                op: BinOp::Coalesce,
                left,
                right,
            } => {
                let lhs = self.lower_expr(left);
                let val_ty = self
                    .infer_expr_fir_type(right)
                    .or_else(|| self.infer_expr_fir_type(left))
                    .unwrap_or(FirType::Int(IntType::I64));

                let res_ptr = self.alloc_value();
                self.emit(
                    Some(res_ptr),
                    ValueExpr::Alloca {
                        ty: val_ty,
                        name: Some(
                            INTERNER.intern(&format!("__coalesce_{}", self.func.next_value_id)),
                        ),
                    },
                    span,
                );

                let is_null = self.alloc_value();
                let null_const = self.alloc_value();
                self.emit(
                    Some(null_const),
                    ValueExpr::Constant(ConstantValue::Null),
                    span,
                );
                self.emit(
                    Some(is_null),
                    ValueExpr::Binary {
                        op: BinaryOp::Eq,
                        lhs,
                        rhs: null_const,
                    },
                    span,
                );

                let fallback_block = self.alloc_block();
                let ok_block = self.alloc_block();
                let join_block = self.alloc_block();

                self.set_terminator(Terminator::BranchCond {
                    cond: is_null,
                    then_block: fallback_block,
                    then_args: Vec::new(),
                    else_block: ok_block,
                    else_args: Vec::new(),
                });

                // ok_block: store lhs
                self.current_block = ok_block;
                self.emit(
                    None,
                    ValueExpr::Store {
                        ptr: res_ptr,
                        val: lhs,
                    },
                    span,
                );
                self.set_terminator(Terminator::Branch {
                    target: join_block,
                    args: Vec::new(),
                });

                // fallback_block: evaluate rhs and store
                self.current_block = fallback_block;
                let rhs = self.lower_expr(right);
                self.emit(
                    None,
                    ValueExpr::Store {
                        ptr: res_ptr,
                        val: rhs,
                    },
                    span,
                );
                self.set_terminator(Terminator::Branch {
                    target: join_block,
                    args: Vec::new(),
                });

                // join_block: load res
                self.current_block = join_block;
                let final_res = self.alloc_value();
                self.emit(Some(final_res), ValueExpr::Load { ptr: res_ptr }, span);
                final_res
            }

            ExprKind::Binary { op, left, right } => {
                if let Some(b) = self.eval_static_bool(expr) {
                    let res = self.alloc_value();
                    self.emit(Some(res), ValueExpr::Constant(ConstantValue::Bool(b)), span);
                    return res;
                }
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

                // Check if calling a Struct constructor directly (e.g. WindowNode(id: ..., parent: ...) or geo::Rectangle(...))
                let module_struct = if let ExprKind::Path(path) = &callee.kind {
                    if path.len() >= 2 {
                        self.symbols
                            .lookup_module(&path[0])
                            .and_then(|m| m.structs.get(&path[1]))
                            .cloned()
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some(st) = module_struct.or_else(|| {
                    direct_name.and_then(|name| self.symbols.lookup_struct(&name).cloned())
                }) {
                    let struct_name = st.name;
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
                        if let Some(arg) = args.iter().find(|a| a.name == Some(field_sym.name)) {
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

                // Check if calling an Enum variant constructor directly (e.g. WebEvent::KeyPress(100) or Some(x))
                let enum_variant_match = match &callee.kind {
                    ExprKind::Path(path) if path.len() >= 2 => self
                        .lookup_qualified_variant_info(path[path.len() - 2], path[path.len() - 1]),
                    _ => {
                        if let Some(name) = direct_name {
                            self.lookup_variant_info(name)
                        } else {
                            None
                        }
                    }
                };

                if let Some((en_name, disc, _opt_payload)) = enum_variant_match {
                    let payload_val = args.first().map(|a| self.lower_expr(&a.value));
                    let res = self.alloc_value();
                    let v_sym = match &callee.kind {
                        ExprKind::Path(path) => *path.last().unwrap(),
                        ExprKind::Ident(s) => *s,
                        _ => INTERNER.intern("variant"),
                    };
                    self.emit(
                        Some(res),
                        ValueExpr::EnumInit {
                            enum_name: en_name,
                            variant: v_sym,
                            discriminant: disc as u32,
                            payload: payload_val,
                        },
                        span,
                    );
                    return res;
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
                safe,
            } => {
                let m_name = INTERNER.resolve(method);
                if *safe {
                    let lhs = self.lower_expr(receiver);
                    let ret_ty = self
                        .infer_expr_fir_type(expr)
                        .unwrap_or(FirType::Optional(Box::new(FirType::Int(IntType::I64))));

                    let res_ptr = self.alloc_value();
                    self.emit(
                        Some(res_ptr),
                        ValueExpr::Alloca {
                            ty: ret_ty.clone(),
                            name: Some(
                                INTERNER.intern(&format!("__safecall_{}", self.func.next_value_id)),
                            ),
                        },
                        span,
                    );

                    let is_null = self.alloc_value();
                    let null_const = self.alloc_value();
                    self.emit(
                        Some(null_const),
                        ValueExpr::Constant(ConstantValue::Null),
                        span,
                    );
                    self.emit(
                        Some(is_null),
                        ValueExpr::Binary {
                            op: BinaryOp::Eq,
                            lhs,
                            rhs: null_const,
                        },
                        span,
                    );

                    let null_block = self.alloc_block();
                    let call_block = self.alloc_block();
                    let join_block = self.alloc_block();

                    self.set_terminator(Terminator::BranchCond {
                        cond: is_null,
                        then_block: null_block,
                        then_args: Vec::new(),
                        else_block: call_block,
                        else_args: Vec::new(),
                    });

                    // null_block: store null (or unit)
                    self.current_block = null_block;
                    let null_val = self.alloc_value();
                    let null_c = if ret_ty == FirType::Unit {
                        ConstantValue::Unit
                    } else {
                        ConstantValue::Null
                    };
                    self.emit(Some(null_val), ValueExpr::Constant(null_c), span);
                    self.emit(
                        None,
                        ValueExpr::Store {
                            ptr: res_ptr,
                            val: null_val,
                        },
                        span,
                    );
                    self.set_terminator(Terminator::Branch {
                        target: join_block,
                        args: Vec::new(),
                    });

                    // call_block: evaluate arguments and invoke method
                    self.current_block = call_block;
                    let call_res = if m_name == "len" {
                        let r = self.alloc_value();
                        self.emit(Some(r), ValueExpr::ArrayLen { array: lhs }, span);
                        r
                    } else {
                        let mut arg_vals = vec![lhs];
                        for a in args {
                            arg_vals.push(self.lower_expr(&a.value));
                        }
                        let target_fn_name =
                            self.resolve_method_call_target(receiver, *method, span);

                        let r = self.alloc_value();
                        self.emit(
                            Some(r),
                            ValueExpr::CallDirect {
                                name: target_fn_name,
                                args: arg_vals,
                            },
                            span,
                        );
                        r
                    };

                    self.emit(
                        None,
                        ValueExpr::Store {
                            ptr: res_ptr,
                            val: call_res,
                        },
                        span,
                    );
                    self.set_terminator(Terminator::Branch {
                        target: join_block,
                        args: Vec::new(),
                    });

                    // join_block
                    self.current_block = join_block;
                    let final_res = self.alloc_value();
                    self.emit(Some(final_res), ValueExpr::Load { ptr: res_ptr }, span);
                    return final_res;
                }

                if m_name == "push" && !args.is_empty() {
                    let val_to_push = self.lower_expr(&args[0].value);
                    let res = self.alloc_value();

                    match &receiver.kind {
                        ExprKind::FieldAccess {
                            receiver: inner_rec,
                            field: field_sym,
                            ..
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
                    let target_fn_name = self.resolve_method_call_target(receiver, *method, span);

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

            ExprKind::FieldAccess {
                receiver,
                field,
                safe,
            } => {
                if *safe {
                    let lhs = self.lower_expr(receiver);
                    let val_ty = self
                        .infer_expr_fir_type(expr)
                        .unwrap_or(FirType::Optional(Box::new(FirType::Int(IntType::I64))));

                    let res_ptr = self.alloc_value();
                    self.emit(
                        Some(res_ptr),
                        ValueExpr::Alloca {
                            ty: val_ty,
                            name: Some(
                                INTERNER.intern(&format!("__safenav_{}", self.func.next_value_id)),
                            ),
                        },
                        span,
                    );

                    let is_null = self.alloc_value();
                    let null_const = self.alloc_value();
                    self.emit(
                        Some(null_const),
                        ValueExpr::Constant(ConstantValue::Null),
                        span,
                    );
                    self.emit(
                        Some(is_null),
                        ValueExpr::Binary {
                            op: BinaryOp::Eq,
                            lhs,
                            rhs: null_const,
                        },
                        span,
                    );

                    let null_block = self.alloc_block();
                    let access_block = self.alloc_block();
                    let join_block = self.alloc_block();

                    self.set_terminator(Terminator::BranchCond {
                        cond: is_null,
                        then_block: null_block,
                        then_args: Vec::new(),
                        else_block: access_block,
                        else_args: Vec::new(),
                    });

                    // null_block: store null
                    self.current_block = null_block;
                    let null_val = self.alloc_value();
                    self.emit(
                        Some(null_val),
                        ValueExpr::Constant(ConstantValue::Null),
                        span,
                    );
                    self.emit(
                        None,
                        ValueExpr::Store {
                            ptr: res_ptr,
                            val: null_val,
                        },
                        span,
                    );
                    self.set_terminator(Terminator::Branch {
                        target: join_block,
                        args: Vec::new(),
                    });

                    // access_block: deref/getfield
                    self.current_block = access_block;
                    let is_gen_ref = self.is_generational_ref_expr(receiver);
                    let checked_base = if is_gen_ref {
                        self.emit(
                            None,
                            ValueExpr::GenCheck {
                                ref_val: lhs,
                                redundant: false,
                            },
                            span,
                        );
                        let deref_res = self.alloc_value();
                        self.emit(Some(deref_res), ValueExpr::GenDeref { ref_val: lhs }, span);
                        deref_res
                    } else {
                        lhs
                    };

                    let field_idx = self.find_field_index(receiver, *field);
                    let access_res = self.alloc_value();
                    self.emit(
                        Some(access_res),
                        ValueExpr::GetField {
                            base: checked_base,
                            field_idx,
                            field_name: *field,
                        },
                        span,
                    );
                    self.emit(
                        None,
                        ValueExpr::Store {
                            ptr: res_ptr,
                            val: access_res,
                        },
                        span,
                    );
                    self.set_terminator(Terminator::Branch {
                        target: join_block,
                        args: Vec::new(),
                    });

                    // join_block
                    self.current_block = join_block;
                    let final_res = self.alloc_value();
                    self.emit(Some(final_res), ValueExpr::Load { ptr: res_ptr }, span);
                    return final_res;
                }

                let base_val = self.lower_expr(receiver);
                // Si le récepteur est une référence ref, émettre GenCheck et GenDeref
                let is_gen_ref = self.is_generational_ref_expr(receiver);
                let checked_base = if is_gen_ref {
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
                if let Some(st_cond) = self.eval_static_bool(cond) {
                    if st_cond {
                        for s in &then_branch.stmts {
                            self.lower_stmt(s);
                        }
                        return then_branch
                            .expr
                            .as_ref()
                            .map(|e| self.lower_expr(e))
                            .unwrap_or_else(|| {
                                let res = self.alloc_value();
                                self.emit(
                                    Some(res),
                                    ValueExpr::Constant(ConstantValue::Unit),
                                    span,
                                );
                                res
                            });
                    } else if let Some(else_expr) = else_branch {
                        return self.lower_expr(else_expr);
                    } else {
                        let res = self.alloc_value();
                        self.emit(Some(res), ValueExpr::Constant(ConstantValue::Unit), span);
                        return res;
                    }
                }

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
                let res = self.alloc_value();
                let (target_sym, arg_vals) = match &e.kind {
                    ExprKind::Call { callee, args } => {
                        let target = match &callee.kind {
                            ExprKind::Ident(sym) => *sym,
                            _ => INTERNER.intern("task"),
                        };
                        let lowered_args: Vec<ValueId> =
                            args.iter().map(|arg| self.lower_expr(&arg.value)).collect();
                        (target, lowered_args)
                    }
                    ExprKind::Ident(sym) => (*sym, Vec::new()),
                    _ => {
                        let _ = self.lower_expr(e);
                        (INTERNER.intern("task"), Vec::new())
                    }
                };
                self.emit(
                    Some(res),
                    ValueExpr::Spawn {
                        target: target_sym,
                        args: arg_vals,
                    },
                    span,
                );
                res
            }

            ExprKind::Comptime(inner) => {
                if let Some(val) = self.symbols.comptime_expr_values.get(&expr.span) {
                    if let Some(c) = comptime_val_to_constant(val) {
                        let res = self.alloc_value();
                        self.emit(Some(res), ValueExpr::Constant(c), span);
                        return res;
                    }
                }
                self.lower_expr(inner)
            }

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

                let target_ty = self
                    .infer_expr_fir_type(target_expr)
                    .unwrap_or(FirType::Int(IntType::I64));

                let mut next_arm_block = self.alloc_block();
                let total_arms = arms.len();

                for (arm_idx, arm) in arms.iter().enumerate() {
                    let saved_allocas = self.var_allocas.clone();
                    let saved_types = self.var_types.clone();

                    let is_last = arm_idx + 1 == total_arms;
                    let arm_check_block = next_arm_block;
                    let arm_body_block = self.alloc_block();
                    let arm_guard_block = if arm.guard.is_some() {
                        Some(self.alloc_block())
                    } else {
                        None
                    };
                    let success_target = arm_guard_block.unwrap_or(arm_body_block);

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

                    self.lower_pattern_match(
                        target_val,
                        &target_ty,
                        &arm.pattern,
                        success_target,
                        next_arm_block,
                        arm.span,
                    );

                    // Optional Guard Evaluation Block
                    if let Some(guard_block) = arm_guard_block {
                        self.current_block = guard_block;
                        let guard_cond = self.lower_expr(arm.guard.as_ref().unwrap());
                        self.set_terminator(Terminator::BranchCond {
                            cond: guard_cond,
                            then_block: arm_body_block,
                            then_args: Vec::new(),
                            else_block: next_arm_block,
                            else_args: Vec::new(),
                        });
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

                    self.var_allocas = saved_allocas;
                    self.var_types = saved_types;
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

            ExprKind::Path(path) => {
                if let Some(val) = self.symbols.comptime_expr_values.get(&expr.span) {
                    if let Some(c) = comptime_val_to_constant(val) {
                        let res = self.alloc_value();
                        self.emit(Some(res), ValueExpr::Constant(c), span);
                        return res;
                    }
                }
                if path.len() >= 2 {
                    if let Some(m) = self.symbols.lookup_module(&path[0]) {
                        if let Some(c) = m.consts.get(&path[1]) {
                            if let Some(val) = &c.value {
                                if let Some(cv) = comptime_val_to_constant(val) {
                                    let res = self.alloc_value();
                                    self.emit(Some(res), ValueExpr::Constant(cv), span);
                                    return res;
                                }
                            }
                        }
                    }
                    if path.len() >= 2 {
                        if let Some((en_name, disc, _)) = self.lookup_qualified_variant_info(
                            path[path.len() - 2],
                            path[path.len() - 1],
                        ) {
                            let res = self.alloc_value();
                            self.emit(
                                Some(res),
                                ValueExpr::EnumInit {
                                    enum_name: en_name,
                                    variant: path[path.len() - 1],
                                    discriminant: disc as u32,
                                    payload: None,
                                },
                                span,
                            );
                            return res;
                        }
                    }
                    if let Some(last_sym) = path.last() {
                        if let Some((en_name, disc, _)) = self.lookup_variant_info(*last_sym) {
                            let res = self.alloc_value();
                            self.emit(
                                Some(res),
                                ValueExpr::EnumInit {
                                    enum_name: en_name,
                                    variant: *last_sym,
                                    discriminant: disc as u32,
                                    payload: None,
                                },
                                span,
                            );
                            return res;
                        }
                    }
                }
                let res = self.alloc_value();
                self.emit(Some(res), ValueExpr::Constant(ConstantValue::Unit), span);
                res
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

    /// Recursively lowers pattern matching against an SSA value, supporting nested variant destructuring,
    /// literals, variables, and wildcards.
    fn lower_pattern_match(
        &mut self,
        target_val: ValueId,
        target_ty: &FirType,
        pat: &Pattern,
        success_target: BlockId,
        fail_target: BlockId,
        _span: Span,
    ) {
        match pat {
            Pattern::Wildcard(_) => {
                self.set_terminator(Terminator::Branch {
                    target: success_target,
                    args: Vec::new(),
                });
            }
            Pattern::Lit(lit, l_span) => {
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
                    Lit::Null => ConstantValue::Null,
                };
                let lit_val = self.alloc_value();
                self.emit(Some(lit_val), ValueExpr::Constant(lit_const), *l_span);
                let matches_cond = self.alloc_value();
                self.emit(
                    Some(matches_cond),
                    ValueExpr::Binary {
                        op: BinaryOp::Eq,
                        lhs: target_val,
                        rhs: lit_val,
                    },
                    *l_span,
                );
                self.set_terminator(Terminator::BranchCond {
                    cond: matches_cond,
                    then_block: success_target,
                    then_args: Vec::new(),
                    else_block: fail_target,
                    else_args: Vec::new(),
                });
            }
            Pattern::Ident(sym, p_span) => {
                let var_ptr = if let Some(existing_ptr) = self.var_allocas.get(sym).copied() {
                    existing_ptr
                } else {
                    let ptr = self.alloc_value();
                    let inst = Instruction::new(
                        Some(ptr),
                        ValueExpr::Alloca {
                            ty: target_ty.clone(),
                            name: Some(*sym),
                        },
                        *p_span,
                    );
                    let entry = self.func.entry_block;
                    if let Some(block) = self.func.get_block_mut(entry) {
                        block.instructions.insert(0, inst);
                    }
                    self.var_allocas.insert(*sym, ptr);
                    self.var_types.insert(*sym, target_ty.clone());
                    ptr
                };
                self.emit(
                    None,
                    ValueExpr::Store {
                        ptr: var_ptr,
                        val: target_val,
                    },
                    *p_span,
                );

                self.set_terminator(Terminator::Branch {
                    target: success_target,
                    args: Vec::new(),
                });
            }
            Pattern::Variant {
                enum_name,
                variant,
                inner,
                span: v_span,
            } => {
                let (disc, opt_payload_ty) = if let Some(e_name) = enum_name {
                    self.lookup_qualified_variant_info(*e_name, *variant)
                        .map(|(_, d, p)| (d, p))
                        .unwrap_or_else(|| {
                            (
                                self.lookup_variant_discriminant(*variant).unwrap_or(0),
                                None,
                            )
                        })
                } else {
                    self.lookup_variant_info(*variant)
                        .map(|(_, d, p)| (d, p))
                        .unwrap_or_else(|| {
                            (
                                self.lookup_variant_discriminant(*variant).unwrap_or(0),
                                None,
                            )
                        })
                };

                let disc_val = self.alloc_value();
                self.emit(
                    Some(disc_val),
                    ValueExpr::EnumGetDiscriminant { base: target_val },
                    *v_span,
                );
                let expected_disc_val = self.alloc_value();
                self.emit(
                    Some(expected_disc_val),
                    ValueExpr::Constant(ConstantValue::Int(disc as i128, IntType::I64)),
                    *v_span,
                );
                let matches_cond = self.alloc_value();
                self.emit(
                    Some(matches_cond),
                    ValueExpr::Binary {
                        op: BinaryOp::Eq,
                        lhs: disc_val,
                        rhs: expected_disc_val,
                    },
                    *v_span,
                );

                if let Some(inner_pat) = inner {
                    let payload_extract_block = self.alloc_block();
                    self.set_terminator(Terminator::BranchCond {
                        cond: matches_cond,
                        then_block: payload_extract_block,
                        then_args: Vec::new(),
                        else_block: fail_target,
                        else_args: Vec::new(),
                    });

                    self.current_block = payload_extract_block;
                    let p_ty = opt_payload_ty.unwrap_or(FirType::Int(IntType::I64));
                    let payload_val = self.alloc_value();
                    self.emit(
                        Some(payload_val),
                        ValueExpr::EnumGetPayload {
                            base: target_val,
                            payload_ty: p_ty.clone(),
                        },
                        *v_span,
                    );

                    self.lower_pattern_match(
                        payload_val,
                        &p_ty,
                        inner_pat,
                        success_target,
                        fail_target,
                        *v_span,
                    );
                } else {
                    self.set_terminator(Terminator::BranchCond {
                        cond: matches_cond,
                        then_block: success_target,
                        then_args: Vec::new(),
                        else_block: fail_target,
                        else_args: Vec::new(),
                    });
                }
            }
            Pattern::Tuple(sub_patterns, t_span) => {
                if sub_patterns.is_empty() {
                    self.set_terminator(Terminator::Branch {
                        target: success_target,
                        args: Vec::new(),
                    });
                    return;
                }

                let total_sub = sub_patterns.len();
                let mut intermediate_blocks = Vec::with_capacity(total_sub);
                intermediate_blocks.push(self.current_block);
                for _ in 0..total_sub - 1 {
                    intermediate_blocks.push(self.alloc_block());
                }

                for (idx, sub_pat) in sub_patterns.iter().enumerate() {
                    let block_for_this = intermediate_blocks[idx];
                    let next_success = if idx + 1 < total_sub {
                        intermediate_blocks[idx + 1]
                    } else {
                        success_target
                    };

                    self.current_block = block_for_this;

                    let elem_fir_ty = match target_ty {
                        FirType::Struct(_, fields) if idx < fields.len() => fields[idx].1.clone(),
                        _ => FirType::Int(IntType::I64),
                    };

                    let elem_val = self.alloc_value();
                    let field_name = INTERNER.intern(&format!("_{}", idx));
                    self.emit(
                        Some(elem_val),
                        ValueExpr::GetField {
                            base: target_val,
                            field_idx: idx,
                            field_name,
                        },
                        *t_span,
                    );

                    self.lower_pattern_match(
                        elem_val,
                        &elem_fir_ty,
                        sub_pat,
                        next_success,
                        fail_target,
                        *t_span,
                    );
                }
            }
            Pattern::Struct {
                name,
                fields,
                span: s_span,
                ..
            } => {
                if fields.is_empty() {
                    self.set_terminator(Terminator::Branch {
                        target: success_target,
                        args: Vec::new(),
                    });
                    return;
                }

                let total_fields = fields.len();
                let mut intermediate_blocks = Vec::with_capacity(total_fields);
                intermediate_blocks.push(self.current_block);
                for _ in 0..total_fields - 1 {
                    intermediate_blocks.push(self.alloc_block());
                }

                let st_name = name.last().copied();

                for (idx, f) in fields.iter().enumerate() {
                    let block_for_this = intermediate_blocks[idx];
                    let next_success = if idx + 1 < total_fields {
                        intermediate_blocks[idx + 1]
                    } else {
                        success_target
                    };

                    self.current_block = block_for_this;

                    let (field_idx, field_ty) = match target_ty {
                        FirType::Struct(s_sym, struct_fields) => {
                            if let Some(pos) = struct_fields
                                .iter()
                                .position(|(f_name, _)| *f_name == f.name)
                            {
                                (pos, struct_fields[pos].1.clone())
                            } else if let Some(st) = self.symbols.lookup_struct(s_sym) {
                                let pos = st.field_indices.get(&f.name).copied().unwrap_or(idx);
                                let ty = st
                                    .get_field(&f.name)
                                    .map(|fl| FirType::from_sema_type(&fl.ty))
                                    .unwrap_or(FirType::Int(IntType::I64));
                                (pos, ty)
                            } else {
                                (idx, FirType::Int(IntType::I64))
                            }
                        }
                        _ => {
                            if let Some(ref s_sym) = st_name {
                                if let Some(st) = self.symbols.lookup_struct(s_sym) {
                                    let pos = st.field_indices.get(&f.name).copied().unwrap_or(idx);
                                    let ty = st
                                        .get_field(&f.name)
                                        .map(|fl| FirType::from_sema_type(&fl.ty))
                                        .unwrap_or(FirType::Int(IntType::I64));
                                    (pos, ty)
                                } else {
                                    (idx, FirType::Int(IntType::I64))
                                }
                            } else {
                                (idx, FirType::Int(IntType::I64))
                            }
                        }
                    };

                    let field_val = self.alloc_value();
                    self.emit(
                        Some(field_val),
                        ValueExpr::GetField {
                            base: target_val,
                            field_idx,
                            field_name: f.name,
                        },
                        f.span,
                    );

                    self.lower_pattern_match(
                        field_val,
                        &field_ty,
                        &f.pattern,
                        next_success,
                        fail_target,
                        *s_span,
                    );
                }
            }
            Pattern::Or(sub_patterns, or_span) => {
                if sub_patterns.is_empty() {
                    self.set_terminator(Terminator::Branch {
                        target: fail_target,
                        args: Vec::new(),
                    });
                    return;
                }

                let total = sub_patterns.len();
                let mut check_blocks = Vec::with_capacity(total);
                check_blocks.push(self.current_block);
                for _ in 0..total - 1 {
                    check_blocks.push(self.alloc_block());
                }

                for (idx, sub_pat) in sub_patterns.iter().enumerate() {
                    self.current_block = check_blocks[idx];
                    let sub_fail_target = if idx + 1 < total {
                        check_blocks[idx + 1]
                    } else {
                        fail_target
                    };

                    self.lower_pattern_match(
                        target_val,
                        target_ty,
                        sub_pat,
                        success_target,
                        sub_fail_target,
                        *or_span,
                    );
                }
            }
            Pattern::Range {
                start,
                end,
                inclusive,
                span: r_span,
            } => {
                let eval_bound = |lowerer: &mut Self, pat: &Pattern| -> ValueId {
                    match pat {
                        Pattern::Lit(lit, l_span) => {
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
                                Lit::Null => ConstantValue::Null,
                            };
                            let lit_val = lowerer.alloc_value();
                            lowerer.emit(Some(lit_val), ValueExpr::Constant(lit_const), *l_span);
                            lit_val
                        }
                        _ => lowerer.alloc_value(),
                    }
                };

                match (start, end) {
                    (Some(s_pat), Some(e_pat)) => {
                        let start_val = eval_bound(self, s_pat);
                        let end_val = eval_bound(self, e_pat);

                        let ge_cond = self.alloc_value();
                        self.emit(
                            Some(ge_cond),
                            ValueExpr::Binary {
                                op: BinaryOp::Ge,
                                lhs: target_val,
                                rhs: start_val,
                            },
                            *r_span,
                        );

                        let check_end_block = self.alloc_block();
                        self.set_terminator(Terminator::BranchCond {
                            cond: ge_cond,
                            then_block: check_end_block,
                            then_args: Vec::new(),
                            else_block: fail_target,
                            else_args: Vec::new(),
                        });

                        self.current_block = check_end_block;
                        let end_op = if *inclusive {
                            BinaryOp::Le
                        } else {
                            BinaryOp::Lt
                        };
                        let end_cond = self.alloc_value();
                        self.emit(
                            Some(end_cond),
                            ValueExpr::Binary {
                                op: end_op,
                                lhs: target_val,
                                rhs: end_val,
                            },
                            *r_span,
                        );

                        self.set_terminator(Terminator::BranchCond {
                            cond: end_cond,
                            then_block: success_target,
                            then_args: Vec::new(),
                            else_block: fail_target,
                            else_args: Vec::new(),
                        });
                    }
                    (Some(s_pat), None) => {
                        let start_val = eval_bound(self, s_pat);
                        let ge_cond = self.alloc_value();
                        self.emit(
                            Some(ge_cond),
                            ValueExpr::Binary {
                                op: BinaryOp::Ge,
                                lhs: target_val,
                                rhs: start_val,
                            },
                            *r_span,
                        );
                        self.set_terminator(Terminator::BranchCond {
                            cond: ge_cond,
                            then_block: success_target,
                            then_args: Vec::new(),
                            else_block: fail_target,
                            else_args: Vec::new(),
                        });
                    }
                    (None, Some(e_pat)) => {
                        let end_val = eval_bound(self, e_pat);
                        let end_op = if *inclusive {
                            BinaryOp::Le
                        } else {
                            BinaryOp::Lt
                        };
                        let end_cond = self.alloc_value();
                        self.emit(
                            Some(end_cond),
                            ValueExpr::Binary {
                                op: end_op,
                                lhs: target_val,
                                rhs: end_val,
                            },
                            *r_span,
                        );
                        self.set_terminator(Terminator::BranchCond {
                            cond: end_cond,
                            then_block: success_target,
                            then_args: Vec::new(),
                            else_block: fail_target,
                            else_args: Vec::new(),
                        });
                    }
                    (None, None) => {
                        self.set_terminator(Terminator::Branch {
                            target: success_target,
                            args: Vec::new(),
                        });
                    }
                }
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
    let mut impl_methods: Vec<(Symbol, &ifa_ast::Function)> = Vec::new();

    for item in &program.items {
        match item {
            Item::Function(f) => {
                all_functions.insert(f.name, f);
            }
            Item::Impl(im) => {
                let target_name = match &im.target_ty.kind {
                    ifa_ast::TypeKind::Named(s) => *s,
                    _ => INTERNER.intern("Type"),
                };
                for f in &im.methods {
                    let mangled_name = INTERNER.intern(&format!(
                        "{}__{}",
                        INTERNER.resolve(&target_name),
                        INTERNER.resolve(&f.name)
                    ));
                    impl_methods.push((mangled_name, f));
                    all_functions.insert(mangled_name, f);
                    all_functions.entry(f.name).or_insert(f);
                }
            }
            _ => {}
        }
    }

    // 4. Lower non-generic functions
    let mut lowered_fn_names = HashSet::new();
    for (fn_name, func_ast) in &all_functions {
        // Skip bare aliases for impl methods so we don't emit duplicates
        if !impl_methods.iter().any(|(m, _)| m == fn_name)
            && impl_methods.iter().any(|(_, f)| &f.name == fn_name)
        {
            continue;
        }

        if func_ast.generics.is_empty() {
            if let Some(body) = &func_ast.body {
                if lowered_fn_names.insert(*fn_name) {
                    let ctx = FunctionLoweringContext::new(
                        func_ast,
                        symbols,
                        &constants,
                        Some(*fn_name),
                        HashMap::new(),
                        &module.structs,
                        &module.enums,
                    );
                    let fir_func = ctx.lower(body);
                    module.functions.push(fir_func);
                }
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

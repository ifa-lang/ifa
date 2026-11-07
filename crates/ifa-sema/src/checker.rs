use crate::escape::EscapeAnalyzer;
use crate::exclusivity::{check_assignment_target, check_call_exclusivity};
use crate::symbol_table::{
    ConstSymbol, EnumSymbol, FieldSymbol, FunctionSymbol, ParamSymbol, StructSymbol, SymbolTable,
    TraitMethodSymbol, TraitSymbol,
};
use crate::types::{IntType, Type};
use ifa_ast::{
    Arg, BinOp, Block, Expr, ExprKind, Function, GenericParam, Impl, Item, Lit, ParamMode, Pattern,
    Program, Stmt, Struct, Trait, UnaryOp,
};
use ifa_diagnostics::Diagnostic;
use ifa_span::{SourceMap, Span, Symbol, INTERNER};
use std::collections::HashMap;

pub struct SemanticAnalyzer<'a> {
    pub source_map: &'a SourceMap,
    pub symbols: SymbolTable,
    pub diagnostics: Vec<Diagnostic>,
    pub current_func_ret_ty: Option<Type>,
    pub current_func_is_strict: bool,
    pub current_func_generics: Vec<GenericParam>,
    pub expr_types: HashMap<Span, Type>,
    pub moved_vars: HashMap<Symbol, Span>,
    pub comptime_vm: ifa_comptime::ComptimeVM,
}

impl<'a> SemanticAnalyzer<'a> {
    pub fn new(source_map: &'a SourceMap) -> Self {
        Self {
            source_map,
            symbols: SymbolTable::new(),
            diagnostics: Vec::new(),
            current_func_ret_ty: None,
            current_func_is_strict: false,
            current_func_generics: Vec::new(),
            expr_types: HashMap::new(),
            moved_vars: HashMap::new(),
            comptime_vm: ifa_comptime::ComptimeVM::new(),
        }
    }

    pub fn analyze(mut self, program: &Program) -> (SymbolTable, Vec<Diagnostic>) {
        // Phase 1: Collect struct and enum declarations
        self.collect_types(program);

        // Phase 2: Collect function and constant signatures
        self.collect_signatures(program);

        // Phase 3: Check bodies and expressions
        self.check_program_bodies(program);

        self.symbols.expr_types = self.expr_types;

        (self.symbols, self.diagnostics)
    }

    // =========================================================================
    // Phase 1: Type Collection
    // =========================================================================

    fn collect_types(&mut self, program: &Program) {
        for item in &program.items {
            match item {
                Item::Struct(st) => self.declare_struct(st),
                Item::Enum(en) => self.declare_enum(en),
                Item::Trait(tr) => self.declare_trait(tr),
                _ => {}
            }
        }
    }

    fn declare_struct(&mut self, st: &Struct) {
        let known_structs = self.get_known_struct_types();
        let known_enums = self.get_known_enum_types();

        let mut fields = Vec::new();
        for f in &st.fields {
            let ty = match Type::from_ast_with_generics(
                &f.ty,
                &known_structs,
                &known_enums,
                &st.generics,
            ) {
                Ok(t) => t,
                Err(d) => {
                    self.diagnostics.push(d);
                    Type::Unknown
                }
            };
            fields.push(FieldSymbol {
                is_pub: f.is_pub,
                name: f.name,
                ty,
                span: f.span,
            });
        }

        if st.generics.is_empty() {
            for f in &fields {
                self.symbols.register_type_if_generic_instance(&f.ty);
            }
        }

        let struct_sym =
            StructSymbol::new(st.name, st.is_pub, st.generics.clone(), fields, st.span);
        if let Err(diag) = self.symbols.define_struct(struct_sym) {
            self.diagnostics.push(diag);
        }
    }

    fn declare_enum(&mut self, en: &ifa_ast::Enum) {
        let known_structs = self.get_known_struct_types();
        let known_enums = self.get_known_enum_types();

        let mut variants = Vec::new();
        for v in &en.variants {
            let payload = if let Some(p) = &v.payload {
                match Type::from_ast(p, &known_structs, &known_enums) {
                    Ok(t) => Some(t),
                    Err(d) => {
                        self.diagnostics.push(d);
                        Some(Type::Unknown)
                    }
                }
            } else {
                None
            };
            variants.push((v.name, payload));
        }

        let enum_sym = EnumSymbol {
            name: en.name,
            is_pub: en.is_pub,
            variants,
            span: en.span,
        };
        if let Err(diag) = self.symbols.define_enum(enum_sym) {
            self.diagnostics.push(diag);
        }
    }

    fn declare_trait(&mut self, tr: &Trait) {
        let known_structs = self.get_known_struct_types();
        let known_enums = self.get_known_enum_types();

        let mut methods = Vec::new();
        for m in &tr.methods {
            let mut params = Vec::new();
            for p in &m.params {
                let ty = match Type::from_ast(&p.ty, &known_structs, &known_enums) {
                    Ok(t) => t,
                    Err(d) => {
                        self.diagnostics.push(d);
                        Type::Unknown
                    }
                };
                params.push(ParamSymbol {
                    mode: p.mode,
                    name: p.name,
                    ty,
                    span: p.span,
                });
            }

            let ret_ty = if let Some(ret) = &m.ret_ty {
                Type::from_ast(ret, &known_structs, &known_enums).unwrap_or(Type::Unknown)
            } else {
                Type::Unit
            };

            methods.push(TraitMethodSymbol {
                name: m.name,
                params,
                ret_ty,
                span: m.span,
            });
        }

        let trait_sym = TraitSymbol {
            name: tr.name,
            is_pub: tr.is_pub,
            methods,
            span: tr.span,
        };
        if let Err(diag) = self.symbols.define_trait(trait_sym) {
            self.diagnostics.push(diag);
        }
    }

    fn get_known_struct_types(&self) -> HashMap<Symbol, Type> {
        let mut map = HashMap::new();
        for (name, st) in &self.symbols.structs {
            let fields: Vec<(Symbol, Type)> =
                st.fields.iter().map(|f| (f.name, f.ty.clone())).collect();
            map.insert(
                *name,
                Type::Struct {
                    name: *name,
                    fields,
                },
            );
        }
        map
    }

    fn get_known_enum_types(&self) -> HashMap<Symbol, Type> {
        let mut map = HashMap::new();
        for (name, en) in &self.symbols.enums {
            map.insert(
                *name,
                Type::Enum {
                    name: *name,
                    variants: en.variants.clone(),
                },
            );
        }
        map
    }

    // =========================================================================
    // Phase 2: Signature Collection
    // =========================================================================

    fn collect_signatures(&mut self, program: &Program) {
        let known_structs = self.get_known_struct_types();
        let known_enums = self.get_known_enum_types();

        for item in &program.items {
            match item {
                Item::Function(f) => {
                    let mut params = Vec::new();
                    for p in &f.params {
                        let ty = match Type::from_ast_with_generics(
                            &p.ty,
                            &known_structs,
                            &known_enums,
                            &f.generics,
                        ) {
                            Ok(t) => t,
                            Err(d) => {
                                self.diagnostics.push(d);
                                Type::Unknown
                            }
                        };
                        params.push(ParamSymbol {
                            mode: p.mode,
                            name: p.name,
                            ty,
                            span: p.span,
                        });
                    }

                    let ret_ty = if let Some(ret) = &f.ret_ty {
                        match Type::from_ast_with_generics(
                            ret,
                            &known_structs,
                            &known_enums,
                            &f.generics,
                        ) {
                            Ok(t) => t,
                            Err(d) => {
                                self.diagnostics.push(d);
                                Type::Unknown
                            }
                        }
                    } else {
                        Type::Unit
                    };

                    if f.generics.is_empty() {
                        for p in &params {
                            self.symbols.register_type_if_generic_instance(&p.ty);
                        }
                        self.symbols.register_type_if_generic_instance(&ret_ty);
                    }

                    let fn_sym = FunctionSymbol {
                        name: f.name,
                        is_pub: f.is_pub,
                        is_strict: f.is_strict,
                        is_comptime: f.is_comptime,
                        is_extern: f.is_extern.clone(),
                        generics: f.generics.clone(),
                        params,
                        ret_ty,
                        span: f.span,
                    };

                    if let Err(diag) = self.symbols.define_function(fn_sym) {
                        self.diagnostics.push(diag);
                    }

                    if f.is_comptime {
                        if let Ok(bc) = ifa_comptime::Compiler::compile_function(f) {
                            self.comptime_vm.register_function(bc);
                        }
                    }
                }
                Item::Const(c) => {
                    let ty = if let Some(t) = &c.ty {
                        Type::from_ast(t, &known_structs, &known_enums).unwrap_or(Type::Unknown)
                    } else {
                        Type::Unknown
                    };
                    let c_sym = ConstSymbol {
                        name: c.name,
                        is_pub: c.is_pub,
                        ty,
                        span: c.span,
                    };
                    if let Err(diag) = self.symbols.define_const(c_sym) {
                        self.diagnostics.push(diag);
                    }
                }
                Item::Impl(im) => {
                    self.declare_impl(im);
                }
                _ => {}
            }
        }
    }

    fn declare_impl(&mut self, im: &Impl) {
        let known_structs = self.get_known_struct_types();
        let known_enums = self.get_known_enum_types();

        let target_ty = match Type::from_ast(&im.target_ty, &known_structs, &known_enums) {
            Ok(t) => t,
            Err(d) => {
                self.diagnostics.push(d);
                Type::Unknown
            }
        };

        if let Some(tr_name) = im.trait_name {
            self.symbols.register_trait_impl(tr_name, target_ty);
        }

        // Register each method in impl block into symbol table
        for f in &im.methods {
            let mut params = Vec::new();
            for p in &f.params {
                let ty = match Type::from_ast_with_generics(
                    &p.ty,
                    &known_structs,
                    &known_enums,
                    &f.generics,
                ) {
                    Ok(t) => t,
                    Err(d) => {
                        self.diagnostics.push(d);
                        Type::Unknown
                    }
                };
                params.push(ParamSymbol {
                    mode: p.mode,
                    name: p.name,
                    ty,
                    span: p.span,
                });
            }

            let ret_ty = if let Some(ret) = &f.ret_ty {
                Type::from_ast_with_generics(ret, &known_structs, &known_enums, &f.generics)
                    .unwrap_or(Type::Unit)
            } else {
                Type::Unit
            };

            if f.generics.is_empty() {
                for p in &params {
                    self.symbols.register_type_if_generic_instance(&p.ty);
                }
                self.symbols.register_type_if_generic_instance(&ret_ty);
            }

            let fn_sym = FunctionSymbol {
                name: f.name,
                is_pub: f.is_pub,
                is_strict: f.is_strict,
                is_comptime: f.is_comptime,
                is_extern: f.is_extern.clone(),
                generics: f.generics.clone(),
                params,
                ret_ty,
                span: f.span,
            };

            if let Err(diag) = self.symbols.define_function(fn_sym) {
                self.diagnostics.push(diag);
            }
        }
    }

    // =========================================================================
    // Phase 3: Body Checking
    // =========================================================================

    fn check_program_bodies(&mut self, program: &Program) {
        for item in &program.items {
            match item {
                Item::Function(f) => self.check_function(f),
                Item::Const(c) => self.check_const(c),
                Item::Impl(im) => {
                    for m in &im.methods {
                        self.check_function(m);
                    }
                }
                _ => {}
            }
        }
    }

    fn check_const(&mut self, c: &ifa_ast::Const) {
        let val_ty = self.infer_expr(&c.value);
        if let Some(expected_ast) = &c.ty {
            let known_structs = self.get_known_struct_types();
            let known_enums = self.get_known_enum_types();
            if let Ok(expected_ty) = Type::from_ast(expected_ast, &known_structs, &known_enums) {
                if !val_ty.is_assignable_to(&expected_ty) {
                    let const_name = INTERNER.resolve(&c.name);
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "type incompatible pour la constante '{}' : attendu {}, trouvé {}",
                            const_name, expected_ty, val_ty
                        ))
                        .with_code("E0001")
                        .with_primary_label(c.value.span, format!("type {} ici", val_ty))
                        .with_secondary_label(c.span, format!("type {} déclaré", expected_ty)),
                    );
                }
            }
        }

        // Static compile-time evaluation check
        match self.comptime_vm.eval_expr(&c.value) {
            Ok(val) => self.comptime_vm.register_constant(c.name, val),
            Err(comptime_err) => self.diagnostics.push(comptime_err.to_diagnostic()),
        }
    }

    fn check_function(&mut self, f: &Function) {
        // Run escape analysis on this function
        let mut escape_analyzer = EscapeAnalyzer::new(&self.symbols, f.is_strict, f.span);
        escape_analyzer.check_function(f);
        self.diagnostics.extend(escape_analyzer.diagnostics);

        // Get function return type from symbol table
        let ret_ty = self
            .symbols
            .lookup_function(&f.name)
            .map(|sym| sym.ret_ty.clone())
            .unwrap_or(Type::Unit);

        let prev_ret = self.current_func_ret_ty.take();
        let prev_strict = self.current_func_is_strict;
        let prev_moved = std::mem::take(&mut self.moved_vars);
        let prev_generics = std::mem::replace(&mut self.current_func_generics, f.generics.clone());
        self.current_func_ret_ty = Some(ret_ty.clone());
        self.current_func_is_strict = f.is_strict;

        // Enter function root scope
        self.symbols.enter_scope(false, true);

        // Register parameters as variables in the function scope
        let fn_params = self
            .symbols
            .lookup_function(&f.name)
            .map(|sym| sym.params.clone())
            .unwrap_or_default();

        for p in fn_params {
            let is_mut = matches!(p.mode, ParamMode::Mut | ParamMode::InOut);
            if let Err(diag) =
                self.symbols
                    .define_variable(p.name, p.ty, is_mut, true, Some(p.mode), p.span)
            {
                self.diagnostics.push(diag);
            }
        }

        // Check function body if present
        if let Some(body) = &f.body {
            self.check_block(body, Some(&ret_ty));
        }

        self.symbols.exit_scope();
        self.current_func_ret_ty = prev_ret;
        self.current_func_is_strict = prev_strict;
        self.moved_vars = prev_moved;
        self.current_func_generics = prev_generics;
    }

    fn check_block(&mut self, block: &Block, expected_ret: Option<&Type>) -> Type {
        for stmt in &block.stmts {
            self.check_stmt(stmt);
        }

        if let Some(expr) = &block.expr {
            let actual = self.check_expr(expr, expected_ret);
            if let Some(expected) = expected_ret {
                if !expected.is_unit() && !actual.is_assignable_to(expected) {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "type de retour incompatible : attendu {}, trouvé {}",
                            expected, actual
                        ))
                        .with_code("E0001")
                        .with_primary_label(expr.span, format!("expression de type {}", actual))
                        .with_help("Vérifiez le type de retour déclaré de la fonction."),
                    );
                }
            }
            actual
        } else {
            Type::Unit
        }
    }

    fn check_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Let {
                is_mut,
                name,
                ty: annotated_ty,
                init,
                span,
            } => {
                let declared_ty = if let Some(ast_ty) = annotated_ty {
                    let known_structs = self.get_known_struct_types();
                    let known_enums = self.get_known_enum_types();
                    match Type::from_ast_with_generics(
                        ast_ty,
                        &known_structs,
                        &known_enums,
                        &self.current_func_generics,
                    ) {
                        Ok(t) => Some(t),
                        Err(d) => {
                            self.diagnostics.push(d);
                            Some(Type::Unknown)
                        }
                    }
                } else {
                    None
                };

                let actual_ty = if let Some(init_expr) = init {
                    let inferred = self.check_expr(init_expr, declared_ty.as_ref());
                    if let Some(expected) = &declared_ty {
                        if !inferred.is_assignable_to(expected) {
                            let var_name = INTERNER.resolve(name);
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "type incompatible pour '{}' : attendu {}, trouvé {}",
                                    var_name, expected, inferred
                                ))
                                .with_code("E0001")
                                .with_primary_label(
                                    init_expr.span,
                                    format!("type {} ici", inferred),
                                )
                                .with_secondary_label(*span, format!("type {} déclaré", expected)),
                            );
                            expected.clone()
                        } else {
                            expected.clone()
                        }
                    } else {
                        inferred.resolve_defaults()
                    }
                } else {
                    declared_ty.unwrap_or(Type::Unknown)
                };

                self.symbols.register_type_if_generic_instance(&actual_ty);

                if let Err(diag) = self.symbols.define_variable(
                    *name,
                    actual_ty,
                    *is_mut,
                    init.is_some(),
                    None,
                    *span,
                ) {
                    self.diagnostics.push(diag);
                }
                self.moved_vars.remove(name);
            }
            Stmt::Assign {
                target,
                op: _,
                val,
                span: _,
            } => {
                // Verify exclusivity & mutability of target
                check_assignment_target(target, &self.symbols, &mut self.diagnostics);

                if let Some((root_sym, _)) = crate::exclusivity::extract_root_variable(target) {
                    self.moved_vars.remove(&root_sym);
                    if let Some(var) = self.symbols.lookup_variable_mut(&root_sym) {
                        var.is_initialized = true;
                    }
                }

                let target_ty = self.infer_expr(target);
                let val_ty = self.check_expr(val, Some(&target_ty));

                if !val_ty.is_assignable_to(&target_ty) {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "type incompatible lors de l'assignation : la cible est {}, mais la valeur est {}",
                            target_ty, val_ty
                        ))
                        .with_code("E0001")
                        .with_primary_label(val.span, format!("valeur de type {}", val_ty))
                        .with_secondary_label(target.span, format!("cible de type {}", target_ty)),
                    );
                }
            }
            Stmt::Expr(expr) => {
                self.infer_expr(expr);
            }
            Stmt::Return(ret_expr, span) => {
                if let Some(func_ret) = &self.current_func_ret_ty {
                    let func_ret = func_ret.clone();
                    if let Some(expr) = ret_expr {
                        let actual = self.check_expr(expr, Some(&func_ret));
                        if !actual.is_assignable_to(&func_ret) {
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "type de retour incompatible : attendu {}, trouvé {}",
                                    func_ret, actual
                                ))
                                .with_code("E0001")
                                .with_primary_label(
                                    expr.span,
                                    format!("expression de type {}", actual),
                                )
                                .with_secondary_label(
                                    *span,
                                    format!("la fonction retourne {}", func_ret),
                                ),
                            );
                        }
                    } else if !func_ret.is_unit() {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "valeur de retour manquante : la fonction attend {}",
                                func_ret
                            ))
                            .with_code("E0001")
                            .with_primary_label(*span, "instruction 'return' sans valeur"),
                        );
                    }
                } else if let Some(expr) = ret_expr {
                    self.infer_expr(expr);
                }
            }
            Stmt::Fail(expr, span) => {
                let func_ret = self.current_func_ret_ty.clone().unwrap_or(Type::Unit);
                match &func_ret {
                    Type::ErrorUnion { err, .. } => {
                        let actual = self.check_expr(expr, Some(err));
                        if !actual.is_assignable_to(err) {
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "type d'erreur incompatible pour 'fail' : attendu {}, trouvé {}",
                                    err, actual
                                ))
                                .with_code("E0031")
                                .with_primary_label(expr.span, format!("expression de type {}", actual))
                                .with_secondary_label(*span, format!("l'union d'erreur attend {}", err)),
                            );
                        }
                    }
                    _ => {
                        self.diagnostics.push(
                            Diagnostic::error("l'instruction 'fail' ne peut être utilisée que dans une fonction retournant un type union d'erreur ('Error!T')")
                                .with_code("E0030")
                                .with_primary_label(*span, "utilisation invalide de 'fail'")
                                .with_help("Changez la signature de retour en 'Error!T' (ex: IoError!String)."),
                        );
                        self.infer_expr(expr);
                    }
                }
            }
            Stmt::While {
                cond,
                body,
                span: _,
            } => {
                let cond_ty = self.check_expr(cond, Some(&Type::Bool));
                if !cond_ty.is_assignable_to(&Type::Bool) {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "la condition de 'while' doit être de type bool, mais trouvé {}",
                            cond_ty
                        ))
                        .with_code("E0001")
                        .with_primary_label(cond.span, "condition non booléenne"),
                    );
                }
                self.symbols.enter_scope(true, false);
                self.check_block(body, None);
                self.symbols.exit_scope();
            }
            Stmt::For {
                var,
                iterable,
                body,
                span,
            } => {
                let iter_ty = self.infer_expr(iterable);
                let elem_ty = match &iter_ty {
                    Type::Array(elem, _) => *elem.clone(),
                    Type::Slice(elem) => *elem.clone(),
                    Type::Generic { name, args }
                        if INTERNER.resolve(name) == "List" && !args.is_empty() =>
                    {
                        args[0].clone()
                    }
                    _ => {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "type '{}' non itérable dans une boucle 'for'",
                                iter_ty
                            ))
                            .with_code("E0032")
                            .with_primary_label(iterable.span, "expression non itérable"),
                        );
                        Type::Unknown
                    }
                };

                self.symbols.enter_scope(true, false);
                if let Err(diag) = self
                    .symbols
                    .define_variable(*var, elem_ty, false, true, None, *span)
                {
                    self.diagnostics.push(diag);
                }
                self.check_block(body, None);
                self.symbols.exit_scope();
            }
            Stmt::Loop(body, _) => {
                self.symbols.enter_scope(true, false);
                self.check_block(body, None);
                self.symbols.exit_scope();
            }
            Stmt::Defer(body, _) => {
                self.symbols.enter_scope(false, false);
                self.check_block(body, None);
                self.symbols.exit_scope();
            }
            Stmt::Break(span) => {
                if !self.symbols.is_inside_loop() {
                    self.diagnostics.push(
                        Diagnostic::error("instruction 'break' en dehors d'une boucle")
                            .with_code("E0033")
                            .with_primary_label(*span, "break orphelin"),
                    );
                }
            }
            Stmt::Continue(span) => {
                if !self.symbols.is_inside_loop() {
                    self.diagnostics.push(
                        Diagnostic::error("instruction 'continue' en dehors d'une boucle")
                            .with_code("E0034")
                            .with_primary_label(*span, "continue orphelin"),
                    );
                }
            }
        }
    }

    // =========================================================================
    // Expression Type Checking & Inference
    // =========================================================================

    pub fn infer_expr(&mut self, expr: &Expr) -> Type {
        self.check_expr(expr, None)
    }

    pub fn check_expr(&mut self, expr: &Expr, expected: Option<&Type>) -> Type {
        let ty = match &expr.kind {
            ExprKind::Lit(lit) => match lit {
                Lit::Int(sym) => {
                    let text = INTERNER.resolve(sym);
                    Type::parse_int_literal(&text, expected)
                }
                Lit::Float(sym) => {
                    let text = INTERNER.resolve(sym);
                    Type::parse_float_literal(&text, expected)
                }
                Lit::String(_) => {
                    if let Some(Type::Str) = expected {
                        Type::Str
                    } else {
                        Type::String
                    }
                }
                Lit::Char(_) => Type::Char,
                Lit::Bool(_) => Type::Bool,
            },
            ExprKind::Ident(sym) => {
                let name = INTERNER.resolve(sym);
                if name == "None" {
                    if let Some(Type::Optional(inner)) = expected {
                        Type::Optional(inner.clone())
                    } else {
                        Type::Optional(Box::new(Type::Unknown))
                    }
                } else if name == "true" || name == "false" {
                    Type::Bool
                } else if let Some(var) = self.symbols.lookup_variable(sym) {
                    if let Some(move_span) = self.moved_vars.get(sym) {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "utilisation de la variable '{}' après transfert de propriété ('sink')",
                                name
                            ))
                            .with_code("E0018")
                            .with_primary_label(expr.span, format!("variable '{}' déjà transférée/consommée", name))
                            .with_secondary_label(*move_span, "transfert 'sink' effectué ici")
                            .with_help("Une variable transférée avec 'sink' ne peut plus être utilisée."),
                        );
                    } else if !var.is_initialized {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "utilisation de la variable non initialisée '{}'",
                                name
                            ))
                            .with_code("E0019")
                            .with_primary_label(expr.span, "variable non initialisée")
                            .with_secondary_label(var.span, "déclarée sans valeur initiale ici")
                            .with_help("Initialisez la variable avant de lire sa valeur."),
                        );
                    }
                    var.ty.clone()
                } else if let Some(c) = self.symbols.lookup_const(sym) {
                    c.ty.clone()
                } else if let Some(st) = self.symbols.lookup_struct(sym) {
                    Type::Struct {
                        name: *sym,
                        fields: st.fields.iter().map(|f| (f.name, f.ty.clone())).collect(),
                    }
                } else {
                    self.diagnostics.push(
                        Diagnostic::error(format!("variable ou identifiant inconnu '{}'", name))
                            .with_code("E0001")
                            .with_primary_label(expr.span, "identifiant non trouvé dans cette portée")
                            .with_help("Vérifiez l'orthographe ou déclarez la variable avant son utilisation."),
                    );
                    Type::Unknown
                }
            }
            ExprKind::Path(path) => {
                let full_path: Vec<String> = path.iter().map(|s| INTERNER.resolve(s)).collect();
                let joined = full_path.join("::");

                if joined == "List::new" {
                    if let Some(Type::Generic { name, args }) = expected {
                        if INTERNER.resolve(name) == "List" {
                            Type::Generic {
                                name: *name,
                                args: args.clone(),
                            }
                        } else {
                            Type::Generic {
                                name: *path.first().unwrap(),
                                args: vec![Type::Unknown],
                            }
                        }
                    } else {
                        Type::Generic {
                            name: *path.first().unwrap(),
                            args: vec![Type::Unknown],
                        }
                    }
                } else if let Some(last) = path.last() {
                    if let Some(var) = self.symbols.lookup_variable(last) {
                        var.ty.clone()
                    } else if let Some(st) = self.symbols.lookup_struct(last) {
                        Type::Struct {
                            name: *last,
                            fields: st.fields.iter().map(|f| (f.name, f.ty.clone())).collect(),
                        }
                    } else {
                        // Module path or foreign reference (e.g. io::println, http::Server)
                        Type::Unknown
                    }
                } else {
                    Type::Unknown
                }
            }
            ExprKind::Binary { op, left, right } => {
                self.check_binary_expr(*op, left, right, expr.span)
            }
            ExprKind::Unary { op, expr: inner } => self.check_unary_expr(*op, inner, expr.span),
            ExprKind::Call { callee, args } => self.check_call_expr(callee, args, expr.span),
            ExprKind::MethodCall {
                receiver,
                method,
                args,
            } => self.check_method_call_expr(receiver, *method, args, expr.span),
            ExprKind::FieldAccess { receiver, field } => {
                let rec_ty = self.infer_expr(receiver);
                if let Some((name, fields)) = self.resolve_struct_fields(&rec_ty) {
                    if let Some((_, fty)) = fields.iter().find(|(n, _)| n == field) {
                        fty.clone()
                    } else {
                        let f_name = INTERNER.resolve(field);
                        let s_name = INTERNER.resolve(&name);
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "champ '{}' introuvable sur la structure '{}'",
                                f_name, s_name
                            ))
                            .with_code("E0007")
                            .with_primary_label(expr.span, format!("champ '{}' inconnu", f_name)),
                        );
                        Type::Unknown
                    }
                } else if matches!(rec_ty, Type::Unknown) {
                    Type::Unknown
                } else {
                    let f_name = INTERNER.resolve(field);
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "accès au champ '{}' impossible sur le type non composite '{}'",
                            f_name, rec_ty
                        ))
                        .with_code("E0007")
                        .with_primary_label(receiver.span, format!("type {} non struct", rec_ty)),
                    );
                    Type::Unknown
                }
            }
            ExprKind::Index { receiver, index } => {
                let rec_ty = self.infer_expr(receiver);
                let idx_ty = self.check_expr(index, Some(&Type::Int(IntType::USize)));
                if !idx_ty.is_integer() {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "l'index doit être un entier, mais trouvé {}",
                            idx_ty
                        ))
                        .with_code("E0001")
                        .with_primary_label(index.span, "index non entier"),
                    );
                }
                match &rec_ty {
                    Type::Array(elem, _) => *elem.clone(),
                    Type::Slice(elem) => *elem.clone(),
                    Type::Generic { name, args }
                        if INTERNER.resolve(name) == "List" && !args.is_empty() =>
                    {
                        args[0].clone()
                    }
                    _ => {
                        self.diagnostics.push(
                            Diagnostic::error(format!("le type '{}' n'est pas indexable", rec_ty))
                                .with_code("E0001")
                                .with_primary_label(receiver.span, "expression non indexable"),
                        );
                        Type::Unknown
                    }
                }
            }
            ExprKind::Array(elems) => {
                if elems.is_empty() {
                    if let Some(Type::Array(elem, 0)) = expected {
                        Type::Array(elem.clone(), 0)
                    } else if let Some(Type::Slice(elem)) = expected {
                        Type::Slice(elem.clone())
                    } else {
                        Type::Array(Box::new(Type::Unknown), 0)
                    }
                } else {
                    let expected_elem = match expected {
                        Some(Type::Array(el, _)) => Some(el.as_ref()),
                        Some(Type::Slice(el)) => Some(el.as_ref()),
                        _ => None,
                    };
                    let first_ty = self.check_expr(&elems[0], expected_elem);
                    for elem in &elems[1..] {
                        let elem_ty = self.check_expr(elem, Some(&first_ty));
                        if !elem_ty.is_assignable_to(&first_ty) {
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "élément de tableau de type incompatible : attendu {}, trouvé {}",
                                    first_ty, elem_ty
                                ))
                                .with_code("E0001")
                                .with_primary_label(elem.span, format!("type {}", elem_ty)),
                            );
                        }
                    }
                    Type::Array(Box::new(first_ty), elems.len() as u32)
                }
            }
            ExprKind::ArrayRepeat(val, count_expr) => {
                let expected_elem = match expected {
                    Some(Type::Array(el, _)) => Some(el.as_ref()),
                    Some(Type::Slice(el)) => Some(el.as_ref()),
                    _ => None,
                };
                let elem_ty = self.check_expr(val, expected_elem);
                let count = match &count_expr.kind {
                    ExprKind::Lit(Lit::Int(sym)) => {
                        let text = INTERNER.resolve(sym);
                        text.trim_end_matches(|c: char| c.is_alphabetic())
                            .parse::<u32>()
                            .unwrap_or(0)
                    }
                    _ => 0,
                };
                Type::Array(Box::new(elem_ty), count)
            }
            ExprKind::Record(_) => Type::Unknown,
            ExprKind::Block(b) => {
                self.symbols.enter_scope(false, false);
                let ty = self.check_block(b, expected);
                self.symbols.exit_scope();
                ty
            }
            ExprKind::If {
                cond,
                then_branch,
                else_branch,
            } => {
                let cond_ty = self.check_expr(cond, Some(&Type::Bool));
                if !cond_ty.is_assignable_to(&Type::Bool) {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "la condition de 'if' doit être de type bool, mais trouvé {}",
                            cond_ty
                        ))
                        .with_code("E0001")
                        .with_primary_label(cond.span, "condition non booléenne"),
                    );
                }
                self.symbols.enter_scope(false, false);
                let then_ty = self.check_block(then_branch, expected);
                self.symbols.exit_scope();

                if let Some(el) = else_branch {
                    let else_ty = self.check_expr(el, Some(&then_ty));
                    if !then_ty.is_never()
                        && !else_ty.is_never()
                        && !else_ty.is_assignable_to(&then_ty)
                    {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "incompatibilité de type entre les branches 'if' ({}) et 'else' ({})",
                                then_ty, else_ty
                            ))
                            .with_code("E0001")
                            .with_primary_label(el.span, format!("branche 'else' de type {}", else_ty))
                            .with_secondary_label(then_branch.span, format!("branche 'then' de type {}", then_ty)),
                        );
                    }
                    then_ty
                } else {
                    Type::Unit
                }
            }
            ExprKind::Catch {
                expr: target,
                err_var,
                body,
            } => {
                let target_ty = self.infer_expr(target);
                match target_ty {
                    Type::ErrorUnion { err, ok } => {
                        self.symbols.enter_scope(false, false);
                        if let Some(err_name) = err_var {
                            if let Err(diag) = self.symbols.define_variable(
                                *err_name,
                                *err,
                                false,
                                true,
                                None,
                                target.span,
                            ) {
                                self.diagnostics.push(diag);
                            }
                        }
                        self.check_block(body, Some(&ok));
                        self.symbols.exit_scope();
                        *ok
                    }
                    _ => {
                        // Gracefully allow catch on any expression if inferred as unknown/any
                        self.symbols.enter_scope(false, false);
                        if let Some(err_name) = err_var {
                            let _ = self.symbols.define_variable(
                                *err_name,
                                Type::Unknown,
                                false,
                                true,
                                None,
                                target.span,
                            );
                        }
                        self.check_block(body, expected);
                        self.symbols.exit_scope();
                        target_ty
                    }
                }
            }
            ExprKind::StructInit { name, fields } => {
                if let Some(struct_name) = name.last() {
                    let s_name_str = INTERNER.resolve(struct_name);
                    if let Some(st) = self.symbols.lookup_struct(struct_name).cloned() {
                        if !st.generics.is_empty() {
                            let mut type_param_map: HashMap<Symbol, Type> = HashMap::new();
                            for (f_sym, f_val) in fields {
                                if let Some(f_def) = st.get_field(f_sym) {
                                    let arg_ty = self.infer_expr(f_val);
                                    f_def.ty.unify_type_params(&arg_ty, &mut type_param_map);
                                }
                            }
                            for (f_sym, f_val) in fields {
                                if let Some(f_def) = st.get_field(f_sym) {
                                    let expected_ty = f_def.ty.substitute(&type_param_map);
                                    let actual = self.check_expr(f_val, Some(&expected_ty));
                                    if !actual.is_assignable_to(&expected_ty) {
                                        let field_name = INTERNER.resolve(f_sym);
                                        self.diagnostics.push(
                                            Diagnostic::error(format!(
                                                "type incompatible pour le champ '{}' de '{}' : attendu {}, trouvé {}",
                                                field_name, s_name_str, expected_ty, actual
                                            ))
                                            .with_code("E0001")
                                            .with_primary_label(f_val.span, format!("type {}", actual)),
                                        );
                                    }
                                } else {
                                    let field_name = INTERNER.resolve(f_sym);
                                    self.diagnostics.push(
                                        Diagnostic::error(format!(
                                            "champ inconnu '{}' pour la structure '{}'",
                                            field_name, s_name_str
                                        ))
                                        .with_code("E0008")
                                        .with_primary_label(f_val.span, "champ inexistant"),
                                    );
                                }
                            }
                            for g in &st.generics {
                                if let Some(concrete_ty) = type_param_map.get(&g.name) {
                                    for bound in &g.bounds {
                                        let is_satisfied = match concrete_ty {
                                            Type::TypeParam(caller_p) => {
                                                self.current_func_generics.iter().any(|cg| {
                                                    cg.name == *caller_p
                                                        && cg.bounds.contains(bound)
                                                })
                                            }
                                            _ => self
                                                .symbols
                                                .type_implements_trait(concrete_ty, bound),
                                        };

                                        if !is_satisfied {
                                            let bound_name = INTERNER.resolve(bound);
                                            let ty_str = format!("{}", concrete_ty);
                                            self.diagnostics.push(
                                                Diagnostic::error(format!(
                                                    "le type '{}' ne satisfait pas la contrainte de trait '{}' requise par la structure '{}'",
                                                    ty_str, bound_name, s_name_str
                                                ))
                                                .with_code("E0030")
                                                .with_primary_label(
                                                    expr.span,
                                                    format!("le type '{}' n'implémente pas le contrat '{}'", ty_str, bound_name),
                                                ),
                                            );
                                        }
                                    }
                                }
                            }
                            let concrete_args: Vec<Type> = st
                                .generics
                                .iter()
                                .map(|g| {
                                    type_param_map
                                        .get(&g.name)
                                        .cloned()
                                        .unwrap_or(Type::Unknown)
                                })
                                .collect();
                            if concrete_args.iter().all(|t| !matches!(t, Type::Unknown)) {
                                self.symbols
                                    .call_instantiations
                                    .insert(expr.span, concrete_args.clone());
                                if concrete_args
                                    .iter()
                                    .all(|t| !matches!(t, Type::TypeParam(_)))
                                {
                                    self.symbols.record_generic_struct_instance(
                                        *struct_name,
                                        concrete_args.clone(),
                                    );
                                }
                            }
                            Type::Generic {
                                name: *struct_name,
                                args: concrete_args,
                            }
                        } else {
                            for (f_sym, f_val) in fields {
                                if let Some(f_def) = st.get_field(f_sym) {
                                    let actual = self.check_expr(f_val, Some(&f_def.ty));
                                    if !actual.is_assignable_to(&f_def.ty) {
                                        let field_name = INTERNER.resolve(f_sym);
                                        self.diagnostics.push(
                                            Diagnostic::error(format!(
                                                "type incompatible pour le champ '{}' de '{}' : attendu {}, trouvé {}",
                                                field_name, s_name_str, f_def.ty, actual
                                            ))
                                            .with_code("E0001")
                                            .with_primary_label(f_val.span, format!("type {}", actual)),
                                        );
                                    }
                                } else {
                                    let field_name = INTERNER.resolve(f_sym);
                                    self.diagnostics.push(
                                        Diagnostic::error(format!(
                                            "champ inconnu '{}' pour la structure '{}'",
                                            field_name, s_name_str
                                        ))
                                        .with_code("E0008")
                                        .with_primary_label(f_val.span, "champ inexistant"),
                                    );
                                }
                            }
                            Type::Struct {
                                name: *struct_name,
                                fields: st.fields.iter().map(|f| (f.name, f.ty.clone())).collect(),
                            }
                        }
                    } else {
                        Type::Unknown
                    }
                } else {
                    Type::Unknown
                }
            }
            ExprKind::Tuple(items) => {
                let types = items.iter().map(|item| self.infer_expr(item)).collect();
                Type::Tuple(types)
            }
            ExprKind::Unit => Type::Unit,
            ExprKind::Lambda { params, body } => {
                self.symbols.enter_scope(false, false);
                let known_structs = self.get_known_struct_types();
                let known_enums = self.get_known_enum_types();
                let mut param_types = Vec::new();
                for p in params {
                    let ty = Type::from_ast(&p.ty, &known_structs, &known_enums)
                        .unwrap_or(Type::Unknown);
                    let _ =
                        self.symbols
                            .define_variable(p.name, ty.clone(), false, true, None, p.span);
                    param_types.push((p.mode, ty));
                }
                let prev_ret = self.current_func_ret_ty.take();
                let ret = self.check_block(body, None);
                self.current_func_ret_ty = prev_ret;
                self.symbols.exit_scope();
                Type::Fn {
                    params: param_types,
                    ret: Box::new(ret),
                }
            }
            ExprKind::Spawn(inner) => {
                self.infer_expr(inner);
                Type::Unit
            }
            ExprKind::Comptime(inner) => {
                let ty = self.check_expr(inner, expected);
                if let Err(comptime_err) = self.comptime_vm.eval_expr(inner) {
                    self.diagnostics.push(comptime_err.to_diagnostic());
                }
                ty
            }
            ExprKind::Match {
                expr: target_expr,
                arms,
            } => {
                let target_ty = self.infer_expr(target_expr);
                if arms.is_empty() {
                    self.diagnostics.push(
                        Diagnostic::error(
                            "l'expression 'match' doit comporter au moins une branche",
                        )
                        .with_code("E0033")
                        .with_primary_label(expr.span, "branches manquantes"),
                    );
                    Type::Unknown
                } else {
                    let mut arm_types = Vec::new();
                    for arm in arms {
                        self.symbols.enter_scope(false, false);
                        self.check_pattern(&arm.pattern, &target_ty);
                        if let Some(guard) = &arm.guard {
                            let guard_ty = self.infer_expr(guard);
                            if !matches!(guard_ty, Type::Bool | Type::Unknown) {
                                self.diagnostics.push(
                                    Diagnostic::error(format!(
                                        "la condition de garde 'match' doit être un booléen, trouvé '{}'",
                                        guard_ty
                                    ))
                                    .with_code("E0034")
                                    .with_primary_label(guard.span, "condition de garde non booléenne"),
                                );
                            }
                        }
                        let arm_ty = self.check_expr(&arm.body, expected);
                        self.symbols.exit_scope();
                        arm_types.push(arm_ty);
                    }

                    let mut unified = arm_types[0].clone();
                    for arm_ty in &arm_types[1..] {
                        if !arm_ty.is_assignable_to(&unified)
                            && !unified.is_assignable_to(arm_ty)
                            && *arm_ty != Type::Unknown
                            && unified != Type::Unknown
                        {
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "incompatibilité de type entre les branches du 'match' : attendu '{}', trouvé '{}'",
                                    unified, arm_ty
                                ))
                                .with_code("E0035")
                                .with_primary_label(expr.span, "types incompatibles entre les branches"),
                            );
                        } else if unified == Type::Unknown {
                            unified = arm_ty.clone();
                        }
                    }
                    unified
                }
            }
        };

        self.expr_types.insert(expr.span, ty.clone());
        ty
    }

    fn check_pattern(&mut self, pat: &Pattern, target_ty: &Type) {
        match pat {
            Pattern::Wildcard(_) => {}
            Pattern::Lit(lit, span) => {
                let lit_ty = match lit {
                    Lit::Int(_) => Type::Int(IntType::I64),
                    Lit::Float(_) => Type::Float(crate::types::FloatType::F64),
                    Lit::Bool(_) => Type::Bool,
                    Lit::Char(_) => Type::Char,
                    Lit::String(_) => Type::Str,
                };
                if !lit_ty.is_assignable_to(target_ty)
                    && !target_ty.is_assignable_to(&lit_ty)
                    && *target_ty != Type::Unknown
                {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "le motif de type '{}' est incompatible avec le type '{}'",
                            lit_ty, target_ty
                        ))
                        .with_code("E0036")
                        .with_primary_label(*span, "type de motif incompatible"),
                    );
                }
            }
            Pattern::Ident(sym, span) => {
                let _ =
                    self.symbols
                        .define_variable(*sym, target_ty.clone(), false, true, None, *span);
            }
            Pattern::Variant {
                enum_name,
                variant,
                inner,
                span,
            } => {
                if let Type::Enum { name: e_sym, .. } = target_ty {
                    if let Some(e_decl) = self.symbols.lookup_enum(e_sym) {
                        if !e_decl.variants.iter().any(|(v, _)| v == variant) {
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "le variant '{}' n'existe pas dans l'énumération '{}'",
                                    INTERNER.resolve(variant),
                                    INTERNER.resolve(e_sym)
                                ))
                                .with_code("E0037")
                                .with_primary_label(*span, "variant inconnu"),
                            );
                        }
                    }
                } else if let Some(e_sym) = enum_name {
                    if let Some(e_decl) = self.symbols.lookup_enum(e_sym) {
                        if !e_decl.variants.iter().any(|(v, _)| v == variant) {
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "le variant '{}' n'existe pas dans l'énumération '{}'",
                                    INTERNER.resolve(variant),
                                    INTERNER.resolve(e_sym)
                                ))
                                .with_code("E0037")
                                .with_primary_label(*span, "variant inconnu"),
                            );
                        }
                    }
                }
                if let Some(inner_pat) = inner {
                    self.check_pattern(inner_pat, &Type::Unknown);
                }
            }
        }
    }

    fn check_binary_expr(&mut self, op: BinOp, left: &Expr, right: &Expr, span: Span) -> Type {
        match op {
            BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Rem => {
                let l_ty = self.infer_expr(left);
                let r_ty = self.check_expr(right, Some(&l_ty));
                if l_ty.is_numeric() && r_ty.is_numeric() {
                    l_ty.resolve_defaults()
                } else if matches!(l_ty, Type::String | Type::Str)
                    && matches!(r_ty, Type::String | Type::Str)
                {
                    Type::String
                } else if matches!(l_ty, Type::TypeParam(_)) && l_ty == r_ty {
                    l_ty.clone()
                } else {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "opération arithmétique impossible entre le type {} et {}",
                            l_ty, r_ty
                        ))
                        .with_code("E0001")
                        .with_primary_label(span, "types incompatibles pour l'opération"),
                    );
                    Type::Unknown
                }
            }
            BinOp::BitAnd | BinOp::BitOr | BinOp::BitXor | BinOp::Shl | BinOp::Shr => {
                let l_ty = self.infer_expr(left);
                let r_ty = self.check_expr(right, Some(&l_ty));
                if l_ty.is_integer() && r_ty.is_integer() {
                    l_ty.resolve_defaults()
                } else if matches!(l_ty, Type::TypeParam(_)) && l_ty == r_ty {
                    l_ty.clone()
                } else {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "opération bitwise impossible entre le type {} et {}",
                            l_ty, r_ty
                        ))
                        .with_code("E0001")
                        .with_primary_label(span, "types non entiers"),
                    );
                    Type::Unknown
                }
            }
            BinOp::Eq | BinOp::NotEq => {
                let l_ty = self.infer_expr(left);
                let _ = self.check_expr(right, Some(&l_ty));
                Type::Bool
            }
            BinOp::Lt | BinOp::LtEq | BinOp::Gt | BinOp::GtEq => {
                let l_ty = self.infer_expr(left);
                let _ = self.check_expr(right, Some(&l_ty));
                Type::Bool
            }
            BinOp::And | BinOp::Or => {
                self.check_expr(left, Some(&Type::Bool));
                self.check_expr(right, Some(&Type::Bool));
                Type::Bool
            }
            BinOp::Coalesce => {
                let l_ty = self.infer_expr(left);
                match l_ty {
                    Type::Optional(inner) => {
                        let _ = self.check_expr(right, Some(&inner));
                        *inner
                    }
                    _ => l_ty,
                }
            }
        }
    }

    fn check_unary_expr(&mut self, op: UnaryOp, inner: &Expr, span: Span) -> Type {
        match op {
            UnaryOp::Neg => {
                let ty = self.infer_expr(inner);
                if !ty.is_numeric() {
                    self.diagnostics.push(
                        Diagnostic::error(format!("négation impossible sur le type {}", ty))
                            .with_code("E0001")
                            .with_primary_label(span, "type non numérique"),
                    );
                }
                ty
            }
            UnaryOp::Not => {
                let ty = self.infer_expr(inner);
                if !matches!(ty, Type::Bool) && !ty.is_integer() {
                    self.diagnostics.push(
                        Diagnostic::error(format!("opérateur '!' impossible sur le type {}", ty))
                            .with_code("E0001")
                            .with_primary_label(span, "attendu bool ou entier"),
                    );
                }
                ty
            }
            UnaryOp::Ref => {
                let ty = self.infer_expr(inner);
                Type::Ref(Box::new(ty))
            }
            UnaryOp::InOut => self.infer_expr(inner),
            UnaryOp::Sink => self.infer_expr(inner),
            UnaryOp::Try => {
                let ty = self.infer_expr(inner);
                match ty {
                    Type::ErrorUnion { err, ok } => {
                        if let Some(func_ret) = &self.current_func_ret_ty {
                            match func_ret {
                                Type::ErrorUnion { err: func_err, .. } => {
                                    if !err.is_assignable_to(func_err) {
                                        self.diagnostics.push(
                                            Diagnostic::error(format!(
                                                "incompatibilité d'erreur pour 'try' : l'expression produit {}, mais la fonction propage {}",
                                                err, func_err
                                            ))
                                            .with_code("E0035")
                                            .with_primary_label(span, format!("erreur de type {}", err)),
                                        );
                                    }
                                }
                                _ => {
                                    self.diagnostics.push(
                                        Diagnostic::error("l'opérateur 'try' ne peut être utilisé que dans une fonction retournant une union d'erreur ('Error!T')")
                                            .with_code("E0036")
                                            .with_primary_label(span, "fonction englobante sans type d'erreur"),
                                    );
                                }
                            }
                        }
                        *ok
                    }
                    _ => {
                        self.diagnostics.push(
                            Diagnostic::error(format!("l'opérateur 'try' nécessite une union d'erreur ('Error!T'), mais trouvé {}", ty))
                                .with_code("E0037")
                                .with_primary_label(span, "type non union d'erreur"),
                        );
                        Type::Unknown
                    }
                }
            }
        }
    }

    fn check_call_expr(&mut self, callee: &Expr, args: &[Arg], span: Span) -> Type {
        // First check if callee is a struct constructor (e.g. WindowNode(...) or IoError(...))
        let struct_match = match &callee.kind {
            ExprKind::Ident(sym) => self.symbols.lookup_struct(sym).cloned(),
            ExprKind::Path(path) => {
                if let Some(last) = path.last() {
                    self.symbols.lookup_struct(last).cloned()
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(st) = struct_match {
            return self.check_struct_constructor_call(&st, args, span);
        }

        // Check if callee is a known function
        let fn_match = match &callee.kind {
            ExprKind::Ident(sym) => self.symbols.lookup_function(sym).cloned(),
            ExprKind::Path(path) => {
                if let Some(last) = path.last() {
                    self.symbols.lookup_function(last).cloned()
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(f) = fn_match {
            self.check_function_call(&f, args, span)
        } else {
            // Function or standard library function not yet in symbol table (e.g. io::println, http::Server::new)
            let param_modes = vec![ParamMode::In; args.len()];
            check_call_exclusivity(args, &param_modes, &self.symbols, &mut self.diagnostics);

            for arg in args {
                self.infer_expr(&arg.value);
                if matches!(
                    &arg.value.kind,
                    ExprKind::Unary {
                        op: UnaryOp::Sink,
                        ..
                    }
                ) {
                    if let Some((root_sym, _)) =
                        crate::exclusivity::extract_root_variable(&arg.value)
                    {
                        self.moved_vars.insert(root_sym, arg.value.span);
                    }
                }
            }
            Type::Unknown
        }
    }

    fn resolve_struct_fields(&self, ty: &Type) -> Option<(Symbol, Vec<(Symbol, Type)>)> {
        match ty {
            Type::Struct { name, fields } => {
                let actual_fields: Vec<(Symbol, Type)> = if fields.is_empty() {
                    if let Some(st_def) = self.symbols.lookup_struct(name) {
                        st_def
                            .fields
                            .iter()
                            .map(|f| (f.name, f.ty.clone()))
                            .collect()
                    } else {
                        fields.clone()
                    }
                } else {
                    fields.clone()
                };
                Some((*name, actual_fields))
            }
            Type::Generic { name, args } => {
                if let Some(st_def) = self.symbols.lookup_struct(name) {
                    let mut mapping = HashMap::new();
                    for (param, concrete) in st_def.generics.iter().zip(args.iter()) {
                        mapping.insert(param.name, concrete.clone());
                    }
                    let fields = st_def
                        .fields
                        .iter()
                        .map(|f| (f.name, f.ty.substitute(&mapping)))
                        .collect();
                    Some((*name, fields))
                } else {
                    None
                }
            }
            Type::Ref(inner) | Type::Optional(inner) => self.resolve_struct_fields(inner),
            _ => None,
        }
    }

    fn check_struct_constructor_call(
        &mut self,
        st: &StructSymbol,
        args: &[Arg],
        span: Span,
    ) -> Type {
        let s_name = INTERNER.resolve(&st.name);

        if !st.generics.is_empty() {
            // Generic struct: perform bidirectional type parameter inference
            let mut type_param_map: HashMap<Symbol, Type> = HashMap::new();
            for (idx, arg) in args.iter().enumerate() {
                let field_info = if let Some(field_name) = arg.name {
                    st.get_field(&field_name)
                } else {
                    st.fields.get(idx)
                };
                if let Some(f_def) = field_info {
                    let arg_ty = self.infer_expr(&arg.value);
                    f_def.ty.unify_type_params(&arg_ty, &mut type_param_map);
                }
            }

            for (idx, arg) in args.iter().enumerate() {
                let field_info = if let Some(field_name) = arg.name {
                    st.get_field(&field_name)
                } else {
                    st.fields.get(idx)
                };
                if let Some(f_def) = field_info {
                    let expected_ty = f_def.ty.substitute(&type_param_map);
                    let actual = self.check_expr(&arg.value, Some(&expected_ty));
                    if !actual.is_assignable_to(&expected_ty) {
                        let f_name = INTERNER.resolve(&f_def.name);
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "type incompatible pour le champ '{}' de '{}' : attendu {}, trouvé {}",
                                f_name, s_name, expected_ty, actual
                            ))
                            .with_code("E0001")
                            .with_primary_label(arg.value.span, format!("valeur de type {}", actual))
                            .with_secondary_label(f_def.span, format!("champ déclaré {}", expected_ty)),
                        );
                    }
                }
            }

            for g in &st.generics {
                if let Some(concrete_ty) = type_param_map.get(&g.name) {
                    for bound in &g.bounds {
                        let is_satisfied = match concrete_ty {
                            Type::TypeParam(caller_p) => self
                                .current_func_generics
                                .iter()
                                .any(|cg| cg.name == *caller_p && cg.bounds.contains(bound)),
                            _ => self.symbols.type_implements_trait(concrete_ty, bound),
                        };

                        if !is_satisfied {
                            let bound_name = INTERNER.resolve(bound);
                            let ty_str = format!("{}", concrete_ty);
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "le type '{}' ne satisfait pas la contrainte de trait '{}' requise par la structure '{}'",
                                    ty_str, bound_name, s_name
                                ))
                                .with_code("E0030")
                                .with_primary_label(
                                    span,
                                    format!("le type '{}' n'implémente pas le contrat '{}'", ty_str, bound_name),
                                ),
                            );
                        }
                    }
                }
            }

            let concrete_args: Vec<Type> = st
                .generics
                .iter()
                .map(|g| {
                    type_param_map
                        .get(&g.name)
                        .cloned()
                        .unwrap_or(Type::Unknown)
                })
                .collect();
            if concrete_args.iter().all(|t| !matches!(t, Type::Unknown)) {
                self.symbols
                    .call_instantiations
                    .insert(span, concrete_args.clone());
                if concrete_args
                    .iter()
                    .all(|t| !matches!(t, Type::TypeParam(_)))
                {
                    self.symbols
                        .record_generic_struct_instance(st.name, concrete_args.clone());
                }
            }
            Type::Generic {
                name: st.name,
                args: concrete_args,
            }
        } else {
            for (idx, arg) in args.iter().enumerate() {
                let field_info = if let Some(field_name) = arg.name {
                    st.get_field(&field_name)
                } else {
                    st.fields.get(idx)
                };

                if let Some(f_def) = field_info {
                    let arg_ty = self.check_expr(&arg.value, Some(&f_def.ty));
                    if !arg_ty.is_assignable_to(&f_def.ty) {
                        let f_name = INTERNER.resolve(&f_def.name);
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "type incompatible pour le champ '{}' de '{}' : attendu {}, trouvé {}",
                                f_name, s_name, f_def.ty, arg_ty
                            ))
                            .with_code("E0001")
                            .with_primary_label(arg.value.span, format!("valeur de type {}", arg_ty))
                            .with_secondary_label(f_def.span, format!("champ déclaré {}", f_def.ty)),
                        );
                    }
                }
            }

            Type::Struct {
                name: st.name,
                fields: st.fields.iter().map(|f| (f.name, f.ty.clone())).collect(),
            }
        }
    }

    fn check_function_call(&mut self, f: &FunctionSymbol, args: &[Arg], span: Span) -> Type {
        let param_modes: Vec<ParamMode> = f.params.iter().map(|p| p.mode).collect();

        // Check Law of Exclusivity on arguments!
        check_call_exclusivity(args, &param_modes, &self.symbols, &mut self.diagnostics);

        // Check argument count
        if args.len() != f.params.len() {
            let fn_name = INTERNER.resolve(&f.name);
            self.diagnostics.push(
                Diagnostic::error(format!(
                    "nombre d'arguments incorrect pour '{}' : attendu {}, trouvé {}",
                    fn_name,
                    f.params.len(),
                    args.len()
                ))
                .with_code("E0009")
                .with_primary_label(span, format!("appel avec {} argument(s)", args.len()))
                .with_secondary_label(
                    f.span,
                    format!("'{}' définie avec {} paramètre(s)", fn_name, f.params.len()),
                ),
            );
        }

        // Generic type parameters bidirectional inference
        let mut type_param_map: HashMap<Symbol, Type> = HashMap::new();
        if !f.generics.is_empty() {
            for (idx, arg) in args.iter().enumerate() {
                if let Some(param) = f.params.get(idx) {
                    let arg_ty = self.infer_expr(&arg.value);
                    param.ty.unify_type_params(&arg_ty, &mut type_param_map);
                }
            }
        }

        for (idx, arg) in args.iter().enumerate() {
            if let Some(param) = f.params.get(idx) {
                let expected_param_ty = if type_param_map.is_empty() {
                    param.ty.clone()
                } else {
                    param.ty.substitute(&type_param_map)
                };

                let arg_ty = self.check_expr(&arg.value, Some(&expected_param_ty));
                if !arg_ty.is_assignable_to(&expected_param_ty) {
                    let fn_name = INTERNER.resolve(&f.name);
                    let p_name = INTERNER.resolve(&param.name);
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "type incorrect pour le paramètre '{}' de '{}' : attendu {}, trouvé {}",
                            p_name, fn_name, expected_param_ty, arg_ty
                        ))
                        .with_code("E0001")
                        .with_primary_label(arg.value.span, format!("argument de type {}", arg_ty))
                        .with_secondary_label(
                            param.span,
                            format!("paramètre attend {}", expected_param_ty),
                        ),
                    );
                }

                if param.mode == ParamMode::Comptime
                    && self.comptime_vm.eval_expr(&arg.value).is_err()
                {
                    let p_name = INTERNER.resolve(&param.name);
                    let fn_name = INTERNER.resolve(&f.name);
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "l'argument pour le paramètre comptime '{}' de '{}' doit être une constante évaluable à la compilation",
                            p_name, fn_name
                        ))
                        .with_code("E0041")
                        .with_primary_label(arg.value.span, "expression constante attendue"),
                    );
                }
            }
        }

        for (idx, arg) in args.iter().enumerate() {
            let is_explicit_sink = matches!(
                &arg.value.kind,
                ExprKind::Unary {
                    op: UnaryOp::Sink,
                    ..
                }
            );
            let is_param_sink = f
                .params
                .get(idx)
                .map(|p| p.mode == ParamMode::Sink)
                .unwrap_or(false);
            if is_explicit_sink || is_param_sink {
                if let Some((root_sym, _)) = crate::exclusivity::extract_root_variable(&arg.value) {
                    self.moved_vars.insert(root_sym, arg.value.span);
                }
            }
        }

        if !f.generics.is_empty() {
            for g in &f.generics {
                if let Some(concrete_ty) = type_param_map.get(&g.name) {
                    for bound in &g.bounds {
                        let is_satisfied = match concrete_ty {
                            Type::TypeParam(caller_p) => self
                                .current_func_generics
                                .iter()
                                .any(|cg| cg.name == *caller_p && cg.bounds.contains(bound)),
                            _ => self.symbols.type_implements_trait(concrete_ty, bound),
                        };

                        if !is_satisfied {
                            let bound_name = INTERNER.resolve(bound);
                            let ty_str = format!("{}", concrete_ty);
                            let fn_name = INTERNER.resolve(&f.name);
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "le type '{}' ne satisfait pas la contrainte de trait '{}' requise par la fonction '{}'",
                                    ty_str, bound_name, fn_name
                                ))
                                .with_code("E0030")
                                .with_primary_label(
                                    span,
                                    format!("le type '{}' n'implémente pas le contrat '{}'", ty_str, bound_name),
                                ),
                            );
                        }
                    }
                }
            }

            let concrete_args: Vec<Type> = f
                .generics
                .iter()
                .map(|g| {
                    type_param_map
                        .get(&g.name)
                        .cloned()
                        .unwrap_or(Type::Unknown)
                })
                .collect();
            if concrete_args.iter().all(|t| !matches!(t, Type::Unknown)) {
                self.symbols
                    .call_instantiations
                    .insert(span, concrete_args.clone());
                if concrete_args
                    .iter()
                    .all(|t| !matches!(t, Type::TypeParam(_)))
                {
                    self.symbols
                        .record_generic_function_instance(f.name, concrete_args);
                }
            }
        }

        if type_param_map.is_empty() {
            f.ret_ty.clone()
        } else {
            f.ret_ty.substitute(&type_param_map)
        }
    }

    fn check_method_call_expr(
        &mut self,
        receiver: &Expr,
        method: Symbol,
        args: &[Arg],
        span: Span,
    ) -> Type {
        let rec_ty = self.infer_expr(receiver);
        let m_name = INTERNER.resolve(&method);

        // Standard method handling (e.g. List.push, List.len, String.len, etc.)
        if m_name == "len" {
            return Type::Int(IntType::I64);
        }
        if m_name == "is_empty" {
            return Type::Bool;
        }

        // Bounded generic type parameter method resolution:
        if let Type::TypeParam(p_name) = &rec_ty {
            let mut trait_ret_ty = None;
            for gp in &self.current_func_generics {
                if gp.name == *p_name {
                    for bound in &gp.bounds {
                        if let Some(tr) = self.symbols.lookup_trait(bound) {
                            if let Some(tm) = tr.methods.iter().find(|m| m.name == method) {
                                trait_ret_ty = Some(tm.ret_ty.clone());
                                break;
                            }
                        }
                    }
                }
            }
            if let Some(ret) = trait_ret_ty {
                for arg in args {
                    self.infer_expr(&arg.value);
                }
                return ret;
            }
        }

        match &rec_ty {
            Type::Generic {
                name,
                args: gen_args,
            } if INTERNER.resolve(name) == "List" && m_name == "push" && !gen_args.is_empty() => {
                if let Some(arg) = args.first() {
                    self.check_expr(&arg.value, Some(&gen_args[0]));
                }
                return Type::Unit;
            }
            _ => {}
        }

        // Polymorphic methods and UFCS (Uniform Function Call Syntax):
        // If a function with `method` name exists taking receiver as first parameter:
        if let Some(f) = self.symbols.lookup_function(&method).cloned() {
            if !f.params.is_empty() {
                let mut full_args = Vec::with_capacity(args.len() + 1);
                full_args.push(Arg::positional(receiver.clone()));
                full_args.extend_from_slice(args);
                return self.check_function_call(&f, &full_args, span);
            }
        }

        if !matches!(rec_ty, Type::Unknown) {
            let m_name_str = INTERNER.resolve(&method);
            self.diagnostics.push(
                Diagnostic::error(format!(
                    "méthode '{}' introuvable sur le type '{}'",
                    m_name_str, rec_ty
                ))
                .with_code("E0008")
                .with_primary_label(span, format!("méthode '{}' inconnue", m_name_str))
                .with_secondary_label(receiver.span, format!("récepteur de type '{}'", rec_ty)),
            );
        } else {
            for arg in args {
                self.infer_expr(&arg.value);
            }
        }

        Type::Unknown
    }
}

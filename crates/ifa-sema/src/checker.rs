use crate::escape::EscapeAnalyzer;
use crate::exclusivity::{check_assignment_target, check_call_exclusivity};
use crate::symbol_table::{
    ConstSymbol, EnumSymbol, FieldSymbol, FunctionSymbol, ParamSymbol, StructSymbol, SymbolTable,
    TraitMethodSymbol, TraitSymbol,
};
use crate::types::{IntType, Type};
use ifa_ast::{
    Arg, BinOp, BindingMode, Block, Expr, ExprKind, Function, GenericParam, Impl, Item, Lit,
    ParamMode, Pattern, Program, Stmt, Struct, Trait, UnaryOp,
};
use ifa_diagnostics::Diagnostic;
use ifa_span::{SourceMap, Span, Symbol, INTERNER};
use std::collections::{HashMap, HashSet};

/// Returns whether a pattern contains an exclusive inout binding.
fn pattern_has_inout(pat: &Pattern) -> bool {
    match pat {
        Pattern::Binding {
            mode: BindingMode::InOut,
            ..
        } => true,
        Pattern::Tuple(elems, _) | Pattern::Or(elems, _) => elems.iter().any(pattern_has_inout),
        Pattern::Struct { fields, .. } => fields.iter().any(|f| pattern_has_inout(&f.pattern)),
        Pattern::Slice {
            prefix,
            rest,
            suffix,
            ..
        } => {
            prefix.iter().any(pattern_has_inout)
                || rest
                    .as_ref()
                    .and_then(|r| r.as_ref())
                    .is_some_and(|p| pattern_has_inout(p))
                || suffix.iter().any(pattern_has_inout)
        }
        Pattern::Variant { inner: Some(p), .. } => pattern_has_inout(p),
        _ => false,
    }
}

/// Control-flow sensitive type narrowing facts deduced from conditional expressions.
#[derive(Debug, Clone, Default)]
pub struct NarrowingFacts {
    pub true_facts: Vec<(Symbol, Type)>,
    pub false_facts: Vec<(Symbol, Type)>,
}

fn is_null_expr(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::Lit(Lit::Null) => true,
        ExprKind::Ident(sym) => {
            let name = INTERNER.resolve(sym);
            name == "null" || name == "None"
        }
        _ => false,
    }
}

fn extract_var_ident(expr: &Expr) -> Option<Symbol> {
    match &expr.kind {
        ExprKind::Ident(sym) => {
            let name = INTERNER.resolve(sym);
            if name == "null" || name == "None" || name == "true" || name == "false" {
                None
            } else {
                Some(*sym)
            }
        }
        _ => None,
    }
}

fn block_always_terminates(block: &Block) -> bool {
    for stmt in &block.stmts {
        match stmt {
            Stmt::Return(..) | Stmt::Fail(..) | Stmt::Break(..) | Stmt::Continue(..) => {
                return true
            }
            _ => {}
        }
    }
    false
}

fn expr_always_terminates(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::Block(b) => block_always_terminates(b),
        _ => false,
    }
}

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
        Self::with_symbols(source_map, SymbolTable::new())
    }

    pub fn with_symbols(source_map: &'a SourceMap, symbols: SymbolTable) -> Self {
        Self {
            source_map,
            symbols,
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
        // Phase 0: Collect and register module imports
        self.collect_imports(program);

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
    // Phase 0: Import Collection & Module Resolution
    // =========================================================================

    fn collect_imports(&mut self, program: &Program) {
        for item in &program.items {
            if let Item::Import(im) = item {
                if im.path.is_empty() {
                    continue;
                }

                let full_path: Vec<String> = im.path.iter().map(|s| INTERNER.resolve(s)).collect();
                let path_str = full_path.join("::");
                let path_sym = INTERNER.intern(&path_str);
                let local_alias = im.alias.unwrap_or_else(|| *im.path.last().unwrap());

                if let Some(existing_mod) = self.symbols.lookup_module(&local_alias).cloned() {
                    // Pre-registered module with this alias
                    self.symbols.modules.insert(local_alias, existing_mod);
                } else if let Some(existing_mod) = self.symbols.lookup_module(&path_sym).cloned() {
                    let mut alias_mod = existing_mod;
                    alias_mod.name = local_alias;
                    self.symbols.modules.insert(local_alias, alias_mod);
                } else if let Some(last_sym) = im.path.last() {
                    if let Some(existing_mod) = self.symbols.lookup_module(last_sym).cloned() {
                        let mut alias_mod = existing_mod;
                        alias_mod.name = local_alias;
                        self.symbols.modules.insert(local_alias, alias_mod);
                    } else {
                        let diag = Diagnostic::error(format!("module '{}' introuvable", path_str))
                            .with_code("E0010")
                            .with_primary_label(
                                im.span,
                                "aucun module de ce nom dans la bibliothèque standard ou les dépendances",
                            );
                        self.diagnostics.push(diag);
                    }
                }

                self.symbols
                    .imports
                    .push((im.path.clone(), im.alias, im.span));
            }
        }
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
        for (mod_name, module) in &self.symbols.modules {
            for (st_name, st) in &module.structs {
                let fields: Vec<(Symbol, Type)> =
                    st.fields.iter().map(|f| (f.name, f.ty.clone())).collect();
                map.insert(
                    *st_name,
                    Type::Struct {
                        name: *st_name,
                        fields: fields.clone(),
                    },
                );
                let qual_str = format!(
                    "{}::{}",
                    INTERNER.resolve(mod_name),
                    INTERNER.resolve(st_name)
                );
                map.insert(
                    INTERNER.intern(&qual_str),
                    Type::Struct {
                        name: *st_name,
                        fields,
                    },
                );
            }
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
        for (mod_name, module) in &self.symbols.modules {
            for (en_name, en) in &module.enums {
                map.insert(
                    *en_name,
                    Type::Enum {
                        name: *en_name,
                        variants: en.variants.clone(),
                    },
                );
                let qual_str = format!(
                    "{}::{}",
                    INTERNER.resolve(mod_name),
                    INTERNER.resolve(en_name)
                );
                map.insert(
                    INTERNER.intern(&qual_str),
                    Type::Enum {
                        name: *en_name,
                        variants: en.variants.clone(),
                    },
                );
            }
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
                        value: None,
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

        let target_sym = match &im.target_ty.kind {
            ifa_ast::TypeKind::Named(s) => Some(*s),
            _ => match &target_ty {
                Type::Struct { name, .. } => Some(*name),
                Type::Generic { name, .. } => Some(*name),
                _ => None,
            },
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
                params: params.clone(),
                ret_ty: ret_ty.clone(),
                span: f.span,
            };

            if let Some(t_sym) = target_sym {
                let mangled_name = INTERNER.intern(&format!(
                    "{}__{}",
                    INTERNER.resolve(&t_sym),
                    INTERNER.resolve(&f.name)
                ));

                let specialized_sym = FunctionSymbol {
                    name: mangled_name,
                    is_pub: f.is_pub,
                    is_strict: f.is_strict,
                    is_comptime: f.is_comptime,
                    is_extern: f.is_extern.clone(),
                    generics: f.generics.clone(),
                    params,
                    ret_ty,
                    span: f.span,
                };

                let _ = self.symbols.define_function(specialized_sym);
                self.symbols
                    .register_type_method(t_sym, f.name, fn_sym.clone());

                if let Some(tr_name) = im.trait_name {
                    self.symbols
                        .register_trait_method_impl(tr_name, t_sym, f.name, fn_sym.clone());
                }
            }

            // Define fallback in functions table only if no conflict exists
            if self.symbols.lookup_function(&f.name).is_none() {
                let _ = self.symbols.define_function(fn_sym);
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
            Ok(val) => {
                self.comptime_vm.register_constant(c.name, val.clone());
                self.symbols.comptime_values.insert(c.name, val.clone());
                if let Some(cs) = self.symbols.consts.get_mut(&c.name) {
                    cs.value = Some(val);
                }
            }
            Err(comptime_err) => self.diagnostics.push(comptime_err.to_diagnostic()),
        }
    }

    fn check_function(&mut self, f: &Function) {
        // Run escape analysis on this function
        let mut escape_analyzer = EscapeAnalyzer::new(&self.symbols, f.is_strict, f.span);
        escape_analyzer.check_function(f);
        self.diagnostics.extend(escape_analyzer.diagnostics);

        // Get function return type from symbol table or AST
        let known_structs = self.get_known_struct_types();
        let known_enums = self.get_known_enum_types();
        let ret_ty = if let Some(ret) = &f.ret_ty {
            Type::from_ast_with_generics(ret, &known_structs, &known_enums, &f.generics)
                .unwrap_or(Type::Unit)
        } else {
            self.symbols
                .lookup_function(&f.name)
                .map(|sym| sym.ret_ty.clone())
                .unwrap_or(Type::Unit)
        };

        let prev_ret = self.current_func_ret_ty.take();
        let prev_strict = self.current_func_is_strict;
        let prev_moved = std::mem::take(&mut self.moved_vars);
        let prev_generics = std::mem::replace(&mut self.current_func_generics, f.generics.clone());
        self.current_func_ret_ty = Some(ret_ty.clone());
        self.current_func_is_strict = f.is_strict;

        // Enter function root scope
        self.symbols.enter_scope(false, true);

        // Register parameters as variables in the function scope
        let fn_params: Vec<ParamSymbol> = f
            .params
            .iter()
            .map(|p| {
                let ty =
                    Type::from_ast_with_generics(&p.ty, &known_structs, &known_enums, &f.generics)
                        .unwrap_or(Type::Unknown);
                ParamSymbol {
                    mode: p.mode,
                    name: p.name,
                    ty,
                    span: p.span,
                }
            })
            .collect();

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

    fn extract_narrowing_facts(&self, expr: &Expr) -> NarrowingFacts {
        match &expr.kind {
            ExprKind::Binary { op, left, right } => match op {
                BinOp::NotEq => {
                    let mut facts = NarrowingFacts::default();
                    if is_null_expr(right) {
                        if let Some(var_sym) = extract_var_ident(left) {
                            if let Some(var) = self.symbols.lookup_variable(&var_sym) {
                                if let Type::Optional(inner) = &var.ty {
                                    facts.true_facts.push((var_sym, *inner.clone()));
                                }
                            }
                        }
                    } else if is_null_expr(left) {
                        if let Some(var_sym) = extract_var_ident(right) {
                            if let Some(var) = self.symbols.lookup_variable(&var_sym) {
                                if let Type::Optional(inner) = &var.ty {
                                    facts.true_facts.push((var_sym, *inner.clone()));
                                }
                            }
                        }
                    }
                    facts
                }
                BinOp::Eq => {
                    let mut facts = NarrowingFacts::default();
                    if is_null_expr(right) {
                        if let Some(var_sym) = extract_var_ident(left) {
                            if let Some(var) = self.symbols.lookup_variable(&var_sym) {
                                if let Type::Optional(inner) = &var.ty {
                                    facts.false_facts.push((var_sym, *inner.clone()));
                                }
                            }
                        }
                    } else if is_null_expr(left) {
                        if let Some(var_sym) = extract_var_ident(right) {
                            if let Some(var) = self.symbols.lookup_variable(&var_sym) {
                                if let Type::Optional(inner) = &var.ty {
                                    facts.false_facts.push((var_sym, *inner.clone()));
                                }
                            }
                        }
                    }
                    facts
                }
                BinOp::And => {
                    let left_facts = self.extract_narrowing_facts(left);
                    let right_facts = self.extract_narrowing_facts(right);
                    let mut true_facts = left_facts.true_facts;
                    for (sym, ty) in right_facts.true_facts {
                        if !true_facts.iter().any(|(s, _)| s == &sym) {
                            true_facts.push((sym, ty));
                        }
                    }
                    let mut false_facts = Vec::new();
                    for (sym_a, ty_a) in &left_facts.false_facts {
                        if right_facts
                            .false_facts
                            .iter()
                            .any(|(sym_b, _)| sym_b == sym_a)
                        {
                            false_facts.push((*sym_a, ty_a.clone()));
                        }
                    }
                    NarrowingFacts {
                        true_facts,
                        false_facts,
                    }
                }
                BinOp::Or => {
                    let left_facts = self.extract_narrowing_facts(left);
                    let right_facts = self.extract_narrowing_facts(right);
                    let mut false_facts = left_facts.false_facts;
                    for (sym, ty) in right_facts.false_facts {
                        if !false_facts.iter().any(|(s, _)| s == &sym) {
                            false_facts.push((sym, ty));
                        }
                    }
                    let mut true_facts = Vec::new();
                    for (sym_a, ty_a) in &left_facts.true_facts {
                        if right_facts
                            .true_facts
                            .iter()
                            .any(|(sym_b, _)| sym_b == sym_a)
                        {
                            true_facts.push((*sym_a, ty_a.clone()));
                        }
                    }
                    NarrowingFacts {
                        true_facts,
                        false_facts,
                    }
                }
                _ => NarrowingFacts::default(),
            },
            ExprKind::Unary {
                op: UnaryOp::Not,
                expr: inner,
            } => {
                let inner_facts = self.extract_narrowing_facts(inner);
                NarrowingFacts {
                    true_facts: inner_facts.false_facts,
                    false_facts: inner_facts.true_facts,
                }
            }
            _ => NarrowingFacts::default(),
        }
    }

    fn check_block(&mut self, block: &Block, expected_ret: Option<&Type>) -> Type {
        for stmt in &block.stmts {
            self.check_stmt(stmt);

            // Flow-sensitive early return guards:
            // if cond { return / fail / break / continue; }
            if let Stmt::Expr(expr) = stmt {
                if let ExprKind::If {
                    cond,
                    then_branch,
                    else_branch,
                } = &expr.kind
                {
                    if else_branch.is_none() && block_always_terminates(then_branch) {
                        let facts = self.extract_narrowing_facts(cond);
                        for (sym, ty) in facts.false_facts {
                            self.symbols.narrow_variable_in_current_scope(sym, ty);
                        }
                    } else if let Some(el) = else_branch {
                        if expr_always_terminates(el) && !block_always_terminates(then_branch) {
                            let facts = self.extract_narrowing_facts(cond);
                            for (sym, ty) in facts.true_facts {
                                self.symbols.narrow_variable_in_current_scope(sym, ty);
                            }
                        }
                    }
                }
            }
        }

        if let Some(expr) = &block.expr {
            let actual = self.check_expr(expr, expected_ret);
            if let Some(expected) = expected_ret {
                if !expected.is_unit()
                    && !expected.is_never()
                    && !actual.is_never()
                    && !actual.is_assignable_to(expected)
                {
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
        } else if block_always_terminates(block) {
            Type::Never
        } else {
            Type::Unit
        }
    }

    fn check_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Let {
                is_mut,
                pattern,
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
                            let pat_desc = match pattern {
                                Pattern::Ident(name, _) | Pattern::Binding { name, .. } => {
                                    format!(" pour '{}'", INTERNER.resolve(name))
                                }
                                _ => String::new(),
                            };
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "type incompatible{} : attendu {}, trouvé {}",
                                    pat_desc, expected, inferred
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

                if init.is_none()
                    && !matches!(pattern, Pattern::Ident(_, _) | Pattern::Binding { .. })
                {
                    self.diagnostics.push(
                        Diagnostic::error(
                            "la déstructuration requiert une expression d'initialisation",
                        )
                        .with_code("E0047")
                        .with_primary_label(
                            pattern.span(),
                            "motif déstructurant sans initialisation",
                        ),
                    );
                }

                self.symbols.register_type_if_generic_instance(&actual_ty);

                // Validation obligatoire d'irréfutabilité en mode déclaration locale
                let is_irrefutable =
                    crate::exhaustiveness::is_irrefutable_pattern_for_type(pattern, &actual_ty);
                if !is_irrefutable && actual_ty != Type::Unknown {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "motif réfutable dans une déclaration de variable : le motif ne couvre pas toutes les valeurs possibles du type '{}'",
                            actual_ty
                        ))
                        .with_code("E0047")
                        .with_primary_label(
                            pattern.span(),
                            "motif réfutable non autorisé dans une déclaration 'let' ou 'mut'",
                        )
                        .with_note(
                            "les motifs réfutables ne sont autorisés que dans les instructions 'match' ou 'if let'",
                        ),
                    );
                }

                self.check_pattern_binding_duplicates(pattern);
                if let Some(init_expr) = init {
                    self.check_inout_source_mutability(pattern, init_expr);
                }

                self.check_pattern_with_mut(pattern, &actual_ty, *is_mut, init.is_some());
                for (sym, _) in pattern.bound_variables() {
                    self.moved_vars.remove(&sym);
                }
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

                let declared_target_ty = if let ExprKind::Ident(target_sym) = &target.kind {
                    self.symbols
                        .lookup_variable(target_sym)
                        .map(|v| v.original_ty.as_ref().unwrap_or(&v.ty).clone())
                } else {
                    None
                };
                let target_ty = declared_target_ty.unwrap_or_else(|| self.infer_expr(target));
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
                } else if let ExprKind::Ident(target_sym) = &target.kind {
                    if matches!(val_ty, Type::Optional(_)) || is_null_expr(val) {
                        if let Some(var) = self.symbols.lookup_variable_mut(target_sym) {
                            if let Some(orig) = var.original_ty.clone() {
                                var.ty = orig;
                            }
                        }
                    }
                }
            }
            Stmt::AssignPattern {
                pattern,
                val,
                span: _,
            } => {
                let val_ty = self.infer_expr(val);

                // Validation obligatoire d'irréfutabilité en mode assignation par déstructuration
                let is_irrefutable =
                    crate::exhaustiveness::is_irrefutable_pattern_for_type(pattern, &val_ty);
                if !is_irrefutable && val_ty != Type::Unknown {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "motif réfutable dans une assignation par déstructuration : le motif ne couvre pas toutes les valeurs possibles du type '{}'",
                            val_ty
                        ))
                        .with_code("E0047")
                        .with_primary_label(
                            pattern.span(),
                            "motif réfutable non autorisé dans une assignation sans condition",
                        )
                        .with_note(
                            "les motifs réfutables ne sont autorisés que dans les instructions 'match' ou 'if let'",
                        ),
                    );
                }

                self.check_destructuring_assignment(pattern, &val_ty);
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
                let facts = self.extract_narrowing_facts(cond);
                self.symbols.enter_scope(true, false);
                for (sym, ty) in &facts.true_facts {
                    self.symbols
                        .narrow_variable_in_current_scope(*sym, ty.clone());
                }
                self.check_block(body, None);
                self.symbols.exit_scope();
            }
            Stmt::WhileLet {
                pattern,
                expr,
                guard,
                body,
                span: _,
            } => {
                let cond_ty = self.infer_expr(expr);
                let is_irrefutable =
                    crate::exhaustiveness::is_irrefutable_pattern_for_type(pattern, &cond_ty);
                if guard.is_none() && is_irrefutable && cond_ty != Type::Unknown {
                    self.diagnostics.push(
                        Diagnostic::warning(format!(
                            "motif irréfutable dans une boucle 'while let' : le motif couvre toutes les valeurs possibles du type '{}'",
                            cond_ty
                        ))
                        .with_code("W0001")
                        .with_primary_label(pattern.span(), "motif irréfutable redondant dans 'while let'")
                        .with_note(
                            "ce motif correspondra toujours, entraînant une boucle infinie ; envisagez d'utiliser 'loop'",
                        ),
                    );
                }

                self.check_pattern_binding_duplicates(pattern);
                self.check_inout_source_mutability(pattern, expr);
                self.symbols.enter_scope(true, false);
                self.check_pattern(pattern, &cond_ty);
                if let Some(g) = guard {
                    let guard_ty = self.infer_expr(g);
                    if !matches!(guard_ty, Type::Bool | Type::Unknown) {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "la condition de garde 'while let' doit être un booléen, trouvé '{}'",
                                guard_ty
                            ))
                            .with_code("E0034")
                            .with_primary_label(g.span, "condition de garde non booléenne"),
                        );
                    }
                }
                self.check_block(body, None);
                self.symbols.exit_scope();
            }
            Stmt::For {
                pattern,
                iterable,
                body,
                span: _,
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

                self.check_pattern_binding_duplicates(pattern);
                self.symbols.enter_scope(true, false);
                self.check_pattern(pattern, &elem_ty);
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
                Lit::Null => {
                    if let Some(Type::Optional(inner)) = expected {
                        Type::Optional(inner.clone())
                    } else if let Some(Type::Ref(inner)) = expected {
                        Type::Optional(Box::new(Type::Ref(inner.clone())))
                    } else {
                        Type::Optional(Box::new(Type::Unknown))
                    }
                }
            },
            ExprKind::Ident(sym) => {
                let name = INTERNER.resolve(sym);
                if name == "None" || name == "null" {
                    if let Some(Type::Optional(inner)) = expected {
                        Type::Optional(inner.clone())
                    } else if let Some(Type::Ref(inner)) = expected {
                        Type::Optional(Box::new(Type::Ref(inner.clone())))
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
                } else if let Some((en, _, _)) = self.symbols.lookup_enum_by_variant(sym) {
                    Type::Enum {
                        name: en.name,
                        variants: en.variants.clone(),
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
                } else if path.len() >= 2 {
                    let mod_sym = path[0];
                    let member_sym = path[1];
                    let mod_name_str = INTERNER.resolve(&mod_sym);
                    let member_name_str = INTERNER.resolve(&member_sym);

                    if let Some(module) = self.symbols.lookup_module(&mod_sym).cloned() {
                        if let Some(c) = module.consts.get(&member_sym) {
                            if !c.is_pub {
                                self.diagnostics.push(
                                    Diagnostic::error(format!(
                                        "la constante '{}' est privée dans le module '{}'",
                                        member_name_str, mod_name_str
                                    ))
                                    .with_code("E0011")
                                    .with_primary_label(expr.span, "accès à une constante privée"),
                                );
                            }
                            c.ty.clone()
                        } else if let Some(st) = module.structs.get(&member_sym) {
                            if !st.is_pub {
                                self.diagnostics.push(
                                    Diagnostic::error(format!(
                                        "la structure '{}' est privée dans le module '{}'",
                                        member_name_str, mod_name_str
                                    ))
                                    .with_code("E0011")
                                    .with_primary_label(expr.span, "accès à une structure privée"),
                                );
                            }
                            Type::Struct {
                                name: member_sym,
                                fields: st.fields.iter().map(|f| (f.name, f.ty.clone())).collect(),
                            }
                        } else if let Some(en) = module.enums.get(&member_sym) {
                            if !en.is_pub {
                                self.diagnostics.push(
                                    Diagnostic::error(format!(
                                        "l'énumération '{}' est privée dans le module '{}'",
                                        member_name_str, mod_name_str
                                    ))
                                    .with_code("E0011")
                                    .with_primary_label(
                                        expr.span,
                                        "accès à une énumération privée",
                                    ),
                                );
                            }
                            Type::Enum {
                                name: member_sym,
                                variants: en.variants.clone(),
                            }
                        } else if let Some(f) = module.functions.get(&member_sym) {
                            if !f.is_pub {
                                self.diagnostics.push(
                                    Diagnostic::error(format!(
                                        "la fonction '{}' est privée dans le module '{}'",
                                        member_name_str, mod_name_str
                                    ))
                                    .with_code("E0011")
                                    .with_primary_label(expr.span, "accès à une fonction privée"),
                                );
                            }
                            f.ret_ty.clone()
                        } else {
                            Type::Unknown
                        }
                    } else if let Some((en, _, _)) =
                        self.symbols.lookup_enum_variant(&mod_sym, &member_sym)
                    {
                        Type::Enum {
                            name: en.name,
                            variants: en.variants.clone(),
                        }
                    } else if let Some(en) = self.symbols.lookup_enum(&mod_sym) {
                        Type::Enum {
                            name: mod_sym,
                            variants: en.variants.clone(),
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
                            Type::Unknown
                        }
                    } else {
                        Type::Unknown
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
                safe,
            } => self.check_method_call_expr(receiver, *method, args, *safe, expr.span),
            ExprKind::FieldAccess {
                receiver,
                field,
                safe,
            } => {
                let rec_ty = self.infer_expr(receiver);
                let is_optional = matches!(rec_ty, Type::Optional(_));
                if !*safe && is_optional {
                    let f_name = INTERNER.resolve(field);
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "accès direct au champ '{}' impossible sur le type optionnel '{}' : utilisez '?.' pour une navigation sûre",
                            f_name, rec_ty
                        ))
                        .with_code("E0007")
                        .with_primary_label(
                            expr.span,
                            "accès risqué sur type optionnel, utilisez '?.'",
                        )
                        .with_secondary_label(receiver.span, format!("récepteur de type '{}'", rec_ty)),
                    );
                    Type::Unknown
                } else if let Some((name, fields)) = self.resolve_struct_fields(&rec_ty) {
                    if let Some((_, fty)) = fields.iter().find(|(n, _)| n == field) {
                        if *safe {
                            match fty {
                                Type::Optional(_) => fty.clone(),
                                _ => Type::Optional(Box::new(fty.clone())),
                            }
                        } else {
                            fty.clone()
                        }
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
                    let op = if *safe { "?." } else { "." };
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "accès au champ '{}' avec '{}' impossible sur le type non composite '{}'",
                            f_name, op, rec_ty
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
                let facts = self.extract_narrowing_facts(cond);

                self.symbols.enter_scope(false, false);
                for (sym, ty) in &facts.true_facts {
                    self.symbols
                        .narrow_variable_in_current_scope(*sym, ty.clone());
                }
                let then_ty = self.check_block(then_branch, expected);
                self.symbols.exit_scope();

                if let Some(el) = else_branch {
                    self.symbols.enter_scope(false, false);
                    for (sym, ty) in &facts.false_facts {
                        self.symbols
                            .narrow_variable_in_current_scope(*sym, ty.clone());
                    }
                    let expected_else = if then_ty.is_never() {
                        expected
                    } else {
                        expected.or(Some(&then_ty))
                    };
                    let else_ty = self.check_expr(el, expected_else);
                    self.symbols.exit_scope();

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
                    if then_ty.is_never() {
                        else_ty
                    } else {
                        then_ty
                    }
                } else {
                    Type::Unit
                }
            }
            ExprKind::IfLet {
                pattern,
                expr: cond_expr,
                guard,
                then_branch,
                else_branch,
            } => {
                let cond_ty = self.infer_expr(cond_expr);
                let is_irrefutable =
                    crate::exhaustiveness::is_irrefutable_pattern_for_type(pattern, &cond_ty);
                if guard.is_none() && is_irrefutable && cond_ty != Type::Unknown {
                    self.diagnostics.push(
                        Diagnostic::warning(format!(
                            "motif irréfutable dans une expression 'if let' : le motif couvre toutes les valeurs possibles du type '{}'",
                            cond_ty
                        ))
                        .with_code("W0001")
                        .with_primary_label(pattern.span(), "motif irréfutable redondant dans 'if let'")
                        .with_note("envisagez d'utiliser une déclaration 'let' ordinaire à la place"),
                    );
                }

                self.check_pattern_binding_duplicates(pattern);
                self.check_inout_source_mutability(pattern, cond_expr);
                self.symbols.enter_scope(false, false);
                self.check_pattern(pattern, &cond_ty);
                if let Some(g) = guard {
                    let guard_ty = self.infer_expr(g);
                    if !matches!(guard_ty, Type::Bool | Type::Unknown) {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "la condition de garde 'if let' doit être un booléen, trouvé '{}'",
                                guard_ty
                            ))
                            .with_code("E0034")
                            .with_primary_label(g.span, "condition de garde non booléenne"),
                        );
                    }
                }
                let then_ty = self.check_block(then_branch, expected);
                self.symbols.exit_scope();

                if let Some(el) = else_branch {
                    self.symbols.enter_scope(false, false);
                    let expected_else = if then_ty.is_never() {
                        expected
                    } else {
                        expected.or(Some(&then_ty))
                    };
                    let else_ty = self.check_expr(el, expected_else);
                    self.symbols.exit_scope();

                    if !then_ty.is_never()
                        && !else_ty.is_never()
                        && !else_ty.is_assignable_to(&then_ty)
                    {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "incompatibilité de type entre les branches 'if let' ({}) et 'else' ({})",
                                then_ty, else_ty
                            ))
                            .with_code("E0001")
                            .with_primary_label(el.span, format!("branche 'else' de type {}", else_ty))
                            .with_secondary_label(then_branch.span, format!("branche 'then' de type {}", then_ty)),
                        );
                    }

                    if then_ty.is_never() {
                        else_ty
                    } else {
                        then_ty
                    }
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
                match self.comptime_vm.eval_expr(inner) {
                    Ok(val) => {
                        self.symbols.comptime_expr_values.insert(expr.span, val);
                    }
                    Err(comptime_err) => {
                        self.diagnostics.push(comptime_err.to_diagnostic());
                    }
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
                        self.check_pattern_binding_duplicates(&arm.pattern);
                        self.check_inout_source_mutability(&arm.pattern, target_expr);
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

                    crate::exhaustiveness::check_match_exhaustiveness(
                        &self.symbols,
                        arms,
                        &target_ty,
                        expr.span,
                        &mut self.diagnostics,
                    );

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
            ExprKind::Select { arms } => {
                if arms.is_empty() {
                    self.diagnostics.push(
                        Diagnostic::error(
                            "l'expression 'select' doit comporter au moins une branche",
                        )
                        .with_code("E0036")
                        .with_primary_label(expr.span, "branches manquantes"),
                    );
                    Type::Unknown
                } else {
                    let mut arm_types = Vec::new();
                    for arm in arms {
                        self.symbols.enter_scope(false, false);
                        let mut elem_ty = Type::Unknown;
                        if let Some(chan_expr) = &arm.channel {
                            let chan_ty = self.infer_expr(chan_expr);
                            if let Type::Generic { name, args } = &chan_ty {
                                if INTERNER.resolve(name) == "Channel" && !args.is_empty() {
                                    elem_ty = args[0].clone();
                                }
                            }
                            if let Some(pat) = &arm.pattern {
                                self.check_pattern(pat, &elem_ty);
                            }
                        }
                        let arm_ty = match &arm.body.kind {
                            ExprKind::Block(b) => self.check_block(b, expected),
                            _ => self.check_expr(&arm.body, expected),
                        };
                        self.symbols.exit_scope();
                        arm_types.push(arm_ty);
                    }

                    if arm_types.is_empty() {
                        Type::Unit
                    } else {
                        let mut unified = arm_types[0].clone();
                        for arm_ty in &arm_types[1..] {
                            if !arm_ty.is_assignable_to(&unified)
                                && !unified.is_assignable_to(arm_ty)
                                && *arm_ty != Type::Unknown
                                && unified != Type::Unknown
                            {
                                // Types differ, fallback to unit or report error
                            } else if unified == Type::Unknown {
                                unified = arm_ty.clone();
                            }
                        }
                        unified
                    }
                }
            }
        };

        self.expr_types.insert(expr.span, ty.clone());
        ty
    }

    fn check_pattern(&mut self, pat: &Pattern, target_ty: &Type) {
        self.check_pattern_with_mut(pat, target_ty, false, true);
    }

    fn check_destructuring_assignment(&mut self, pat: &Pattern, target_ty: &Type) {
        match pat {
            Pattern::Wildcard(_) => {}
            Pattern::Lit(lit, span) => {
                let lit_ty = match lit {
                    Lit::Int(_) => Type::Int(IntType::I64),
                    Lit::Float(_) => Type::Float(crate::types::FloatType::F64),
                    Lit::Bool(_) => Type::Bool,
                    Lit::Char(_) => Type::Char,
                    Lit::String(_) => Type::Str,
                    Lit::Null => Type::Optional(Box::new(Type::Unknown)),
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
            Pattern::Ident(sym, span)
            | Pattern::Binding {
                name: sym, span, ..
            } => {
                let var_name = INTERNER.resolve(sym);
                if let Some(var) = self.symbols.lookup_variable(sym).cloned() {
                    if !var.is_mut && var.is_initialized {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "impossible d'assigner à la variable immuable '{}'",
                                var_name
                            ))
                            .with_code("E0014")
                            .with_primary_label(
                                *span,
                                format!("tentative de réassignation de '{}'", var_name),
                            )
                            .with_secondary_label(
                                var.span,
                                format!(
                                    "variable '{}' déclarée immuable avec 'let' (utilisez 'mut')",
                                    var_name
                                ),
                            )
                            .with_help(
                                "Déclarez la variable avec 'mut' si vous devez la réassigner.",
                            ),
                        );
                    }
                    if !target_ty.is_assignable_to(&var.ty) && *target_ty != Type::Unknown {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "type incompatible lors de l'assignation : la cible est {}, mais la valeur est {}",
                                var.ty, target_ty
                            ))
                            .with_code("E0001")
                            .with_primary_label(*span, format!("cible de type {}", var.ty))
                            .with_note(format!("valeur extraite du motif de type {}", target_ty)),
                        );
                    }
                    self.moved_vars.remove(sym);
                    if let Some(v_mut) = self.symbols.lookup_variable_mut(sym) {
                        v_mut.is_initialized = true;
                    }
                } else {
                    self.diagnostics.push(
                        Diagnostic::error(format!("variable inconnue '{}'", var_name))
                            .with_code("E0001")
                            .with_primary_label(*span, "variable non trouvée dans cette portée")
                            .with_help("Déclarez la variable avec 'mut' avant de lui réassigner une valeur."),
                    );
                }
            }
            Pattern::Tuple(elems, span) => match target_ty {
                Type::Tuple(expected_elems) => {
                    if elems.len() != expected_elems.len() {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "le motif tuple contient {} élément(s), mais le type attendu '{}' en contient {}",
                                elems.len(),
                                target_ty,
                                expected_elems.len()
                            ))
                            .with_code("E0036")
                            .with_primary_label(*span, "arité de tuple incompatible"),
                        );
                    } else {
                        for (elem_pat, elem_ty) in elems.iter().zip(expected_elems.iter()) {
                            self.check_destructuring_assignment(elem_pat, elem_ty);
                        }
                    }
                }
                Type::Unit if elems.is_empty() => {}
                Type::Unknown => {
                    for elem_pat in elems {
                        self.check_destructuring_assignment(elem_pat, &Type::Unknown);
                    }
                }
                _ => {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "le motif tuple est incompatible avec le type non-tuple '{}'",
                            target_ty
                        ))
                        .with_code("E0036")
                        .with_primary_label(*span, "type de motif incompatible"),
                    );
                }
            },
            Pattern::Struct {
                name,
                fields,
                has_rest,
                span,
            } => {
                let st_name = match name.last() {
                    Some(sym) => *sym,
                    None => return,
                };

                let st_opt = self.symbols.lookup_struct(&st_name).cloned();
                if st_opt.is_none() {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "structure inconnue '{}'",
                            INTERNER.resolve(&st_name)
                        ))
                        .with_code("E0006")
                        .with_primary_label(*span, "structure inconnue"),
                    );
                    return;
                }
                let st = st_opt.unwrap();

                let is_compatible = match target_ty {
                    Type::Struct { name: t_name, .. } => *t_name == st_name,
                    Type::Generic { name: t_name, .. } => *t_name == st_name,
                    Type::Unknown => true,
                    _ => false,
                };

                if !is_compatible {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "le motif de structure '{}' est incompatible avec le type '{}'",
                            INTERNER.resolve(&st_name),
                            target_ty
                        ))
                        .with_code("E0036")
                        .with_primary_label(*span, "structure incompatible"),
                    );
                }

                if !has_rest && fields.len() < st.fields.len() {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "champs manquants dans le motif de déstructuration de '{}' (ajoutez '..' ou les champs manquants)",
                            INTERNER.resolve(&st_name)
                        ))
                        .with_code("E0048")
                        .with_primary_label(*span, "motif incomplet"),
                    );
                }

                for f in fields {
                    if let Some(struct_field) = st.get_field(&f.name) {
                        self.check_destructuring_assignment(&f.pattern, &struct_field.ty);
                    } else {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "le champ '{}' n'existe pas dans la structure '{}'",
                                INTERNER.resolve(&f.name),
                                INTERNER.resolve(&st_name)
                            ))
                            .with_code("E0007")
                            .with_primary_label(f.span, "champ inconnu"),
                        );
                    }
                }
            }
            Pattern::Slice {
                prefix,
                rest,
                suffix,
                span,
            } => match target_ty {
                Type::Array(elem_ty, len) => {
                    let min_len = prefix.len() + suffix.len();
                    if rest.is_none() && min_len != *len as usize {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "taille de motif de tranche incompatible : attendu {} élément(s), motif avec {}",
                                len, min_len
                            ))
                            .with_code("E0036")
                            .with_primary_label(*span, "taille de tableau incompatible"),
                        );
                    } else if rest.is_some() && min_len > *len as usize {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "le motif de tranche exige au moins {} élément(s), mais le tableau n'en contient que {}",
                                min_len, len
                            ))
                            .with_code("E0036")
                            .with_primary_label(*span, "trop d'éléments pour ce tableau"),
                        );
                    }
                    for p in prefix {
                        self.check_destructuring_assignment(p, elem_ty);
                    }
                    if let Some(Some(r)) = rest {
                        let rest_ty = Type::Slice(elem_ty.clone());
                        self.check_destructuring_assignment(r, &rest_ty);
                    }
                    for s in suffix {
                        self.check_destructuring_assignment(s, elem_ty);
                    }
                }
                Type::Slice(elem_ty) => {
                    for p in prefix {
                        self.check_destructuring_assignment(p, elem_ty);
                    }
                    if let Some(Some(r)) = rest {
                        let rest_ty = Type::Slice(elem_ty.clone());
                        self.check_destructuring_assignment(r, &rest_ty);
                    }
                    for s in suffix {
                        self.check_destructuring_assignment(s, elem_ty);
                    }
                }
                Type::Unknown => {
                    for p in prefix {
                        self.check_destructuring_assignment(p, &Type::Unknown);
                    }
                    if let Some(Some(r)) = rest {
                        self.check_destructuring_assignment(r, &Type::Unknown);
                    }
                    for s in suffix {
                        self.check_destructuring_assignment(s, &Type::Unknown);
                    }
                }
                _ => {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "le motif de tranche est incompatible avec le type non-tranche '{}'",
                            target_ty
                        ))
                        .with_code("E0036")
                        .with_primary_label(*span, "type incompatible avec une tranche"),
                    );
                }
            },
            Pattern::Variant { span, .. } => {
                self.diagnostics.push(
                    Diagnostic::error(
                        "les motifs de variant d'énumération ne sont pas autorisés dans une assignation par déstructuration inconditionnelle",
                    )
                    .with_code("E0047")
                    .with_primary_label(*span, "motif de variant non autorisé ici"),
                );
            }
            Pattern::Or(_, span) => {
                self.diagnostics.push(
                    Diagnostic::error(
                        "les motifs d'alternative 'or' ('|') ne sont pas autorisés dans une assignation par déstructuration",
                    )
                    .with_code("E0047")
                    .with_primary_label(*span, "motif 'or' non autorisé ici"),
                );
            }
            Pattern::Range { span, .. } => {
                self.diagnostics.push(
                    Diagnostic::error(
                        "les motifs d'intervalle ne sont pas autorisés dans une assignation par déstructuration",
                    )
                    .with_code("E0047")
                    .with_primary_label(*span, "motif d'intervalle non autorisé ici"),
                );
            }
        }
    }

    fn check_pattern_with_mut(
        &mut self,
        pat: &Pattern,
        target_ty: &Type,
        is_mut: bool,
        is_initialized: bool,
    ) {
        match pat {
            Pattern::Wildcard(_) => {}
            Pattern::Lit(lit, span) => {
                let lit_ty = match lit {
                    Lit::Int(_) => Type::Int(IntType::I64),
                    Lit::Float(_) => Type::Float(crate::types::FloatType::F64),
                    Lit::Bool(_) => Type::Bool,
                    Lit::Char(_) => Type::Char,
                    Lit::String(_) => Type::Str,
                    Lit::Null => Type::Optional(Box::new(Type::Unknown)),
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
                if let Err(diag) = self.symbols.define_variable(
                    *sym,
                    target_ty.clone(),
                    is_mut,
                    is_initialized,
                    None,
                    *span,
                ) {
                    self.diagnostics.push(diag);
                }
            }
            Pattern::Binding { mode, name, span } => {
                let (var_ty, var_mut, param_mode) = match mode {
                    BindingMode::Value => (target_ty.clone(), is_mut, None),
                    BindingMode::Mut => (target_ty.clone(), true, Some(ParamMode::Mut)),
                    BindingMode::Ref => {
                        let inner_ref = match target_ty {
                            Type::Ref(inner) => inner.clone(),
                            other => Box::new(other.clone()),
                        };
                        (Type::Ref(inner_ref), false, None)
                    }
                    BindingMode::InOut => (target_ty.clone(), true, Some(ParamMode::InOut)),
                };
                if let Err(diag) = self.symbols.define_variable(
                    *name,
                    var_ty,
                    var_mut,
                    is_initialized,
                    param_mode,
                    *span,
                ) {
                    self.diagnostics.push(diag);
                }
            }
            Pattern::Variant {
                enum_name,
                variant,
                inner,
                span,
            } => {
                let mut cur_ty = target_ty;
                let mut is_ref_target = false;
                while let Type::Ref(inner_ref) = cur_ty {
                    cur_ty = inner_ref;
                    is_ref_target = true;
                }

                if is_ref_target {
                    if let Some(inner_pat) = inner {
                        if pattern_has_inout(inner_pat) {
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "impossible de créer un emprunt mutable exclusif 'inout' à travers une référence générationnelle immuable ('{}')",
                                    target_ty
                                ))
                                .with_code("E0010")
                                .with_primary_label(
                                    inner_pat.span(),
                                    "liaison exclusive 'inout' interdite sur une cible 'ref'",
                                )
                                .with_help("Les références 'ref' sont des emprunts immuables. Utilisez 'ref' ou une copie par valeur."),
                            );
                        }
                    }
                }

                let mut found_payload_ty: Option<Type> = None;
                let mut valid_variant = false;

                if let Type::Enum {
                    name: e_sym,
                    variants,
                } = cur_ty
                {
                    if let Some((_, opt_ty)) = variants.iter().find(|(v, _)| v == variant) {
                        valid_variant = true;
                        found_payload_ty = opt_ty.clone();
                    } else {
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
                } else if let Some(e_sym) = enum_name {
                    if let Some((_, _, opt_ty)) = self.symbols.lookup_enum_variant(e_sym, variant) {
                        valid_variant = true;
                        found_payload_ty = opt_ty.cloned();
                    } else {
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
                } else if let Some((_, _, opt_ty)) = self.symbols.lookup_enum_by_variant(variant) {
                    valid_variant = true;
                    found_payload_ty = opt_ty.cloned();
                } else if *cur_ty != Type::Unknown {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "le motif variant '{}' ne correspond pas au type '{}'",
                            INTERNER.resolve(variant),
                            target_ty
                        ))
                        .with_code("E0036")
                        .with_primary_label(*span, "type de motif incompatible"),
                    );
                }

                if valid_variant {
                    match (inner, found_payload_ty) {
                        (Some(inner_pat), Some(payload_ty)) => {
                            self.check_pattern_with_mut(
                                inner_pat,
                                &payload_ty,
                                is_mut,
                                is_initialized,
                            );
                        }
                        (Some(inner_pat), None) => {
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "le variant '{}' ne contient aucune donnée associée",
                                    INTERNER.resolve(variant)
                                ))
                                .with_code("E0038")
                                .with_primary_label(
                                    inner_pat.span(),
                                    "aucun argument attendu pour ce variant",
                                ),
                            );
                        }
                        (None, Some(payload_ty)) => {
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "le variant '{}' attend une charge utile de type '{}'",
                                    INTERNER.resolve(variant),
                                    payload_ty
                                ))
                                .with_code("E0039")
                                .with_primary_label(*span, "charge utile manquante"),
                            );
                        }
                        (None, None) => {}
                    }
                }
            }
            Pattern::Tuple(elems, span) => {
                let mut cur_ty = target_ty;
                let mut is_ref_target = false;
                while let Type::Ref(inner_ref) = cur_ty {
                    cur_ty = inner_ref;
                    is_ref_target = true;
                }

                if is_ref_target {
                    for elem in elems {
                        if pattern_has_inout(elem) {
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "impossible de créer un emprunt mutable exclusif 'inout' à travers une référence générationnelle immuable ('{}')",
                                    target_ty
                                ))
                                .with_code("E0010")
                                .with_primary_label(
                                    elem.span(),
                                    "liaison exclusive 'inout' interdite sur une cible 'ref'",
                                )
                                .with_help("Les références 'ref' sont des emprunts immuables. Utilisez 'ref' ou une copie par valeur."),
                            );
                        }
                    }
                }

                match cur_ty {
                    Type::Tuple(expected_elems) => {
                        if elems.len() != expected_elems.len() {
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "le motif tuple contient {} élément(s), mais le type attendu '{}' en contient {}",
                                    elems.len(),
                                    cur_ty,
                                    expected_elems.len()
                                ))
                                .with_code("E0036")
                                .with_primary_label(*span, "arité de tuple incompatible"),
                            );
                        } else {
                            for (elem_pat, elem_ty) in elems.iter().zip(expected_elems.iter()) {
                                self.check_pattern_with_mut(
                                    elem_pat,
                                    elem_ty,
                                    is_mut,
                                    is_initialized,
                                );
                            }
                        }
                    }
                    Type::Unit if elems.is_empty() => {}
                    Type::Unknown => {
                        for elem_pat in elems {
                            self.check_pattern_with_mut(
                                elem_pat,
                                &Type::Unknown,
                                is_mut,
                                is_initialized,
                            );
                        }
                    }
                    _ => {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "le motif tuple est incompatible avec le type non-tuple '{}'",
                                cur_ty
                            ))
                            .with_code("E0036")
                            .with_primary_label(*span, "type de motif incompatible"),
                        );
                    }
                }
            }
            Pattern::Struct {
                name,
                fields,
                has_rest,
                span,
            } => {
                let st_name = match name.last() {
                    Some(sym) => *sym,
                    None => return,
                };

                let st_opt = self.symbols.lookup_struct(&st_name).cloned();
                if st_opt.is_none() {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "structure inconnue '{}'",
                            INTERNER.resolve(&st_name)
                        ))
                        .with_code("E0006")
                        .with_primary_label(*span, "structure inconnue"),
                    );
                    return;
                }
                let st = st_opt.unwrap();

                let mut cur_ty = target_ty;
                let mut is_ref_target = false;
                while let Type::Ref(inner_ref) = cur_ty {
                    cur_ty = inner_ref;
                    is_ref_target = true;
                }

                if is_ref_target {
                    for f in fields {
                        if pattern_has_inout(&f.pattern) {
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "impossible de créer un emprunt mutable exclusif 'inout' à travers une référence générationnelle immuable ('{}')",
                                    target_ty
                                ))
                                .with_code("E0010")
                                .with_primary_label(
                                    f.pattern.span(),
                                    "liaison exclusive 'inout' interdite sur une cible 'ref'",
                                )
                                .with_help("Les références 'ref' sont des emprunts immuables. Utilisez 'ref' ou une copie par valeur."),
                            );
                        }
                    }
                }

                // Check type compatibility
                let is_compatible = match cur_ty {
                    Type::Struct { name: t_name, .. } => *t_name == st_name,
                    Type::Generic { name: t_name, .. } => *t_name == st_name,
                    Type::Unknown => true,
                    _ => false,
                };

                if !is_compatible {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "le motif de structure '{}' ne correspond pas au type '{}'",
                            INTERNER.resolve(&st_name),
                            target_ty
                        ))
                        .with_code("E0036")
                        .with_primary_label(*span, "type de motif incompatible"),
                    );
                    return;
                }

                let mut type_subst: HashMap<Symbol, Type> = HashMap::new();
                if let Type::Generic { args, .. } = cur_ty {
                    for (g, a) in st.generics.iter().zip(args.iter()) {
                        type_subst.insert(g.name, a.clone());
                    }
                }

                let mut bound_fields = HashSet::new();
                for f in fields {
                    bound_fields.insert(f.name);
                    if let Some(f_sym) = st.get_field(&f.name) {
                        let expected_field_ty = if type_subst.is_empty() {
                            f_sym.ty.clone()
                        } else {
                            f_sym.ty.substitute(&type_subst)
                        };
                        self.check_pattern_with_mut(
                            &f.pattern,
                            &expected_field_ty,
                            is_mut,
                            is_initialized,
                        );
                    } else {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "le champ '{}' n'existe pas dans la structure '{}'",
                                INTERNER.resolve(&f.name),
                                INTERNER.resolve(&st_name)
                            ))
                            .with_code("E0037")
                            .with_primary_label(f.span, "champ inconnu"),
                        );
                    }
                }

                if !has_rest && bound_fields.len() < st.fields.len() {
                    let missing_fields: Vec<String> = st
                        .fields
                        .iter()
                        .filter(|f| !bound_fields.contains(&f.name))
                        .map(|f| INTERNER.resolve(&f.name).to_string())
                        .collect();
                    if !missing_fields.is_empty() {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "motif incomplet pour la structure '{}' : champs manquants : {}. Utilisez '..' pour ignorer les champs restants",
                                INTERNER.resolve(&st_name),
                                missing_fields.iter().map(|s| format!("'{}'", s)).collect::<Vec<_>>().join(", ")
                            ))
                            .with_code("E0043")
                            .with_primary_label(*span, "champs omis non ignorés"),
                        );
                    }
                }
            }
            Pattern::Or(patterns, _span) => {
                if patterns.is_empty() {
                    return;
                }

                let mut all_bindings: Vec<HashMap<Symbol, (Type, Span)>> =
                    Vec::with_capacity(patterns.len());

                for sub_pat in patterns {
                    self.symbols.enter_scope(false, false);
                    self.check_pattern_with_mut(sub_pat, target_ty, is_mut, is_initialized);

                    let mut sub_bindings = HashMap::new();
                    if let Some(scope) = self.symbols.scopes.last() {
                        for (name, var) in &scope.variables {
                            sub_bindings.insert(*name, (var.ty.clone(), var.span));
                        }
                    }
                    self.symbols.exit_scope();
                    all_bindings.push(sub_bindings);
                }

                // Verify that all alternatives bind identical variables with compatible types
                let first_bindings = &all_bindings[0];
                for (i, other_bindings) in all_bindings.iter().enumerate().skip(1) {
                    for (var_name, (var_ty, var_span)) in first_bindings {
                        if let Some((other_ty, _)) = other_bindings.get(var_name) {
                            if !var_ty.is_assignable_to(other_ty)
                                && !other_ty.is_assignable_to(var_ty)
                            {
                                self.diagnostics.push(
                                    Diagnostic::error(format!(
                                        "la variable '{}' est liée avec des types incompatibles dans les alternatives du motif ('{}' vs '{}')",
                                        INTERNER.resolve(var_name),
                                        var_ty,
                                        other_ty
                                    ))
                                    .with_code("E0045")
                                    .with_primary_label(
                                        *var_span,
                                        "type de variable divergent dans l'alternative",
                                    ),
                                );
                            }
                        } else {
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "la variable '{}' n'est pas liée dans toutes les alternatives du motif",
                                    INTERNER.resolve(var_name)
                                ))
                                .with_code("E0045")
                                .with_primary_label(
                                    patterns[i].span(),
                                    format!(
                                        "variable '{}' manquante ici",
                                        INTERNER.resolve(var_name)
                                    ),
                                ),
                            );
                        }
                    }
                    for (var_name, (_, var_span)) in other_bindings {
                        if !first_bindings.contains_key(var_name) {
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "la variable '{}' n'est pas liée dans toutes les alternatives du motif",
                                    INTERNER.resolve(var_name)
                                ))
                                .with_code("E0045")
                                .with_primary_label(
                                    *var_span,
                                    format!(
                                        "variable '{}' présente uniquement dans cette alternative",
                                        INTERNER.resolve(var_name)
                                    ),
                                ),
                            );
                        }
                    }
                }

                // Define bindings in the current arm scope
                for (var_name, (var_ty, var_span)) in first_bindings {
                    let _ = self.symbols.define_variable(
                        *var_name,
                        var_ty.clone(),
                        is_mut,
                        is_initialized,
                        None,
                        *var_span,
                    );
                }
            }
            Pattern::Range {
                start,
                end,
                inclusive: _,
                span,
            } => {
                let is_scalar = matches!(
                    target_ty,
                    Type::Int(_) | Type::Float(_) | Type::Char | Type::Unknown
                );
                if !is_scalar {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "le motif de plage est incompatible avec le type non-scalaire '{}'",
                            target_ty
                        ))
                        .with_code("E0036")
                        .with_primary_label(*span, "type de motif incompatible"),
                    );
                    return;
                }

                if let Some(s) = start {
                    self.check_pattern_with_mut(s, target_ty, is_mut, is_initialized);
                }
                if let Some(e) = end {
                    self.check_pattern_with_mut(e, target_ty, is_mut, is_initialized);
                }
            }
            Pattern::Slice {
                prefix,
                rest,
                suffix,
                span,
            } => {
                let elem_ty = match target_ty {
                    Type::Array(elem, len) => {
                        let min_len = prefix.len() + suffix.len();
                        if rest.is_none() {
                            if min_len as u32 != *len {
                                self.diagnostics.push(
                                    Diagnostic::error(format!(
                                        "le motif de tableau attend {} élément(s), mais le tableau '{}' en compte {}",
                                        min_len, target_ty, len
                                    ))
                                    .with_code("E0036")
                                    .with_primary_label(*span, "arité de tableau incompatible"),
                                );
                            }
                        } else if (min_len as u32) > *len {
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "le motif de tranche requiert au moins {} élément(s), mais le tableau '{}' n'en compte que {}",
                                    min_len, target_ty, len
                                ))
                                .with_code("E0036")
                                .with_primary_label(*span, "nombre d'éléments insuffisant"),
                            );
                        }
                        *elem.clone()
                    }
                    Type::Slice(elem) => *elem.clone(),
                    Type::Unknown => Type::Unknown,
                    _ => {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "le motif de tranche est incompatible avec le type non-indexable '{}'",
                                target_ty
                            ))
                            .with_code("E0036")
                            .with_primary_label(*span, "type de motif incompatible"),
                        );
                        Type::Unknown
                    }
                };

                for p in prefix {
                    self.check_pattern_with_mut(p, &elem_ty, is_mut, is_initialized);
                }

                if let Some(Some(rest_pat)) = rest {
                    let slice_ty = Type::Slice(Box::new(elem_ty.clone()));
                    self.check_pattern_with_mut(rest_pat, &slice_ty, is_mut, is_initialized);
                }

                for s in suffix {
                    self.check_pattern_with_mut(s, &elem_ty, is_mut, is_initialized);
                }
            }
        }
    }

    fn check_pattern_binding_duplicates(&mut self, pat: &Pattern) {
        let mut seen = HashMap::new();
        self.collect_pattern_bindings_unique(pat, &mut seen);
    }

    fn collect_pattern_bindings_unique(&mut self, pat: &Pattern, seen: &mut HashMap<Symbol, Span>) {
        match pat {
            Pattern::Ident(sym, span)
            | Pattern::Binding {
                name: sym, span, ..
            } => {
                if let Some(prev_span) = seen.insert(*sym, *span) {
                    let var_name = INTERNER.resolve(sym);
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "l'identifiant '{}' est lié plusieurs fois dans le même motif",
                            var_name
                        ))
                        .with_code("E0048")
                        .with_primary_label(*span, "identifiant déjà lié dans ce motif")
                        .with_secondary_label(prev_span, "première liaison ici"),
                    );
                }
            }
            Pattern::Tuple(elems, _) => {
                for e in elems {
                    self.collect_pattern_bindings_unique(e, seen);
                }
            }
            Pattern::Struct { fields, .. } => {
                for f in fields {
                    self.collect_pattern_bindings_unique(&f.pattern, seen);
                }
            }
            Pattern::Slice {
                prefix,
                rest,
                suffix,
                ..
            } => {
                for p in prefix {
                    self.collect_pattern_bindings_unique(p, seen);
                }
                if let Some(Some(r)) = rest {
                    self.collect_pattern_bindings_unique(r, seen);
                }
                for s in suffix {
                    self.collect_pattern_bindings_unique(s, seen);
                }
            }
            Pattern::Variant { inner: Some(p), .. } => {
                self.collect_pattern_bindings_unique(p, seen);
            }
            Pattern::Or(pats, _) => {
                for p in pats {
                    let mut branch_seen = HashMap::new();
                    self.collect_pattern_bindings_unique(p, &mut branch_seen);
                }
            }
            _ => {}
        }
    }

    fn check_inout_source_mutability(&mut self, pat: &Pattern, source_expr: &Expr) {
        if pattern_has_inout(pat) {
            if let Some((root_sym, _)) = crate::exclusivity::extract_root_variable(source_expr) {
                if let Some(var) = self.symbols.lookup_variable(&root_sym) {
                    if !var.is_mut {
                        let var_name = INTERNER.resolve(&root_sym);
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "impossible de créer une liaison mutable exclusive 'inout' sur la variable immuable '{}'",
                                var_name
                            ))
                            .with_code("E0010")
                            .with_primary_label(
                                pat.span(),
                                format!(
                                    "liaison exclusive 'inout' interdite sur la variable immuable '{}'",
                                    var_name
                                ),
                            )
                            .with_secondary_label(
                                var.span,
                                format!(
                                    "la variable '{}' a été déclarée immuable avec 'let' (utilisez 'mut')",
                                    var_name
                                ),
                            )
                            .with_help("Changez la déclaration en 'mut' pour autoriser l'emprunt mutable exclusif 'inout'."),
                        );
                    }
                }
            }
        }
    }

    fn check_binary_expr(&mut self, op: BinOp, left: &Expr, right: &Expr, span: Span) -> Type {
        match op {
            BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Rem => {
                let l_ty = self.infer_expr(left);
                let r_ty = self.check_expr(right, Some(&l_ty));
                let mut eff_l = &l_ty;
                while let Type::Ref(inner) = eff_l {
                    eff_l = inner;
                }
                let mut eff_r = &r_ty;
                while let Type::Ref(inner) = eff_r {
                    eff_r = inner;
                }
                if eff_l.is_numeric() && eff_r.is_numeric() {
                    eff_l.resolve_defaults()
                } else if matches!(eff_l, Type::String | Type::Str)
                    && matches!(eff_r, Type::String | Type::Str)
                {
                    Type::String
                } else if matches!(eff_l, Type::TypeParam(_)) && eff_l == eff_r {
                    eff_l.clone()
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
                let mut eff_l = &l_ty;
                while let Type::Ref(inner) = eff_l {
                    eff_l = inner;
                }
                let mut eff_r = &r_ty;
                while let Type::Ref(inner) = eff_r {
                    eff_r = inner;
                }
                if eff_l.is_integer() && eff_r.is_integer() {
                    eff_l.resolve_defaults()
                } else if matches!(eff_l, Type::TypeParam(_)) && eff_l == eff_r {
                    eff_l.clone()
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
            BinOp::And => {
                self.check_expr(left, Some(&Type::Bool));
                let left_facts = self.extract_narrowing_facts(left);
                self.symbols.enter_scope(false, false);
                for (sym, ty) in &left_facts.true_facts {
                    self.symbols
                        .narrow_variable_in_current_scope(*sym, ty.clone());
                }
                self.check_expr(right, Some(&Type::Bool));
                self.symbols.exit_scope();
                Type::Bool
            }
            BinOp::Or => {
                self.check_expr(left, Some(&Type::Bool));
                let left_facts = self.extract_narrowing_facts(left);
                self.symbols.enter_scope(false, false);
                for (sym, ty) in &left_facts.false_facts {
                    self.symbols
                        .narrow_variable_in_current_scope(*sym, ty.clone());
                }
                self.check_expr(right, Some(&Type::Bool));
                self.symbols.exit_scope();
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
        // First check if callee is a qualified module member or struct constructor
        if let ExprKind::Path(path) = &callee.kind {
            if path.len() >= 2 {
                let mod_sym = path[0];
                let member_sym = path[1];
                let mod_name_str = INTERNER.resolve(&mod_sym);
                let member_name_str = INTERNER.resolve(&member_sym);

                if let Some(module) = self.symbols.lookup_module(&mod_sym).cloned() {
                    if let Some(st) = module.structs.get(&member_sym).cloned() {
                        if !st.is_pub {
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "la structure '{}' est privée dans le module '{}'",
                                    member_name_str, mod_name_str
                                ))
                                .with_code("E0011")
                                .with_primary_label(
                                    span,
                                    "structure privée inaccessible de l'extérieur",
                                ),
                            );
                        }
                        return self.check_struct_constructor_call(&st, args, span);
                    } else if let Some(f) = module.functions.get(&member_sym).cloned() {
                        if !f.is_pub {
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "la fonction '{}' est privée dans le module '{}'",
                                    member_name_str, mod_name_str
                                ))
                                .with_code("E0011")
                                .with_primary_label(
                                    span,
                                    "fonction privée inaccessible de l'extérieur",
                                ),
                            );
                        }
                        return self.check_function_call(&f, args, false, span);
                    }
                }
            }
        }

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

        // Check if callee is an enum variant constructor (e.g. WebEvent::KeyPress(...) or Some(...))
        let enum_variant_match = match &callee.kind {
            ExprKind::Path(path) => {
                if path.len() >= 2 {
                    let en_sym = path[path.len() - 2];
                    let v_sym = path[path.len() - 1];
                    self.symbols
                        .lookup_enum_variant(&en_sym, &v_sym)
                        .map(|(en, idx, p)| (en.clone(), idx, p.cloned()))
                } else if let Some(last) = path.last() {
                    self.symbols
                        .lookup_enum_by_variant(last)
                        .map(|(en, idx, p)| (en.clone(), idx, p.cloned()))
                } else {
                    None
                }
            }
            ExprKind::Ident(sym) => self
                .symbols
                .lookup_enum_by_variant(sym)
                .map(|(en, idx, p)| (en.clone(), idx, p.cloned())),
            _ => None,
        };

        if let Some((en, _variant_idx, opt_payload_ty)) = enum_variant_match {
            if let Some(payload_ty) = opt_payload_ty {
                if args.len() != 1 {
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "le variant '{}' attend exactement 1 argument de type '{}', mais {} arguments ont été fournis",
                            INTERNER.resolve(&en.name),
                            payload_ty,
                            args.len()
                        ))
                        .with_code("E0040")
                        .with_primary_label(span, "nombre d'arguments invalide pour le variant"),
                    );
                } else {
                    let arg_ty = self.check_expr(&args[0].value, Some(&payload_ty));
                    if !arg_ty.is_assignable_to(&payload_ty) && arg_ty != Type::Unknown {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "type d'argument invalide pour le variant '{}' : attendu '{}', trouvé '{}'",
                                INTERNER.resolve(&en.name),
                                payload_ty,
                                arg_ty
                            ))
                            .with_code("E0041")
                            .with_primary_label(args[0].span, "type incompatible pour la charge utile du variant"),
                        );
                    }
                }
            } else {
                self.diagnostics.push(
                    Diagnostic::error(format!(
                        "le variant '{}' n'accepte aucun argument",
                        INTERNER.resolve(&en.name)
                    ))
                    .with_code("E0042")
                    .with_primary_label(span, "appel invalide sur un variant sans charge utile"),
                );
            }
            return Type::Enum {
                name: en.name,
                variants: en.variants,
            };
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
            self.check_function_call(&f, args, false, span)
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

    fn check_function_call(
        &mut self,
        f: &FunctionSymbol,
        args: &[Arg],
        safe_first_arg: bool,
        span: Span,
    ) -> Type {
        let param_modes: Vec<ParamMode> = f.params.iter().map(|p| p.mode).collect();

        // Check Law of Exclusivity on arguments!
        check_call_exclusivity(args, &param_modes, &self.symbols, &mut self.diagnostics);

        // Check argument count
        let fn_name = INTERNER.resolve(&f.name);
        let is_assert_call = (fn_name == "assert" && (args.len() == 1 || args.len() == 2))
            || ((fn_name == "assert_eq" || fn_name == "assert_ne")
                && (args.len() == 2 || args.len() == 3));

        if args.len() != f.params.len() && !is_assert_call {
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
                    let effective_arg_ty = if idx == 0 && safe_first_arg {
                        match &arg_ty {
                            Type::Optional(inner) => inner.as_ref().clone(),
                            other => other.clone(),
                        }
                    } else {
                        arg_ty
                    };
                    param
                        .ty
                        .unify_type_params(&effective_arg_ty, &mut type_param_map);
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
                let is_match = arg_ty.is_assignable_to(&expected_param_ty)
                    || (idx == 0
                        && safe_first_arg
                        && matches!(&arg_ty, Type::Optional(inner) if inner.is_assignable_to(&expected_param_ty)));
                if !is_match {
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
        safe: bool,
        span: Span,
    ) -> Type {
        let rec_ty = self.infer_expr(receiver);
        let m_name = INTERNER.resolve(&method);

        if !safe && matches!(rec_ty, Type::Optional(_)) {
            self.diagnostics.push(
                Diagnostic::error(format!(
                    "appel direct de méthode '{}' impossible sur le type optionnel '{}' : utilisez '?.' pour un appel optionnel sécurisé",
                    m_name, rec_ty
                ))
                .with_code("E0008")
                .with_primary_label(span, "appel risqué sur type optionnel, utilisez '?.'")
                .with_secondary_label(receiver.span, format!("récepteur de type '{}'", rec_ty)),
            );
            return Type::Unknown;
        }

        let effective_rec_ty = if safe {
            match &rec_ty {
                Type::Optional(inner) => inner.as_ref().clone(),
                other => other.clone(),
            }
        } else {
            rec_ty.clone()
        };

        let wrap_optional = |ret: Type| {
            if safe {
                match ret {
                    Type::Unit => Type::Unit,
                    Type::Optional(_) => ret,
                    Type::Unknown => Type::Unknown,
                    other => Type::Optional(Box::new(other)),
                }
            } else {
                ret
            }
        };

        // Standard method handling (e.g. List.push, List.len, String.len, etc.)
        if m_name == "len" {
            return wrap_optional(Type::Int(IntType::I64));
        }
        if m_name == "is_empty" {
            return wrap_optional(Type::Bool);
        }
        if m_name == "send" {
            for arg in args {
                self.infer_expr(&arg.value);
            }
            return Type::Unit;
        }
        if m_name == "recv" {
            if let Type::Generic {
                name,
                args: gen_args,
            } = &effective_rec_ty
            {
                if INTERNER.resolve(name) == "Channel" && !gen_args.is_empty() {
                    return wrap_optional(gen_args[0].clone());
                }
            }
            return Type::Unknown;
        }
        if m_name == "try_recv" {
            if let Type::Generic {
                name,
                args: gen_args,
            } = &effective_rec_ty
            {
                if INTERNER.resolve(name) == "Channel" && !gen_args.is_empty() {
                    return Type::Optional(Box::new(gen_args[0].clone()));
                }
            }
            return Type::Optional(Box::new(Type::Unknown));
        }
        if m_name == "close" {
            return Type::Unit;
        }

        // Bounded generic type parameter method resolution:
        if let Type::TypeParam(p_name) = &effective_rec_ty {
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
                return wrap_optional(ret);
            }
        }

        match &effective_rec_ty {
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

        // Concrete type associated method resolution (AOT devirtualization)
        let mut rec_struct_sym = None;
        let mut cur_ty = &effective_rec_ty;
        while let Type::Ref(inner) = cur_ty {
            cur_ty = inner;
        }
        if let Type::Struct { name, .. } = cur_ty {
            rec_struct_sym = Some(*name);
        } else if let Type::Generic { name, .. } = cur_ty {
            rec_struct_sym = Some(*name);
        }

        if let Some(st_sym) = rec_struct_sym {
            if let Some(f) = self.symbols.lookup_type_method(&st_sym, &method).cloned() {
                let mangled_name = INTERNER.intern(&format!(
                    "{}__{}",
                    INTERNER.resolve(&st_sym),
                    INTERNER.resolve(&method)
                ));
                self.symbols.method_resolutions.insert(span, mangled_name);

                let mut full_args = Vec::with_capacity(args.len() + 1);
                full_args.push(Arg::positional(receiver.clone()));
                full_args.extend_from_slice(args);
                let ret = self.check_function_call(&f, &full_args, safe, span);
                return wrap_optional(ret);
            }
        }

        // Polymorphic methods and UFCS (Uniform Function Call Syntax):
        // If a function with `method` name exists taking receiver as first parameter:
        if let Some(f) = self.symbols.lookup_function(&method).cloned() {
            if !f.params.is_empty() {
                let mut full_args = Vec::with_capacity(args.len() + 1);
                full_args.push(Arg::positional(receiver.clone()));
                full_args.extend_from_slice(args);
                let ret = self.check_function_call(&f, &full_args, safe, span);
                return wrap_optional(ret);
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

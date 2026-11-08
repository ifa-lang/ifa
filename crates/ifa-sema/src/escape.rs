use crate::exclusivity::{extract_access_path, AccessPath, PathSegment};
use crate::symbol_table::SymbolTable;
use crate::types::Type;
use ifa_ast::{Expr, ExprKind, Function, ParamMode, Pattern, Stmt, UnaryOp};
use ifa_diagnostics::Diagnostic;
use ifa_span::{Span, Symbol, INTERNER};
use std::collections::{HashMap, HashSet};

/// Determines if a type contains or is a generational reference (`ref T`).
pub fn type_contains_ref(ty: &Type) -> bool {
    match ty {
        Type::Ref(_) => true,
        Type::Optional(inner) => type_contains_ref(inner),
        Type::Slice(inner) => type_contains_ref(inner),
        Type::Array(inner, _) => type_contains_ref(inner),
        Type::Range { elem, .. } => type_contains_ref(elem),
        Type::ErrorUnion { err, ok } => type_contains_ref(err) || type_contains_ref(ok),
        Type::Tuple(elems) => elems.iter().any(type_contains_ref),
        Type::Generic { args, .. } => args.iter().any(type_contains_ref),
        Type::Struct { fields, .. } => fields.iter().any(|(_, fty)| type_contains_ref(fty)),
        _ => false,
    }
}

/// Determines if a type contains a self-referential or recursive definition.
pub fn is_recursive_type(
    ty: &Type,
    target_struct: Option<Symbol>,
    visited: &mut HashSet<Symbol>,
) -> bool {
    match ty {
        Type::Struct { name, fields } => {
            if let Some(target) = target_struct {
                if *name == target {
                    return true;
                }
            }
            if !visited.insert(*name) {
                return true;
            }
            let target = target_struct.unwrap_or(*name);
            let recursive = fields
                .iter()
                .any(|(_, fty)| is_recursive_type(fty, Some(target), visited));
            visited.remove(name);
            recursive
        }
        Type::Ref(inner) | Type::Optional(inner) | Type::Slice(inner) | Type::Array(inner, _) => {
            is_recursive_type(inner, target_struct, visited)
        }
        Type::Tuple(elems) => elems
            .iter()
            .any(|e| is_recursive_type(e, target_struct, visited)),
        Type::Generic { args, .. } => args
            .iter()
            .any(|a| is_recursive_type(a, target_struct, visited)),
        Type::ErrorUnion { err, ok } => {
            is_recursive_type(err, target_struct, visited)
                || is_recursive_type(ok, target_struct, visited)
        }
        _ => false,
    }
}

/// Identifies the root variable of an expression, traversing field accesses, array indices,
/// chained method calls, and unary operators (inout, sink, ref).
pub fn extract_escape_root(expr: &Expr) -> Option<(Symbol, Span)> {
    match &expr.kind {
        ExprKind::Ident(sym) => Some((*sym, expr.span)),
        ExprKind::FieldAccess { receiver, .. } => extract_escape_root(receiver),
        ExprKind::Index { receiver, .. } => extract_escape_root(receiver),
        ExprKind::MethodCall { receiver, .. } => extract_escape_root(receiver),
        ExprKind::Unary { expr: inner, .. } => extract_escape_root(inner),
        _ => None,
    }
}

/// Formats a projection expression into a human-readable representation for diagnostics.
pub fn format_projection_expr(expr: &Expr) -> String {
    match &expr.kind {
        ExprKind::Ident(sym) => INTERNER.resolve(sym),
        ExprKind::FieldAccess {
            receiver,
            field,
            safe,
        } => {
            let op = if *safe { "?." } else { "." };
            format!(
                "{}{}{}",
                format_projection_expr(receiver),
                op,
                INTERNER.resolve(field)
            )
        }
        ExprKind::Index { receiver, index } => {
            if let ExprKind::Range {
                start,
                end,
                step,
                inclusive,
            } = &index.kind
            {
                let s_val = start.as_ref().and_then(|e| match &e.kind {
                    ExprKind::Lit(ifa_ast::Lit::Int(sym)) => Some(INTERNER.resolve(sym)),
                    _ => None,
                });
                let e_val = end.as_ref().and_then(|e| match &e.kind {
                    ExprKind::Lit(ifa_ast::Lit::Int(sym)) => Some(INTERNER.resolve(sym)),
                    _ => None,
                });
                let step_val = step.as_ref().and_then(|e| match &e.kind {
                    ExprKind::Lit(ifa_ast::Lit::Int(sym)) => Some(INTERNER.resolve(sym)),
                    _ => None,
                });
                let s_str = s_val.unwrap_or_default();
                let sep = if *inclusive { "..=" } else { ".." };
                let e_str = e_val.unwrap_or_default();
                let step_suffix = if let Some(st) = step_val {
                    format!(":{}", st)
                } else {
                    String::new()
                };
                format!(
                    "{}[{}{}{}{}]",
                    format_projection_expr(receiver),
                    s_str,
                    sep,
                    e_str,
                    step_suffix
                )
            } else {
                format!("{}[...]", format_projection_expr(receiver))
            }
        }
        ExprKind::MethodCall {
            receiver, method, ..
        } => {
            format!(
                "{}.{}()",
                format_projection_expr(receiver),
                INTERNER.resolve(method)
            )
        }
        ExprKind::Unary { op, expr } => match op {
            UnaryOp::Ref => format!("ref {}", format_projection_expr(expr)),
            UnaryOp::InOut => format!("inout {}", format_projection_expr(expr)),
            UnaryOp::Sink => format!("sink {}", format_projection_expr(expr)),
            _ => format_projection_expr(expr),
        },
        _ => "expression".to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocKind {
    Stack,
    HeapGenerational,
    ArenaScoped,
}

/// Determines if an expression allocates or evaluates to an arena-scoped object.
pub fn is_arena_expr(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::Ident(sym) => {
            let name = INTERNER.resolve(sym);
            name.starts_with("arena") || name.contains("Arena")
        }
        ExprKind::Call { callee, .. } => match &callee.kind {
            ExprKind::Ident(sym) => {
                let name = INTERNER.resolve(sym);
                name.contains("arena") || name.contains("Arena")
            }
            ExprKind::FieldAccess { field, .. } => {
                let name = INTERNER.resolve(field);
                name.contains("arena") || name.contains("Arena")
            }
            _ => false,
        },
        ExprKind::MethodCall { method, .. } => {
            let name = INTERNER.resolve(method);
            name.contains("arena") || name.contains("Arena")
        }
        ExprKind::StructInit { name, .. } => {
            if let Some(sym) = name.last() {
                let n = INTERNER.resolve(sym);
                n.contains("arena") || n.contains("Arena")
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Determines if a type corresponds to a memory Arena or an arena reference.
pub fn is_arena_type(ty: &Type) -> bool {
    match ty {
        Type::Struct { name, .. } => {
            let n = INTERNER.resolve(name);
            n == "Arena" || n.contains("Arena") || n.contains("arena")
        }
        Type::Ref(inner) => is_arena_type(inner),
        Type::Generic { name, .. } => {
            let n = INTERNER.resolve(name);
            n == "Arena" || n.contains("Arena") || n.contains("arena")
        }
        _ => false,
    }
}

/// Determines if a variable or symbol represents an Arena.
pub fn is_arena_symbol(sym: &Symbol, symbols: &SymbolTable) -> bool {
    let name = INTERNER.resolve(sym);
    if name.to_lowercase().contains("arena") {
        return true;
    }
    if let Some(var) = symbols.lookup_variable(sym) {
        if is_arena_type(&var.ty) {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscapeStatus {
    Local,
    EscapesFunction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarOrigin {
    Local,
    Param(ParamMode),
}

#[derive(Debug, Clone)]
pub struct ContainedRef {
    pub target_var: Symbol,
    pub ref_span: Span,
    pub is_projection: bool,
}

#[derive(Debug, Clone)]
pub struct VarEscapeInfo {
    pub var: Symbol,
    pub origin: VarOrigin,
    pub alloc_kind: AllocKind,
    pub escape_status: EscapeStatus,
    pub defined_span: Span,
    pub contained_refs: Vec<ContainedRef>,
    pub is_compound: bool,
}

/// Nature of an access performed within a concurrent fiber or borrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConcurrentAccessKind {
    Read,
    Write,
    Sink,
}

/// An access to a structured path performed within a concurrent fiber (`spawn`).
#[derive(Debug, Clone)]
pub struct ConcurrentAccess {
    pub path: AccessPath,
    pub is_write: bool,
    pub kind: ConcurrentAccessKind,
    pub spawn_id: usize,
    pub span: Span,
}

pub struct EscapeAnalyzer<'a> {
    pub symbols: &'a SymbolTable,
    pub current_func_is_strict: bool,
    pub current_func_is_comptime: bool,
    pub current_func_span: Span,
    pub var_info: HashMap<Symbol, VarEscapeInfo>,
    pub ref_dependencies: HashMap<Symbol, Vec<Symbol>>,
    pub shared_values: HashMap<Symbol, HashSet<Symbol>>,
    pub stack_arrays: HashMap<Symbol, Span>,
    pub arena_capturing_closures: HashMap<Symbol, Symbol>,
    pub arena_lambda_spans: HashMap<Span, Symbol>,
    pub comptime_isolated_arenas: HashSet<Symbol>,
    pub comptime_recursive_structs: HashMap<Symbol, Symbol>,
    pub comptime_mutable_arena_closures: HashMap<Symbol, Symbol>,
    pub var_struct_type: HashMap<Symbol, Symbol>,
    pub spawn_depth: usize,
    pub spawn_counter: usize,
    pub current_spawn_id: Option<usize>,
    pub concurrent_accesses: Vec<ConcurrentAccess>,
    pub diagnostics: Vec<Diagnostic>,
}

impl<'a> EscapeAnalyzer<'a> {
    pub fn new(symbols: &'a SymbolTable, is_strict: bool, func_span: Span) -> Self {
        Self {
            symbols,
            current_func_is_strict: is_strict,
            current_func_is_comptime: false,
            current_func_span: func_span,
            var_info: HashMap::new(),
            ref_dependencies: HashMap::new(),
            shared_values: HashMap::new(),
            stack_arrays: HashMap::new(),
            arena_capturing_closures: HashMap::new(),
            arena_lambda_spans: HashMap::new(),
            comptime_isolated_arenas: HashSet::new(),
            comptime_recursive_structs: HashMap::new(),
            comptime_mutable_arena_closures: HashMap::new(),
            var_struct_type: HashMap::new(),
            spawn_depth: 0,
            spawn_counter: 0,
            current_spawn_id: None,
            concurrent_accesses: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    pub fn with_comptime(mut self, is_comptime: bool) -> Self {
        self.current_func_is_comptime = is_comptime;
        self
    }

    /// Checks if a struct definition contains recursive self-referential fields.
    pub fn is_recursive_struct_symbol(&self, struct_name: Symbol) -> bool {
        if let Some(st_def) = self.symbols.lookup_struct(&struct_name) {
            let mut visited = HashSet::new();
            visited.insert(struct_name);
            for f in &st_def.fields {
                if is_recursive_type(&f.ty, Some(struct_name), &mut visited) {
                    return true;
                }
            }
        }
        false
    }

    pub fn record_local_var(&mut self, var: Symbol, span: Span) {
        if let Some(var_sym) = self.symbols.lookup_variable(&var) {
            if matches!(var_sym.ty, Type::Array(_, _)) {
                self.stack_arrays.insert(var, span);
            }
        }
        self.var_info.insert(
            var,
            VarEscapeInfo {
                var,
                origin: VarOrigin::Local,
                alloc_kind: AllocKind::Stack,
                escape_status: EscapeStatus::Local,
                defined_span: span,
                contained_refs: Vec::new(),
                is_compound: false,
            },
        );
    }

    pub fn record_param(&mut self, var: Symbol, mode: ParamMode, span: Span) {
        let is_compound = self
            .symbols
            .lookup_variable(&var)
            .map(|v| v.ty.is_cow_candidate())
            .unwrap_or(false);
        self.var_info.insert(
            var,
            VarEscapeInfo {
                var,
                origin: VarOrigin::Param(mode),
                alloc_kind: AllocKind::Stack,
                escape_status: EscapeStatus::Local,
                defined_span: span,
                contained_refs: Vec::new(),
                is_compound,
            },
        );
    }

    /// Checks whether a variable is of a type candidate for Copy-on-Write (CoW).
    pub fn is_type_cow_candidate(&self, sym: &Symbol) -> bool {
        if let Some(info) = self.var_info.get(sym) {
            if info.is_compound {
                return true;
            }
        }
        if self.stack_arrays.contains_key(sym) {
            return true;
        }
        if let Some(var_sym) = self.symbols.lookup_variable(sym) {
            var_sym.ty.is_cow_candidate()
        } else {
            false
        }
    }

    /// Records that variable `a` and `b` share the same underlying memory/value without exclusive transfer.
    pub fn record_share(&mut self, a: Symbol, b: Symbol) {
        if a == b {
            return;
        }
        if !self.is_type_cow_candidate(&b) && !self.is_type_cow_candidate(&a) {
            return;
        }
        let existing: Vec<Symbol> = self
            .shared_values
            .get(&b)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default();

        self.shared_values.entry(a).or_default().insert(b);
        self.shared_values.entry(b).or_default().insert(a);

        for other in existing {
            if other != a {
                self.shared_values.entry(a).or_default().insert(other);
                self.shared_values.entry(other).or_default().insert(a);
            }
        }
    }

    /// Removes all sharing associations for a consumed (`sink`) or reassigned variable.
    pub fn remove_share(&mut self, a: Symbol) {
        if let Some(aliases) = self.shared_values.remove(&a) {
            for other in aliases {
                if let Some(other_set) = self.shared_values.get_mut(&other) {
                    other_set.remove(&a);
                }
            }
        }
    }

    /// Checks if a mutation on `target` in a strict function violates the prohibition
    /// of hidden Copy-on-Write (CoW) by operating on a shared, non-unique memory object.
    pub fn check_strict_cow_mutation(&mut self, target: &Expr, span: Span) -> bool {
        if !self.current_func_is_strict {
            return true;
        }

        if let Some((root_sym, root_span)) = extract_escape_root(target) {
            if let Some(aliases) = self.shared_values.get(&root_sym) {
                if !aliases.is_empty()
                    && (self.is_type_cow_candidate(&root_sym)
                        || !matches!(target.kind, ExprKind::Ident(_)))
                {
                    let root_name = INTERNER.resolve(&root_sym);
                    let alias_names: Vec<String> =
                        aliases.iter().map(|s| INTERNER.resolve(s)).collect();
                    let target_repr = format_projection_expr(target);

                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "violation du mode strict : mutation sur '{}' nécessitant un Copy-on-Write (CoW) masqué interdite dans une fonction 'strict fn'",
                            target_repr
                        ))
                        .with_code("E0020")
                        .with_primary_label(
                            span,
                            format!(
                                "mutation sur '{}' requérant un dédoublement CoW masqué interdit en mode strict",
                                target_repr
                            ),
                        )
                        .with_secondary_label(
                            root_span,
                            format!(
                                "'{}' partage sa mémoire avec '{}' sans transfert exclusif 'sink'",
                                root_name,
                                alias_names.join(", ")
                            ),
                        )
                        .with_note("Le mode strict garantit l'absence totale d'allocation implicite sur le tas. Tout Copy-on-Write masqué est prohibé.")
                        .with_help("Transférez la propriété exclusive avec 'sink' (ex: 'let b = sink a'), utilisez un emprunt 'inout' exclusif sans aliasing, ou opérez dans une 'Arena' pré-allouée."),
                    );
                    return false;
                }
            }
        }
        true
    }

    pub fn check_function(&mut self, func: &Function) {
        for param in &func.params {
            self.record_param(param.name, param.mode, param.span);
        }

        if let Some(body) = &func.body {
            for stmt in &body.stmts {
                self.check_stmt(stmt);
            }
            if let Some(ret_expr) = &body.expr {
                self.check_return_expr(ret_expr);
            }
        }
    }

    /// Determines the parameter passing mode for a method receiver.
    fn method_receiver_mode(&self, receiver: &Expr, method: Symbol, span: Span) -> ParamMode {
        if let Some(&resolved) = self.symbols.method_resolutions.get(&span) {
            if let Some(fn_sym) = self.symbols.lookup_function(&resolved) {
                if let Some(first_p) = fn_sym.params.first() {
                    return first_p.mode;
                }
            }
        }
        if let Some(fn_sym) = self.symbols.lookup_function(&method) {
            if let Some(first_p) = fn_sym.params.first() {
                return first_p.mode;
            }
        }
        if let Some((root_sym, _)) = extract_escape_root(receiver) {
            if let Some(var) = self.symbols.lookup_variable(&root_sym) {
                let type_sym = match &var.ty {
                    Type::Struct { name, .. } | Type::Generic { name, .. } => Some(*name),
                    _ => None,
                };
                if let Some(t_sym) = type_sym {
                    if let Some(fn_sym) = self.symbols.lookup_type_method(&t_sym, &method) {
                        if let Some(first_p) = fn_sym.params.first() {
                            return first_p.mode;
                        }
                    }
                }
            }
        }
        ParamMode::In
    }

    /// Determines whether the method receiver is passed by `inout`.
    #[allow(dead_code)]
    pub(crate) fn is_method_receiver_inout(
        &self,
        receiver: &Expr,
        method: Symbol,
        span: Span,
    ) -> bool {
        self.method_receiver_mode(receiver, method, span) == ParamMode::InOut
    }

    /// Checks and records an access (`inout`, `ref`, or `sink`) within a `spawn` fiber,
    /// permitting provably disjoint slice or field projections across concurrent fibers
    /// while statically detecting and blocking all overlapping data races.
    fn check_concurrent_arg(
        &mut self,
        inner: &Expr,
        arg_span: Span,
        kind: ConcurrentAccessKind,
    ) -> bool {
        let cur_spawn = match self.current_spawn_id {
            Some(id) => id,
            None => return true,
        };

        if self
            .concurrent_accesses
            .iter()
            .any(|a| a.span == arg_span && a.spawn_id == cur_spawn)
        {
            return true;
        }

        if let Some((root_sym, root_span)) = extract_escape_root(inner) {
            if self.var_info.contains_key(&root_sym) {
                let var_name = INTERNER.resolve(&root_sym);
                if let Some(path) = extract_access_path(inner) {
                    let has_slice_or_field = path.segments.iter().any(|seg| {
                        matches!(
                            seg,
                            PathSegment::SliceConst { .. }
                                | PathSegment::SliceRange { .. }
                                | PathSegment::SlicePatternRest { .. }
                                | PathSegment::Field(_)
                        )
                    });

                    if kind == ConcurrentAccessKind::Write && !has_slice_or_field {
                        let is_projection = !matches!(&inner.kind, ExprKind::Ident(_));
                        let inner_repr = format_projection_expr(inner);

                        let error_msg = if is_projection {
                            format!(
                                "mutation concurrente interdite : l'argument 'inout' sur la projection scalaire '{}' de '{}' crée un accès mutable concurrent au sein d'une fibre 'spawn'",
                                inner_repr, var_name
                            )
                        } else {
                            format!(
                                "mutation concurrente interdite : l'argument 'inout {}' crée un accès mutable concurrent au sein d'une fibre 'spawn'",
                                var_name
                            )
                        };

                        let primary_label = if is_projection {
                            format!(
                                "passage inout de '{}' interdit dans une fibre concurrente",
                                inner_repr
                            )
                        } else {
                            "passage inout interdit dans une fibre concurrente".to_string()
                        };

                        self.diagnostics.push(
                            Diagnostic::error(error_msg)
                                .with_code("E0025")
                                .with_primary_label(arg_span, primary_label)
                                .with_secondary_label(
                                    root_span,
                                    format!("'{}' appartient au thread parent", var_name),
                                )
                                .with_help("Transférez la propriété avec 'sink' ou envoyez un message via un canal."),
                        );
                        return false;
                    }

                    for other in &self.concurrent_accesses {
                        if other.spawn_id != cur_spawn && other.path.overlaps(&path) {
                            let conflict = !matches!(
                                (kind, other.kind),
                                (ConcurrentAccessKind::Read, ConcurrentAccessKind::Read)
                            );

                            if conflict {
                                let (err_msg, primary_lbl, secondary_lbl, help_msg) =
                                    match (kind, other.kind) {
                                        (ConcurrentAccessKind::Write, ConcurrentAccessKind::Write) => (
                                            format!(
                                                "mutation concurrente interdite : l'argument 'inout' sur la projection '{}' dans une fibre 'spawn' chevauche l'accès concurrent sur '{}' dans une autre fibre (data race statique)",
                                                path.display, other.path.display
                                            ),
                                            format!("passage inout en conflit sur '{}'", path.display),
                                            format!("accès concurrent actif ici sur '{}'", other.path.display),
                                            "Partitionnez vos tranches de façon strictement disjointe (ex: '[0..3]' et '[3..6]') ou utilisez un 'Channel'."
                                        ),
                                        (ConcurrentAccessKind::Write, ConcurrentAccessKind::Read) => (
                                            format!(
                                                "conflit d'accès concurrent : la mutation 'inout' sur la projection '{}' dans une fibre 'spawn' chevauche la lecture concurrente ('ref') sur '{}' dans une autre fibre (data race statique)",
                                                path.display, other.path.display
                                            ),
                                            format!("mutation inout en conflit avec la lecture concurrente sur '{}'", path.display),
                                            format!("lecture concurrente active ici sur '{}'", other.path.display),
                                            "Synchronisez l'accès via un canal 'Channel' ou séparez les champs accédés de façon disjointe."
                                        ),
                                        (ConcurrentAccessKind::Read, ConcurrentAccessKind::Write) => (
                                            format!(
                                                "conflit d'accès concurrent : la référence de lecture ('ref') sur la projection '{}' dans une fibre 'spawn' chevauche la mutation concurrente ('inout') sur '{}' dans une autre fibre (data race statique)",
                                                path.display, other.path.display
                                            ),
                                            format!("lecture 'ref' en conflit avec la mutation concurrente sur '{}'", path.display),
                                            format!("mutation concurrente active ici sur '{}'", other.path.display),
                                            "Synchronisez l'accès via un canal 'Channel' ou séparez les champs accédés de façon disjointe."
                                        ),
                                        (ConcurrentAccessKind::Sink, _) | (_, ConcurrentAccessKind::Sink) => (
                                            format!(
                                                "transfert concurrent interdit : le transfert de propriété ('sink') sur la projection '{}' dans une fibre 'spawn' chevauche l'accès concurrent sur '{}' dans une autre fibre",
                                                path.display, other.path.display
                                            ),
                                            format!("transfert 'sink' en conflit sur '{}'", path.display),
                                            format!("accès concurrent actif ici sur '{}'", other.path.display),
                                            "Une valeur transférée par 'sink' ne peut être accédée simultanément par une autre fibre."
                                        ),
                                        _ => unreachable!(),
                                    };

                                self.diagnostics.push(
                                    Diagnostic::error(err_msg)
                                        .with_code("E0025")
                                        .with_primary_label(arg_span, primary_lbl)
                                        .with_secondary_label(other.span, secondary_lbl)
                                        .with_note("Deux fibres concurrentes ne peuvent pas emprunter simultanément des projections mémoires chevauchantes.")
                                        .with_help(help_msg),
                                );
                                return false;
                            }
                        }
                    }

                    self.concurrent_accesses.push(ConcurrentAccess {
                        path,
                        is_write: kind == ConcurrentAccessKind::Write,
                        kind,
                        spawn_id: cur_spawn,
                        span: arg_span,
                    });
                    return true;
                }
            }
        }
        true
    }

    /// Checks and records an `inout` borrow within a `spawn` fiber.
    #[allow(dead_code)]
    pub(crate) fn check_concurrent_inout(&mut self, inner: &Expr, arg_span: Span) -> bool {
        self.check_concurrent_arg(inner, arg_span, ConcurrentAccessKind::Write)
    }

    /// Recursively collects reference targets embedded in an expression.
    fn collect_contained_refs(&self, expr: &Expr) -> Vec<ContainedRef> {
        let mut refs = Vec::new();
        self.collect_contained_refs_rec(expr, &mut refs);
        refs
    }

    fn collect_contained_refs_rec(&self, expr: &Expr, out: &mut Vec<ContainedRef>) {
        match &expr.kind {
            ExprKind::Unary {
                op: UnaryOp::Ref,
                expr: inner,
            } => {
                if let Some((root_sym, _)) = extract_escape_root(inner) {
                    let is_projection = !matches!(&inner.kind, ExprKind::Ident(_));
                    out.push(ContainedRef {
                        target_var: root_sym,
                        ref_span: expr.span,
                        is_projection,
                    });
                }
            }
            ExprKind::Ident(sym) => {
                if let Some(info) = self.var_info.get(sym) {
                    for cr in &info.contained_refs {
                        out.push(cr.clone());
                    }
                }
            }
            ExprKind::FieldAccess { receiver, .. } => {
                if let Some((root_sym, _)) = extract_escape_root(receiver) {
                    if let Some(info) = self.var_info.get(&root_sym) {
                        for cr in &info.contained_refs {
                            let mut copy = cr.clone();
                            copy.is_projection = true;
                            out.push(copy);
                        }
                    }
                }
                self.collect_contained_refs_rec(receiver, out);
            }
            ExprKind::Index { receiver, index } => {
                if let Some((root_sym, _)) = extract_escape_root(receiver) {
                    if let Some(info) = self.var_info.get(&root_sym) {
                        for cr in &info.contained_refs {
                            let mut copy = cr.clone();
                            copy.is_projection = true;
                            out.push(copy);
                        }
                    }
                }
                self.collect_contained_refs_rec(receiver, out);
                self.collect_contained_refs_rec(index, out);
            }
            ExprKind::StructInit { fields, .. } => {
                for (_, val) in fields {
                    self.collect_contained_refs_rec(val, out);
                }
            }
            ExprKind::Call { callee, args } => {
                if let ExprKind::Ident(sym) = &callee.kind {
                    // Struct constructors (e.g. Container(item: ref x, id: 1))
                    if self.symbols.lookup_struct(sym).is_some() {
                        for arg in args {
                            self.collect_contained_refs_rec(&arg.value, out);
                        }
                    } else if let Some(fn_def) = self.symbols.lookup_function(sym) {
                        // Function call only propagates references if its return type contains references
                        if type_contains_ref(&fn_def.ret_ty) {
                            for arg in args {
                                self.collect_contained_refs_rec(&arg.value, out);
                            }
                        }
                    }
                }
            }
            ExprKind::Tuple(items) => {
                for item in items {
                    self.collect_contained_refs_rec(item, out);
                }
            }
            ExprKind::Array(elems) => {
                for elem in elems {
                    self.collect_contained_refs_rec(elem, out);
                }
            }
            ExprKind::ArrayRepeat(val, count) => {
                self.collect_contained_refs_rec(val, out);
                self.collect_contained_refs_rec(count, out);
            }
            ExprKind::If {
                cond,
                then_branch,
                else_branch,
            } => {
                self.collect_contained_refs_rec(cond, out);
                for s in &then_branch.stmts {
                    if let Stmt::Expr(e) = s {
                        self.collect_contained_refs_rec(e, out);
                    }
                }
                if let Some(e) = &then_branch.expr {
                    self.collect_contained_refs_rec(e, out);
                }
                if let Some(el) = else_branch {
                    self.collect_contained_refs_rec(el, out);
                }
            }
            ExprKind::IfLet {
                expr,
                guard,
                then_branch,
                else_branch,
                ..
            } => {
                self.collect_contained_refs_rec(expr, out);
                if let Some(g) = guard {
                    self.collect_contained_refs_rec(g, out);
                }
                for s in &then_branch.stmts {
                    if let Stmt::Expr(e) = s {
                        self.collect_contained_refs_rec(e, out);
                    }
                }
                if let Some(e) = &then_branch.expr {
                    self.collect_contained_refs_rec(e, out);
                }
                if let Some(el) = else_branch {
                    self.collect_contained_refs_rec(el, out);
                }
            }
            ExprKind::Block(blk) => {
                for s in &blk.stmts {
                    if let Stmt::Expr(e) = s {
                        self.collect_contained_refs_rec(e, out);
                    }
                }
                if let Some(e) = &blk.expr {
                    self.collect_contained_refs_rec(e, out);
                }
            }
            _ => {}
        }
    }

    fn check_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Let {
                pattern,
                init,
                else_block,
                span,
                ..
            } => {
                let bound = pattern.bound_variables();
                let is_arena = init.as_ref().is_some_and(is_arena_expr);
                let is_array_init = init.as_ref().is_some_and(|e| {
                    matches!(&e.kind, ExprKind::Array(_) | ExprKind::ArrayRepeat(..))
                });
                let is_compound_init = init.as_ref().is_some_and(|e| match &e.kind {
                    ExprKind::Array(_)
                    | ExprKind::ArrayRepeat(..)
                    | ExprKind::StructInit { .. }
                    | ExprKind::Tuple(_) => true,
                    ExprKind::Call { .. } => true,
                    ExprKind::Index { .. } => true,
                    ExprKind::Ident(s) => self.is_type_cow_candidate(s),
                    ExprKind::Unary {
                        op: UnaryOp::Sink,
                        expr: inner,
                    } => {
                        if let Some((s, _)) = extract_escape_root(inner) {
                            self.is_type_cow_candidate(&s)
                        } else {
                            false
                        }
                    }
                    _ => false,
                });

                for (sym, p_span) in &bound {
                    self.record_local_var(*sym, *p_span);
                    if is_array_init {
                        self.stack_arrays.insert(*sym, *p_span);
                    }
                    if is_compound_init {
                        if let Some(info) = self.var_info.get_mut(sym) {
                            info.is_compound = true;
                        }
                    }
                    let sym_str = INTERNER.resolve(sym);
                    if is_arena || sym_str.to_lowercase().contains("arena") {
                        if let Some(info) = self.var_info.get_mut(sym) {
                            info.alloc_kind = AllocKind::ArenaScoped;
                        }
                    }
                }
                self.check_pattern_ref_bindings(pattern, init.as_ref(), *span);
                if let Some(expr) = init {
                    // Track value sharing for Copy-on-Write analysis
                    if let ExprKind::Unary {
                        op: UnaryOp::Sink,
                        expr: inner,
                    } = &expr.kind
                    {
                        if let Some((consumed_sym, _)) = extract_escape_root(inner) {
                            self.remove_share(consumed_sym);
                        }
                    } else if let ExprKind::Ident(src_sym) = &expr.kind {
                        if self.is_type_cow_candidate(src_sym) {
                            for (bound_sym, _) in &bound {
                                self.record_share(*bound_sym, *src_sym);
                            }
                        }
                    } else if let Some((src_sym, _)) = extract_escape_root(expr) {
                        let is_inout_param = self
                            .var_info
                            .get(&src_sym)
                            .map(|v| v.origin == VarOrigin::Param(ParamMode::InOut))
                            .unwrap_or(false);

                        if !is_inout_param {
                            let is_range_slice = match &expr.kind {
                                ExprKind::Index { index, .. } => {
                                    matches!(index.kind, ExprKind::Range { .. })
                                }
                                _ => false,
                            };
                            if is_range_slice && self.is_type_cow_candidate(&src_sym) {
                                for (bound_sym, _) in &bound {
                                    self.record_share(*bound_sym, src_sym);
                                }
                            }
                        }
                    }

                    let refs = self.collect_contained_refs(expr);
                    if !refs.is_empty() {
                        for (sym, _) in &bound {
                            for r in &refs {
                                self.ref_dependencies
                                    .entry(*sym)
                                    .or_default()
                                    .push(r.target_var);
                            }
                            if let Some(info) = self.var_info.get_mut(sym) {
                                info.contained_refs.extend(refs.clone());
                            }
                        }
                        self.detect_and_handle_cycles();
                    }
                    self.check_expr(expr);
                    if let Some(&arena_sym) = self.arena_lambda_spans.get(&expr.span) {
                        for (bound_sym, _) in &bound {
                            self.arena_capturing_closures.insert(*bound_sym, arena_sym);
                        }
                    } else if let ExprKind::Ident(src_sym) = &expr.kind {
                        if let Some(&arena_sym) = self.arena_capturing_closures.get(src_sym) {
                            for (bound_sym, _) in &bound {
                                self.arena_capturing_closures.insert(*bound_sym, arena_sym);
                            }
                        }
                    }

                    if let Some(init_expr) = init {
                        if let ExprKind::StructInit { name, .. } = &init_expr.kind {
                            if let Some(&st_sym) = name.last() {
                                for (b, _) in &bound {
                                    self.var_struct_type.insert(*b, st_sym);
                                }
                            }
                        }
                    }

                    if self.current_func_is_comptime {
                        for (bound_sym, _) in &bound {
                            if is_arena || is_arena_symbol(bound_sym, self.symbols) {
                                self.comptime_isolated_arenas.insert(*bound_sym);
                            }
                            if let Some(var_sym) = self.symbols.lookup_variable(bound_sym) {
                                if is_recursive_type(&var_sym.ty, None, &mut HashSet::new()) {
                                    if let Some(e) = init {
                                        if is_arena_expr(e) {
                                            let arena_sym = extract_escape_root(e)
                                                .map(|(s, _)| s)
                                                .unwrap_or(*bound_sym);
                                            self.comptime_recursive_structs
                                                .insert(*bound_sym, arena_sym);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if let Some(eb) = else_block {
                    for s in &eb.stmts {
                        self.check_stmt(s);
                    }
                    if let Some(e) = &eb.expr {
                        self.check_expr(e);
                    }
                }
            }
            Stmt::Assign {
                target, val, span, ..
            } => {
                // Static detection of concurrent data race in spawn
                if self.spawn_depth > 0 {
                    if let Some((root_sym, root_span)) = extract_escape_root(target) {
                        if self.var_info.contains_key(&root_sym) {
                            let var_name = INTERNER.resolve(&root_sym);
                            let is_projection = !matches!(&target.kind, ExprKind::Ident(_));
                            let target_repr = format_projection_expr(target);

                            let error_msg = if is_projection {
                                format!(
                                    "mutation concurrente interdite : la projection scalaire '{}' sur la variable locale '{}' ne peut pas être modifiée au sein d'une fibre 'spawn' sans synchronisation atomique",
                                    target_repr, var_name
                                )
                            } else {
                                format!(
                                    "mutation concurrente interdite : la variable locale '{}' ne peut pas être modifiée au sein d'une fibre 'spawn' sans synchronisation atomique",
                                    var_name
                                )
                            };

                            let primary_label = if is_projection {
                                format!("mutation concurrente de '{}' dans spawn", target_repr)
                            } else {
                                format!("mutation concurrente de '{}' dans spawn", var_name)
                            };

                            self.diagnostics.push(
                                Diagnostic::error(error_msg)
                                    .with_code("E0025")
                                    .with_primary_label(*span, primary_label)
                                    .with_secondary_label(
                                        root_span,
                                        format!("'{}' appartient au cadre de pile parent", var_name),
                                    )
                                    .with_note("Les fibres partagent la mémoire de manière non-bloquante et interdisent les courses aux données statiques.")
                                    .with_help("Utilisez un canal 'Channel', un type atomique ou transférez la variable avec 'sink'."),
                            );
                        }
                    }
                }

                self.check_expr(target);
                self.check_expr(val);

                // Static detection of hidden Copy-on-Write in strict fn
                self.check_strict_cow_mutation(target, *span);

                if let Some((root_sym, _)) = extract_escape_root(target) {
                    if matches!(target.kind, ExprKind::Ident(_)) {
                        // Reassignment of whole variable with fresh value breaks old sharing
                        if !matches!(&val.kind, ExprKind::Ident(_)) {
                            self.remove_share(root_sym);
                        }
                    }
                }

                if is_arena_expr(val) {
                    if let Some((root_sym, _)) = extract_escape_root(target) {
                        if let Some(info) = self.var_info.get_mut(&root_sym) {
                            info.alloc_kind = AllocKind::ArenaScoped;
                        }
                        if self.current_func_is_comptime {
                            if let Some(var_sym) = self.symbols.lookup_variable(&root_sym) {
                                if is_recursive_type(&var_sym.ty, None, &mut HashSet::new()) {
                                    let arena_sym = extract_escape_root(val)
                                        .map(|(s, _)| s)
                                        .unwrap_or(root_sym);
                                    self.comptime_recursive_structs.insert(root_sym, arena_sym);
                                }
                            }
                        }
                    }
                }

                // Track reference assignment to variables or container fields
                let target_root = extract_escape_root(target).map(|(s, _)| s);
                let val_refs = self.collect_contained_refs(val);

                if let Some(recv_sym) = target_root {
                    if !val_refs.is_empty() {
                        for r in &val_refs {
                            self.ref_dependencies
                                .entry(recv_sym)
                                .or_default()
                                .push(r.target_var);
                        }
                        if let Some(info) = self.var_info.get_mut(&recv_sym) {
                            info.contained_refs.extend(val_refs);
                        }
                        self.detect_and_handle_cycles();
                    }
                }

                // Check direct ref assignment (e.g. child.parent = ref parent)
                if let ExprKind::Unary {
                    op: UnaryOp::Ref,
                    expr: ref_target,
                } = &val.kind
                {
                    self.handle_ref_assignment(target, ref_target, val.span);
                }

                if let ExprKind::Ident(target_sym) = &target.kind {
                    if let Some(&arena_sym) = self.arena_lambda_spans.get(&val.span) {
                        self.arena_capturing_closures.insert(*target_sym, arena_sym);
                    } else if let ExprKind::Ident(val_sym) = &val.kind {
                        if let Some(&arena_sym) = self.arena_capturing_closures.get(val_sym) {
                            self.arena_capturing_closures.insert(*target_sym, arena_sym);
                        }
                    }
                }
            }
            Stmt::AssignPattern {
                pattern,
                val,
                else_block,
                span,
            } => {
                self.check_pattern_ref_bindings(pattern, Some(val), *span);
                if self.spawn_depth > 0 {
                    for (root_sym, root_span) in pattern.bound_variables() {
                        if self.var_info.contains_key(&root_sym) {
                            let var_name = INTERNER.resolve(&root_sym);
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "mutation concurrente interdite : la variable locale '{}' ne peut pas être modifiée au sein d'une fibre 'spawn' sans synchronisation atomique",
                                    var_name
                                ))
                                .with_code("E0025")
                                .with_primary_label(*span, format!("mutation concurrente de '{}' dans spawn", var_name))
                                .with_secondary_label(
                                    root_span,
                                    format!("'{}' appartient au cadre de pile parent", var_name),
                                )
                                .with_note("Les fibres partagent la mémoire de manière non-bloquante et interdisent les courses aux données statiques.")
                                .with_help("Utilisez un canal 'Channel', un type atomique ou transférez la variable avec 'sink'."),
                            );
                        }
                    }
                }
                self.check_expr(val);
                if let Some(eb) = else_block {
                    for s in &eb.stmts {
                        self.check_stmt(s);
                    }
                    if let Some(e) = &eb.expr {
                        self.check_expr(e);
                    }
                }
            }
            Stmt::Expr(expr) => self.check_expr(expr),
            Stmt::Return(ret_expr, _) => {
                if let Some(expr) = ret_expr {
                    self.check_return_expr(expr);
                }
            }
            Stmt::Fail(expr, _) => self.check_expr(expr),
            Stmt::While { cond, body, .. } => {
                self.check_expr(cond);
                for s in &body.stmts {
                    self.check_stmt(s);
                }
                if let Some(e) = &body.expr {
                    self.check_expr(e);
                }
            }
            Stmt::WhileLet {
                pattern,
                expr,
                guard,
                body,
                span,
            } => {
                let bound = pattern.bound_variables();
                for (sym, p_span) in &bound {
                    self.record_local_var(*sym, *p_span);
                }
                self.check_pattern_ref_bindings(pattern, Some(expr), *span);
                self.check_expr(expr);
                if let Some(g) = guard {
                    self.check_expr(g);
                }
                for s in &body.stmts {
                    self.check_stmt(s);
                }
                if let Some(e) = &body.expr {
                    self.check_expr(e);
                }
            }
            Stmt::For { iterable, body, .. } => {
                self.check_expr(iterable);
                for s in &body.stmts {
                    self.check_stmt(s);
                }
                if let Some(e) = &body.expr {
                    self.check_expr(e);
                }
            }
            Stmt::Loop(body, _) => {
                for s in &body.stmts {
                    self.check_stmt(s);
                }
                if let Some(e) = &body.expr {
                    self.check_expr(e);
                }
            }
            Stmt::Defer(body, _) => {
                for s in &body.stmts {
                    self.check_stmt(s);
                }
            }
            Stmt::Break(_) | Stmt::Continue(_) => {}
        }
    }

    fn check_expr(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Unary {
                op: UnaryOp::Ref,
                expr: inner,
            } => {
                if self.spawn_depth > 0 {
                    if let Some((root_sym, root_span)) = extract_escape_root(inner) {
                        if let Some(info) = self.var_info.get(&root_sym) {
                            if info.alloc_kind == AllocKind::ArenaScoped {
                                let var_name = INTERNER.resolve(&root_sym);
                                self.diagnostics.push(
                                    Diagnostic::error(format!(
                                        "évasion d'arène interdite : emprunt générationnel 'ref' sur la variable d'arène '{}' interdit au sein d'une fibre 'spawn'",
                                        var_name
                                    ))
                                    .with_code("E0026")
                                    .with_primary_label(expr.span, format!("emprunt 'ref' sur l'arène '{}' dans spawn", var_name))
                                    .with_secondary_label(root_span, format!("'{}' appartient à l'arène privée du thread parent", var_name))
                                    .with_note("Les arènes mémoire pré-allouées sont strictement isolées par fibre/thread dans l'ordonnanceur M:N.")
                                    .with_help("Utilisez un canal 'Channel', un type atomique ou transférez la variable avec 'sink'."),
                                );
                            }
                        }
                    }
                    self.check_concurrent_arg(inner, expr.span, ConcurrentAccessKind::Read);
                }
                self.handle_ref_creation(inner, expr.span);
                self.check_expr(inner);
            }
            ExprKind::Unary {
                op: UnaryOp::Sink,
                expr: inner,
            } => {
                if self.spawn_depth > 0 {
                    self.check_concurrent_arg(inner, expr.span, ConcurrentAccessKind::Sink);
                }
                self.check_expr(inner);
            }
            ExprKind::Unary {
                op: UnaryOp::InOut,
                expr: inner,
            } => {
                if self.spawn_depth > 0 {
                    self.check_concurrent_arg(inner, expr.span, ConcurrentAccessKind::Write);
                }
                self.check_expr(inner);
            }
            ExprKind::Unary { expr: inner, .. } => {
                self.check_expr(inner);
            }
            ExprKind::Call { callee, args } => {
                self.check_expr(callee);
                for arg in args {
                    // Check for invalid inout passing or arena escape into concurrent spawn
                    if self.spawn_depth > 0 {
                        if let Some((root_sym, root_span)) = extract_escape_root(&arg.value) {
                            if let Some(info) = self.var_info.get(&root_sym) {
                                if info.alloc_kind == AllocKind::ArenaScoped {
                                    let var_name = INTERNER.resolve(&root_sym);
                                    self.diagnostics.push(
                                        Diagnostic::error(format!(
                                            "évasion d'arène interdite : la variable '{}' allouée dans une arène locale ne peut pas être transmise au sein d'une fibre 'spawn'",
                                            var_name
                                        ))
                                        .with_code("E0026")
                                        .with_primary_label(arg.value.span, format!("passage de la variable d'arène '{}' dans spawn", var_name))
                                        .with_secondary_label(root_span, format!("'{}' est allouée dans l'arène locale du thread parent", var_name))
                                        .with_note("Les arènes mémoire pré-allouées sont strictement isolées par fibre/thread dans l'ordonnanceur M:N pour garantir la localité de cache et l'absence de contention.")
                                        .with_help("Allouez sur le tas global, transférez la propriété avec 'sink' ou échangez des messages via un 'Channel'."),
                                    );
                                }
                            }
                        }

                        match &arg.value.kind {
                            ExprKind::Unary {
                                op: UnaryOp::InOut,
                                expr: inner,
                            } => {
                                self.check_concurrent_arg(
                                    inner,
                                    arg.value.span,
                                    ConcurrentAccessKind::Write,
                                );
                            }
                            ExprKind::Unary {
                                op: UnaryOp::Sink,
                                expr: inner,
                            } => {
                                self.check_concurrent_arg(
                                    inner,
                                    arg.value.span,
                                    ConcurrentAccessKind::Sink,
                                );
                            }
                            ExprKind::Unary {
                                op: UnaryOp::Ref,
                                expr: inner,
                            } => {
                                self.check_concurrent_arg(
                                    inner,
                                    arg.value.span,
                                    ConcurrentAccessKind::Read,
                                );
                            }
                            _ => {}
                        }
                    }
                    if let ExprKind::Unary {
                        op: UnaryOp::InOut,
                        expr: inner,
                    } = &arg.value.kind
                    {
                        self.check_strict_cow_mutation(inner, arg.value.span);
                    }
                    self.check_expr(&arg.value);
                }
            }
            ExprKind::MethodCall {
                receiver,
                method,
                args,
                ..
            } => {
                let rx_mode = self.method_receiver_mode(receiver, *method, expr.span);
                if rx_mode == ParamMode::InOut {
                    self.check_strict_cow_mutation(receiver, receiver.span);
                }
                if self.spawn_depth > 0 {
                    if rx_mode == ParamMode::InOut {
                        self.check_concurrent_arg(
                            receiver,
                            receiver.span,
                            ConcurrentAccessKind::Write,
                        );
                    } else if rx_mode == ParamMode::Sink {
                        self.check_concurrent_arg(
                            receiver,
                            receiver.span,
                            ConcurrentAccessKind::Sink,
                        );
                    }
                }
                self.check_expr(receiver);
                for arg in args {
                    if let ExprKind::Unary {
                        op: UnaryOp::InOut,
                        expr: inner,
                    } = &arg.value.kind
                    {
                        self.check_strict_cow_mutation(inner, arg.value.span);
                    }
                    if self.spawn_depth > 0 {
                        if let Some((root_sym, root_span)) = extract_escape_root(&arg.value) {
                            if let Some(info) = self.var_info.get(&root_sym) {
                                if info.alloc_kind == AllocKind::ArenaScoped {
                                    let var_name = INTERNER.resolve(&root_sym);
                                    self.diagnostics.push(
                                        Diagnostic::error(format!(
                                            "évasion d'arène interdite : la variable '{}' allouée dans une arène locale ne peut pas être transmise au sein d'une fibre 'spawn'",
                                            var_name
                                        ))
                                        .with_code("E0026")
                                        .with_primary_label(arg.value.span, format!("passage de la variable d'arène '{}' dans spawn", var_name))
                                        .with_secondary_label(root_span, format!("'{}' est allouée dans l'arène locale du thread parent", var_name))
                                        .with_note("Les arènes mémoire pré-allouées sont strictement isolées par fibre/thread dans l'ordonnanceur M:N pour garantir la localité de cache et l'absence de contention.")
                                        .with_help("Allouez sur le tas global, transférez la propriété avec 'sink' ou échangez des messages via un 'Channel'."),
                                    );
                                }
                            }
                        }

                        match &arg.value.kind {
                            ExprKind::Unary {
                                op: UnaryOp::InOut,
                                expr: inner,
                            } => {
                                self.check_concurrent_arg(
                                    inner,
                                    arg.value.span,
                                    ConcurrentAccessKind::Write,
                                );
                            }
                            ExprKind::Unary {
                                op: UnaryOp::Sink,
                                expr: inner,
                            } => {
                                self.check_concurrent_arg(
                                    inner,
                                    arg.value.span,
                                    ConcurrentAccessKind::Sink,
                                );
                            }
                            ExprKind::Unary {
                                op: UnaryOp::Ref,
                                expr: inner,
                            } => {
                                self.check_concurrent_arg(
                                    inner,
                                    arg.value.span,
                                    ConcurrentAccessKind::Read,
                                );
                            }
                            _ => {}
                        }
                    }
                    self.check_expr(&arg.value);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.check_expr(left);
                self.check_expr(right);
            }
            ExprKind::FieldAccess { receiver, .. } => self.check_expr(receiver),
            ExprKind::Index { receiver, index } => {
                self.check_expr(receiver);
                self.check_expr(index);
            }
            ExprKind::Array(elems) => {
                for elem in elems {
                    self.check_expr(elem);
                }
            }
            ExprKind::ArrayRepeat(val, count) => {
                self.check_expr(val);
                self.check_expr(count);
            }
            ExprKind::If {
                cond,
                then_branch,
                else_branch,
            } => {
                self.check_expr(cond);
                for s in &then_branch.stmts {
                    self.check_stmt(s);
                }
                if let Some(e) = &then_branch.expr {
                    self.check_expr(e);
                }
                if let Some(el) = else_branch {
                    self.check_expr(el);
                }
            }
            ExprKind::IfLet {
                pattern,
                expr,
                guard,
                then_branch,
                else_branch,
                ..
            } => {
                let bound = pattern.bound_variables();
                for (sym, p_span) in &bound {
                    self.record_local_var(*sym, *p_span);
                }
                self.check_pattern_ref_bindings(pattern, Some(expr), expr.span);
                self.check_expr(expr);
                if let Some(g) = guard {
                    self.check_expr(g);
                }
                for s in &then_branch.stmts {
                    self.check_stmt(s);
                }
                if let Some(e) = &then_branch.expr {
                    self.check_expr(e);
                }
                if let Some(el) = else_branch {
                    self.check_expr(el);
                }
            }
            ExprKind::Catch { expr, body, .. } => {
                self.check_expr(expr);
                for s in &body.stmts {
                    self.check_stmt(s);
                }
                if let Some(e) = &body.expr {
                    self.check_expr(e);
                }
            }
            ExprKind::StructInit { fields, .. } => {
                for (_, val) in fields {
                    self.check_expr(val);
                }
            }
            ExprKind::Tuple(items) => {
                for item in items {
                    self.check_expr(item);
                }
            }
            ExprKind::Block(blk) => {
                for s in &blk.stmts {
                    self.check_stmt(s);
                }
                if let Some(e) = &blk.expr {
                    self.check_expr(e);
                }
            }
            ExprKind::Lambda { params, body, .. } => {
                let mut declared = HashSet::new();
                for p in params {
                    declared.insert(p.name);
                }
                let mut free_symbols = HashSet::new();
                collect_free_identifiers_in_block(body, &mut declared, &mut free_symbols);

                let arena_cap = free_symbols.iter().find(|sym| {
                    self.var_info
                        .get(sym)
                        .map(|i| i.alloc_kind == AllocKind::ArenaScoped)
                        .unwrap_or(false)
                        || is_arena_symbol(sym, self.symbols)
                });

                if let Some(&arena_sym) = arena_cap {
                    let arena_name = INTERNER.resolve(&arena_sym);
                    self.arena_lambda_spans.insert(expr.span, arena_sym);

                    if self.current_func_is_strict {
                        // Strict zero-heap verification for remaining captures
                        for sym in &free_symbols {
                            if *sym != arena_sym {
                                let is_c_arena = self
                                    .var_info
                                    .get(sym)
                                    .map(|i| i.alloc_kind == AllocKind::ArenaScoped)
                                    .unwrap_or(false)
                                    || is_arena_symbol(sym, self.symbols);

                                if !is_c_arena {
                                    let c_name = INTERNER.resolve(sym);
                                    if self.stack_arrays.contains_key(sym) {
                                        self.diagnostics.push(
                                            Diagnostic::error(format!(
                                                "violation du mode strict : la clôture capture le tableau de pile locale '{}' en dehors de l'arène locale '{}'",
                                                c_name, arena_name
                                            ))
                                            .with_code("E0020")
                                            .with_primary_label(
                                                expr.span,
                                                format!("capture du tableau de pile '{}' sans allocation dans l'arène locale", c_name),
                                            )
                                            .with_note("En mode strict zéro-heap, les structures de données capturées doivent être allouées dans l'arène pré-allouée.")
                                            .with_help("Allouez le tableau dans l'arène pré-allouée ou transmettez-le par tranche 'Slice' en paramètre."),
                                        );
                                    } else if let Some(info) = self.var_info.get(sym) {
                                        if info.is_compound {
                                            self.diagnostics.push(
                                                Diagnostic::error(format!(
                                                    "violation du mode strict : la clôture capture la variable locale complexe '{}' en dehors de l'arène locale '{}'",
                                                    c_name, arena_name
                                                ))
                                                .with_code("E0020")
                                                .with_primary_label(
                                                    expr.span,
                                                    format!("capture de la structure '{}' risquant une promotion sur le tas", c_name),
                                                )
                                                .with_note("En mode strict zéro-heap, toutes les captures composées doivent résider dans l'arène pré-allouée ou être des scalaires directs.")
                                                .with_help("Allouez cette structure dans l'arène pré-allouée ou passez-la par référence explicite en paramètre."),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if self.spawn_depth > 0 {
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "évasion d'arène interdite : clôture capturant l'arène locale '{}' au sein d'une fibre 'spawn'",
                                arena_name
                            ))
                            .with_code("E0026")
                            .with_primary_label(
                                expr.span,
                                format!("clôture liée à l'arène locale '{}' dans spawn", arena_name),
                            )
                            .with_note("Les arènes mémoire pré-allouées sont strictement isolées par fibre/thread dans l'ordonnanceur M:N pour garantir la localité de cache et l'absence de contention.")
                            .with_help("Exécutez la clôture de manière synchrone sur le thread courant ou transférez les données par un 'Channel'."),
                        );
                    }
                } else if self.current_func_is_strict {
                    // Check if non-arena local variables are captured
                    let captured_locals: Vec<Symbol> = free_symbols
                        .iter()
                        .filter(|sym| self.var_info.contains_key(sym))
                        .copied()
                        .collect();
                    if !captured_locals.is_empty() {
                        let cap_names: Vec<String> = captured_locals
                            .iter()
                            .map(|c| INTERNER.resolve(c))
                            .collect();
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "violation du mode strict : la clôture capture des variables locales ('{}') provoquant une promotion implicite vers le tas interdite dans une fonction 'strict fn'",
                                cap_names.join(", ")
                            ))
                            .with_code("E0020")
                            .with_primary_label(
                                expr.span,
                                "capture d'environnement local provoquant une promotion implicite sur le tas",
                            )
                            .with_note("Le mode strict impose une exécution zéro-heap déterministe. Les clôtures avec capture d'environnement dynamique sont interdites.")
                            .with_help("Utilisez des fonctions pures sans capture ou opérez dans une 'Arena' pré-allouée."),
                        );
                    }
                }
                for s in &body.stmts {
                    self.check_stmt(s);
                }
                if let Some(e) = &body.expr {
                    self.check_expr(e);
                }
            }
            ExprKind::Spawn(inner) => {
                let prev_depth = self.spawn_depth;
                let prev_spawn_id = self.current_spawn_id;
                let spawn_id = self.spawn_counter;
                self.spawn_counter += 1;
                self.spawn_depth += 1;
                self.current_spawn_id = Some(spawn_id);
                self.check_expr(inner);
                self.spawn_depth = prev_depth;
                self.current_spawn_id = prev_spawn_id;
            }
            ExprKind::Comptime(inner) => self.check_expr(inner),
            ExprKind::Range {
                start, end, step, ..
            } => {
                if let Some(s) = start {
                    self.check_expr(s);
                }
                if let Some(e) = end {
                    self.check_expr(e);
                }
                if let Some(st) = step {
                    self.check_expr(st);
                }
            }
            ExprKind::InterpolatedString(parts) => {
                for part in parts {
                    self.check_expr(part);
                }
            }
            ExprKind::Match { expr: target, arms } => {
                self.check_expr(target);
                for arm in arms {
                    let bound = arm.pattern.bound_variables();
                    for (sym, p_span) in &bound {
                        self.record_local_var(*sym, *p_span);
                    }
                    self.check_pattern_ref_bindings(&arm.pattern, Some(target), arm.span);
                    if let Some(guard) = &arm.guard {
                        self.check_expr(guard);
                    }
                    self.check_expr(&arm.body);
                }
            }
            ExprKind::Select { arms } => {
                for arm in arms {
                    if let Some(chan) = &arm.channel {
                        self.check_expr(chan);
                    }
                    self.check_expr(&arm.body);
                }
            }
            ExprKind::Ident(sym) if self.spawn_depth > 0 => {
                if let Some(&arena_sym) = self.arena_capturing_closures.get(sym) {
                    let closure_name = INTERNER.resolve(sym);
                    let arena_name = INTERNER.resolve(&arena_sym);
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "évasion d'arène interdite : la clôture '{}' capturant l'arène locale '{}' ne peut pas être transmise au sein d'une fibre 'spawn'",
                            closure_name, arena_name
                        ))
                        .with_code("E0026")
                        .with_primary_label(
                            expr.span,
                            format!("transmission interdite de la clôture '{}' liée à une arène locale dans spawn", closure_name),
                        )
                        .with_secondary_label(
                            self.var_info.get(&arena_sym).map(|i| i.defined_span).unwrap_or(expr.span),
                            format!("'{}' appartient à l'arène privée du thread parent", arena_name),
                        )
                        .with_note("Les arènes mémoire pré-allouées sont strictement isolées par fibre/thread dans l'ordonnanceur M:N pour garantir la localité de cache et l'absence de contention.")
                        .with_help("Exécutez la clôture de manière synchrone sur le thread courant ou transférez les données par un 'Channel'."),
                    );
                }
                if let Some(info) = self.var_info.get(sym) {
                    if info.alloc_kind == AllocKind::ArenaScoped {
                        let var_name = INTERNER.resolve(sym);
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "évasion d'arène interdite : la variable '{}' allouée dans une arène locale ne peut pas être capturée au sein d'une fibre 'spawn'",
                                var_name
                            ))
                            .with_code("E0026")
                            .with_primary_label(expr.span, format!("capture interdite de la variable d'arène '{}' dans spawn", var_name))
                            .with_secondary_label(info.defined_span, format!("'{}' est allouée dans l'arène locale du thread parent", var_name))
                            .with_note("Les arènes mémoire pré-allouées sont strictement isolées par fibre/thread dans l'ordonnanceur M:N pour garantir la localité de cache et l'absence de contention.")
                            .with_help("Allouez sur le tas global, transférez la propriété avec 'sink' ou échangez des messages via un 'Channel'."),
                        );
                    }
                }
            }
            _ => {}
        }
    }

    fn check_pattern_ref_bindings(
        &mut self,
        pattern: &Pattern,
        source_expr: Option<&Expr>,
        _pat_span: Span,
    ) {
        let refs = pattern.ref_bindings();
        if refs.is_empty() {
            return;
        }

        for (bound_sym, b_span) in refs {
            if self.current_func_is_strict {
                self.diagnostics.push(
                    Diagnostic::error("violation du mode strict : les références générationnelles ('ref') dans les motifs sont interdites dans une fonction 'strict fn'")
                        .with_code("E0020")
                        .with_primary_label(b_span, "emprunt 'ref' dans un motif interdit en mode strict")
                        .with_secondary_label(self.current_func_span, "cette fonction est annotée 'strict fn'")
                        .with_note("Le mode strict garantit l'absence totale d'allocation sur le tas et de références indirectes.")
                        .with_help("Utilisez des liaisons par valeur directe ou des projections 'inout'."),
                );
            }

            if let Some(src) = source_expr {
                if let Some((root_sym, root_span)) = extract_escape_root(src) {
                    if self.spawn_depth > 0 {
                        if let Some(root_info) = self.var_info.get(&root_sym) {
                            if root_info.origin == VarOrigin::Local {
                                let var_name = INTERNER.resolve(&root_sym);
                                self.diagnostics.push(
                                    Diagnostic::error(format!(
                                        "course aux données concurrente : emprunt générationnel 'ref' sur la variable locale '{}' interdit au sein d'une fibre 'spawn'",
                                        var_name
                                    ))
                                    .with_code("E0025")
                                    .with_primary_label(b_span, format!("emprunt 'ref' sur '{}' dans spawn", var_name))
                                    .with_secondary_label(root_span, format!("'{}' appartient au cadre de pile parent", var_name))
                                    .with_note("Les fibres partagent la mémoire de manière non-bloquante et interdisent les courses aux données statiques.")
                                    .with_help("Utilisez un canal 'Channel', un type atomique ou transférez la variable avec 'sink'."),
                                );
                            }
                        }
                    }

                    self.ref_dependencies
                        .entry(bound_sym)
                        .or_default()
                        .push(root_sym);
                    if let Some(info) = self.var_info.get_mut(&bound_sym) {
                        info.contained_refs.push(ContainedRef {
                            target_var: root_sym,
                            ref_span: b_span,
                            is_projection: true,
                        });
                    }
                    if let Some(root_info) = self.var_info.get_mut(&root_sym) {
                        root_info.alloc_kind = AllocKind::HeapGenerational;
                    }
                }
            }
        }
        self.detect_and_handle_cycles();
    }

    fn handle_ref_creation(&mut self, target: &Expr, span: Span) {
        if self.current_func_is_strict {
            self.diagnostics.push(
                Diagnostic::error("violation du mode strict : les références générationnelles ('ref') sont interdites dans une fonction 'strict fn'")
                    .with_code("E0020")
                    .with_primary_label(span, "création de 'ref' interdite en mode strict")
                    .with_secondary_label(self.current_func_span, "cette fonction est annotée 'strict fn'")
                    .with_note("Le mode strict garantit l'absence totale d'allocation sur le tas et de références indirectes.")
                    .with_help("Utilisez des projections directes 'in' ou 'inout' sur la pile.")
            );
        }

        if let Some((root_sym, _)) = extract_escape_root(target) {
            if let Some(info) = self.var_info.get_mut(&root_sym) {
                // Mark variable or container as requiring generational slab header
                info.alloc_kind = AllocKind::HeapGenerational;
            }
        }
    }

    fn handle_ref_assignment(&mut self, receiver: &Expr, ref_target: &Expr, span: Span) {
        if self.current_func_is_strict {
            self.diagnostics.push(
                Diagnostic::error("violation du mode strict : assignation de référence 'ref' interdite en mode strict")
                    .with_code("E0020")
                    .with_primary_label(span, "assignation de 'ref' interdite")
            );
        }

        let recv_root = extract_escape_root(receiver).map(|(s, _)| s);
        let target_root = extract_escape_root(ref_target).map(|(s, _)| s);

        if let (Some(recv), Some(tgt)) = (recv_root, target_root) {
            self.ref_dependencies.entry(recv).or_default().push(tgt);
            self.detect_and_handle_cycles();
        }

        if let Some((tgt_sym, _)) = extract_escape_root(ref_target) {
            if let Some(info) = self.var_info.get_mut(&tgt_sym) {
                info.alloc_kind = AllocKind::HeapGenerational;
            }
        }
    }

    fn detect_and_handle_cycles(&mut self) {
        let nodes: Vec<Symbol> = self.ref_dependencies.keys().copied().collect();
        for start_node in nodes {
            let mut visited = Vec::new();
            if self.has_cycle(start_node, start_node, &mut visited) {
                // Promote all participating nodes in the cycle to HeapGenerational
                for sym in &visited {
                    if let Some(info) = self.var_info.get_mut(sym) {
                        info.alloc_kind = AllocKind::HeapGenerational;
                    }
                }

                if self.current_func_is_strict {
                    let names: Vec<String> = visited.iter().map(|s| INTERNER.resolve(s)).collect();
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "violation du mode strict : graphe d'objets cyclique ('{}') interdit en mode strict",
                            names.join(" -> ")
                        ))
                        .with_code("E0020")
                        .with_primary_label(
                            self.current_func_span,
                            "les graphes cycliques par référence 'ref' sont interdits dans une fonction 'strict fn'",
                        )
                        .with_note("Le mode strict impose une hiérarchie de pile stricte sans cycles de pointeurs.")
                        .with_help("Allouez les graphes cycliques dans une arène ou utilisez des indices entiers."),
                    );
                }
                break;
            }
        }
    }

    fn has_cycle(&self, current: Symbol, target: Symbol, visited: &mut Vec<Symbol>) -> bool {
        visited.push(current);
        if let Some(neighbors) = self.ref_dependencies.get(&current) {
            for &next in neighbors {
                if next == target && visited.len() >= 2 {
                    return true;
                }
                if !visited.contains(&next) && self.has_cycle(next, target, visited) {
                    return true;
                }
            }
        }
        visited.pop();
        false
    }

    fn check_return_expr(&mut self, expr: &Expr) {
        self.check_expr(expr);

        // Comptime Escape Checks: isolated arena escape for recursive structures and mutable closures
        if self.current_func_is_comptime {
            // 1. Direct return of lambda capturing isolated arena
            if let Some(&arena_sym) = self.arena_lambda_spans.get(&expr.span) {
                let arena_name = INTERNER.resolve(&arena_sym);
                self.diagnostics.push(
                    Diagnostic::error(format!(
                        "violation d'évasion comptime : tentative d'évasion d'une fermeture mutable capturant l'arène isolée '{}' hors du contexte comptime",
                        arena_name
                    ))
                    .with_code("E0029")
                    .with_primary_label(
                        expr.span,
                        format!("retour d'une fermeture mutable liée à l'arène isolée '{}' interdite en comptime", arena_name),
                    )
                    .with_note("Les arènes isolées à la compilation sont détruites à la fin de l'évaluation comptime.")
                    .with_help("Appliquez la fermeture directement au sein du contexte comptime ou retournez une valeur pure sérialisable."),
                );
            }

            // 2. Return of variable holding a closure capturing isolated arena
            if let ExprKind::Ident(sym) = &expr.kind {
                if let Some(&arena_sym) = self.arena_capturing_closures.get(sym) {
                    let closure_name = INTERNER.resolve(sym);
                    let arena_name = INTERNER.resolve(&arena_sym);
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "violation d'évasion comptime : tentative d'évasion d'une fermeture mutable '{}' capturant l'arène isolée '{}' hors du contexte comptime",
                            closure_name, arena_name
                        ))
                        .with_code("E0029")
                        .with_primary_label(
                            expr.span,
                            format!("retour de la fermeture mutable '{}' liée à l'arène isolée '{}' interdite en comptime", closure_name, arena_name),
                        )
                        .with_note("Les arènes isolées et les fermetures mutables qui les capturent ne peuvent pas franchir la frontière de l'évaluation comptime.")
                        .with_help("Appliquez la fermeture directement au sein du contexte comptime ou retournez une valeur pure sérialisable."),
                    );
                }
            }

            // 3. Return of recursive structure allocated in isolated arena
            if let Some((root_sym, _)) = extract_escape_root(expr) {
                let is_recursive = self
                    .symbols
                    .lookup_variable(&root_sym)
                    .map(|v| is_recursive_type(&v.ty, None, &mut HashSet::new()))
                    .unwrap_or(false)
                    || self
                        .var_struct_type
                        .get(&root_sym)
                        .is_some_and(|&st| self.is_recursive_struct_symbol(st));
                let is_arena_allocated = self
                    .var_info
                    .get(&root_sym)
                    .map(|v| v.alloc_kind == AllocKind::ArenaScoped)
                    .unwrap_or(false)
                    || self.comptime_recursive_structs.contains_key(&root_sym)
                    || !self.comptime_isolated_arenas.is_empty();

                if is_recursive && is_arena_allocated {
                    let struct_name = INTERNER.resolve(&root_sym);
                    let arena_name = self
                        .comptime_recursive_structs
                        .get(&root_sym)
                        .or_else(|| self.comptime_isolated_arenas.iter().next())
                        .map(|s| INTERNER.resolve(s))
                        .unwrap_or_else(|| "isolée".to_string());
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "violation d'évasion comptime : tentative d'évasion de la structure récursive '{}' allouée dans l'arène isolée '{}' hors du contexte comptime",
                            struct_name, arena_name
                        ))
                        .with_code("E0028")
                        .with_primary_label(
                            expr.span,
                            format!("retour de la structure récursive '{}' liée à l'arène isolée '{}' interdite en comptime", struct_name, arena_name),
                        )
                        .with_note("Les arènes isolées à la compilation sont détruites à l'issue de l'évaluation comptime. Les structures récursives contenant des pointeurs vers une arène isolée ne peuvent pas franchir la frontière comptime/runtime.")
                        .with_help("Copiez la structure par valeur dans un type sans pointeurs ou évaluez-la dynamiquement à l'exécution."),
                    );
                }
            }
        }

        // Strict Mode: Check for illegal heap promotion, arena closure escape, or slice escape
        if self.current_func_is_strict {
            // 1. Direct return of lambda capturing local arena
            if let Some(&arena_sym) = self.arena_lambda_spans.get(&expr.span) {
                let arena_name = INTERNER.resolve(&arena_sym);
                self.diagnostics.push(
                    Diagnostic::error(format!(
                        "violation du mode strict : tentative d'évasion d'une clôture capturant l'arène locale '{}' hors du cadre de pile de la fonction",
                        arena_name
                    ))
                    .with_code("E0020")
                    .with_primary_label(
                        expr.span,
                        format!("retour d'une clôture liée à l'arène locale '{}' expirant avec la fonction", arena_name),
                    )
                    .with_note("Les arènes locales et leurs clôtures associées sont détruites à la fin du cadre de fonction pour garantir le déterminisme zéro-heap.")
                    .with_help("Exécutez la clôture localement ou allouez le résultat dans une arène transmise par le contexte appelant."),
                );
            }

            // 2. Return of variable holding a closure capturing local arena
            if let ExprKind::Ident(sym) = &expr.kind {
                if let Some(&arena_sym) = self.arena_capturing_closures.get(sym) {
                    let closure_name = INTERNER.resolve(sym);
                    let arena_name = INTERNER.resolve(&arena_sym);
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "violation du mode strict : tentative d'évasion de la clôture '{}' capturant l'arène locale '{}' hors du cadre de pile de la fonction",
                            closure_name, arena_name
                        ))
                        .with_code("E0020")
                        .with_primary_label(
                            expr.span,
                            format!("retour de la clôture '{}' liée à l'arène locale '{}' expirant avec la fonction", closure_name, arena_name),
                        )
                        .with_note("Les arènes locales et leurs clôtures associées sont détruites à la fin du cadre de fonction pour garantir le déterminisme zéro-heap.")
                        .with_help("Exécutez la clôture localement ou transmettez l'arène depuis l'appelant."),
                    );
                }
            }

            if let Some((root_sym, _)) = extract_escape_root(expr) {
                if let Some(arr_span) = self.stack_arrays.get(&root_sym) {
                    let is_slice_or_proj = matches!(
                        &expr.kind,
                        ExprKind::Index { .. }
                            | ExprKind::FieldAccess { .. }
                            | ExprKind::Unary {
                                op: UnaryOp::Ref,
                                ..
                            }
                    );
                    if is_slice_or_proj {
                        let var_name = INTERNER.resolve(&root_sym);
                        self.diagnostics.push(
                            Diagnostic::error(format!(
                                "violation du mode strict : tentative de promotion implicite vers le tas interdite : la tranche retournée pointe vers le tableau de pile locale '{}'",
                                var_name
                            ))
                            .with_code("E0020")
                            .with_primary_label(
                                expr.span,
                                format!("retour de tranche pointant vers le tableau de pile '{}' expirant avec la fonction", var_name),
                            )
                            .with_secondary_label(
                                *arr_span,
                                format!("'{}' est alloué sur le cadre de pile locale", var_name),
                            )
                            .with_note("Le mode strict interdit la promotion implicite de pointeurs de pile vers le tas.")
                            .with_help("Retournez le tableau par valeur '[T; N]' ou allouez le tampon dans une 'Arena' pré-allouée."),
                        );
                    }
                }
            }
        }

        // Case 1: Returning a direct reference `ref target` or `ref target.field`
        if let ExprKind::Unary {
            op: UnaryOp::Ref,
            expr: inner,
        } = &expr.kind
        {
            if let Some((root_sym, _)) = extract_escape_root(inner) {
                let var_name = INTERNER.resolve(&root_sym);
                if let Some(info) = self.var_info.get_mut(&root_sym) {
                    let is_projection = !matches!(&inner.kind, ExprKind::Ident(_));
                    let inner_repr = format_projection_expr(inner);

                    match info.origin {
                        VarOrigin::Local => {
                            info.escape_status = EscapeStatus::EscapesFunction;
                            let msg = if is_projection {
                                format!(
                                    "échappement illégal : la référence pointe vers une projection scalaire '{}' de la variable locale de pile '{}'",
                                    inner_repr, var_name
                                )
                            } else {
                                format!(
                                    "échappement illégal : la référence 'ref {}' pointe vers une variable locale de la pile",
                                    var_name
                                )
                            };
                            let primary_label = if is_projection {
                                format!(
                                    "la référence vers la projection scalaire '{}' s'échappe de la fonction",
                                    inner_repr
                                )
                            } else {
                                format!("la référence vers '{}' s'échappe de la fonction", var_name)
                            };

                            self.diagnostics.push(
                                Diagnostic::error(msg)
                                    .with_code("E0021")
                                    .with_primary_label(expr.span, primary_label)
                                    .with_secondary_label(
                                        info.defined_span,
                                        format!("'{}' est allouée sur la pile locale de cette fonction", var_name),
                                    )
                                    .with_note("La mémoire de la pile locale est libérée dès le retour de la fonction.")
                                    .with_help("Ne retournez pas de référence vers une variable locale ou ses champs dont la durée de vie expire avec la pile."),
                            );
                        }
                        VarOrigin::Param(ParamMode::In) => {
                            let msg = if is_projection {
                                format!(
                                    "échappement illégal : conservation interdite d'une référence issue de la projection '{}' du paramètre 'in {}'",
                                    inner_repr, var_name
                                )
                            } else {
                                format!(
                                    "échappement illégal : conservation interdite d'une référence issue du paramètre 'in {}'",
                                    var_name
                                )
                            };
                            self.diagnostics.push(
                                Diagnostic::error(msg)
                                    .with_code("E0021")
                                    .with_primary_label(
                                        expr.span,
                                        format!("la référence issue du paramètre 'in {}' ne peut pas s'échapper de la fonction", var_name),
                                    )
                                    .with_secondary_label(
                                        info.defined_span,
                                        format!("paramètre '{}' déclaré en mode 'in'", var_name),
                                    )
                                    .with_note("Les paramètres en mode 'in' sont des projections en lecture seule à durée de vie restreinte.")
                                    .with_help("Passez la structure en mode 'sink' pour en transférer la propriété ou retournez une valeur copiée."),
                            );
                        }
                        _ => {}
                    }
                }
            }
            return;
        }

        // Case 2: Returning an identifier of a local container/variable holding local references
        if let ExprKind::Ident(sym) = &expr.kind {
            if let Some(info) = self.var_info.get(sym) {
                let var_name = INTERNER.resolve(sym);
                for cr in &info.contained_refs {
                    if let Some(target_info) = self.var_info.get(&cr.target_var) {
                        if target_info.origin == VarOrigin::Local {
                            let target_name = INTERNER.resolve(&cr.target_var);
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "échappement illégal : le conteneur '{}' contient une référence vers la variable locale de pile '{}' dont la durée de vie expire avec la pile",
                                    var_name, target_name
                                ))
                                .with_code("E0021")
                                .with_primary_label(
                                    expr.span,
                                    format!("le conteneur '{}' détenant une référence locale s'échappe de la fonction", var_name),
                                )
                                .with_secondary_label(
                                    target_info.defined_span,
                                    format!("'{}' est allouée sur la pile locale", target_name),
                                )
                                .with_note("Les conteneurs sur la pile ne peuvent pas laisser échapper des références vers des variables du cadre de pile courant.")
                                .with_help("Allouez les données ciblées dans une arène persistante ou transférez les valeurs par copie."),
                            );
                            break;
                        }
                    }
                }
            }
            return;
        }

        // Case 3: Returning a scalar projection (field access or index) that resolves to a local reference
        if matches!(
            &expr.kind,
            ExprKind::FieldAccess { .. } | ExprKind::Index { .. }
        ) {
            if let Some((root_sym, _)) = extract_escape_root(expr) {
                if let Some(root_info) = self.var_info.get(&root_sym) {
                    let root_name = INTERNER.resolve(&root_sym);
                    let proj_repr = format_projection_expr(expr);
                    for cr in &root_info.contained_refs {
                        if let Some(target_info) = self.var_info.get(&cr.target_var) {
                            if target_info.origin == VarOrigin::Local {
                                let target_name = INTERNER.resolve(&cr.target_var);
                                self.diagnostics.push(
                                    Diagnostic::error(format!(
                                        "échappement illégal : la projection scalaire '{}' sur '{}' propage une référence vers la variable locale de pile '{}'",
                                        proj_repr, root_name, target_name
                                    ))
                                    .with_code("E0021")
                                    .with_primary_label(
                                        expr.span,
                                        format!("projection scalaire déréférençant '{}' s'échappant de la fonction", target_name),
                                    )
                                    .with_secondary_label(
                                        target_info.defined_span,
                                        format!("'{}' est allouée sur la pile locale", target_name),
                                    )
                                    .with_help("Ne retournez pas de projection scalaire contenant des références vers des variables locales."),
                                );
                                break;
                            }
                        }
                    }
                }
            }
            return;
        }

        // Case 4: Returning an inline literal container (StructInit, Tuple, Array, struct constructor) holding local references
        let is_candidate_container = match &expr.kind {
            ExprKind::StructInit { .. }
            | ExprKind::Tuple(_)
            | ExprKind::Array(_)
            | ExprKind::ArrayRepeat(..) => true,
            ExprKind::Call { callee, .. } => {
                if let ExprKind::Ident(sym) = &callee.kind {
                    self.symbols.lookup_struct(sym).is_some()
                        || self
                            .symbols
                            .lookup_function(sym)
                            .map(|f| type_contains_ref(&f.ret_ty))
                            .unwrap_or(false)
                } else {
                    false
                }
            }
            _ => false,
        };

        if !is_candidate_container {
            return;
        }

        let direct_refs = self.collect_contained_refs(expr);
        for cr in &direct_refs {
            if let Some(target_info) = self.var_info.get(&cr.target_var) {
                if target_info.origin == VarOrigin::Local {
                    let target_name = INTERNER.resolve(&cr.target_var);
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "échappement illégal : le conteneur temporaire s'échappe en détenant une référence vers la variable locale de pile '{}'",
                            target_name
                        ))
                        .with_code("E0021")
                        .with_primary_label(
                            expr.span,
                            format!("conteneur temporaire détenant une référence vers '{}'", target_name),
                        )
                        .with_secondary_label(
                            target_info.defined_span,
                            format!("'{}' est allouée sur la pile locale", target_name),
                        )
                        .with_help("Ne créez pas de conteneurs temporaires retournés avec des références vers la pile locale."),
                    );
                    break;
                }
            }
        }
    }
}

/// Recursively collect all free identifiers in an AST block that are not locally declared within it.
fn collect_free_identifiers_in_block(
    block: &ifa_ast::Block,
    declared: &mut HashSet<Symbol>,
    free: &mut HashSet<Symbol>,
) {
    let mut scope_declared = declared.clone();
    for stmt in &block.stmts {
        collect_free_identifiers_in_stmt(stmt, &mut scope_declared, free);
    }
    if let Some(e) = &block.expr {
        collect_free_identifiers_in_expr(e, &scope_declared, free);
    }
}

fn collect_free_identifiers_in_stmt(
    stmt: &Stmt,
    declared: &mut HashSet<Symbol>,
    free: &mut HashSet<Symbol>,
) {
    match stmt {
        Stmt::Let {
            pattern,
            init,
            else_block,
            ..
        } => {
            if let Some(e) = init {
                collect_free_identifiers_in_expr(e, declared, free);
            }
            if let Some(eb) = else_block {
                collect_free_identifiers_in_block(eb, declared, free);
            }
            for (sym, _) in pattern.bound_variables() {
                declared.insert(sym);
            }
        }
        Stmt::Assign { target, val, .. } => {
            collect_free_identifiers_in_expr(target, declared, free);
            collect_free_identifiers_in_expr(val, declared, free);
        }
        Stmt::AssignPattern {
            pattern,
            val,
            else_block,
            ..
        } => {
            collect_free_identifiers_in_expr(val, declared, free);
            if let Some(eb) = else_block {
                collect_free_identifiers_in_block(eb, declared, free);
            }
            for (sym, _) in pattern.bound_variables() {
                declared.insert(sym);
            }
        }
        Stmt::Expr(e) | Stmt::Fail(e, _) => collect_free_identifiers_in_expr(e, declared, free),
        Stmt::Return(e, _) => {
            if let Some(expr) = e {
                collect_free_identifiers_in_expr(expr, declared, free);
            }
        }
        Stmt::Defer(b, _) | Stmt::Loop(b, _) => {
            collect_free_identifiers_in_block(b, declared, free)
        }
        Stmt::While { cond, body, .. } => {
            collect_free_identifiers_in_expr(cond, declared, free);
            collect_free_identifiers_in_block(body, declared, free);
        }
        Stmt::WhileLet {
            pattern,
            expr,
            guard,
            body,
            ..
        } => {
            collect_free_identifiers_in_expr(expr, declared, free);
            let mut loop_declared = declared.clone();
            for (sym, _) in pattern.bound_variables() {
                loop_declared.insert(sym);
            }
            if let Some(g) = guard {
                collect_free_identifiers_in_expr(g, &loop_declared, free);
            }
            collect_free_identifiers_in_block(body, &mut loop_declared, free);
        }
        Stmt::For {
            pattern,
            iterable,
            body,
            ..
        } => {
            collect_free_identifiers_in_expr(iterable, declared, free);
            let mut loop_declared = declared.clone();
            for (sym, _) in pattern.bound_variables() {
                loop_declared.insert(sym);
            }
            collect_free_identifiers_in_block(body, &mut loop_declared, free);
        }
        Stmt::Break(_) | Stmt::Continue(_) => {}
    }
}

fn collect_free_identifiers_in_expr(
    expr: &Expr,
    declared: &HashSet<Symbol>,
    free: &mut HashSet<Symbol>,
) {
    match &expr.kind {
        ExprKind::Ident(sym) => {
            if !declared.contains(sym) {
                free.insert(*sym);
            }
        }
        ExprKind::Binary { left, right, .. } => {
            collect_free_identifiers_in_expr(left, declared, free);
            collect_free_identifiers_in_expr(right, declared, free);
        }
        ExprKind::Unary { expr: inner, .. } => {
            collect_free_identifiers_in_expr(inner, declared, free);
        }
        ExprKind::Call { callee, args } => {
            collect_free_identifiers_in_expr(callee, declared, free);
            for a in args {
                collect_free_identifiers_in_expr(&a.value, declared, free);
            }
        }
        ExprKind::MethodCall { receiver, args, .. } => {
            collect_free_identifiers_in_expr(receiver, declared, free);
            for a in args {
                collect_free_identifiers_in_expr(&a.value, declared, free);
            }
        }
        ExprKind::FieldAccess { receiver, .. } => {
            collect_free_identifiers_in_expr(receiver, declared, free);
        }
        ExprKind::Index { receiver, index } => {
            collect_free_identifiers_in_expr(receiver, declared, free);
            collect_free_identifiers_in_expr(index, declared, free);
        }
        ExprKind::Array(items) | ExprKind::Tuple(items) => {
            for item in items {
                collect_free_identifiers_in_expr(item, declared, free);
            }
        }
        ExprKind::ArrayRepeat(val, count) => {
            collect_free_identifiers_in_expr(val, declared, free);
            collect_free_identifiers_in_expr(count, declared, free);
        }
        ExprKind::Record(fields) | ExprKind::StructInit { fields, .. } => {
            for (_, val) in fields {
                collect_free_identifiers_in_expr(val, declared, free);
            }
        }
        ExprKind::Block(b) => {
            collect_free_identifiers_in_block(b, &mut declared.clone(), free);
        }
        ExprKind::If {
            cond,
            then_branch,
            else_branch,
        } => {
            collect_free_identifiers_in_expr(cond, declared, free);
            collect_free_identifiers_in_block(then_branch, &mut declared.clone(), free);
            if let Some(eb) = else_branch {
                collect_free_identifiers_in_expr(eb, declared, free);
            }
        }
        ExprKind::IfLet {
            pattern,
            expr,
            guard,
            then_branch,
            else_branch,
        } => {
            collect_free_identifiers_in_expr(expr, declared, free);
            let mut if_decl = declared.clone();
            for (sym, _) in pattern.bound_variables() {
                if_decl.insert(sym);
            }
            if let Some(g) = guard {
                collect_free_identifiers_in_expr(g, &if_decl, free);
            }
            collect_free_identifiers_in_block(then_branch, &mut if_decl, free);
            if let Some(eb) = else_branch {
                collect_free_identifiers_in_expr(eb, declared, free);
            }
        }
        ExprKind::Match { expr: target, arms } => {
            collect_free_identifiers_in_expr(target, declared, free);
            for arm in arms {
                let mut arm_decl = declared.clone();
                for (sym, _) in arm.pattern.bound_variables() {
                    arm_decl.insert(sym);
                }
                if let Some(g) = &arm.guard {
                    collect_free_identifiers_in_expr(g, &arm_decl, free);
                }
                collect_free_identifiers_in_expr(&arm.body, &arm_decl, free);
            }
        }
        ExprKind::Select { arms } => {
            for arm in arms {
                if let Some(ch) = &arm.channel {
                    collect_free_identifiers_in_expr(ch, declared, free);
                }
                collect_free_identifiers_in_expr(&arm.body, declared, free);
            }
        }
        ExprKind::Spawn(e) | ExprKind::Comptime(e) => {
            collect_free_identifiers_in_expr(e, declared, free);
        }
        ExprKind::Catch {
            expr: inner,
            err_var,
            body,
        } => {
            collect_free_identifiers_in_expr(inner, declared, free);
            let mut catch_decl = declared.clone();
            if let Some(ev) = err_var {
                catch_decl.insert(*ev);
            }
            collect_free_identifiers_in_block(body, &mut catch_decl, free);
        }
        ExprKind::Lambda { params, body, .. } => {
            let mut lambda_decl = declared.clone();
            for p in params {
                lambda_decl.insert(p.name);
            }
            collect_free_identifiers_in_block(body, &mut lambda_decl, free);
        }
        ExprKind::InterpolatedString(parts) => {
            for part in parts {
                collect_free_identifiers_in_expr(part, declared, free);
            }
        }
        ExprKind::Range {
            start, end, step, ..
        } => {
            if let Some(s) = start {
                collect_free_identifiers_in_expr(s, declared, free);
            }
            if let Some(e) = end {
                collect_free_identifiers_in_expr(e, declared, free);
            }
            if let Some(st) = step {
                collect_free_identifiers_in_expr(st, declared, free);
            }
        }
        ExprKind::Lit(_) | ExprKind::Path(_) | ExprKind::Unit => {}
    }
}

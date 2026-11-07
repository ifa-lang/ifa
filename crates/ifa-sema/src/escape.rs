use crate::symbol_table::SymbolTable;
use crate::types::Type;
use ifa_ast::{Expr, ExprKind, Function, ParamMode, Pattern, Stmt, UnaryOp};
use ifa_diagnostics::Diagnostic;
use ifa_span::{Span, Symbol, INTERNER};
use std::collections::HashMap;

/// Determines if a type contains or is a generational reference (`ref T`).
pub fn type_contains_ref(ty: &Type) -> bool {
    match ty {
        Type::Ref(_) => true,
        Type::Optional(inner) => type_contains_ref(inner),
        Type::Slice(inner) => type_contains_ref(inner),
        Type::Array(inner, _) => type_contains_ref(inner),
        Type::ErrorUnion { err, ok } => type_contains_ref(err) || type_contains_ref(ok),
        Type::Tuple(elems) => elems.iter().any(type_contains_ref),
        Type::Generic { args, .. } => args.iter().any(type_contains_ref),
        Type::Struct { fields, .. } => fields.iter().any(|(_, fty)| type_contains_ref(fty)),
        _ => false,
    }
}

/// Identifies the root variable of an expression, traversing field accesses, array indices,
/// and unary operators (inout, sink, ref).
pub fn extract_escape_root(expr: &Expr) -> Option<(Symbol, Span)> {
    match &expr.kind {
        ExprKind::Ident(sym) => Some((*sym, expr.span)),
        ExprKind::FieldAccess { receiver, .. } => extract_escape_root(receiver),
        ExprKind::Index { receiver, .. } => extract_escape_root(receiver),
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
        ExprKind::Index { receiver, .. } => {
            format!("{}[...]", format_projection_expr(receiver))
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
}

pub struct EscapeAnalyzer<'a> {
    pub symbols: &'a SymbolTable,
    pub current_func_is_strict: bool,
    pub current_func_span: Span,
    pub var_info: HashMap<Symbol, VarEscapeInfo>,
    pub ref_dependencies: HashMap<Symbol, Vec<Symbol>>,
    pub spawn_depth: usize,
    pub diagnostics: Vec<Diagnostic>,
}

impl<'a> EscapeAnalyzer<'a> {
    pub fn new(symbols: &'a SymbolTable, is_strict: bool, func_span: Span) -> Self {
        Self {
            symbols,
            current_func_is_strict: is_strict,
            current_func_span: func_span,
            var_info: HashMap::new(),
            ref_dependencies: HashMap::new(),
            spawn_depth: 0,
            diagnostics: Vec::new(),
        }
    }

    pub fn record_local_var(&mut self, var: Symbol, span: Span) {
        self.var_info.insert(
            var,
            VarEscapeInfo {
                var,
                origin: VarOrigin::Local,
                alloc_kind: AllocKind::Stack,
                escape_status: EscapeStatus::Local,
                defined_span: span,
                contained_refs: Vec::new(),
            },
        );
    }

    pub fn record_param(&mut self, var: Symbol, mode: ParamMode, span: Span) {
        self.var_info.insert(
            var,
            VarEscapeInfo {
                var,
                origin: VarOrigin::Param(mode),
                alloc_kind: AllocKind::Stack,
                escape_status: EscapeStatus::Local,
                defined_span: span,
                contained_refs: Vec::new(),
            },
        );
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
                span,
                ..
            } => {
                let bound = pattern.bound_variables();
                for (sym, p_span) in &bound {
                    self.record_local_var(*sym, *p_span);
                }
                self.check_pattern_ref_bindings(pattern, init.as_ref(), *span);
                if let Some(expr) = init {
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
            }
            Stmt::AssignPattern { pattern, val, span } => {
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
                self.handle_ref_creation(inner, expr.span);
            }
            ExprKind::Call { callee, args } => {
                self.check_expr(callee);
                for arg in args {
                    // Check for invalid inout passing into concurrent spawn
                    if self.spawn_depth > 0 {
                        if let ExprKind::Unary {
                            op: UnaryOp::InOut,
                            expr: inner,
                        } = &arg.value.kind
                        {
                            if let Some((root_sym, root_span)) = extract_escape_root(inner) {
                                if self.var_info.contains_key(&root_sym) {
                                    let var_name = INTERNER.resolve(&root_sym);
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
                                        format!("passage inout de '{}' interdit dans une fibre concurrente", inner_repr)
                                    } else {
                                        "passage inout interdit dans une fibre concurrente"
                                            .to_string()
                                    };

                                    self.diagnostics.push(
                                        Diagnostic::error(error_msg)
                                            .with_code("E0025")
                                            .with_primary_label(arg.value.span, primary_label)
                                            .with_secondary_label(
                                                root_span,
                                                format!("'{}' appartient au thread parent", var_name),
                                            )
                                            .with_help("Transférez la propriété avec 'sink' ou envoyez un message via un canal."),
                                    );
                                }
                            }
                        }
                    }
                    self.check_expr(&arg.value);
                }
            }
            ExprKind::MethodCall { receiver, args, .. } => {
                self.check_expr(receiver);
                for arg in args {
                    if self.spawn_depth > 0 {
                        if let ExprKind::Unary {
                            op: UnaryOp::InOut,
                            expr: inner,
                        } = &arg.value.kind
                        {
                            if let Some((root_sym, root_span)) = extract_escape_root(inner) {
                                if self.var_info.contains_key(&root_sym) {
                                    let var_name = INTERNER.resolve(&root_sym);
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
                                        format!("passage inout de '{}' interdit dans une fibre concurrente", inner_repr)
                                    } else {
                                        "passage inout interdit dans une fibre concurrente"
                                            .to_string()
                                    };

                                    self.diagnostics.push(
                                        Diagnostic::error(error_msg)
                                            .with_code("E0025")
                                            .with_primary_label(arg.value.span, primary_label)
                                            .with_secondary_label(
                                                root_span,
                                                format!("'{}' appartient au thread parent", var_name),
                                            )
                                            .with_help("Transférez la propriété avec 'sink' ou envoyez un message via un canal."),
                                    );
                                }
                            }
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
            ExprKind::Spawn(inner) => {
                let prev_depth = self.spawn_depth;
                self.spawn_depth += 1;
                self.check_expr(inner);
                self.spawn_depth = prev_depth;
            }
            ExprKind::Comptime(inner) => self.check_expr(inner),
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

use crate::symbol_table::SymbolTable;
use ifa_ast::{Arg, Block, Expr, ExprKind, Function, Item, ParamMode, Program, Stmt, UnaryOp};
use ifa_diagnostics::Diagnostic;
use ifa_span::{Span, Symbol, INTERNER};
use std::collections::HashMap;

/// Identifies the root variable of an lvalue expression.
/// For example, `x.y.z` or `x[0]` has root variable `x`.
pub fn extract_root_variable(expr: &Expr) -> Option<(Symbol, Span)> {
    match &expr.kind {
        ExprKind::Ident(sym) => Some((*sym, expr.span)),
        ExprKind::FieldAccess { receiver, .. } => extract_root_variable(receiver),
        ExprKind::Index { receiver, .. } => extract_root_variable(receiver),
        ExprKind::Unary {
            op: UnaryOp::InOut | UnaryOp::Sink | UnaryOp::Ref,
            expr: inner,
        } => extract_root_variable(inner),
        _ => None,
    }
}

/// A segment in a structured memory access path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathSegment {
    Field(Symbol),
    IndexConst(i64),
    IndexUnknown,
}

/// A relative access path starting from a parameter or local base variable.
pub type RelativePath = Vec<PathSegment>;

/// A path-sensitive access descriptor representing variable or field projections (e.g. `node.lhs.rhs` or `p.a`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessPath {
    pub root: Symbol,
    pub segments: Vec<PathSegment>,
    pub display: String,
}

impl AccessPath {
    /// Determines whether two access paths overlap (alias).
    /// If both paths refer to the same root, and their prefix of field/index segments match
    /// without proven disjointness, they overlap.
    pub fn overlaps(&self, other: &AccessPath) -> bool {
        if self.root != other.root {
            return false;
        }
        let min_len = self.segments.len().min(other.segments.len());
        for i in 0..min_len {
            match (&self.segments[i], &other.segments[i]) {
                (PathSegment::Field(f1), PathSegment::Field(f2)) if f1 != f2 => {
                    return false; // distinct fields at the same depth are provably disjoint
                }
                (PathSegment::IndexConst(c1), PathSegment::IndexConst(c2)) if c1 != c2 => {
                    return false; // distinct constant indices are provably disjoint
                }
                _ => {
                    // Unknown index or matching segment -> potentially overlapping
                }
            }
        }
        true
    }

    /// Extends this access path by appending relative projection segments.
    pub fn append_relative(&self, rel_segments: &[PathSegment]) -> AccessPath {
        if rel_segments.is_empty() {
            return self.clone();
        }
        let mut new_segments = self.segments.clone();
        new_segments.extend_from_slice(rel_segments);
        let mut display = self.display.clone();
        for seg in rel_segments {
            match seg {
                PathSegment::Field(f) => {
                    display.push('.');
                    display.push_str(&INTERNER.resolve(f));
                }
                PathSegment::IndexConst(c) => {
                    display.push_str(&format!("[{}]", c));
                }
                PathSegment::IndexUnknown => {
                    display.push_str("[*]");
                }
            }
        }
        AccessPath {
            root: self.root,
            segments: new_segments,
            display,
        }
    }
}

/// Summary of fine-grained memory sub-paths accessed on a function parameter.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParamAccessSummary {
    /// Relative sub-paths mutated (via assignment, inout sub-call, or inout ref).
    pub writes: Vec<RelativePath>,
    /// Relative sub-paths inspected (via ref borrow or read-only projection).
    pub reads: Vec<RelativePath>,
    /// Whether the entire argument is consumed or moved (sink).
    pub is_sink: bool,
}

/// Propagation edge between a caller argument and a callee parameter.
#[derive(Debug, Clone)]
pub struct CallPropagationEdge {
    pub caller_sym: Symbol,
    pub caller_param_idx: usize,
    pub callee_sym: Symbol,
    pub callee_param_idx: usize,
    pub rel_prefix: RelativePath,
    pub is_inout: bool,
    pub is_ref: bool,
    pub is_sink: bool,
}

/// Whole-function inter-procedural access summary for all formal parameters.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FunctionAccessSummary {
    pub params: Vec<ParamAccessSummary>,
}

/// Whole-module inter-procedural access path repository computed across call graphs.
#[derive(Debug, Clone, Default)]
pub struct InterproceduralAccessMap {
    pub summaries: HashMap<Symbol, FunctionAccessSummary>,
}

impl InterproceduralAccessMap {
    /// Retrieve the inter-procedural access summary for a named function if available.
    pub fn get_summary(&self, name: &Symbol) -> Option<&FunctionAccessSummary> {
        if let Some(s) = self.summaries.get(name) {
            return Some(s);
        }
        let name_str = INTERNER.resolve(name);
        if let Some((st_part, rest)) = name_str.split_once("__") {
            if let Some(m_part) = rest.rsplit("__").next() {
                let base_sym = INTERNER.intern(&format!("{}__{}", st_part, m_part));
                if let Some(s) = self.summaries.get(&base_sym) {
                    return Some(s);
                }
            }
            let short_sym = INTERNER.intern(rest);
            if let Some(s) = self.summaries.get(&short_sym) {
                return Some(s);
            }
        }
        None
    }

    /// Computes inter-procedural access path summaries for all functions declared in the AST.
    ///
    /// The algorithm performs an initial AST sweep collecting direct field assignments and borrows,
    /// constructs caller-callee propagation edges, and runs a fixed-point iteration to propagate
    /// sub-path projections transitively across recursive and nested call graphs.
    pub fn compute_module_summaries(program: &Program) -> Self {
        let mut map = InterproceduralAccessMap::default();
        let mut call_edges = Vec::new();

        // 1. Initial collection of functions and intra-procedural access summaries
        for item in &program.items {
            match item {
                Item::Function(func) => {
                    Self::analyze_single_func(func, None, &mut map, &mut call_edges);
                }
                Item::Impl(imp) => {
                    let target_sym = match &imp.target_ty.kind {
                        ifa_ast::TypeKind::Named(s) => Some(*s),
                        ifa_ast::TypeKind::Generic(s, _) => Some(*s),
                        _ => None,
                    };
                    for method in &imp.methods {
                        Self::analyze_single_func(method, target_sym, &mut map, &mut call_edges);
                    }
                }
                _ => {}
            }
        }

        // 2. Inter-procedural fixed-point propagation
        // Path depth is bounded at 8 segments to guarantee strict termination on cyclic call graphs.
        const MAX_PATH_DEPTH: usize = 8;
        let mut changed = true;
        let mut iterations = 0;

        while changed && iterations < 32 {
            changed = false;
            iterations += 1;

            for edge in &call_edges {
                let CallPropagationEdge {
                    caller_sym,
                    caller_param_idx,
                    callee_sym,
                    callee_param_idx,
                    rel_prefix,
                    is_inout,
                    is_ref,
                    is_sink,
                } = edge;

                if let Some(callee_summary) = map.summaries.get(callee_sym).cloned() {
                    if let Some(callee_param) = callee_summary.params.get(*callee_param_idx) {
                        let caller_summary = map.summaries.get_mut(caller_sym).unwrap();
                        let caller_param = &mut caller_summary.params[*caller_param_idx];

                        // Propagate sub-path writes
                        for w in &callee_param.writes {
                            if rel_prefix.len() + w.len() <= MAX_PATH_DEPTH {
                                let mut combined = rel_prefix.clone();
                                combined.extend_from_slice(w);
                                if !caller_param.writes.contains(&combined) {
                                    caller_param.writes.push(combined);
                                    changed = true;
                                }
                            }
                        }

                        // Propagate sub-path reads
                        for r in &callee_param.reads {
                            if rel_prefix.len() + r.len() <= MAX_PATH_DEPTH {
                                let mut combined = rel_prefix.clone();
                                combined.extend_from_slice(r);
                                if !caller_param.reads.contains(&combined) {
                                    caller_param.reads.push(combined);
                                    changed = true;
                                }
                            }
                        }

                        // Propagate sink
                        if callee_param.is_sink && !caller_param.is_sink {
                            caller_param.is_sink = true;
                            changed = true;
                        }
                    }
                } else {
                    // Callee is external or unresolved: conservatively propagate call mode
                    let caller_summary = map.summaries.get_mut(caller_sym).unwrap();
                    let caller_param = &mut caller_summary.params[*caller_param_idx];
                    if *is_inout && !caller_param.writes.contains(rel_prefix) {
                        caller_param.writes.push(rel_prefix.clone());
                        changed = true;
                    }
                    if *is_ref && !caller_param.reads.contains(rel_prefix) {
                        caller_param.reads.push(rel_prefix.clone());
                        changed = true;
                    }
                    if *is_sink && !caller_param.is_sink {
                        caller_param.is_sink = true;
                        changed = true;
                    }
                }
            }
        }

        // 3. Normalization: if a parameter is inout/mut and no specific sub-path was discovered,
        // fall back to conservative full parameter mutation `[]`.
        for summary in map.summaries.values_mut() {
            for param in &mut summary.params {
                if param.writes.contains(&Vec::new()) {
                    param.writes.retain(|w| w.is_empty());
                }
                if param.reads.contains(&Vec::new()) {
                    param.reads.retain(|r| r.is_empty());
                }
            }
        }

        map
    }

    fn analyze_single_func(
        func: &Function,
        target_sym: Option<Symbol>,
        map: &mut InterproceduralAccessMap,
        call_edges: &mut Vec<CallPropagationEdge>,
    ) {
        let mut param_indices = HashMap::new();
        let mut initial_summary = FunctionAccessSummary {
            params: Vec::with_capacity(func.params.len()),
        };

        for (idx, p) in func.params.iter().enumerate() {
            param_indices.insert(p.name, idx);
            let mut p_sum = ParamAccessSummary::default();
            if p.mode == ParamMode::Sink {
                p_sum.is_sink = true;
            }
            initial_summary.params.push(p_sum);
        }

        let mangled_sym = target_sym.map(|st| {
            INTERNER.intern(&format!(
                "{}__{}",
                INTERNER.resolve(&st),
                INTERNER.resolve(&func.name)
            ))
        });
        let effective_caller_sym = mangled_sym.unwrap_or(func.name);
        let self_sym = INTERNER.intern("self");

        if let Some(body) = &func.body {
            let mut collector = AccessCollector {
                param_indices: &param_indices,
                summary: initial_summary,
                caller_sym: effective_caller_sym,
                enclosing_struct: target_sym,
                self_sym,
                call_edges,
            };
            collector.visit_block(body);
            if let Some(m_sym) = mangled_sym {
                map.summaries.insert(m_sym, collector.summary.clone());
            }
            map.summaries.entry(func.name).or_insert(collector.summary);
        } else {
            // Function without body (e.g. extern): mark all inout parameters with full write `[]`
            for (idx, p) in func.params.iter().enumerate() {
                if p.mode == ParamMode::InOut || p.mode == ParamMode::Mut {
                    initial_summary.params[idx].writes.push(Vec::new());
                } else if p.mode == ParamMode::In {
                    initial_summary.params[idx].reads.push(Vec::new());
                }
            }
            if let Some(m_sym) = mangled_sym {
                map.summaries.insert(m_sym, initial_summary.clone());
            }
            map.summaries.entry(func.name).or_insert(initial_summary);
        }
    }
}

struct AccessCollector<'a> {
    param_indices: &'a HashMap<Symbol, usize>,
    summary: FunctionAccessSummary,
    caller_sym: Symbol,
    enclosing_struct: Option<Symbol>,
    self_sym: Symbol,
    call_edges: &'a mut Vec<CallPropagationEdge>,
}

impl<'a> AccessCollector<'a> {
    fn visit_block(&mut self, block: &Block) {
        for stmt in &block.stmts {
            self.visit_stmt(stmt);
        }
        if let Some(expr) = &block.expr {
            self.visit_expr(expr);
        }
    }

    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Assign { target, val, .. } => {
                if let Some(path) = extract_access_path(target) {
                    if let Some(&p_idx) = self.param_indices.get(&path.root) {
                        if !self.summary.params[p_idx].writes.contains(&path.segments) {
                            self.summary.params[p_idx].writes.push(path.segments);
                        }
                    }
                }
                self.visit_expr(val);
            }
            Stmt::AssignPattern {
                val, else_block, ..
            } => {
                self.visit_expr(val);
                if let Some(eb) = else_block {
                    self.visit_block(eb);
                }
            }
            Stmt::Expr(expr) => self.visit_expr(expr),
            Stmt::Let {
                init, else_block, ..
            } => {
                if let Some(i) = init {
                    self.visit_expr(i);
                }
                if let Some(eb) = else_block {
                    self.visit_block(eb);
                }
            }
            Stmt::While { cond, body, .. } => {
                self.visit_expr(cond);
                self.visit_block(body);
            }
            Stmt::WhileLet {
                expr, guard, body, ..
            } => {
                self.visit_expr(expr);
                if let Some(g) = guard {
                    self.visit_expr(g);
                }
                self.visit_block(body);
            }
            Stmt::For { iterable, body, .. } => {
                self.visit_expr(iterable);
                self.visit_block(body);
            }
            Stmt::Loop(body, _) => self.visit_block(body),
            Stmt::Return(opt_expr, _) => {
                if let Some(e) = opt_expr {
                    self.visit_expr(e);
                }
            }
            Stmt::Defer(block, _) => self.visit_block(block),
            Stmt::Fail(expr, _) => self.visit_expr(expr),
            Stmt::Break(_) | Stmt::Continue(_) => {}
        }
    }

    fn visit_expr(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Unary { op, expr: inner } => {
                if let Some(path) = extract_access_path(inner) {
                    if let Some(&p_idx) = self.param_indices.get(&path.root) {
                        match op {
                            UnaryOp::InOut => {
                                if !self.summary.params[p_idx].writes.contains(&path.segments) {
                                    self.summary.params[p_idx]
                                        .writes
                                        .push(path.segments.clone());
                                }
                            }
                            UnaryOp::Ref => {
                                if !self.summary.params[p_idx].reads.contains(&path.segments) {
                                    self.summary.params[p_idx].reads.push(path.segments.clone());
                                }
                            }
                            UnaryOp::Sink => {
                                self.summary.params[p_idx].is_sink = true;
                            }
                            _ => {}
                        }
                    }
                }
                self.visit_expr(inner);
            }
            ExprKind::Call { callee, args } => {
                let callee_sym = match &callee.kind {
                    ExprKind::Ident(s) => Some(*s),
                    ExprKind::Path(p) => p.last().copied(),
                    _ => None,
                };

                if let Some(target_func) = callee_sym {
                    for (arg_idx, arg) in args.iter().enumerate() {
                        if let Some(path) = extract_access_path(&arg.value) {
                            if let Some(&p_idx) = self.param_indices.get(&path.root) {
                                let is_inout = matches!(
                                    &arg.value.kind,
                                    ExprKind::Unary {
                                        op: UnaryOp::InOut,
                                        ..
                                    }
                                );
                                let is_ref = matches!(
                                    &arg.value.kind,
                                    ExprKind::Unary {
                                        op: UnaryOp::Ref,
                                        ..
                                    }
                                );
                                let is_sink = matches!(
                                    &arg.value.kind,
                                    ExprKind::Unary {
                                        op: UnaryOp::Sink,
                                        ..
                                    }
                                );
                                self.call_edges.push(CallPropagationEdge {
                                    caller_sym: self.caller_sym,
                                    caller_param_idx: p_idx,
                                    callee_sym: target_func,
                                    callee_param_idx: arg_idx,
                                    rel_prefix: path.segments,
                                    is_inout,
                                    is_ref,
                                    is_sink,
                                });
                            }
                        }
                    }
                }

                self.visit_expr(callee);
                for arg in args {
                    match &arg.value.kind {
                        ExprKind::Unary {
                            op: UnaryOp::InOut | UnaryOp::Ref | UnaryOp::Sink,
                            expr: inner,
                        } => self.visit_expr(inner),
                        _ => self.visit_expr(&arg.value),
                    }
                }
            }
            ExprKind::MethodCall {
                receiver,
                method,
                args,
                ..
            } => {
                let callee_method_sym = if let Some(st) = self.enclosing_struct {
                    if let Some(path) = extract_access_path(receiver) {
                        if path.root == self.self_sym {
                            INTERNER.intern(&format!(
                                "{}__{}",
                                INTERNER.resolve(&st),
                                INTERNER.resolve(method)
                            ))
                        } else {
                            *method
                        }
                    } else {
                        *method
                    }
                } else {
                    *method
                };

                // Receiver corresponds to parameter 0
                if let Some(path) = extract_access_path(receiver) {
                    if let Some(&p_idx) = self.param_indices.get(&path.root) {
                        self.call_edges.push(CallPropagationEdge {
                            caller_sym: self.caller_sym,
                            caller_param_idx: p_idx,
                            callee_sym: callee_method_sym,
                            callee_param_idx: 0,
                            rel_prefix: path.segments,
                            is_inout: true,
                            is_ref: false,
                            is_sink: false,
                        });
                    }
                }

                for (arg_idx, arg) in args.iter().enumerate() {
                    if let Some(path) = extract_access_path(&arg.value) {
                        if let Some(&p_idx) = self.param_indices.get(&path.root) {
                            let is_inout = matches!(
                                &arg.value.kind,
                                ExprKind::Unary {
                                    op: UnaryOp::InOut,
                                    ..
                                }
                            );
                            let is_ref = matches!(
                                &arg.value.kind,
                                ExprKind::Unary {
                                    op: UnaryOp::Ref,
                                    ..
                                }
                            );
                            let is_sink = matches!(
                                &arg.value.kind,
                                ExprKind::Unary {
                                    op: UnaryOp::Sink,
                                    ..
                                }
                            );
                            self.call_edges.push(CallPropagationEdge {
                                caller_sym: self.caller_sym,
                                caller_param_idx: p_idx,
                                callee_sym: callee_method_sym,
                                callee_param_idx: arg_idx + 1,
                                rel_prefix: path.segments,
                                is_inout,
                                is_ref,
                                is_sink,
                            });
                        }
                    }
                }

                match &receiver.kind {
                    ExprKind::Unary {
                        op: UnaryOp::InOut | UnaryOp::Ref | UnaryOp::Sink,
                        expr: inner,
                    } => self.visit_expr(inner),
                    _ => self.visit_expr(receiver),
                }
                for arg in args {
                    match &arg.value.kind {
                        ExprKind::Unary {
                            op: UnaryOp::InOut | UnaryOp::Ref | UnaryOp::Sink,
                            expr: inner,
                        } => self.visit_expr(inner),
                        _ => self.visit_expr(&arg.value),
                    }
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.visit_expr(left);
                self.visit_expr(right);
            }
            ExprKind::FieldAccess { receiver, .. } => self.visit_expr(receiver),
            ExprKind::Index { receiver, index } => {
                self.visit_expr(receiver);
                self.visit_expr(index);
            }
            ExprKind::Block(b) => self.visit_block(b),
            ExprKind::Array(elems) => {
                for el in elems {
                    self.visit_expr(el);
                }
            }
            ExprKind::StructInit { fields, .. } => {
                for (_, f_expr) in fields {
                    self.visit_expr(f_expr);
                }
            }
            ExprKind::If {
                cond,
                then_branch,
                else_branch,
            } => {
                self.visit_expr(cond);
                self.visit_block(then_branch);
                if let Some(eb) = else_branch {
                    self.visit_expr(eb);
                }
            }
            ExprKind::IfLet {
                expr: i_expr,
                guard,
                then_branch,
                else_branch,
                ..
            } => {
                self.visit_expr(i_expr);
                if let Some(g) = guard {
                    self.visit_expr(g);
                }
                self.visit_block(then_branch);
                if let Some(eb) = else_branch {
                    self.visit_expr(eb);
                }
            }
            ExprKind::Match { expr: m_expr, arms } => {
                self.visit_expr(m_expr);
                for arm in arms {
                    if let Some(g) = &arm.guard {
                        self.visit_expr(g);
                    }
                    self.visit_expr(&arm.body);
                }
            }
            ExprKind::Lambda { body, .. } => self.visit_block(body),
            ExprKind::Catch {
                expr: c_expr, body, ..
            } => {
                self.visit_expr(c_expr);
                self.visit_block(body);
            }
            ExprKind::Spawn(s_expr) => self.visit_expr(s_expr),
            _ => {}
        }
    }
}

/// Extracts a path-sensitive access descriptor from an lvalue expression.
pub fn extract_access_path(expr: &Expr) -> Option<AccessPath> {
    match &expr.kind {
        ExprKind::Ident(sym) => {
            let name = INTERNER.resolve(sym).to_string();
            Some(AccessPath {
                root: *sym,
                segments: Vec::new(),
                display: name,
            })
        }
        ExprKind::FieldAccess {
            receiver, field, ..
        } => {
            let mut parent = extract_access_path(receiver)?;
            let field_name = INTERNER.resolve(field);
            parent.display.push('.');
            parent.display.push_str(&field_name);
            parent.segments.push(PathSegment::Field(*field));
            Some(parent)
        }
        ExprKind::Index { receiver, index } => {
            let mut parent = extract_access_path(receiver)?;
            match &index.kind {
                ExprKind::Lit(ifa_ast::Lit::Int(sym)) => {
                    let s = INTERNER.resolve(sym);
                    parent.display.push_str(&format!("[{}]", s));
                    let val: i64 = s.parse().unwrap_or(0);
                    parent.segments.push(PathSegment::IndexConst(val));
                }
                _ => {
                    parent.display.push_str("[*]");
                    parent.segments.push(PathSegment::IndexUnknown);
                }
            }
            Some(parent)
        }
        ExprKind::Unary {
            op: UnaryOp::InOut | UnaryOp::Sink | UnaryOp::Ref,
            expr: inner,
        } => extract_access_path(inner),
        _ => None,
    }
}

/// Checks whether an expression is a valid lvalue suitable for `inout` or `sink` mutation/move.
pub fn is_lvalue(expr: &Expr) -> bool {
    matches!(
        &expr.kind,
        ExprKind::Ident(_)
            | ExprKind::FieldAccess { .. }
            | ExprKind::Index { .. }
            | ExprKind::Unary {
                op: UnaryOp::InOut | UnaryOp::Sink | UnaryOp::Ref,
                ..
            }
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BorrowKind {
    In,
    InOut,
    Sink,
}

#[derive(Debug, Clone)]
pub struct BorrowRecord {
    pub path: AccessPath,
    pub kind: BorrowKind,
    pub span: Span,
}

/// Verifies the Law of Exclusivity across arguments of a function or method call.
/// In IFA: "une même variable racine ne peut jamais être passée deux fois en inout
/// (ou en inout et in simultanément) dans le même appel de fonction."
/// Path-sensitive analysis permits concurrent inout borrows on provably disjoint fields
/// (e.g. `p.a` and `p.b`), while statically rejecting overlapping paths (e.g. `node.lhs` and `node.lhs.rhs`).
pub fn check_call_exclusivity(
    args: &[Arg],
    param_modes: &[ParamMode],
    symbols: &SymbolTable,
    diagnostics: &mut Vec<Diagnostic>,
) {
    check_call_exclusivity_with_active(args, param_modes, &[], symbols, diagnostics);
}

/// Verifies the Law of Exclusivity across arguments of a function or method call,
/// leveraging inter-procedural path-sensitive access summaries when available.
pub fn check_call_exclusivity_interproc(
    callee_name: Option<Symbol>,
    args: &[Arg],
    param_modes: &[ParamMode],
    active_borrows: &[BorrowRecord],
    interproc: Option<&InterproceduralAccessMap>,
    symbols: &SymbolTable,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut borrows: Vec<BorrowRecord> = active_borrows.to_vec();
    let callee_summary = callee_name.and_then(|sym| interproc.and_then(|m| m.get_summary(&sym)));

    for (idx, arg) in args.iter().enumerate() {
        let is_explicit_inout = matches!(
            &arg.value.kind,
            ExprKind::Unary {
                op: UnaryOp::InOut,
                ..
            }
        );
        let is_explicit_sink = matches!(
            &arg.value.kind,
            ExprKind::Unary {
                op: UnaryOp::Sink,
                ..
            }
        );

        let param_mode = param_modes.get(idx).copied().unwrap_or(ParamMode::In);
        let is_sink = is_explicit_sink || param_mode == ParamMode::Sink;
        let is_inout = is_explicit_inout || param_mode == ParamMode::InOut;

        if let Some(path) = extract_access_path(&arg.value) {
            let root_sym = path.root;
            let var_name = INTERNER.resolve(&root_sym);

            // Compute effective borrows based on inter-procedural sub-path summary
            let mut effective_borrows = Vec::new();
            let param_summary = callee_summary.and_then(|s| s.params.get(idx));

            if is_sink {
                effective_borrows.push((path.clone(), BorrowKind::Sink));
            } else if is_inout {
                if let Some(p_sum) = param_summary {
                    if !p_sum.writes.is_empty() && !p_sum.writes.iter().any(|w| w.is_empty()) {
                        for sub in &p_sum.writes {
                            effective_borrows.push((path.append_relative(sub), BorrowKind::InOut));
                        }
                    } else {
                        effective_borrows.push((path.clone(), BorrowKind::InOut));
                    }
                } else {
                    effective_borrows.push((path.clone(), BorrowKind::InOut));
                }
            } else {
                // Read-only borrow ('in')
                if let Some(p_sum) = param_summary {
                    if !p_sum.reads.is_empty() && !p_sum.reads.iter().any(|r| r.is_empty()) {
                        for sub in &p_sum.reads {
                            effective_borrows.push((path.append_relative(sub), BorrowKind::In));
                        }
                    } else {
                        effective_borrows.push((path.clone(), BorrowKind::In));
                    }
                } else {
                    effective_borrows.push((path.clone(), BorrowKind::In));
                }
            }

            // Validate mutability for inout
            if is_inout {
                if let Some(var) = symbols.lookup_variable(&root_sym) {
                    if !var.is_mut {
                        diagnostics.push(
                            Diagnostic::error(format!(
                                "impossible de passer la variable immuable '{}' en paramètre 'inout'",
                                var_name
                            ))
                            .with_code("E0010")
                            .with_primary_label(
                                arg.value.span,
                                format!("mutation exclusive 'inout' interdite sur '{}'", var_name),
                            )
                            .with_secondary_label(
                                var.span,
                                format!(
                                    "la variable '{}' a été déclarée immuable avec 'let' (utilisez 'mut')",
                                    var_name
                                ),
                            )
                            .with_help("Changez la déclaration en 'mut' pour autoriser la modification sur place."),
                        );
                    }
                }
            }

            // Now check exclusivity for each effective borrow
            for (eff_path, eff_kind) in effective_borrows {
                if let Some(existing) = borrows.iter().find(|b| b.path.overlaps(&eff_path)) {
                    match (eff_kind, existing.kind) {
                        (BorrowKind::Sink, BorrowKind::Sink) => {
                            diagnostics.push(
                                Diagnostic::error(format!(
                                    "loi d'exclusivité violée : la variable '{}' est transférée ('sink') plusieurs fois dans le même appel",
                                    eff_path.display
                                ))
                                .with_code("E0016")
                                .with_primary_label(
                                    arg.value.span,
                                    "second transfert de propriété ('sink') interdit",
                                )
                                .with_secondary_label(
                                    existing.span,
                                    "premier transfert 'sink' ici",
                                )
                                .with_help("Une variable ne peut être déplacée/transférée qu'une seule fois."),
                            );
                        }
                        (BorrowKind::Sink, BorrowKind::InOut)
                        | (BorrowKind::Sink, BorrowKind::In) => {
                            let other_mode = if existing.kind == BorrowKind::InOut {
                                "inout"
                            } else {
                                "in"
                            };
                            diagnostics.push(
                                Diagnostic::error(format!(
                                    "loi d'exclusivité violée : la variable '{}' ne peut pas être simultanément transférée ('sink') et passée en '{}'",
                                    eff_path.display, other_mode
                                ))
                                .with_code("E0017")
                                .with_primary_label(
                                    arg.value.span,
                                    format!("conflit : transfert 'sink' sur une variable passée en '{}'", other_mode),
                                )
                                .with_secondary_label(
                                    existing.span,
                                    format!("passage en '{}' ici", other_mode),
                                ),
                            );
                        }
                        (BorrowKind::InOut, BorrowKind::Sink) => {
                            diagnostics.push(
                                Diagnostic::error(format!(
                                    "loi d'exclusivité violée : la variable '{}' ne peut pas être mutée ('inout') car elle est déjà transférée ('sink')",
                                    eff_path.display
                                ))
                                .with_code("E0017")
                                .with_primary_label(
                                    arg.value.span,
                                    "conflit : emprunt exclusif 'inout' sur une variable déjà transférée",
                                )
                                .with_secondary_label(
                                    existing.span,
                                    "transfert exclusif ('sink') ici",
                                ),
                            );
                        }
                        (BorrowKind::InOut, BorrowKind::InOut) => {
                            let msg = if eff_path.display == existing.path.display {
                                format!(
                                    "loi d'exclusivité violée : la variable '{}' est empruntée plusieurs fois en 'inout' dans le même appel",
                                    eff_path.display
                                )
                            } else {
                                format!(
                                    "loi d'exclusivité violée : l'emprunt 'inout' sur '{}' chevauche l'emprunt 'inout' sur '{}'",
                                    eff_path.display, existing.path.display
                                )
                            };
                            diagnostics.push(
                                Diagnostic::error(msg)
                                .with_code("E0011")
                                .with_primary_label(
                                    arg.value.span,
                                    "second emprunt mutable exclusif ('inout') interdit",
                                )
                                .with_secondary_label(
                                    existing.span,
                                    "premier emprunt 'inout' ici",
                                )
                                .with_help("Une variable ne peut avoir qu'un seul accès 'inout' exclusif à la fois."),
                            );
                        }
                        (BorrowKind::InOut, BorrowKind::In) => {
                            diagnostics.push(
                                Diagnostic::error(format!(
                                    "loi d'exclusivité violée : la variable '{}' ne peut pas être passée simultanément en lecture ('in') et en écriture ('inout')",
                                    eff_path.display
                                ))
                                .with_code("E0012")
                                .with_primary_label(
                                    arg.value.span,
                                    "conflit : emprunt exclusif 'inout' sur une variable déjà lue",
                                )
                                .with_secondary_label(
                                    existing.span,
                                    "emprunt en lecture ('in') ici",
                                ),
                            );
                        }
                        (BorrowKind::In, BorrowKind::Sink) => {
                            diagnostics.push(
                                Diagnostic::error(format!(
                                    "loi d'exclusivité violée : la variable '{}' ne peut pas être passée en lecture ('in') lorsqu'elle est déjà transférée ('sink')",
                                    eff_path.display
                                ))
                                .with_code("E0017")
                                .with_primary_label(
                                    arg.value.span,
                                    "conflit : lecture ('in') sur une variable déjà transférée ('sink')",
                                )
                                .with_secondary_label(
                                    existing.span,
                                    "transfert exclusif ('sink') ici",
                                ),
                            );
                        }
                        (BorrowKind::In, BorrowKind::InOut) => {
                            diagnostics.push(
                                Diagnostic::error(format!(
                                    "loi d'exclusivité violée : la variable '{}' ne peut pas être passée en lecture ('in') lorsqu'elle est déjà empruntée en 'inout'",
                                    eff_path.display
                                ))
                                .with_code("E0012")
                                .with_primary_label(
                                    arg.value.span,
                                    "conflit : lecture ('in') sur une variable déjà empruntée en écriture",
                                )
                                .with_secondary_label(
                                    existing.span,
                                    "emprunt exclusif ('inout') ici",
                                ),
                            );
                        }
                        (BorrowKind::In, BorrowKind::In) => {}
                    }
                } else {
                    borrows.push(BorrowRecord {
                        path: eff_path,
                        kind: eff_kind,
                        span: arg.value.span,
                    });
                }
            }
        } else if is_inout || is_sink {
            // Passing a literal or complex non-lvalue expression to inout or sink
            let kw = if is_inout { "inout" } else { "sink" };
            diagnostics.push(
                Diagnostic::error(format!(
                    "l'argument '{}' doit être une variable ou un champ modifiable (lvalue)",
                    kw
                ))
                .with_code("E0013")
                .with_primary_label(
                    arg.value.span,
                    "cette expression n'est pas modifiable ou transférable sur place",
                )
                .with_help("Passez une variable existante au lieu d'une valeur temporaire."),
            );
        }
    }
}

/// Verifies the Law of Exclusivity across arguments of a function or method call,
/// taking into account enclosing CFG active borrows (e.g. outer iteration loops).
pub fn check_call_exclusivity_with_active(
    args: &[Arg],
    param_modes: &[ParamMode],
    active_borrows: &[BorrowRecord],
    symbols: &SymbolTable,
    diagnostics: &mut Vec<Diagnostic>,
) {
    check_call_exclusivity_interproc(
        None,
        args,
        param_modes,
        active_borrows,
        None,
        symbols,
        diagnostics,
    );
}

/// Checks that an assignment target is mutable, assignable, and does not conflict with active borrows.
pub fn check_assignment_target(
    target: &Expr,
    symbols: &SymbolTable,
    diagnostics: &mut Vec<Diagnostic>,
) {
    check_assignment_target_with_active(target, &[], symbols, diagnostics);
}

/// Checks that an assignment target is mutable, assignable, and does not violate exclusivity against CFG active borrows.
pub fn check_assignment_target_with_active(
    target: &Expr,
    active_borrows: &[BorrowRecord],
    symbols: &SymbolTable,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if let Some(target_path) = extract_access_path(target) {
        if let Some(conflict) = active_borrows
            .iter()
            .find(|b| b.path.overlaps(&target_path))
        {
            let mode = match conflict.kind {
                BorrowKind::In => "en lecture ('in')",
                BorrowKind::InOut => "en écriture exclusive ('inout')",
                BorrowKind::Sink => "transférée ('sink')",
            };
            diagnostics.push(
                Diagnostic::error(format!(
                    "loi d'exclusivité violée : la variable '{}' ne peut pas être modifiée car elle fait l'objet d'un emprunt actif {}",
                    target_path.display, mode
                ))
                .with_code("E0012")
                .with_primary_label(
                    target.span,
                    format!("mutation interdite sur '{}' pendant un emprunt actif", target_path.display),
                )
                .with_secondary_label(
                    conflict.span,
                    format!("emprunt actif {} ici", mode),
                )
                .with_help("Terminez la portée de l'emprunt actif (ex: boucle d'itération) avant de modifier la variable."),
            );
            return;
        }
    }

    if let Some((root_sym, _)) = extract_root_variable(target) {
        let var_name = INTERNER.resolve(&root_sym);
        if let Some(var) = symbols.lookup_variable(&root_sym) {
            if !var.is_mut && var.is_initialized {
                diagnostics.push(
                    Diagnostic::error(format!(
                        "impossible d'assigner à la variable immuable '{}'",
                        var_name
                    ))
                    .with_code("E0014")
                    .with_primary_label(
                        target.span,
                        format!("tentative de réassignation de '{}'", var_name),
                    )
                    .with_secondary_label(
                        var.span,
                        format!(
                            "variable '{}' déclarée immuable avec 'let' (utilisez 'mut')",
                            var_name
                        ),
                    )
                    .with_help("Déclarez la variable avec 'mut' si vous devez la réassigner."),
                );
            }
        }
    } else {
        diagnostics.push(
            Diagnostic::error(
                "cible d'assignation invalide (doit être une variable mutable ou un champ)",
            )
            .with_code("E0015")
            .with_primary_label(target.span, "cette expression n'est pas assignable"),
        );
    }
}

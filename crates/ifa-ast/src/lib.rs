use ifa_span::{Span, Symbol};
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub struct Program {
    pub items: Vec<Item>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Item {
    Function(Function),
    Struct(Struct),
    Enum(Enum),
    Import(Import),
    Const(Const),
    Trait(Trait),
    Impl(Impl),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamMode {
    In,       // Default: read-only projection
    InOut,    // Mutation exclusive on-place
    Sink,     // Move ownership
    Mut,      // Mutable local value parameter
    Comptime, // Static evaluation
}

impl fmt::Display for ParamMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParamMode::In => write!(f, "in"),
            ParamMode::InOut => write!(f, "inout"),
            ParamMode::Sink => write!(f, "sink"),
            ParamMode::Mut => write!(f, "mut"),
            ParamMode::Comptime => write!(f, "comptime"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Param {
    pub mode: ParamMode,
    pub name: Symbol,
    pub ty: Type,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GenericParam {
    pub name: Symbol,
    pub bounds: Vec<Symbol>,
    pub span: Span,
}

impl GenericParam {
    pub fn new(name: Symbol, span: Span) -> Self {
        Self {
            name,
            bounds: Vec::new(),
            span,
        }
    }

    pub fn with_bounds(name: Symbol, bounds: Vec<Symbol>, span: Span) -> Self {
        Self { name, bounds, span }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Function {
    pub is_pub: bool,
    pub is_strict: bool,
    pub is_comptime: bool,
    pub is_extern: Option<String>,
    pub name: Symbol,
    pub generics: Vec<GenericParam>,
    pub params: Vec<Param>,
    pub ret_ty: Option<Type>,
    pub body: Option<Block>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StructField {
    pub is_pub: bool,
    pub name: Symbol,
    pub ty: Type,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Struct {
    pub is_pub: bool,
    pub name: Symbol,
    pub generics: Vec<GenericParam>,
    pub fields: Vec<StructField>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Variant {
    pub name: Symbol,
    pub payload: Option<Type>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Enum {
    pub is_pub: bool,
    pub name: Symbol,
    pub variants: Vec<Variant>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Import {
    pub path: Vec<Symbol>,
    pub alias: Option<Symbol>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Const {
    pub is_pub: bool,
    pub name: Symbol,
    pub ty: Option<Type>,
    pub value: Expr,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TraitMethod {
    pub name: Symbol,
    pub params: Vec<Param>,
    pub ret_ty: Option<Type>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Trait {
    pub is_pub: bool,
    pub name: Symbol,
    pub methods: Vec<TraitMethod>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Impl {
    pub trait_name: Option<Symbol>,
    pub target_ty: Type,
    pub methods: Vec<Function>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TypeKind {
    Named(Symbol),
    Path(Vec<Symbol>),
    Generic(Symbol, Vec<Type>),
    Ref(Box<Type>),                   // ref T: Generational reference
    Optional(Box<Type>),              // ?T: Option
    Slice(Box<Type>),                 // Slice<T>
    Array(Box<Type>, u32),            // [T; N]
    ErrorUnion(Box<Type>, Box<Type>), // Error!Success
    Tuple(Vec<Type>),
    Unit,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Type {
    pub kind: TypeKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub expr: Option<Box<Expr>>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    Let {
        is_mut: bool,
        name: Symbol,
        ty: Option<Type>,
        init: Option<Expr>,
        span: Span,
    },
    Assign {
        target: Expr,
        op: Option<AssignOp>,
        val: Expr,
        span: Span,
    },
    Expr(Expr),
    Defer(Block, Span),
    Return(Option<Expr>, Span),
    Fail(Expr, Span),
    While {
        cond: Expr,
        body: Block,
        span: Span,
    },
    For {
        var: Symbol,
        iterable: Expr,
        body: Block,
        span: Span,
    },
    Loop(Block, Span),
    Break(Span),
    Continue(Span),
}

impl Stmt {
    pub fn span(&self) -> Span {
        match self {
            Stmt::Let { span, .. } => *span,
            Stmt::Assign { span, .. } => *span,
            Stmt::Expr(e) => e.span,
            Stmt::Defer(_, span) => *span,
            Stmt::Return(_, span) => *span,
            Stmt::Fail(_, span) => *span,
            Stmt::While { span, .. } => *span,
            Stmt::For { span, .. } => *span,
            Stmt::Loop(_, span) => *span,
            Stmt::Break(span) => *span,
            Stmt::Continue(span) => *span,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    BitXor,
    BitAnd,
    BitOr,
    Shl,
    Shr,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Lit {
    Int(Symbol),
    Float(Symbol),
    String(Symbol),
    Char(char),
    Bool(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    And,
    Or,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    Coalesce, // ??
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Neg,
    Not,
    Try,
    Ref,
    InOut,
    Sink,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MatchArm {
    pub pattern: Pattern,
    pub guard: Option<Expr>,
    pub body: Expr,
    pub span: Span,
}

/// A single branch in a concurrent multi-channel `select` statement or expression.
#[derive(Debug, Clone, PartialEq)]
pub struct SelectArm {
    pub pattern: Option<Pattern>,
    pub channel: Option<Expr>,
    pub is_default: bool,
    pub body: Expr,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Pattern {
    Wildcard(Span),
    Lit(Lit, Span),
    Ident(Symbol, Span),
    Variant {
        enum_name: Option<Symbol>,
        variant: Symbol,
        inner: Option<Box<Pattern>>,
        span: Span,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Arg {
    pub name: Option<Symbol>,
    pub value: Expr,
    pub span: Span,
}

impl Arg {
    pub fn positional(value: Expr) -> Self {
        let span = value.span;
        Self {
            name: None,
            value,
            span,
        }
    }

    pub fn named(name: Symbol, value: Expr, span: Span) -> Self {
        Self {
            name: Some(name),
            value,
            span,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExprKind {
    Lit(Lit),
    Ident(Symbol),
    Path(Vec<Symbol>),
    Binary {
        op: BinOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    Unary {
        op: UnaryOp,
        expr: Box<Expr>,
    },
    Call {
        callee: Box<Expr>,
        args: Vec<Arg>,
    },
    MethodCall {
        receiver: Box<Expr>,
        method: Symbol,
        args: Vec<Arg>,
    },
    FieldAccess {
        receiver: Box<Expr>,
        field: Symbol,
    },
    Index {
        receiver: Box<Expr>,
        index: Box<Expr>,
    },
    Array(Vec<Expr>),
    ArrayRepeat(Box<Expr>, Box<Expr>),
    Record(Vec<(Symbol, Expr)>),
    Block(Block),
    If {
        cond: Box<Expr>,
        then_branch: Block,
        else_branch: Option<Box<Expr>>,
    },
    Match {
        expr: Box<Expr>,
        arms: Vec<MatchArm>,
    },
    Select {
        arms: Vec<SelectArm>,
    },
    Spawn(Box<Expr>),
    Catch {
        expr: Box<Expr>,
        err_var: Option<Symbol>,
        body: Block,
    },
    StructInit {
        name: Vec<Symbol>,
        fields: Vec<(Symbol, Expr)>,
    },
    Tuple(Vec<Expr>),
    Unit,
    Lambda {
        params: Vec<Param>,
        body: Block,
    },
    Comptime(Box<Expr>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Expr {
    pub kind: ExprKind,
    pub span: Span,
}

impl Expr {
    pub fn new(kind: ExprKind, span: Span) -> Self {
        Self { kind, span }
    }
}

pub trait Visitor<'ast>: Sized {
    fn visit_program(&mut self, prog: &'ast Program) {
        for item in &prog.items {
            self.visit_item(item);
        }
    }

    fn visit_item(&mut self, item: &'ast Item) {
        match item {
            Item::Function(f) => self.visit_function(f),
            Item::Struct(s) => self.visit_struct(s),
            Item::Enum(e) => self.visit_enum(e),
            Item::Import(i) => self.visit_import(i),
            Item::Const(c) => self.visit_const(c),
            Item::Trait(t) => self.visit_trait(t),
            Item::Impl(i) => self.visit_impl(i),
        }
    }

    fn visit_function(&mut self, func: &'ast Function) {
        if let Some(body) = &func.body {
            self.visit_block(body);
        }
    }

    fn visit_struct(&mut self, _st: &'ast Struct) {}
    fn visit_enum(&mut self, _en: &'ast Enum) {}
    fn visit_import(&mut self, _im: &'ast Import) {}
    fn visit_const(&mut self, c: &'ast Const) {
        self.visit_expr(&c.value);
    }
    fn visit_trait(&mut self, _t: &'ast Trait) {}
    fn visit_impl(&mut self, i: &'ast Impl) {
        for m in &i.methods {
            self.visit_function(m);
        }
    }

    fn visit_block(&mut self, block: &'ast Block) {
        for stmt in &block.stmts {
            self.visit_stmt(stmt);
        }
        if let Some(expr) = &block.expr {
            self.visit_expr(expr);
        }
    }

    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        match stmt {
            Stmt::Let { init, .. } => {
                if let Some(e) = init {
                    self.visit_expr(e);
                }
            }
            Stmt::Assign { target, val, .. } => {
                self.visit_expr(target);
                self.visit_expr(val);
            }
            Stmt::Expr(e) => self.visit_expr(e),
            Stmt::Defer(b, _) => self.visit_block(b),
            Stmt::Return(e, _) => {
                if let Some(expr) = e {
                    self.visit_expr(expr);
                }
            }
            Stmt::Fail(e, _) => self.visit_expr(e),
            Stmt::While { cond, body, .. } => {
                self.visit_expr(cond);
                self.visit_block(body);
            }
            Stmt::For { iterable, body, .. } => {
                self.visit_expr(iterable);
                self.visit_block(body);
            }
            Stmt::Loop(b, _) => self.visit_block(b),
            Stmt::Break(_) | Stmt::Continue(_) => {}
        }
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        match &expr.kind {
            ExprKind::Lit(_) | ExprKind::Ident(_) | ExprKind::Path(_) => {}
            ExprKind::Binary { left, right, .. } => {
                self.visit_expr(left);
                self.visit_expr(right);
            }
            ExprKind::Unary { expr, .. } => self.visit_expr(expr),
            ExprKind::Call { callee, args } => {
                self.visit_expr(callee);
                for arg in args {
                    self.visit_expr(&arg.value);
                }
            }
            ExprKind::MethodCall { receiver, args, .. } => {
                self.visit_expr(receiver);
                for arg in args {
                    self.visit_expr(&arg.value);
                }
            }
            ExprKind::FieldAccess { receiver, .. } => self.visit_expr(receiver),
            ExprKind::Index { receiver, index } => {
                self.visit_expr(receiver);
                self.visit_expr(index);
            }
            ExprKind::Array(elems) => {
                for elem in elems {
                    self.visit_expr(elem);
                }
            }
            ExprKind::ArrayRepeat(val, count) => {
                self.visit_expr(val);
                self.visit_expr(count);
            }
            ExprKind::Record(entries) => {
                for (_, val) in entries {
                    self.visit_expr(val);
                }
            }
            ExprKind::Block(b) => self.visit_block(b),
            ExprKind::If {
                cond,
                then_branch,
                else_branch,
            } => {
                self.visit_expr(cond);
                self.visit_block(then_branch);
                if let Some(els) = else_branch {
                    self.visit_expr(els);
                }
            }
            ExprKind::Match { expr, arms } => {
                self.visit_expr(expr);
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        self.visit_expr(guard);
                    }
                    self.visit_expr(&arm.body);
                }
            }
            ExprKind::Select { arms } => {
                for arm in arms {
                    if let Some(chan) = &arm.channel {
                        self.visit_expr(chan);
                    }
                    self.visit_expr(&arm.body);
                }
            }
            ExprKind::Spawn(e) => self.visit_expr(e),
            ExprKind::Catch { expr, body, .. } => {
                self.visit_expr(expr);
                self.visit_block(body);
            }
            ExprKind::StructInit { fields, .. } => {
                for (_, f_expr) in fields {
                    self.visit_expr(f_expr);
                }
            }
            ExprKind::Tuple(exprs) => {
                for expr in exprs {
                    self.visit_expr(expr);
                }
            }
            ExprKind::Unit => {}
            ExprKind::Lambda { body, .. } => {
                self.visit_block(body);
            }
            ExprKind::Comptime(e) => self.visit_expr(e),
        }
    }
}

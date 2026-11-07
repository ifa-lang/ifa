use crate::types::FirType;
use ifa_ast::ParamMode;
use ifa_sema::types::{FloatType, IntType};
use ifa_span::{Span, Symbol};
use std::fmt;

/// Unique identifier for an SSA value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValueId(pub u32);

impl fmt::Display for ValueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// Unique identifier for a basic block in the Control Flow Graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockId(pub u32);

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bb{}", self.0)
    }
}

/// Constant literal values in FIR.
#[derive(Debug, Clone, PartialEq)]
pub enum ConstantValue {
    Unit,
    Bool(bool),
    Int(i128, IntType),
    Float(f64, FloatType),
    Char(char),
    String(Symbol),
    Function(Symbol),
    Null,
}

impl fmt::Display for ConstantValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConstantValue::Unit => write!(f, "()"),
            ConstantValue::Bool(b) => write!(f, "{}", b),
            ConstantValue::Int(i, ty) => write!(f, "{}_{}", i, ty),
            ConstantValue::Float(fl, ty) => write!(f, "{}_{}", fl, ty),
            ConstantValue::Char(c) => write!(f, "{:?}", c),
            ConstantValue::String(s) => write!(f, "{:?}", s.as_str()),
            ConstantValue::Function(s) => write!(f, "fn({})", s.as_str()),
            ConstantValue::Null => write!(f, "null"),
        }
    }
}

/// Binary operators supported in FIR instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
}

impl fmt::Display for BinaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BinaryOp::Add => write!(f, "add"),
            BinaryOp::Sub => write!(f, "sub"),
            BinaryOp::Mul => write!(f, "mul"),
            BinaryOp::Div => write!(f, "div"),
            BinaryOp::Rem => write!(f, "rem"),
            BinaryOp::Eq => write!(f, "eq"),
            BinaryOp::Ne => write!(f, "ne"),
            BinaryOp::Lt => write!(f, "lt"),
            BinaryOp::Le => write!(f, "le"),
            BinaryOp::Gt => write!(f, "gt"),
            BinaryOp::Ge => write!(f, "ge"),
            BinaryOp::And => write!(f, "and"),
            BinaryOp::Or => write!(f, "or"),
            BinaryOp::BitAnd => write!(f, "bitand"),
            BinaryOp::BitOr => write!(f, "bitor"),
            BinaryOp::BitXor => write!(f, "bitxor"),
            BinaryOp::Shl => write!(f, "shl"),
            BinaryOp::Shr => write!(f, "shr"),
        }
    }
}

/// Unary operators supported in FIR instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnaryOp {
    Neg,
    Not,
}

impl fmt::Display for UnaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnaryOp::Neg => write!(f, "neg"),
            UnaryOp::Not => write!(f, "not"),
        }
    }
}

/// Core expression evaluated by a FIR instruction.
#[derive(Debug, Clone, PartialEq)]
pub enum ValueExpr {
    Constant(ConstantValue),
    Alloca {
        ty: FirType,
        name: Option<Symbol>,
    },
    Load {
        ptr: ValueId,
    },
    Store {
        ptr: ValueId,
        val: ValueId,
    },
    Binary {
        op: BinaryOp,
        lhs: ValueId,
        rhs: ValueId,
    },
    Unary {
        op: UnaryOp,
        val: ValueId,
    },
    GetField {
        base: ValueId,
        field_idx: usize,
        field_name: Symbol,
    },
    GetFieldPtr {
        base: ValueId,
        field_idx: usize,
        field_name: Symbol,
    },
    SetField {
        base: ValueId,
        field_idx: usize,
        val: ValueId,
    },
    GetElement {
        base: ValueId,
        index: ValueId,
    },
    GetElementPtr {
        base: ValueId,
        index: ValueId,
    },
    SetElement {
        base: ValueId,
        index: ValueId,
        val: ValueId,
    },
    Call {
        callee: ValueId,
        args: Vec<ValueId>,
    },
    CallDirect {
        name: Symbol,
        args: Vec<ValueId>,
    },
    StructInit {
        name: Symbol,
        fields: Vec<ValueId>,
    },
    TupleInit(Vec<ValueId>),
    ArrayInit(Vec<ValueId>),
    ArrayPush {
        array: ValueId,
        val: ValueId,
    },
    ArrayLen {
        array: ValueId,
    },
    SliceSub {
        base: ValueId,
        start: ValueId,
        end: ValueId,
    },
    StructPushField {
        base: ValueId,
        field_idx: usize,
        val: ValueId,
    },

    // Value Semantics & Copy-on-Write (CoW) Primitives
    CoWMakeUnique {
        val: ValueId,
    },
    CoWCheckShared {
        val: ValueId,
    },
    CoWClone {
        val: ValueId,
    },

    // Generational Reference Primitives
    GenAlloc {
        ty: FirType,
        arena: Option<u16>,
    },
    GenFree {
        ptr: ValueId,
    },
    GenRef {
        ptr: ValueId,
    },
    GenCheck {
        ref_val: ValueId,
        redundant: bool,
    },
    GenDeref {
        ref_val: ValueId,
    },

    // Concurrency / Fibers Primitives
    Yield,
    Spawn {
        target: Symbol,
        args: Vec<ValueId>,
    },
    ChanCreate {
        elem_ty: FirType,
        capacity: Option<ValueId>,
    },
    ChanSend {
        chan: ValueId,
        val: ValueId,
    },
    ChanRecv {
        chan: ValueId,
    },
    ChanTryRecv {
        chan: ValueId,
    },
    ChanClose {
        chan: ValueId,
    },
    ChanSelect {
        channels: Vec<ValueId>,
        has_default: bool,
    },

    // Algebraic Data Types (Enums / Tagged Unions) Primitives
    EnumInit {
        enum_name: Symbol,
        variant: Symbol,
        discriminant: u32,
        payload: Option<ValueId>,
    },
    EnumGetDiscriminant {
        base: ValueId,
    },
    EnumGetPayload {
        base: ValueId,
        payload_ty: FirType,
    },
    FormatString(Vec<ValueId>),
}

impl ValueExpr {
    /// Return all ValueIds used as inputs in this expression.
    pub fn uses(&self) -> Vec<ValueId> {
        match self {
            ValueExpr::Constant(_) | ValueExpr::Alloca { .. } | ValueExpr::Yield => Vec::new(),
            ValueExpr::Load { ptr } => vec![*ptr],
            ValueExpr::Store { ptr, val } => vec![*ptr, *val],
            ValueExpr::Binary { lhs, rhs, .. } => vec![*lhs, *rhs],
            ValueExpr::Unary { val, .. } => vec![*val],
            ValueExpr::GetField { base, .. } | ValueExpr::GetFieldPtr { base, .. } => {
                vec![*base]
            }
            ValueExpr::SetField { base, val, .. } => vec![*base, *val],
            ValueExpr::GetElement { base, index } | ValueExpr::GetElementPtr { base, index } => {
                vec![*base, *index]
            }
            ValueExpr::SetElement { base, index, val } => vec![*base, *index, *val],
            ValueExpr::Call { callee, args } => {
                let mut u = vec![*callee];
                u.extend_from_slice(args);
                u
            }
            ValueExpr::CallDirect { args, .. } => args.clone(),
            ValueExpr::StructInit { fields, .. } => fields.clone(),
            ValueExpr::TupleInit(fields) => fields.clone(),
            ValueExpr::ArrayInit(elements) => elements.clone(),
            ValueExpr::ArrayPush { array, val } => vec![*array, *val],
            ValueExpr::ArrayLen { array } => vec![*array],
            ValueExpr::SliceSub { base, start, end } => vec![*base, *start, *end],
            ValueExpr::StructPushField { base, val, .. } => vec![*base, *val],
            ValueExpr::CoWMakeUnique { val }
            | ValueExpr::CoWCheckShared { val }
            | ValueExpr::CoWClone { val } => vec![*val],
            ValueExpr::GenAlloc { .. } => Vec::new(),
            ValueExpr::GenFree { ptr } => vec![*ptr],
            ValueExpr::GenRef { ptr } => vec![*ptr],
            ValueExpr::GenCheck { ref_val, .. } => vec![*ref_val],
            ValueExpr::GenDeref { ref_val } => vec![*ref_val],
            ValueExpr::Spawn { args, .. } => args.clone(),
            ValueExpr::ChanCreate { capacity, .. } => capacity.iter().copied().collect(),
            ValueExpr::ChanSend { chan, val } => vec![*chan, *val],
            ValueExpr::ChanRecv { chan }
            | ValueExpr::ChanTryRecv { chan }
            | ValueExpr::ChanClose { chan } => vec![*chan],
            ValueExpr::ChanSelect { channels, .. } => channels.clone(),
            ValueExpr::EnumInit { payload, .. } => payload.iter().copied().collect(),
            ValueExpr::EnumGetDiscriminant { base } => vec![*base],
            ValueExpr::EnumGetPayload { base, .. } => vec![*base],
            ValueExpr::FormatString(parts) => parts.clone(),
        }
    }
}

/// A single SSA instruction in a basic block.
#[derive(Debug, Clone, PartialEq)]
pub struct Instruction {
    pub result: Option<ValueId>,
    pub expr: ValueExpr,
    pub span: Span,
}

impl Instruction {
    pub fn new(result: Option<ValueId>, expr: ValueExpr, span: Span) -> Self {
        Self { result, expr, span }
    }
}

/// Control flow terminator ending every basic block.
#[derive(Debug, Clone, PartialEq)]
pub enum Terminator {
    Branch {
        target: BlockId,
        args: Vec<ValueId>,
    },
    BranchCond {
        cond: ValueId,
        then_block: BlockId,
        then_args: Vec<ValueId>,
        else_block: BlockId,
        else_args: Vec<ValueId>,
    },
    Switch {
        val: ValueId,
        cases: Vec<(ConstantValue, BlockId, Vec<ValueId>)>,
        default_block: BlockId,
        default_args: Vec<ValueId>,
    },
    Return(Option<ValueId>),
    Fail(ValueId),
    Unreachable,
}

impl Terminator {
    /// Return target block successors for CFG traversal.
    pub fn successors(&self) -> Vec<BlockId> {
        match self {
            Terminator::Branch { target, .. } => vec![*target],
            Terminator::BranchCond {
                then_block,
                else_block,
                ..
            } => vec![*then_block, *else_block],
            Terminator::Switch {
                cases,
                default_block,
                ..
            } => {
                let mut succs: Vec<BlockId> = cases.iter().map(|(_, b, _)| *b).collect();
                succs.push(*default_block);
                succs
            }
            Terminator::Return(_) | Terminator::Fail(_) | Terminator::Unreachable => Vec::new(),
        }
    }

    /// Return all ValueIds used in this terminator.
    pub fn uses(&self) -> Vec<ValueId> {
        match self {
            Terminator::Branch { args, .. } => args.clone(),
            Terminator::BranchCond {
                cond,
                then_args,
                else_args,
                ..
            } => {
                let mut u = vec![*cond];
                u.extend_from_slice(then_args);
                u.extend_from_slice(else_args);
                u
            }
            Terminator::Switch {
                val,
                cases,
                default_args,
                ..
            } => {
                let mut u = vec![*val];
                for (_, _, args) in cases {
                    u.extend_from_slice(args);
                }
                u.extend_from_slice(default_args);
                u
            }
            Terminator::Return(Some(val)) => vec![*val],
            Terminator::Return(None) => Vec::new(),
            Terminator::Fail(val) => vec![*val],
            Terminator::Unreachable => Vec::new(),
        }
    }
}

/// Optimization hint for loop vectorization (SIMD lane width, interleave, and unroll directives).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LoopVectorHint {
    pub vector_width: u32,
    pub interleave_count: u32,
    pub unroll_enable: bool,
}

/// Basic block containing sequential instructions and ending with a terminator.
#[derive(Debug, Clone, PartialEq)]
pub struct BasicBlock {
    pub id: BlockId,
    pub params: Vec<(ValueId, FirType)>,
    pub instructions: Vec<Instruction>,
    pub terminator: Option<Terminator>,
    pub vector_hint: Option<LoopVectorHint>,
}

impl BasicBlock {
    pub fn new(id: BlockId) -> Self {
        Self {
            id,
            params: Vec::new(),
            instructions: Vec::new(),
            terminator: None,
            vector_hint: None,
        }
    }

    pub fn set_vector_hint(&mut self, hint: LoopVectorHint) {
        self.vector_hint = Some(hint);
    }

    pub fn push_param(&mut self, val: ValueId, ty: FirType) {
        self.params.push((val, ty));
    }

    pub fn push_instruction(&mut self, inst: Instruction) {
        self.instructions.push(inst);
    }

    pub fn set_terminator(&mut self, term: Terminator) {
        self.terminator = Some(term);
    }

    pub fn is_terminated(&self) -> bool {
        self.terminator.is_some()
    }
}

/// Function parameter in FIR.
#[derive(Debug, Clone, PartialEq)]
pub struct FirParam {
    pub name: Symbol,
    pub val: ValueId,
    pub ty: FirType,
    pub mode: ParamMode,
}

/// A function in SSA FIR.
#[derive(Debug, Clone, PartialEq)]
pub struct FirFunction {
    pub name: Symbol,
    pub params: Vec<FirParam>,
    pub ret_ty: FirType,
    pub blocks: Vec<BasicBlock>,
    pub entry_block: BlockId,
    pub is_strict: bool,
    pub is_pub: bool,
    pub is_comptime: bool,
    pub is_extern: Option<String>,
    pub span: Span,
    pub next_value_id: u32,
    pub next_block_id: u32,
}

impl FirFunction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: Symbol,
        params: Vec<FirParam>,
        ret_ty: FirType,
        is_strict: bool,
        is_pub: bool,
        is_comptime: bool,
        is_extern: Option<String>,
        span: Span,
    ) -> Self {
        let entry_id = BlockId(0);
        let entry_block = BasicBlock::new(entry_id);
        Self {
            name,
            params,
            ret_ty,
            blocks: vec![entry_block],
            entry_block: entry_id,
            is_strict,
            is_pub,
            is_comptime,
            is_extern,
            span,
            next_value_id: 0,
            next_block_id: 1,
        }
    }

    pub fn alloc_value(&mut self) -> ValueId {
        let id = ValueId(self.next_value_id);
        self.next_value_id += 1;
        id
    }

    pub fn alloc_block(&mut self) -> BlockId {
        let id = BlockId(self.next_block_id);
        self.next_block_id += 1;
        self.blocks.push(BasicBlock::new(id));
        id
    }

    pub fn get_block_mut(&mut self, id: BlockId) -> Option<&mut BasicBlock> {
        self.blocks.iter_mut().find(|b| b.id == id)
    }

    pub fn get_block(&self, id: BlockId) -> Option<&BasicBlock> {
        self.blocks.iter().find(|b| b.id == id)
    }
}

/// Structure definition in FIR.
#[derive(Debug, Clone, PartialEq)]
pub struct FirStruct {
    pub name: Symbol,
    pub fields: Vec<(Symbol, FirType)>,
    pub is_pub: bool,
    pub span: Span,
}

/// Enumeration definition in FIR.
#[derive(Debug, Clone, PartialEq)]
pub struct FirEnum {
    pub name: Symbol,
    pub variants: Vec<(Symbol, Option<FirType>)>,
    pub is_pub: bool,
    pub span: Span,
}

/// Global constant definition in FIR.
#[derive(Debug, Clone, PartialEq)]
pub struct FirConst {
    pub name: Symbol,
    pub ty: FirType,
    pub value: ConstantValue,
    pub is_pub: bool,
    pub span: Span,
}

/// Complete module in FIR containing all items.
#[derive(Debug, Clone, PartialEq)]
pub struct FirModule {
    pub name: Symbol,
    pub structs: Vec<FirStruct>,
    pub enums: Vec<FirEnum>,
    pub constants: Vec<FirConst>,
    pub functions: Vec<FirFunction>,
}

impl FirModule {
    pub fn new(name: Symbol) -> Self {
        Self {
            name,
            structs: Vec::new(),
            enums: Vec::new(),
            constants: Vec::new(),
            functions: Vec::new(),
        }
    }

    pub fn get_function(&self, name: &Symbol) -> Option<&FirFunction> {
        self.functions.iter().find(|f| &f.name == name)
    }

    pub fn get_function_mut(&mut self, name: &Symbol) -> Option<&mut FirFunction> {
        self.functions.iter_mut().find(|f| &f.name == name)
    }

    /// Merges definitions from another FIR module into this module, avoiding duplicates.
    pub fn merge(&mut self, other: FirModule) {
        for s in other.structs {
            if !self.structs.iter().any(|existing| existing.name == s.name) {
                self.structs.push(s);
            }
        }
        for e in other.enums {
            if !self.enums.iter().any(|existing| existing.name == e.name) {
                self.enums.push(e);
            }
        }
        for c in other.constants {
            if !self
                .constants
                .iter()
                .any(|existing| existing.name == c.name)
            {
                self.constants.push(c);
            }
        }
        for f in other.functions {
            if !self
                .functions
                .iter()
                .any(|existing| existing.name == f.name)
            {
                self.functions.push(f);
            }
        }
    }
}

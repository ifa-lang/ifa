use crate::value::Value;
use ifa_span::{Span, Symbol};

/// Low-level bytecode instruction set executed by the IFA compile-time VM.
#[derive(Debug, Clone, PartialEq)]
pub enum OpCode {
    // Constant & Stack management
    Const(u32),
    ConstInt(i64),
    ConstBool(bool),
    Unit,
    Pop,
    Dup,

    // Local Variables
    LoadLocal(u32),
    StoreLocal(u32),

    // Global / Top-level Variables
    LoadGlobal(Symbol),
    StoreGlobal(Symbol),

    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Neg,

    // Bitwise
    BitAnd,
    BitOr,
    BitXor,
    BitNot,
    Shl,
    Shr,

    // Logical & Comparison
    Not,
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,

    // Control Flow
    Jump(usize),
    JumpIfFalse(usize),
    JumpIfTrue(usize),

    // Compound Structures
    MakeArray(u32),
    MakeArrayRepeat,
    MakeTuple(u32),
    MakeStruct(Symbol, Vec<Symbol>),
    GetField(Symbol),
    SetField(Symbol),
    GetIndex,
    SetIndex,
    ArrayLen,

    // Function Calls & Control
    Call { func_name: Symbol, arg_count: u32 },
    CallIntrinsic { name: Symbol, arg_count: u32 },
    Return,

    // Assertions and Compile Errors
    Assert,
    CompileError,
}

/// A contiguous chunk of bytecode with associated debug spans and constant pool.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Chunk {
    pub code: Vec<OpCode>,
    pub spans: Vec<Span>,
    pub constants: Vec<Value>,
}

impl Chunk {
    pub fn new() -> Self {
        Self {
            code: Vec::new(),
            spans: Vec::new(),
            constants: Vec::new(),
        }
    }

    /// Emits an instruction into the bytecode stream.
    pub fn emit(&mut self, op: OpCode, span: Span) -> usize {
        let idx = self.code.len();
        self.code.push(op);
        self.spans.push(span);
        idx
    }

    /// Appends a constant value into the pool and returns its index.
    pub fn add_constant(&mut self, val: Value) -> u32 {
        self.constants.push(val);
        (self.constants.len() - 1) as u32
    }

    /// Emits a conditional or unconditional jump instruction with a dummy target.
    pub fn emit_jump(&mut self, op: OpCode, span: Span) -> usize {
        let idx = self.code.len();
        self.code.push(op);
        self.spans.push(span);
        idx
    }

    /// Patches a previously emitted jump instruction to point to the current code offset.
    pub fn patch_jump(&mut self, offset: usize) {
        let target = self.code.len();
        match &mut self.code[offset] {
            OpCode::Jump(t) | OpCode::JumpIfFalse(t) | OpCode::JumpIfTrue(t) => {
                *t = target;
            }
            _ => panic!("Tentative de patch d'instruction non-saut"),
        }
    }
}

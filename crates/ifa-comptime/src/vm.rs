use crate::compiler::{Compiler, FunctionBytecode};
use crate::error::{ComptimeError, ComptimeErrorKind};
use crate::intrinsics::call_intrinsic;
use crate::op::{Chunk, OpCode};
use crate::value::Value;
use ifa_ast::{Expr, Item, Program};
use ifa_span::{sym, Span, Symbol, INTERNER};
use std::collections::HashMap;

/// An active stack frame during bytecode execution.
#[derive(Debug, Clone)]
struct CallFrame {
    #[allow(dead_code)]
    func_name: Symbol,
    chunk: Chunk,
    ip: usize,
    base_pointer: usize,
}

/// The compile-time Virtual Machine executing IFA functions and expressions.
pub struct ComptimeVM {
    pub functions: HashMap<Symbol, FunctionBytecode>,
    pub constants: HashMap<Symbol, Value>,
    stack: Vec<Value>,
    frames: Vec<CallFrame>,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub max_call_depth: usize,
    pub max_memory_bytes: usize,
    pub memory_allocated: usize,
}

impl Default for ComptimeVM {
    fn default() -> Self {
        Self::new()
    }
}

impl ComptimeVM {
    /// Creates a fresh VM instance with safe defaults (1,000,000 max gas steps, max 512 call depth, 64 MiB memory sandbox).
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
            constants: HashMap::new(),
            stack: Vec::with_capacity(1024),
            frames: Vec::with_capacity(64),
            gas_limit: 1_000_000,
            gas_used: 0,
            max_call_depth: 512,
            max_memory_bytes: 64 * 1024 * 1024,
            memory_allocated: 0,
        }
    }

    /// Configures the maximum instruction gas allowed before aborting.
    pub fn with_gas_limit(mut self, limit: u64) -> Self {
        self.gas_limit = limit;
        self
    }

    /// Configures the maximum heap memory sandbox quota (in bytes) allowed before aborting.
    pub fn with_max_memory(mut self, limit_bytes: usize) -> Self {
        self.max_memory_bytes = limit_bytes;
        self
    }

    /// Checks if allocating `bytes` exceeds the memory sandbox quota.
    #[inline]
    pub fn check_memory_quota(&mut self, bytes: usize, span: Span) -> Result<(), ComptimeError> {
        if self.memory_allocated.saturating_add(bytes) > self.max_memory_bytes {
            return Err(ComptimeError::new(
                ComptimeErrorKind::MemoryLimitExceeded {
                    limit_bytes: self.max_memory_bytes,
                    requested_bytes: bytes,
                },
                span,
            ));
        }
        self.memory_allocated = self.memory_allocated.saturating_add(bytes);
        Ok(())
    }

    /// Registers a compiled function bytecode into the VM's function table.
    pub fn register_function(&mut self, func: FunctionBytecode) {
        self.functions.insert(func.name, func);
    }

    /// Registers a named constant value into the VM's constant environment.
    pub fn register_constant(&mut self, name: Symbol, value: Value) {
        self.constants.insert(name, value);
    }

    /// Loads an entire AST Program, registering functions and statically evaluating constants.
    pub fn load_program(&mut self, program: &Program) -> Result<(), ComptimeError> {
        // Pass 1: Compile all functions
        for item in &program.items {
            if let Item::Function(func) = item {
                let bc = Compiler::compile_function(func)?;
                self.register_function(bc);
            }
        }

        // Pass 2: Evaluate and register all top-level constants
        for item in &program.items {
            if let Item::Const(c) = item {
                let val = self.eval_expr(&c.value)?;
                self.register_constant(c.name, val);
            }
        }

        Ok(())
    }

    /// Compiles and evaluates an arbitrary expression in the current VM environment.
    pub fn eval_expr(&mut self, expr: &Expr) -> Result<Value, ComptimeError> {
        let chunk = Compiler::compile_expr_to_chunk(expr)?;
        self.stack.clear();
        self.frames.clear();
        self.gas_used = 0;
        self.memory_allocated = 0;

        let frame = CallFrame {
            func_name: sym("__comptime_eval"),
            chunk,
            ip: 0,
            base_pointer: 0,
        };
        self.frames.push(frame);

        self.run()
    }

    /// Executes a registered function by name with given arguments.
    pub fn call_function(
        &mut self,
        name: Symbol,
        args: Vec<Value>,
        span: Span,
    ) -> Result<Value, ComptimeError> {
        let func = self.functions.get(&name).cloned().ok_or_else(|| {
            ComptimeError::new(
                ComptimeErrorKind::UndefinedFunction(INTERNER.resolve(&name)),
                span,
            )
        })?;

        if args.len() != func.params.len() {
            return Err(ComptimeError::new(
                ComptimeErrorKind::ArityMismatch {
                    expected: func.params.len(),
                    found: args.len(),
                },
                span,
            ));
        }

        self.stack.clear();
        self.frames.clear();
        self.gas_used = 0;
        self.memory_allocated = 0;

        let base_pointer = 0;
        for arg in args {
            self.stack.push(arg);
        }

        // Reserve slots for locals beyond parameters
        for _ in func.params.len()..func.num_locals {
            self.stack.push(Value::Unit);
        }

        let frame = CallFrame {
            func_name: name,
            chunk: func.chunk,
            ip: 0,
            base_pointer,
        };
        self.frames.push(frame);

        self.run()
    }

    /// Core bytecode interpreter execution loop.
    pub fn run(&mut self) -> Result<Value, ComptimeError> {
        while let Some(frame) = self.frames.last_mut() {
            if self.gas_used >= self.gas_limit {
                let span = if frame.ip > 0 && frame.ip - 1 < frame.chunk.spans.len() {
                    frame.chunk.spans[frame.ip - 1]
                } else {
                    Span::new(
                        ifa_span::FileId(0),
                        ifa_span::BytePos(0),
                        ifa_span::BytePos(0),
                    )
                };
                return Err(ComptimeError::new(
                    ComptimeErrorKind::GasLimitExceeded {
                        limit: self.gas_limit,
                    },
                    span,
                ));
            }
            self.gas_used += 1;

            if frame.ip >= frame.chunk.code.len() {
                // Fallen through without return: pop frame and return Unit
                self.frames.pop();
                if self.frames.is_empty() {
                    return Ok(self.stack.pop().unwrap_or(Value::Unit));
                }
                continue;
            }

            let op = frame.chunk.code[frame.ip].clone();
            let span = frame.chunk.spans[frame.ip];
            frame.ip += 1;

            match op {
                OpCode::Const(idx) => {
                    let val = frame.chunk.constants[idx as usize].clone();
                    self.stack.push(val);
                }
                OpCode::ConstInt(val) => {
                    self.stack.push(Value::Int(val));
                }
                OpCode::ConstBool(val) => {
                    self.stack.push(Value::Bool(val));
                }
                OpCode::Unit => {
                    self.stack.push(Value::Unit);
                }
                OpCode::Pop => {
                    self.stack.pop();
                }
                OpCode::Dup => {
                    let top =
                        self.stack.last().cloned().ok_or_else(|| {
                            ComptimeError::new(ComptimeErrorKind::EmptyStack, span)
                        })?;
                    self.stack.push(top);
                }
                OpCode::LoadLocal(slot) => {
                    let base = self.frames.last().unwrap().base_pointer;
                    let val = self.stack[base + slot as usize].clone();
                    self.stack.push(val);
                }
                OpCode::StoreLocal(slot) => {
                    let val = self
                        .stack
                        .pop()
                        .ok_or_else(|| ComptimeError::new(ComptimeErrorKind::EmptyStack, span))?;
                    let base = self.frames.last().unwrap().base_pointer;
                    self.stack[base + slot as usize] = val;
                }
                OpCode::LoadGlobal(sym) => {
                    if let Some(val) = self.constants.get(&sym) {
                        self.stack.push(val.clone());
                    } else {
                        let name = INTERNER.resolve(&sym);
                        return Err(ComptimeError::new(
                            ComptimeErrorKind::UndefinedVariable(name),
                            span,
                        ));
                    }
                }
                OpCode::StoreGlobal(sym) => {
                    let val = self
                        .stack
                        .pop()
                        .ok_or_else(|| ComptimeError::new(ComptimeErrorKind::EmptyStack, span))?;
                    self.constants.insert(sym, val);
                }
                OpCode::Add => {
                    let right = self.pop_stack(span)?;
                    let left = self.pop_stack(span)?;
                    self.stack.push(left.add(&right, span)?);
                }
                OpCode::Sub => {
                    let right = self.pop_stack(span)?;
                    let left = self.pop_stack(span)?;
                    self.stack.push(left.sub(&right, span)?);
                }
                OpCode::Mul => {
                    let right = self.pop_stack(span)?;
                    let left = self.pop_stack(span)?;
                    self.stack.push(left.mul(&right, span)?);
                }
                OpCode::Div => {
                    let right = self.pop_stack(span)?;
                    let left = self.pop_stack(span)?;
                    self.stack.push(left.div(&right, span)?);
                }
                OpCode::Mod => {
                    let right = self.pop_stack(span)?;
                    let left = self.pop_stack(span)?;
                    self.stack.push(left.rem(&right, span)?);
                }
                OpCode::Neg => {
                    let top = self.pop_stack(span)?;
                    self.stack.push(top.neg(span)?);
                }
                OpCode::Not => {
                    let top = self.pop_stack(span)?;
                    self.stack.push(top.not(span)?);
                }
                OpCode::BitAnd => {
                    let right = self.pop_stack(span)?;
                    let left = self.pop_stack(span)?;
                    self.stack.push(left.bit_and(&right, span)?);
                }
                OpCode::BitOr => {
                    let right = self.pop_stack(span)?;
                    let left = self.pop_stack(span)?;
                    self.stack.push(left.bit_or(&right, span)?);
                }
                OpCode::BitXor => {
                    let right = self.pop_stack(span)?;
                    let left = self.pop_stack(span)?;
                    self.stack.push(left.bit_xor(&right, span)?);
                }
                OpCode::BitNot => {
                    let top = self.pop_stack(span)?;
                    self.stack.push(top.bit_not(span)?);
                }
                OpCode::Shl => {
                    let right = self.pop_stack(span)?;
                    let left = self.pop_stack(span)?;
                    self.stack.push(left.shl(&right, span)?);
                }
                OpCode::Shr => {
                    let right = self.pop_stack(span)?;
                    let left = self.pop_stack(span)?;
                    self.stack.push(left.shr(&right, span)?);
                }
                OpCode::Eq => {
                    let right = self.pop_stack(span)?;
                    let left = self.pop_stack(span)?;
                    self.stack.push(Value::Bool(left.val_eq(&right)));
                }
                OpCode::NotEq => {
                    let right = self.pop_stack(span)?;
                    let left = self.pop_stack(span)?;
                    self.stack.push(Value::Bool(!left.val_eq(&right)));
                }
                OpCode::Lt => {
                    let right = self.pop_stack(span)?;
                    let left = self.pop_stack(span)?;
                    self.stack.push(left.lt(&right, span)?);
                }
                OpCode::LtEq => {
                    let right = self.pop_stack(span)?;
                    let left = self.pop_stack(span)?;
                    self.stack.push(left.lte(&right, span)?);
                }
                OpCode::Gt => {
                    let right = self.pop_stack(span)?;
                    let left = self.pop_stack(span)?;
                    self.stack.push(left.gt(&right, span)?);
                }
                OpCode::GtEq => {
                    let right = self.pop_stack(span)?;
                    let left = self.pop_stack(span)?;
                    self.stack.push(left.gte(&right, span)?);
                }
                OpCode::Jump(target) => {
                    self.frames.last_mut().unwrap().ip = target;
                }
                OpCode::JumpIfFalse(target) => {
                    let cond = self.pop_stack(span)?;
                    if !cond.is_truthy() {
                        self.frames.last_mut().unwrap().ip = target;
                    }
                }
                OpCode::JumpIfTrue(target) => {
                    let cond = self.pop_stack(span)?;
                    if cond.is_truthy() {
                        self.frames.last_mut().unwrap().ip = target;
                    }
                }
                OpCode::MakeArray(count) => {
                    let mem_req = (count as usize).saturating_mul(std::mem::size_of::<Value>());
                    self.check_memory_quota(mem_req, span)?;
                    let mut elems = Vec::with_capacity(count as usize);
                    for _ in 0..count {
                        elems.push(self.pop_stack(span)?);
                    }
                    elems.reverse();
                    self.stack.push(Value::Array(elems));
                }
                OpCode::MakeArrayRepeat => {
                    let count_val = self.pop_stack(span)?;
                    let initial_val = self.pop_stack(span)?;
                    let count = count_val.as_int().ok_or_else(|| {
                        ComptimeError::new(
                            ComptimeErrorKind::TypeMismatch {
                                expected: "int".to_string(),
                                found: count_val.type_name().to_string(),
                            },
                            span,
                        )
                    })?;
                    if count < 0 {
                        return Err(ComptimeError::new(
                            ComptimeErrorKind::ArrayRepeatNegativeCount(count),
                            span,
                        ));
                    }
                    let requested_bytes =
                        (count as usize).saturating_mul(std::mem::size_of::<Value>());
                    self.check_memory_quota(requested_bytes, span)?;
                    let arr = vec![initial_val; count as usize];
                    self.stack.push(Value::Array(arr));
                }
                OpCode::MakeTuple(count) => {
                    let mem_req = (count as usize).saturating_mul(std::mem::size_of::<Value>());
                    self.check_memory_quota(mem_req, span)?;
                    let mut items = Vec::with_capacity(count as usize);
                    for _ in 0..count {
                        items.push(self.pop_stack(span)?);
                    }
                    items.reverse();
                    self.stack.push(Value::Tuple(items));
                }
                OpCode::MakeStruct(name, field_names) => {
                    let mem_req = field_names
                        .len()
                        .saturating_mul(std::mem::size_of::<(Symbol, Value)>());
                    self.check_memory_quota(mem_req, span)?;
                    let mut fields = Vec::with_capacity(field_names.len());
                    for &fname in field_names.iter().rev() {
                        let val = self.pop_stack(span)?;
                        fields.push((fname, val));
                    }
                    fields.reverse();
                    self.stack.push(Value::Struct { name, fields });
                }
                OpCode::GetField(field) => {
                    let st = self.pop_stack(span)?;
                    self.stack.push(st.get_field(field, span)?);
                }
                OpCode::SetField(field) => {
                    let val = self.pop_stack(span)?;
                    let mut st = self.pop_stack(span)?;
                    st.set_field(field, val, span)?;
                    self.stack.push(st);
                }
                OpCode::GetIndex => {
                    let index_val = self.pop_stack(span)?;
                    let target = self.pop_stack(span)?;
                    let idx = index_val.as_int().ok_or_else(|| {
                        ComptimeError::new(
                            ComptimeErrorKind::TypeMismatch {
                                expected: "int".to_string(),
                                found: index_val.type_name().to_string(),
                            },
                            span,
                        )
                    })?;
                    self.stack.push(target.get_index(idx, span)?);
                }
                OpCode::SetIndex => {
                    let val = self.pop_stack(span)?;
                    let index_val = self.pop_stack(span)?;
                    let mut target = self.pop_stack(span)?;
                    let idx = index_val.as_int().ok_or_else(|| {
                        ComptimeError::new(
                            ComptimeErrorKind::TypeMismatch {
                                expected: "int".to_string(),
                                found: index_val.type_name().to_string(),
                            },
                            span,
                        )
                    })?;
                    target.set_index(idx, val, span)?;
                    self.stack.push(target);
                }
                OpCode::ArrayLen => {
                    let target = self.pop_stack(span)?;
                    let length = target.len(span)?;
                    self.stack.push(Value::Int(length as i64));
                }
                OpCode::Call {
                    func_name,
                    arg_count,
                } => {
                    let func = self.functions.get(&func_name).cloned().ok_or_else(|| {
                        ComptimeError::new(
                            ComptimeErrorKind::UndefinedFunction(INTERNER.resolve(&func_name)),
                            span,
                        )
                    })?;

                    if (arg_count as usize) != func.params.len() {
                        return Err(ComptimeError::new(
                            ComptimeErrorKind::ArityMismatch {
                                expected: func.params.len(),
                                found: arg_count as usize,
                            },
                            span,
                        ));
                    }

                    if self.frames.len() >= self.max_call_depth {
                        return Err(ComptimeError::new(
                            ComptimeErrorKind::CallStackOverflow {
                                max_depth: self.max_call_depth,
                            },
                            span,
                        ));
                    }

                    let base_pointer = self.stack.len() - arg_count as usize;
                    // Allocate remaining local slots beyond arguments
                    for _ in (arg_count as usize)..func.num_locals {
                        self.stack.push(Value::Unit);
                    }

                    let new_frame = CallFrame {
                        func_name,
                        chunk: func.chunk,
                        ip: 0,
                        base_pointer,
                    };
                    self.frames.push(new_frame);
                }
                OpCode::CallIntrinsic { name, arg_count } => {
                    let mut args = Vec::with_capacity(arg_count as usize);
                    for _ in 0..arg_count {
                        args.push(self.pop_stack(span)?);
                    }
                    args.reverse();
                    let res = call_intrinsic(name, &args, span)?;
                    self.stack.push(res);
                }
                OpCode::Return => {
                    let ret_val = self
                        .stack
                        .pop()
                        .ok_or_else(|| ComptimeError::new(ComptimeErrorKind::EmptyStack, span))?;
                    let finished_frame = self.frames.pop().unwrap();
                    // Clean up local slots
                    self.stack.truncate(finished_frame.base_pointer);

                    if self.frames.is_empty() {
                        return Ok(ret_val);
                    } else {
                        self.stack.push(ret_val);
                    }
                }
                OpCode::Assert => {
                    let cond = self.pop_stack(span)?;
                    if !cond.is_truthy() {
                        return Err(ComptimeError::new(
                            ComptimeErrorKind::AssertionFailed(
                                "assertion échouée à la compilation".to_string(),
                            ),
                            span,
                        ));
                    }
                }
                OpCode::CompileError => {
                    let msg = self.pop_stack(span)?;
                    return Err(ComptimeError::new(
                        ComptimeErrorKind::CompileError(msg.to_string()),
                        span,
                    ));
                }
            }
        }

        Ok(self.stack.pop().unwrap_or(Value::Unit))
    }

    fn pop_stack(&mut self, span: Span) -> Result<Value, ComptimeError> {
        self.stack
            .pop()
            .ok_or_else(|| ComptimeError::new(ComptimeErrorKind::EmptyStack, span))
    }
}

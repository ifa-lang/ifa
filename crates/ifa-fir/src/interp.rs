use crate::ir::*;
use crate::types::FirType;
use ifa_span::{Symbol, INTERNER};
use std::collections::{HashMap, VecDeque};
use std::fmt;

/// Runtime value representation for FIR SSA execution.
#[derive(Debug, Clone, PartialEq)]
pub enum FirValue {
    Unit,
    Bool(bool),
    Int(i128),
    Float(f64),
    String(String),
    Pointer(usize),
    FieldPointer {
        base_addr: usize,
        path: Vec<usize>,
    },
    ElementPointer {
        base_addr: usize,
        index: usize,
    },
    HeapFieldPointer {
        slot: usize,
        generation: u32,
        path: Vec<usize>,
    },
    GenRef {
        slot: usize,
        generation: u32,
    },
    Array(Vec<FirValue>),
    Tuple(Vec<FirValue>),
    Struct {
        name: Symbol,
        fields: Vec<FirValue>,
    },
    Enum {
        enum_name: Symbol,
        variant: Symbol,
        discriminant: u32,
        payload: Option<Box<FirValue>>,
    },
    Null,
}

impl FirValue {
    pub fn is_truthy(&self) -> bool {
        match self {
            FirValue::Bool(b) => *b,
            FirValue::Int(i) => *i != 0,
            FirValue::String(s) => !s.is_empty(),
            FirValue::Unit | FirValue::Null => false,
            FirValue::GenRef { slot, generation } => *slot != 0 || *generation != 0,
            _ => true,
        }
    }

    pub fn is_null(&self) -> bool {
        match self {
            FirValue::Null => true,
            FirValue::GenRef { slot, generation } => *slot == 0 && *generation == 0,
            _ => false,
        }
    }
}

impl fmt::Display for FirValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FirValue::Unit => write!(f, "()"),
            FirValue::Bool(b) => write!(f, "{}", b),
            FirValue::Int(i) => write!(f, "{}", i),
            FirValue::Float(fl) => write!(f, "{}", fl),
            FirValue::String(s) => write!(f, "{}", s),
            FirValue::Pointer(addr) => write!(f, "ptr(0x{:x})", addr),
            FirValue::FieldPointer { base_addr, path } => {
                let p = path
                    .iter()
                    .map(|i| format!("#{}", i))
                    .collect::<Vec<_>>()
                    .join(".");
                write!(f, "field_ptr(0x{:x}.{})", base_addr, p)
            }
            FirValue::HeapFieldPointer {
                slot,
                generation,
                path,
            } => {
                let p = path
                    .iter()
                    .map(|i| format!("#{}", i))
                    .collect::<Vec<_>>()
                    .join(".");
                write!(f, "heap_field_ptr({}#{}@{})", slot, generation, p)
            }
            FirValue::ElementPointer { base_addr, index } => {
                write!(f, "elem_ptr(0x{:x}[{}])", base_addr, index)
            }
            FirValue::GenRef { slot, generation } => {
                write!(f, "ref(slot={}, gen={})", slot, generation)
            }
            FirValue::Array(elements) => {
                write!(f, "[")?;
                for (i, el) in elements.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", el)?;
                }
                write!(f, "]")
            }
            FirValue::Tuple(fields) => {
                write!(f, "(")?;
                for (i, el) in fields.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", el)?;
                }
                write!(f, ")")
            }
            FirValue::Struct { name, fields } => {
                write!(f, "{} {{", name)?;
                for (i, field) in fields.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", field)?;
                }
                write!(f, "}}")
            }
            FirValue::Enum {
                enum_name,
                variant,
                payload,
                ..
            } => {
                if let Some(p) = payload {
                    write!(f, "{}::{}({})", enum_name.as_str(), variant.as_str(), p)
                } else {
                    write!(f, "{}::{}", enum_name.as_str(), variant.as_str())
                }
            }
            FirValue::Null => write!(f, "null"),
        }
    }
}

/// Generational memory header representing a slab slot with 32-bit generation counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenHeader {
    pub generation_counter: u32,
    pub is_allocated: bool,
}

/// Generational slab heap providing deterministic memory safety without GC.
#[derive(Debug, Default)]
pub struct GenHeap {
    slots: Vec<(GenHeader, FirValue)>,
    free_list: Vec<usize>,
}

impl GenHeap {
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            free_list: Vec::new(),
        }
    }

    /// Allocate a value on the generational heap, assigning a slot and generation.
    pub fn alloc(&mut self, val: FirValue) -> (usize, u32) {
        if let Some(slot) = self.free_list.pop() {
            let (header, slot_val) = &mut self.slots[slot];
            header.is_allocated = true;
            *slot_val = val;
            (slot, header.generation_counter)
        } else {
            let slot = self.slots.len();
            let header = GenHeader {
                generation_counter: 1,
                is_allocated: true,
            };
            self.slots.push((header, val));
            (slot, 1)
        }
    }

    /// Free a slot, incrementing generation counter to detect any subsequent Use-After-Free.
    pub fn free(&mut self, slot: usize) -> Result<(), InterpError> {
        if slot >= self.slots.len() {
            return Err(InterpError::InvalidPointer(slot));
        }
        let (header, val) = &mut self.slots[slot];
        if !header.is_allocated {
            return Err(InterpError::DoubleFree(slot));
        }
        header.is_allocated = false;
        header.generation_counter = header.generation_counter.wrapping_add(1);
        *val = FirValue::Unit;
        self.free_list.push(slot);
        Ok(())
    }

    /// 1-cycle CPU generation check: verify target slot generation matches remembered generation.
    pub fn check(&self, slot: usize, remembered_gen: u32) -> Result<(), InterpError> {
        if slot >= self.slots.len() {
            return Err(InterpError::InvalidPointer(slot));
        }
        let (header, _) = &self.slots[slot];
        if !header.is_allocated || header.generation_counter != remembered_gen {
            return Err(InterpError::UseAfterFree {
                slot,
                expected_gen: remembered_gen,
                actual_gen: header.generation_counter,
            });
        }
        Ok(())
    }

    /// Dereference slot after verification.
    pub fn deref(&self, slot: usize) -> Result<&FirValue, InterpError> {
        if slot >= self.slots.len() {
            return Err(InterpError::InvalidPointer(slot));
        }
        let (header, val) = &self.slots[slot];
        if !header.is_allocated {
            return Err(InterpError::UseAfterFree {
                slot,
                expected_gen: header.generation_counter,
                actual_gen: header.generation_counter,
            });
        }
        Ok(val)
    }

    /// Dereference mutable slot after verification.
    pub fn deref_mut(&mut self, slot: usize) -> Result<&mut FirValue, InterpError> {
        if slot >= self.slots.len() {
            return Err(InterpError::InvalidPointer(slot));
        }
        let (header, val) = &mut self.slots[slot];
        if !header.is_allocated {
            return Err(InterpError::UseAfterFree {
                slot,
                expected_gen: header.generation_counter,
                actual_gen: header.generation_counter,
            });
        }
        Ok(val)
    }
}

/// Execution error produced during FIR SSA interpretation.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum InterpError {
    #[error("Use-After-Free detected at slot {slot}: expected generation {expected_gen}, got {actual_gen}")]
    UseAfterFree {
        slot: usize,
        expected_gen: u32,
        actual_gen: u32,
    },
    #[error("Double free detected at slot {0}")]
    DoubleFree(usize),
    #[error("Invalid pointer address 0x{0:x}")]
    InvalidPointer(usize),
    #[error("Use of undefined SSA value {0}")]
    UndefinedValue(ValueId),
    #[error("Type mismatch during execution: {0}")]
    TypeMismatch(String),
    #[error("Integer division by zero")]
    DivisionByZero,
    #[error("Function @{0} not found in module")]
    FunctionNotFound(String),
    #[error("Program reached block without terminator")]
    BlockNotTerminated,
    #[error("Program reached unreachable terminator")]
    UnreachableReached,
    #[error("Explicit fail returned: {0}")]
    ExplicitFail(String),
    #[error("Execution panic: {0}")]
    Panic(String),
}

fn navigate_value<'b>(root: &'b FirValue, path: &[usize]) -> Result<&'b FirValue, InterpError> {
    let mut cur = root;
    for (step, &idx) in path.iter().enumerate() {
        match cur {
            FirValue::Struct { fields, .. } | FirValue::Tuple(fields) => {
                if let Some(next) = fields.get(idx) {
                    cur = next;
                } else {
                    return Err(InterpError::Panic(format!(
                        "Field index {} out of bounds at path step {}",
                        idx, step
                    )));
                }
            }
            other => {
                return Err(InterpError::TypeMismatch(format!(
                    "Cannot traverse field {} on non-composite value {}",
                    idx, other
                )));
            }
        }
    }
    Ok(cur)
}

fn navigate_value_mut<'b>(
    root: &'b mut FirValue,
    path: &[usize],
) -> Result<&'b mut FirValue, InterpError> {
    let mut cur = root;
    for (step, &idx) in path.iter().enumerate() {
        match cur {
            FirValue::Struct { fields, .. } | FirValue::Tuple(fields) => {
                if let Some(next) = fields.get_mut(idx) {
                    cur = next;
                } else {
                    return Err(InterpError::Panic(format!(
                        "Field index {} out of bounds at path step {}",
                        idx, step
                    )));
                }
            }
            other => {
                return Err(InterpError::TypeMismatch(format!(
                    "Cannot traverse field {} on non-composite value {}",
                    idx, other
                )));
            }
        }
    }
    Ok(cur)
}

/// SSA FIR Interpreter executing functions deterministically.
pub struct FirInterpreter<'a> {
    module: &'a FirModule,
    pub heap: GenHeap,
    pub stack_memory: HashMap<usize, FirValue>,
    next_stack_addr: usize,
    pub captured_output: Vec<String>,
    pub channels: HashMap<u64, VecDeque<FirValue>>,
    next_chan_id: u64,
}

impl<'a> FirInterpreter<'a> {
    pub fn new(module: &'a FirModule) -> Self {
        Self {
            module,
            heap: GenHeap::new(),
            stack_memory: HashMap::new(),
            next_stack_addr: 0x1000,
            captured_output: Vec::new(),
            channels: HashMap::new(),
            next_chan_id: 1,
        }
    }

    /// Find a function by its interned symbol or name string.
    pub fn find_function(&self, name: &str) -> Option<&'a FirFunction> {
        self.module
            .functions
            .iter()
            .find(|f| INTERNER.resolve(&f.name) == name)
    }

    /// Find a struct declaration by its symbol or name string.
    pub fn find_struct(&self, name: &str) -> Option<&'a FirStruct> {
        self.module
            .structs
            .iter()
            .find(|s| INTERNER.resolve(&s.name) == name)
    }

    /// Resolve field position for a known struct or fallback to precalculated index.
    fn resolve_struct_field_index(
        &self,
        struct_name: Symbol,
        fallback_idx: usize,
        field_name: Symbol,
    ) -> usize {
        if let Some(st) = self.module.structs.iter().find(|s| s.name == struct_name) {
            if let Some(pos) = st.fields.iter().position(|(f, _)| *f == field_name) {
                return pos;
            }
        }
        fallback_idx
    }

    /// Execute a function by name with provided arguments.
    pub fn execute_function(
        &mut self,
        name: &str,
        args: Vec<FirValue>,
    ) -> Result<FirValue, InterpError> {
        let func = self
            .find_function(name)
            .cloned()
            .ok_or_else(|| InterpError::FunctionNotFound(name.to_string()))?;
        self.execute_fir_function(&func, args)
    }

    /// Execute a specific FIR function.
    pub fn execute_fir_function(
        &mut self,
        func: &FirFunction,
        args: Vec<FirValue>,
    ) -> Result<FirValue, InterpError> {
        let mut env: HashMap<ValueId, FirValue> = HashMap::new();

        // Bind function parameters
        for (param, arg) in func.params.iter().zip(args) {
            env.insert(param.val, arg);
        }

        let mut current_block = func.entry_block;

        loop {
            let block = func.get_block(current_block).ok_or_else(|| {
                InterpError::Panic(format!("Block {:?} not found", current_block))
            })?;

            // Execute instructions within the basic block
            for inst in &block.instructions {
                let res = self.evaluate_expr(&inst.expr, &env)?;
                if let Some(val_id) = inst.result {
                    env.insert(val_id, res);
                }
            }

            // Execute the block terminator
            let term = block
                .terminator
                .as_ref()
                .ok_or(InterpError::BlockNotTerminated)?;

            match term {
                Terminator::Return(ret_val) => {
                    let val = if let Some(v_id) = ret_val {
                        env.get(v_id)
                            .cloned()
                            .ok_or(InterpError::UndefinedValue(*v_id))?
                    } else {
                        FirValue::Unit
                    };
                    let final_val = match val {
                        FirValue::GenRef { slot, generation }
                            if !matches!(func.ret_ty, FirType::GenerationalRef(_)) =>
                        {
                            self.heap.check(slot, generation)?;
                            self.heap.deref(slot)?.clone()
                        }
                        other => other,
                    };
                    return Ok(final_val);
                }
                Terminator::Fail(fail_val) => {
                    let val = env
                        .get(fail_val)
                        .cloned()
                        .ok_or(InterpError::UndefinedValue(*fail_val))?;
                    if matches!(func.ret_ty, FirType::ErrorUnion { .. }) {
                        return Ok(FirValue::Tuple(vec![FirValue::Int(1), val]));
                    }
                    return Err(InterpError::ExplicitFail(val.to_string()));
                }
                Terminator::Branch { target, args } => {
                    let target_block = func.get_block(*target).ok_or_else(|| {
                        InterpError::Panic(format!("Target block {:?} not found", target))
                    })?;

                    let mut target_vals = Vec::new();
                    for a in args {
                        let v = env.get(a).cloned().ok_or(InterpError::UndefinedValue(*a))?;
                        target_vals.push(v);
                    }

                    for ((param_id, _), val) in target_block.params.iter().zip(target_vals) {
                        env.insert(*param_id, val);
                    }

                    current_block = *target;
                }
                Terminator::BranchCond {
                    cond,
                    then_block,
                    then_args,
                    else_block,
                    else_args,
                } => {
                    let cond_val = env.get(cond).ok_or(InterpError::UndefinedValue(*cond))?;
                    let (target, args) = if cond_val.is_truthy() {
                        (*then_block, then_args)
                    } else {
                        (*else_block, else_args)
                    };

                    let target_bb = func.get_block(target).ok_or_else(|| {
                        InterpError::Panic(format!("Target block {:?} not found", target))
                    })?;

                    let mut target_vals = Vec::new();
                    for a in args {
                        let v = env.get(a).cloned().ok_or(InterpError::UndefinedValue(*a))?;
                        target_vals.push(v);
                    }

                    for ((param_id, _), val) in target_bb.params.iter().zip(target_vals) {
                        env.insert(*param_id, val);
                    }

                    current_block = target;
                }
                Terminator::Switch {
                    val,
                    cases,
                    default_block,
                    default_args,
                } => {
                    let switch_val = env
                        .get(val)
                        .cloned()
                        .ok_or(InterpError::UndefinedValue(*val))?;
                    let mut matched = false;

                    for (c_val, target, args) in cases {
                        let matches = match (c_val, &switch_val) {
                            (ConstantValue::Int(a, _), FirValue::Int(b)) => *a == *b,
                            (ConstantValue::Bool(a), FirValue::Bool(b)) => a == b,
                            (ConstantValue::String(a), FirValue::String(b)) => {
                                INTERNER.resolve(a) == *b
                            }
                            (ConstantValue::Function(a), FirValue::String(b)) => {
                                INTERNER.resolve(a) == *b
                            }
                            _ => false,
                        };

                        if matches {
                            let target_bb = func.get_block(*target).ok_or_else(|| {
                                InterpError::Panic(format!("Target block {:?} not found", target))
                            })?;

                            for ((param_id, _), arg_id) in target_bb.params.iter().zip(args) {
                                let v = env
                                    .get(arg_id)
                                    .cloned()
                                    .ok_or(InterpError::UndefinedValue(*arg_id))?;
                                env.insert(*param_id, v);
                            }
                            current_block = *target;
                            matched = true;
                            break;
                        }
                    }

                    if !matched {
                        let target_bb = func.get_block(*default_block).ok_or_else(|| {
                            InterpError::Panic(format!(
                                "Default block {:?} not found",
                                default_block
                            ))
                        })?;

                        for ((param_id, _), arg_id) in target_bb.params.iter().zip(default_args) {
                            let v = env
                                .get(arg_id)
                                .cloned()
                                .ok_or(InterpError::UndefinedValue(*arg_id))?;
                            env.insert(*param_id, v);
                        }
                        current_block = *default_block;
                    }
                }
                Terminator::Unreachable => return Err(InterpError::UnreachableReached),
            }
        }
    }

    /// Evaluate an SSA ValueExpr within the current environment.
    fn evaluate_expr(
        &mut self,
        expr: &ValueExpr,
        env: &HashMap<ValueId, FirValue>,
    ) -> Result<FirValue, InterpError> {
        match expr {
            ValueExpr::Constant(c) => Ok(match c {
                ConstantValue::Unit => FirValue::Unit,
                ConstantValue::Bool(b) => FirValue::Bool(*b),
                ConstantValue::Int(i, _) => FirValue::Int(*i),
                ConstantValue::Float(f, _) => FirValue::Float(*f),
                ConstantValue::Char(ch) => FirValue::Int(*ch as u32 as i128),
                ConstantValue::String(s) => FirValue::String(INTERNER.resolve(s)),
                ConstantValue::Function(s) => FirValue::String(INTERNER.resolve(s)),
                ConstantValue::Null => FirValue::Null,
            }),

            ValueExpr::Alloca { .. } => {
                let addr = self.next_stack_addr;
                self.next_stack_addr += 8;
                self.stack_memory.insert(addr, FirValue::Unit);
                Ok(FirValue::Pointer(addr))
            }

            ValueExpr::Store { ptr, val } => {
                let ptr_val = env.get(ptr).ok_or(InterpError::UndefinedValue(*ptr))?;
                let val_to_store = env
                    .get(val)
                    .cloned()
                    .ok_or(InterpError::UndefinedValue(*val))?;

                match ptr_val {
                    FirValue::Pointer(addr) => {
                        self.stack_memory.insert(*addr, val_to_store);
                        Ok(FirValue::Unit)
                    }
                    FirValue::FieldPointer { base_addr, path } => {
                        let target = self
                            .stack_memory
                            .get_mut(base_addr)
                            .ok_or(InterpError::InvalidPointer(*base_addr))?;
                        let leaf = navigate_value_mut(target, path)?;
                        *leaf = val_to_store;
                        Ok(FirValue::Unit)
                    }
                    FirValue::HeapFieldPointer {
                        slot,
                        generation,
                        path,
                    } => {
                        self.heap.check(*slot, *generation)?;
                        let target = self.heap.deref_mut(*slot)?;
                        let leaf = navigate_value_mut(target, path)?;
                        *leaf = val_to_store;
                        Ok(FirValue::Unit)
                    }
                    FirValue::ElementPointer { base_addr, index } => {
                        let target = self
                            .stack_memory
                            .get_mut(base_addr)
                            .ok_or(InterpError::InvalidPointer(*base_addr))?;
                        match target {
                            FirValue::Array(elements) => {
                                if let Some(slot) = elements.get_mut(*index) {
                                    *slot = val_to_store;
                                    Ok(FirValue::Unit)
                                } else {
                                    Err(InterpError::Panic(format!(
                                        "Element index {} out of bounds",
                                        index
                                    )))
                                }
                            }
                            other => Err(InterpError::TypeMismatch(format!(
                                "ElementPointer target must be array, got {}",
                                other
                            ))),
                        }
                    }
                    FirValue::GenRef { slot, generation } => {
                        self.heap.check(*slot, *generation)?;
                        let target = self.heap.deref_mut(*slot)?;
                        *target = val_to_store;
                        Ok(FirValue::Unit)
                    }
                    other => Err(InterpError::TypeMismatch(format!(
                        "Store target must be pointer, got {}",
                        other
                    ))),
                }
            }

            ValueExpr::Load { ptr } => {
                let ptr_val = env.get(ptr).ok_or(InterpError::UndefinedValue(*ptr))?;
                match ptr_val {
                    FirValue::Pointer(addr) => {
                        let val = self
                            .stack_memory
                            .get(addr)
                            .cloned()
                            .unwrap_or(FirValue::Unit);
                        Ok(val)
                    }
                    FirValue::FieldPointer { base_addr, path } => {
                        let target = self
                            .stack_memory
                            .get(base_addr)
                            .ok_or(InterpError::InvalidPointer(*base_addr))?;
                        let leaf = navigate_value(target, path)?;
                        Ok(leaf.clone())
                    }
                    FirValue::HeapFieldPointer {
                        slot,
                        generation,
                        path,
                    } => {
                        self.heap.check(*slot, *generation)?;
                        let target = self.heap.deref(*slot)?;
                        let leaf = navigate_value(target, path)?;
                        Ok(leaf.clone())
                    }
                    FirValue::ElementPointer { base_addr, index } => {
                        let target = self
                            .stack_memory
                            .get(base_addr)
                            .ok_or(InterpError::InvalidPointer(*base_addr))?;
                        match target {
                            FirValue::Array(elements) => {
                                if let Some(el) = elements.get(*index) {
                                    Ok(el.clone())
                                } else {
                                    Err(InterpError::Panic(format!(
                                        "Element index {} out of bounds",
                                        index
                                    )))
                                }
                            }
                            other => Err(InterpError::TypeMismatch(format!(
                                "ElementPointer target must be array, got {}",
                                other
                            ))),
                        }
                    }
                    FirValue::GenRef { slot, generation } => {
                        self.heap.check(*slot, *generation)?;
                        let target = self.heap.deref(*slot)?;
                        Ok(target.clone())
                    }
                    other => Err(InterpError::TypeMismatch(format!(
                        "Load source must be pointer, got {}",
                        other
                    ))),
                }
            }

            ValueExpr::Binary { op, lhs, rhs } => {
                let l = env.get(lhs).ok_or(InterpError::UndefinedValue(*lhs))?;
                let r = env.get(rhs).ok_or(InterpError::UndefinedValue(*rhs))?;
                self.evaluate_binary_op(*op, l, r)
            }

            ValueExpr::Unary { op, val } => {
                let v = env.get(val).ok_or(InterpError::UndefinedValue(*val))?;
                match (op, v) {
                    (UnaryOp::Neg, FirValue::Int(i)) => Ok(FirValue::Int(-i)),
                    (UnaryOp::Neg, FirValue::Float(f)) => Ok(FirValue::Float(-f)),
                    (UnaryOp::Not, FirValue::Bool(b)) => Ok(FirValue::Bool(!b)),
                    _ => Err(InterpError::TypeMismatch(format!(
                        "Invalid unary op {:?} on {}",
                        op, v
                    ))),
                }
            }

            ValueExpr::GetField {
                base,
                field_idx,
                field_name,
            } => {
                let base_val = env.get(base).ok_or(InterpError::UndefinedValue(*base))?;
                match base_val {
                    FirValue::Struct { name, fields } => {
                        let actual_idx =
                            self.resolve_struct_field_index(*name, *field_idx, *field_name);
                        if let Some(f) = fields.get(actual_idx) {
                            Ok(f.clone())
                        } else {
                            Err(InterpError::Panic(format!(
                                "Field index {} out of bounds",
                                actual_idx
                            )))
                        }
                    }
                    FirValue::Tuple(fields) => {
                        if let Some(f) = fields.get(*field_idx) {
                            Ok(f.clone())
                        } else {
                            Err(InterpError::Panic(format!(
                                "Tuple index {} out of bounds",
                                field_idx
                            )))
                        }
                    }
                    FirValue::Pointer(addr) => {
                        if let Some(target) = self.stack_memory.get(addr) {
                            match target {
                                FirValue::Struct { name, fields } => {
                                    let actual_idx = self.resolve_struct_field_index(
                                        *name,
                                        *field_idx,
                                        *field_name,
                                    );
                                    if let Some(f) = fields.get(actual_idx) {
                                        Ok(f.clone())
                                    } else {
                                        Err(InterpError::Panic(format!(
                                            "Field index {} out of bounds",
                                            actual_idx
                                        )))
                                    }
                                }
                                FirValue::GenRef { slot, generation } => {
                                    self.heap.check(*slot, *generation)?;
                                    let heap_val = self.heap.deref(*slot)?;
                                    if let FirValue::Struct { name, fields } = heap_val {
                                        let actual_idx = self.resolve_struct_field_index(
                                            *name,
                                            *field_idx,
                                            *field_name,
                                        );
                                        if let Some(f) = fields.get(actual_idx) {
                                            Ok(f.clone())
                                        } else {
                                            Err(InterpError::Panic(format!(
                                                "Field index {} out of bounds",
                                                actual_idx
                                            )))
                                        }
                                    } else {
                                        Err(InterpError::TypeMismatch(
                                            "Heap target is not a struct".into(),
                                        ))
                                    }
                                }
                                _ => Err(InterpError::TypeMismatch(
                                    "Pointer target is not a struct".into(),
                                )),
                            }
                        } else {
                            Err(InterpError::InvalidPointer(*addr))
                        }
                    }
                    FirValue::GenRef { slot, generation } => {
                        self.heap.check(*slot, *generation)?;
                        let heap_val = self.heap.deref(*slot)?;
                        if let FirValue::Struct { name, fields } = heap_val {
                            let actual_idx =
                                self.resolve_struct_field_index(*name, *field_idx, *field_name);
                            if let Some(f) = fields.get(actual_idx) {
                                Ok(f.clone())
                            } else {
                                Err(InterpError::Panic(format!(
                                    "Field index {} out of bounds",
                                    actual_idx
                                )))
                            }
                        } else {
                            Err(InterpError::TypeMismatch(
                                "Referenced target is not a struct".into(),
                            ))
                        }
                    }
                    FirValue::FieldPointer { base_addr, path } => {
                        let target = self
                            .stack_memory
                            .get(base_addr)
                            .ok_or(InterpError::InvalidPointer(*base_addr))?;
                        let sub = navigate_value(target, path)?;
                        match sub {
                            FirValue::Struct { name, fields } => {
                                let actual_idx =
                                    self.resolve_struct_field_index(*name, *field_idx, *field_name);
                                if let Some(f) = fields.get(actual_idx) {
                                    Ok(f.clone())
                                } else {
                                    Err(InterpError::Panic(format!(
                                        "Field index {} out of bounds",
                                        actual_idx
                                    )))
                                }
                            }
                            FirValue::Tuple(fields) => {
                                if let Some(f) = fields.get(*field_idx) {
                                    Ok(f.clone())
                                } else {
                                    Err(InterpError::Panic(format!(
                                        "Tuple index {} out of bounds",
                                        field_idx
                                    )))
                                }
                            }
                            FirValue::GenRef { slot, generation } => {
                                self.heap.check(*slot, *generation)?;
                                let heap_val = self.heap.deref(*slot)?;
                                if let FirValue::Struct { name, fields } = heap_val {
                                    let actual_idx = self.resolve_struct_field_index(
                                        *name,
                                        *field_idx,
                                        *field_name,
                                    );
                                    if let Some(f) = fields.get(actual_idx) {
                                        Ok(f.clone())
                                    } else {
                                        Err(InterpError::Panic(format!(
                                            "Field index {} out of bounds",
                                            actual_idx
                                        )))
                                    }
                                } else {
                                    Err(InterpError::TypeMismatch(
                                        "Heap target is not a struct".into(),
                                    ))
                                }
                            }
                            other => Err(InterpError::TypeMismatch(format!(
                                "Cannot access field of {}",
                                other
                            ))),
                        }
                    }
                    FirValue::HeapFieldPointer {
                        slot,
                        generation,
                        path,
                    } => {
                        self.heap.check(*slot, *generation)?;
                        let target = self.heap.deref(*slot)?;
                        let sub = navigate_value(target, path)?;
                        match sub {
                            FirValue::Struct { name, fields } => {
                                let actual_idx =
                                    self.resolve_struct_field_index(*name, *field_idx, *field_name);
                                if let Some(f) = fields.get(actual_idx) {
                                    Ok(f.clone())
                                } else {
                                    Err(InterpError::Panic(format!(
                                        "Field index {} out of bounds",
                                        actual_idx
                                    )))
                                }
                            }
                            FirValue::Tuple(fields) => {
                                if let Some(f) = fields.get(*field_idx) {
                                    Ok(f.clone())
                                } else {
                                    Err(InterpError::Panic(format!(
                                        "Tuple index {} out of bounds",
                                        field_idx
                                    )))
                                }
                            }
                            FirValue::GenRef { slot, generation } => {
                                self.heap.check(*slot, *generation)?;
                                let heap_val = self.heap.deref(*slot)?;
                                if let FirValue::Struct { name, fields } = heap_val {
                                    let actual_idx = self.resolve_struct_field_index(
                                        *name,
                                        *field_idx,
                                        *field_name,
                                    );
                                    if let Some(f) = fields.get(actual_idx) {
                                        Ok(f.clone())
                                    } else {
                                        Err(InterpError::Panic(format!(
                                            "Field index {} out of bounds",
                                            actual_idx
                                        )))
                                    }
                                } else {
                                    Err(InterpError::TypeMismatch(
                                        "Heap target is not a struct".into(),
                                    ))
                                }
                            }
                            other => Err(InterpError::TypeMismatch(format!(
                                "Cannot access field of {}",
                                other
                            ))),
                        }
                    }
                    other => Err(InterpError::TypeMismatch(format!(
                        "Cannot access field of {}",
                        other
                    ))),
                }
            }

            ValueExpr::GetFieldPtr {
                base,
                field_idx,
                field_name,
            } => {
                let base_val = env.get(base).ok_or(InterpError::UndefinedValue(*base))?;
                match base_val {
                    FirValue::Pointer(addr) => {
                        let actual_idx = if let Some(FirValue::Struct { name, .. }) =
                            self.stack_memory.get(addr)
                        {
                            self.resolve_struct_field_index(*name, *field_idx, *field_name)
                        } else {
                            *field_idx
                        };
                        Ok(FirValue::FieldPointer {
                            base_addr: *addr,
                            path: vec![actual_idx],
                        })
                    }
                    FirValue::FieldPointer { base_addr, path } => {
                        let actual_idx = if let Some(target) = self.stack_memory.get(base_addr) {
                            if let Ok(FirValue::Struct { name, .. }) = navigate_value(target, path)
                            {
                                self.resolve_struct_field_index(*name, *field_idx, *field_name)
                            } else {
                                *field_idx
                            }
                        } else {
                            *field_idx
                        };
                        let mut new_path = path.clone();
                        new_path.push(actual_idx);
                        Ok(FirValue::FieldPointer {
                            base_addr: *base_addr,
                            path: new_path,
                        })
                    }
                    FirValue::GenRef { slot, generation } => {
                        self.heap.check(*slot, *generation)?;
                        let actual_idx =
                            if let Ok(FirValue::Struct { name, .. }) = self.heap.deref(*slot) {
                                self.resolve_struct_field_index(*name, *field_idx, *field_name)
                            } else {
                                *field_idx
                            };
                        Ok(FirValue::HeapFieldPointer {
                            slot: *slot,
                            generation: *generation,
                            path: vec![actual_idx],
                        })
                    }
                    FirValue::HeapFieldPointer {
                        slot,
                        generation,
                        path,
                    } => {
                        self.heap.check(*slot, *generation)?;
                        let actual_idx = if let Ok(target) = self.heap.deref(*slot) {
                            if let Ok(FirValue::Struct { name, .. }) = navigate_value(target, path)
                            {
                                self.resolve_struct_field_index(*name, *field_idx, *field_name)
                            } else {
                                *field_idx
                            }
                        } else {
                            *field_idx
                        };
                        let mut new_path = path.clone();
                        new_path.push(actual_idx);
                        Ok(FirValue::HeapFieldPointer {
                            slot: *slot,
                            generation: *generation,
                            path: new_path,
                        })
                    }
                    other => Err(InterpError::TypeMismatch(format!(
                        "GetFieldPtr requires pointer base, got {}",
                        other
                    ))),
                }
            }

            ValueExpr::SetField {
                base,
                field_idx,
                val,
            } => {
                let base_val = env.get(base).ok_or(InterpError::UndefinedValue(*base))?;
                let val_to_set = env
                    .get(val)
                    .cloned()
                    .ok_or(InterpError::UndefinedValue(*val))?;

                match base_val {
                    FirValue::Pointer(addr) => {
                        if let Some(struct_val) = self.stack_memory.get_mut(addr) {
                            match struct_val {
                                FirValue::Struct { fields, .. } => {
                                    if let Some(slot) = fields.get_mut(*field_idx) {
                                        *slot = val_to_set;
                                        Ok(FirValue::Unit)
                                    } else {
                                        Err(InterpError::Panic(format!(
                                            "Field index {} out of bounds",
                                            field_idx
                                        )))
                                    }
                                }
                                FirValue::GenRef { slot, generation } => {
                                    let slot_num = *slot;
                                    let gen_num = *generation;
                                    self.heap.check(slot_num, gen_num)?;
                                    let target = self.heap.deref_mut(slot_num)?;
                                    if let FirValue::Struct { fields, .. } = target {
                                        if let Some(field_slot) = fields.get_mut(*field_idx) {
                                            *field_slot = val_to_set;
                                            Ok(FirValue::Unit)
                                        } else {
                                            Err(InterpError::Panic(format!(
                                                "Field index {} out of bounds",
                                                field_idx
                                            )))
                                        }
                                    } else {
                                        Err(InterpError::TypeMismatch(
                                            "Referenced target is not a struct".into(),
                                        ))
                                    }
                                }
                                _ => {
                                    Err(InterpError::TypeMismatch("Target must be a struct".into()))
                                }
                            }
                        } else {
                            Err(InterpError::InvalidPointer(*addr))
                        }
                    }
                    FirValue::GenRef { slot, generation } => {
                        self.heap.check(*slot, *generation)?;
                        let target = self.heap.deref_mut(*slot)?;
                        if let FirValue::Struct { fields, .. } = target {
                            if let Some(field_slot) = fields.get_mut(*field_idx) {
                                *field_slot = val_to_set;
                                Ok(FirValue::Unit)
                            } else {
                                Err(InterpError::Panic(format!(
                                    "Field index {} out of bounds",
                                    field_idx
                                )))
                            }
                        } else {
                            Err(InterpError::TypeMismatch(
                                "Referenced target is not a struct".into(),
                            ))
                        }
                    }
                    FirValue::FieldPointer { base_addr, path } => {
                        let target = self
                            .stack_memory
                            .get_mut(base_addr)
                            .ok_or(InterpError::InvalidPointer(*base_addr))?;
                        let sub_struct = navigate_value_mut(target, path)?;
                        match sub_struct {
                            FirValue::Struct { fields, .. } => {
                                if let Some(slot) = fields.get_mut(*field_idx) {
                                    *slot = val_to_set;
                                    Ok(FirValue::Unit)
                                } else {
                                    Err(InterpError::Panic(format!(
                                        "Field index {} out of bounds",
                                        field_idx
                                    )))
                                }
                            }
                            _ => Err(InterpError::TypeMismatch("Target must be a struct".into())),
                        }
                    }
                    FirValue::HeapFieldPointer {
                        slot,
                        generation,
                        path,
                    } => {
                        self.heap.check(*slot, *generation)?;
                        let target = self.heap.deref_mut(*slot)?;
                        let sub_struct = navigate_value_mut(target, path)?;
                        match sub_struct {
                            FirValue::Struct { fields, .. } => {
                                if let Some(slot_item) = fields.get_mut(*field_idx) {
                                    *slot_item = val_to_set;
                                    Ok(FirValue::Unit)
                                } else {
                                    Err(InterpError::Panic(format!(
                                        "Field index {} out of bounds",
                                        field_idx
                                    )))
                                }
                            }
                            _ => Err(InterpError::TypeMismatch("Target must be a struct".into())),
                        }
                    }
                    _ => Err(InterpError::TypeMismatch(
                        "SetField requires pointer or generational reference".into(),
                    )),
                }
            }

            ValueExpr::GetElement { base, index } => {
                let base_val = env.get(base).ok_or(InterpError::UndefinedValue(*base))?;
                let idx_val = env.get(index).ok_or(InterpError::UndefinedValue(*index))?;
                let idx = match idx_val {
                    FirValue::Int(i) => *i as usize,
                    _ => return Err(InterpError::TypeMismatch("Index must be an integer".into())),
                };

                match base_val {
                    FirValue::Array(elements) => {
                        if let Some(el) = elements.get(idx) {
                            Ok(el.clone())
                        } else {
                            Err(InterpError::Panic(format!(
                                "Array index {} out of bounds",
                                idx
                            )))
                        }
                    }
                    FirValue::Pointer(addr) => {
                        if let Some(target) = self.stack_memory.get(addr) {
                            match target {
                                FirValue::Array(elements) => {
                                    if let Some(el) = elements.get(idx) {
                                        Ok(el.clone())
                                    } else {
                                        Err(InterpError::Panic(format!(
                                            "Array index {} out of bounds",
                                            idx
                                        )))
                                    }
                                }
                                FirValue::GenRef { slot, generation } => {
                                    self.heap.check(*slot, *generation)?;
                                    let heap_val = self.heap.deref(*slot)?;
                                    if let FirValue::Array(elements) = heap_val {
                                        if let Some(el) = elements.get(idx) {
                                            Ok(el.clone())
                                        } else {
                                            Err(InterpError::Panic(format!(
                                                "Array index {} out of bounds",
                                                idx
                                            )))
                                        }
                                    } else {
                                        Err(InterpError::TypeMismatch(
                                            "Heap target is not an array".into(),
                                        ))
                                    }
                                }
                                _ => Err(InterpError::TypeMismatch(
                                    "Pointer target is not an array".into(),
                                )),
                            }
                        } else {
                            Err(InterpError::InvalidPointer(*addr))
                        }
                    }
                    FirValue::GenRef { slot, generation } => {
                        self.heap.check(*slot, *generation)?;
                        let heap_val = self.heap.deref(*slot)?;
                        if let FirValue::Array(elements) = heap_val {
                            if let Some(el) = elements.get(idx) {
                                Ok(el.clone())
                            } else {
                                Err(InterpError::Panic(format!(
                                    "Array index {} out of bounds",
                                    idx
                                )))
                            }
                        } else {
                            Err(InterpError::TypeMismatch(
                                "Referenced target is not an array".into(),
                            ))
                        }
                    }
                    FirValue::String(s) => {
                        if let Some(byte) = s.as_bytes().get(idx) {
                            Ok(FirValue::Int(*byte as i128))
                        } else {
                            Err(InterpError::Panic(format!(
                                "String index {} out of bounds",
                                idx
                            )))
                        }
                    }
                    other => Err(InterpError::TypeMismatch(format!(
                        "Cannot index into {}",
                        other
                    ))),
                }
            }

            ValueExpr::GetElementPtr { base, index } => {
                let base_val = env.get(base).ok_or(InterpError::UndefinedValue(*base))?;
                let idx_val = env.get(index).ok_or(InterpError::UndefinedValue(*index))?;
                let idx = match idx_val {
                    FirValue::Int(i) => *i as usize,
                    _ => return Err(InterpError::TypeMismatch("Index must be an integer".into())),
                };
                match base_val {
                    FirValue::Pointer(addr) => Ok(FirValue::ElementPointer {
                        base_addr: *addr,
                        index: idx,
                    }),
                    other => Err(InterpError::TypeMismatch(format!(
                        "GetElementPtr requires pointer base, got {}",
                        other
                    ))),
                }
            }

            ValueExpr::SetElement { base, index, val } => {
                let base_val = env.get(base).ok_or(InterpError::UndefinedValue(*base))?;
                let idx_val = env.get(index).ok_or(InterpError::UndefinedValue(*index))?;
                let val_to_set = env
                    .get(val)
                    .cloned()
                    .ok_or(InterpError::UndefinedValue(*val))?;

                let idx = match idx_val {
                    FirValue::Int(i) => *i as usize,
                    _ => return Err(InterpError::TypeMismatch("Index must be an integer".into())),
                };

                match base_val {
                    FirValue::Pointer(addr) => {
                        if let Some(arr_val) = self.stack_memory.get_mut(addr) {
                            match arr_val {
                                FirValue::Array(elements) => {
                                    if let Some(slot) = elements.get_mut(idx) {
                                        *slot = val_to_set;
                                        Ok(FirValue::Unit)
                                    } else {
                                        Err(InterpError::Panic(format!(
                                            "Array index {} out of bounds",
                                            idx
                                        )))
                                    }
                                }
                                FirValue::GenRef { slot, generation } => {
                                    let slot_num = *slot;
                                    let gen_num = *generation;
                                    self.heap.check(slot_num, gen_num)?;
                                    let target = self.heap.deref_mut(slot_num)?;
                                    if let FirValue::Array(elements) = target {
                                        if let Some(slot) = elements.get_mut(idx) {
                                            *slot = val_to_set;
                                            Ok(FirValue::Unit)
                                        } else {
                                            Err(InterpError::Panic(format!(
                                                "Array index {} out of bounds",
                                                idx
                                            )))
                                        }
                                    } else {
                                        Err(InterpError::TypeMismatch(
                                            "Heap target is not an array".into(),
                                        ))
                                    }
                                }
                                _ => {
                                    Err(InterpError::TypeMismatch("Target must be an array".into()))
                                }
                            }
                        } else {
                            Err(InterpError::InvalidPointer(*addr))
                        }
                    }
                    FirValue::GenRef { slot, generation } => {
                        self.heap.check(*slot, *generation)?;
                        let target = self.heap.deref_mut(*slot)?;
                        if let FirValue::Array(elements) = target {
                            if let Some(slot) = elements.get_mut(idx) {
                                *slot = val_to_set;
                                Ok(FirValue::Unit)
                            } else {
                                Err(InterpError::Panic(format!(
                                    "Array index {} out of bounds",
                                    idx
                                )))
                            }
                        } else {
                            Err(InterpError::TypeMismatch(
                                "Referenced target is not an array".into(),
                            ))
                        }
                    }
                    _ => Err(InterpError::TypeMismatch(
                        "SetElement requires pointer or reference".into(),
                    )),
                }
            }

            ValueExpr::ArrayPush { array, val } => {
                let arr_val = env.get(array).ok_or(InterpError::UndefinedValue(*array))?;
                let val_to_push = env
                    .get(val)
                    .cloned()
                    .ok_or(InterpError::UndefinedValue(*val))?;
                match arr_val {
                    FirValue::Pointer(addr) => {
                        if let Some(target) = self.stack_memory.get_mut(addr) {
                            match target {
                                FirValue::Array(elements) => {
                                    elements.push(val_to_push);
                                    Ok(FirValue::Unit)
                                }
                                FirValue::GenRef { slot, generation } => {
                                    let s = *slot;
                                    let g = *generation;
                                    self.heap.check(s, g)?;
                                    let heap_target = self.heap.deref_mut(s)?;
                                    if let FirValue::Array(elements) = heap_target {
                                        elements.push(val_to_push);
                                        Ok(FirValue::Unit)
                                    } else {
                                        Err(InterpError::TypeMismatch(
                                            "Heap slot is not an array".into(),
                                        ))
                                    }
                                }
                                _ => {
                                    Err(InterpError::TypeMismatch("Target must be an array".into()))
                                }
                            }
                        } else {
                            Err(InterpError::InvalidPointer(*addr))
                        }
                    }
                    FirValue::GenRef { slot, generation } => {
                        self.heap.check(*slot, *generation)?;
                        let heap_target = self.heap.deref_mut(*slot)?;
                        if let FirValue::Array(elements) = heap_target {
                            elements.push(val_to_push);
                            Ok(FirValue::Unit)
                        } else {
                            Err(InterpError::TypeMismatch(
                                "Referenced target is not an array".into(),
                            ))
                        }
                    }
                    _ => Err(InterpError::TypeMismatch(
                        "ArrayPush requires pointer or reference".into(),
                    )),
                }
            }

            ValueExpr::ArrayLen { array } => {
                let arr_val = env.get(array).ok_or(InterpError::UndefinedValue(*array))?;
                match arr_val {
                    FirValue::Array(elements) => Ok(FirValue::Int(elements.len() as i128)),
                    FirValue::String(s) => Ok(FirValue::Int(s.len() as i128)),
                    FirValue::Pointer(addr) => {
                        if let Some(target) = self.stack_memory.get(addr) {
                            match target {
                                FirValue::Array(elements) => {
                                    Ok(FirValue::Int(elements.len() as i128))
                                }
                                FirValue::String(s) => Ok(FirValue::Int(s.len() as i128)),
                                FirValue::GenRef { slot, generation } => {
                                    self.heap.check(*slot, *generation)?;
                                    if let FirValue::Array(elements) = self.heap.deref(*slot)? {
                                        Ok(FirValue::Int(elements.len() as i128))
                                    } else if let FirValue::String(s) = self.heap.deref(*slot)? {
                                        Ok(FirValue::Int(s.len() as i128))
                                    } else {
                                        Ok(FirValue::Int(0))
                                    }
                                }
                                _ => Ok(FirValue::Int(0)),
                            }
                        } else {
                            Err(InterpError::InvalidPointer(*addr))
                        }
                    }
                    FirValue::GenRef { slot, generation } => {
                        self.heap.check(*slot, *generation)?;
                        if let FirValue::Array(elements) = self.heap.deref(*slot)? {
                            Ok(FirValue::Int(elements.len() as i128))
                        } else if let FirValue::String(s) = self.heap.deref(*slot)? {
                            Ok(FirValue::Int(s.len() as i128))
                        } else {
                            Ok(FirValue::Int(0))
                        }
                    }
                    _ => Ok(FirValue::Int(0)),
                }
            }

            ValueExpr::SliceSub { base, start, end } => {
                let base_val = env.get(base).ok_or(InterpError::UndefinedValue(*base))?;
                let start_val = env.get(start).ok_or(InterpError::UndefinedValue(*start))?;
                let end_val = env.get(end).ok_or(InterpError::UndefinedValue(*end))?;
                let s_idx = match start_val {
                    FirValue::Int(i) => (*i).max(0) as usize,
                    _ => {
                        return Err(InterpError::TypeMismatch(
                            "Slice start must be an integer".into(),
                        ))
                    }
                };
                let e_idx = match end_val {
                    FirValue::Int(i) => (*i).max(0) as usize,
                    _ => {
                        return Err(InterpError::TypeMismatch(
                            "Slice end must be an integer".into(),
                        ))
                    }
                };

                let extract_sub = |elements: &[FirValue]| -> FirValue {
                    let s = s_idx.min(elements.len());
                    let e = e_idx.min(elements.len()).max(s);
                    FirValue::Array(elements[s..e].to_vec())
                };

                match base_val {
                    FirValue::Array(elements) => Ok(extract_sub(elements)),
                    FirValue::Pointer(addr) => {
                        if let Some(target) = self.stack_memory.get(addr) {
                            match target {
                                FirValue::Array(elements) => Ok(extract_sub(elements)),
                                _ => Err(InterpError::TypeMismatch(
                                    "Referenced target is not an array".into(),
                                )),
                            }
                        } else {
                            Err(InterpError::InvalidPointer(*addr))
                        }
                    }
                    FirValue::GenRef { slot, generation } => {
                        self.heap.check(*slot, *generation)?;
                        if let FirValue::Array(elements) = self.heap.deref(*slot)? {
                            Ok(extract_sub(elements))
                        } else {
                            Err(InterpError::TypeMismatch(
                                "Referenced target is not an array".into(),
                            ))
                        }
                    }
                    _ => Err(InterpError::TypeMismatch(
                        "Base for SliceSub must be an array or slice".into(),
                    )),
                }
            }

            ValueExpr::StructPushField {
                base,
                field_idx,
                val,
            } => {
                let base_val = env.get(base).ok_or(InterpError::UndefinedValue(*base))?;
                let val_to_push = env
                    .get(val)
                    .cloned()
                    .ok_or(InterpError::UndefinedValue(*val))?;
                match base_val {
                    FirValue::Pointer(addr) => {
                        if let Some(target) = self.stack_memory.get_mut(addr) {
                            match target {
                                FirValue::Struct { fields, .. } => {
                                    if let Some(field) = fields.get_mut(*field_idx) {
                                        if let FirValue::Array(items) = field {
                                            items.push(val_to_push);
                                            Ok(FirValue::Unit)
                                        } else {
                                            Err(InterpError::TypeMismatch(
                                                "Struct field is not an array".into(),
                                            ))
                                        }
                                    } else {
                                        Err(InterpError::Panic(format!(
                                            "Field index {} out of bounds",
                                            field_idx
                                        )))
                                    }
                                }
                                FirValue::GenRef { slot, generation } => {
                                    let s = *slot;
                                    let g = *generation;
                                    self.heap.check(s, g)?;
                                    let heap_target = self.heap.deref_mut(s)?;
                                    if let FirValue::Struct { fields, .. } = heap_target {
                                        if let Some(field) = fields.get_mut(*field_idx) {
                                            if let FirValue::Array(items) = field {
                                                items.push(val_to_push);
                                                Ok(FirValue::Unit)
                                            } else {
                                                Err(InterpError::TypeMismatch(
                                                    "Struct field is not an array".into(),
                                                ))
                                            }
                                        } else {
                                            Err(InterpError::Panic(format!(
                                                "Field index {} out of bounds",
                                                field_idx
                                            )))
                                        }
                                    } else {
                                        Err(InterpError::TypeMismatch(
                                            "Heap target is not a struct".into(),
                                        ))
                                    }
                                }
                                _ => {
                                    Err(InterpError::TypeMismatch("Target is not a struct".into()))
                                }
                            }
                        } else {
                            Err(InterpError::InvalidPointer(*addr))
                        }
                    }
                    FirValue::GenRef { slot, generation } => {
                        self.heap.check(*slot, *generation)?;
                        let heap_target = self.heap.deref_mut(*slot)?;
                        if let FirValue::Struct { fields, .. } = heap_target {
                            if let Some(field) = fields.get_mut(*field_idx) {
                                if let FirValue::Array(items) = field {
                                    items.push(val_to_push);
                                    Ok(FirValue::Unit)
                                } else {
                                    Err(InterpError::TypeMismatch(
                                        "Struct field is not an array".into(),
                                    ))
                                }
                            } else {
                                Err(InterpError::Panic(format!(
                                    "Field index {} out of bounds",
                                    field_idx
                                )))
                            }
                        } else {
                            Err(InterpError::TypeMismatch(
                                "Referenced target is not a struct".into(),
                            ))
                        }
                    }
                    _ => Err(InterpError::TypeMismatch(
                        "StructPushField requires pointer or reference".into(),
                    )),
                }
            }

            ValueExpr::ArrayInit(elements) => {
                let mut vals = Vec::new();
                for el in elements {
                    vals.push(
                        env.get(el)
                            .cloned()
                            .ok_or(InterpError::UndefinedValue(*el))?,
                    );
                }
                Ok(FirValue::Array(vals))
            }

            ValueExpr::TupleInit(fields) => {
                let mut vals = Vec::new();
                for f in fields {
                    vals.push(env.get(f).cloned().ok_or(InterpError::UndefinedValue(*f))?);
                }
                Ok(FirValue::Tuple(vals))
            }

            ValueExpr::StructInit { name, fields } => {
                let mut vals = Vec::new();
                for f in fields {
                    vals.push(env.get(f).cloned().ok_or(InterpError::UndefinedValue(*f))?);
                }
                Ok(FirValue::Struct {
                    name: *name,
                    fields: vals,
                })
            }

            ValueExpr::CallDirect { name, args } | ValueExpr::BlockingCallDirect { name, args } => {
                let fn_name = INTERNER.resolve(name);
                let mut evaluated_args = Vec::new();
                for arg in args {
                    evaluated_args.push(
                        env.get(arg)
                            .cloned()
                            .ok_or(InterpError::UndefinedValue(*arg))?,
                    );
                }

                // Check for standard library / runtime intrinsics
                if fn_name == "println" || fn_name == "print" {
                    let mut output = String::new();
                    for (i, a) in evaluated_args.iter().enumerate() {
                        if i > 0 {
                            output.push(' ');
                        }
                        match a {
                            FirValue::String(s) => output.push_str(s),
                            other => output.push_str(&other.to_string()),
                        }
                    }
                    if fn_name == "println" {
                        println!("{}", output);
                        self.captured_output.push(output);
                    } else {
                        print!("{}", output);
                    }
                    Ok(FirValue::Unit)
                } else if fn_name == "assert" {
                    if let Some(cond) = evaluated_args.first() {
                        if !cond.is_truthy() {
                            let msg = if evaluated_args.len() > 1 {
                                match &evaluated_args[1] {
                                    FirValue::String(s) => s.clone(),
                                    other => other.to_string(),
                                }
                            } else {
                                "assertion failed".to_string()
                            };
                            return Err(InterpError::Panic(msg));
                        }
                    }
                    Ok(FirValue::Unit)
                } else if fn_name == "assert_eq" {
                    if evaluated_args.len() >= 2 {
                        let left = &evaluated_args[0];
                        let right = &evaluated_args[1];
                        if left != right {
                            let extra = if evaluated_args.len() > 2 {
                                match &evaluated_args[2] {
                                    FirValue::String(s) => format!(": {}", s),
                                    other => format!(": {}", other),
                                }
                            } else {
                                String::new()
                            };
                            let msg = format!(
                                "assertion failed: `(left == right)`\n  left: `{}`\n right: `{}`{}",
                                left, right, extra
                            );
                            return Err(InterpError::Panic(msg));
                        }
                    }
                    Ok(FirValue::Unit)
                } else if fn_name == "assert_ne" {
                    if evaluated_args.len() >= 2 {
                        let left = &evaluated_args[0];
                        let right = &evaluated_args[1];
                        if left == right {
                            let extra = if evaluated_args.len() > 2 {
                                match &evaluated_args[2] {
                                    FirValue::String(s) => format!(": {}", s),
                                    other => format!(": {}", other),
                                }
                            } else {
                                String::new()
                            };
                            let msg = format!(
                                "assertion failed: `(left != right)`\n  both equal to `{}`{}",
                                left, extra
                            );
                            return Err(InterpError::Panic(msg));
                        }
                    }
                    Ok(FirValue::Unit)
                } else if fn_name == "new" || fn_name == "List::new" {
                    Ok(FirValue::Array(Vec::new()))
                } else if let Some(target_func) = self.find_function(&fn_name) {
                    // Direct function call to another FIR function in module
                    let func_clone = target_func.clone();
                    self.execute_fir_function(&func_clone, evaluated_args)
                } else if let Some(target_struct) = self.find_struct(&fn_name) {
                    Ok(FirValue::Struct {
                        name: target_struct.name,
                        fields: evaluated_args,
                    })
                } else {
                    Err(InterpError::FunctionNotFound(fn_name))
                }
            }

            ValueExpr::Call { callee, args } => {
                let callee_val = env
                    .get(callee)
                    .ok_or(InterpError::UndefinedValue(*callee))?;
                // Indirect call
                match callee_val {
                    FirValue::String(name) => {
                        let sym = INTERNER.intern(name);
                        self.evaluate_expr(
                            &ValueExpr::CallDirect {
                                name: sym,
                                args: args.clone(),
                            },
                            env,
                        )
                    }
                    FirValue::Struct { fields, .. } if !fields.is_empty() => {
                        if let FirValue::String(name) = &fields[0] {
                            let sym = INTERNER.intern(name);
                            let mut full_args = Vec::new();
                            let mut child_env = env.clone();
                            if fields.len() > 1 {
                                let env_vid = ValueId(u32::MAX - 1000 - callee.0);
                                child_env.insert(env_vid, fields[1].clone());
                                full_args.push(env_vid);
                            }
                            full_args.extend_from_slice(args);
                            self.evaluate_expr(
                                &ValueExpr::CallDirect {
                                    name: sym,
                                    args: full_args,
                                },
                                &child_env,
                            )
                        } else {
                            Ok(FirValue::Unit)
                        }
                    }
                    _ => Ok(FirValue::Unit),
                }
            }

            // Copy-on-Write (CoW) Primitives
            ValueExpr::CoWMakeUnique { val } | ValueExpr::CoWClone { val } => {
                let v = env
                    .get(val)
                    .cloned()
                    .ok_or(InterpError::UndefinedValue(*val))?;
                Ok(v)
            }
            ValueExpr::CoWCheckShared { .. } => Ok(FirValue::Bool(false)),

            // Generational References Primitives
            ValueExpr::GenAlloc { .. } => {
                let (slot, generation) = self.heap.alloc(FirValue::Unit);
                Ok(FirValue::GenRef { slot, generation })
            }
            ValueExpr::GenFree { ptr } => {
                let v = env.get(ptr).ok_or(InterpError::UndefinedValue(*ptr))?;
                match v {
                    FirValue::GenRef { slot, .. } => {
                        self.heap.free(*slot)?;
                        Ok(FirValue::Unit)
                    }
                    FirValue::Pointer(addr) => {
                        if let Some(FirValue::GenRef { slot, .. }) = self.stack_memory.get(addr) {
                            self.heap.free(*slot)?;
                            return Ok(FirValue::Unit);
                        }
                        Err(InterpError::TypeMismatch(
                            "GenFree requires a generational reference".into(),
                        ))
                    }
                    _ => Err(InterpError::TypeMismatch(
                        "GenFree requires a generational reference".into(),
                    )),
                }
            }
            ValueExpr::GenRef { ptr } => {
                let v = env.get(ptr).ok_or(InterpError::UndefinedValue(*ptr))?;
                match v {
                    FirValue::Pointer(addr) => {
                        let addr_val = *addr;
                        if let Some(target) = self.stack_memory.get_mut(&addr_val) {
                            match target {
                                FirValue::GenRef { slot, generation } => Ok(FirValue::GenRef {
                                    slot: *slot,
                                    generation: *generation,
                                }),
                                other => {
                                    let obj = std::mem::replace(other, FirValue::Unit);
                                    let (slot, generation) = self.heap.alloc(obj);
                                    let gen_ref = FirValue::GenRef { slot, generation };
                                    *self.stack_memory.get_mut(&addr_val).unwrap() =
                                        gen_ref.clone();
                                    Ok(gen_ref)
                                }
                            }
                        } else {
                            Err(InterpError::InvalidPointer(addr_val))
                        }
                    }
                    FirValue::GenRef { slot, generation } => Ok(FirValue::GenRef {
                        slot: *slot,
                        generation: *generation,
                    }),
                    FirValue::FieldPointer { base_addr, path } => {
                        let target = self
                            .stack_memory
                            .get(base_addr)
                            .ok_or(InterpError::InvalidPointer(*base_addr))?;
                        let leaf = navigate_value(target, path)?;
                        match leaf {
                            FirValue::GenRef { slot, generation } => Ok(FirValue::GenRef {
                                slot: *slot,
                                generation: *generation,
                            }),
                            other => {
                                let (new_slot, new_gen) = self.heap.alloc(other.clone());
                                Ok(FirValue::GenRef {
                                    slot: new_slot,
                                    generation: new_gen,
                                })
                            }
                        }
                    }
                    FirValue::HeapFieldPointer {
                        slot,
                        generation,
                        path,
                    } => {
                        self.heap.check(*slot, *generation)?;
                        let target = self.heap.deref(*slot)?;
                        let leaf = navigate_value(target, path)?;
                        match leaf {
                            FirValue::GenRef {
                                slot: inner_slot,
                                generation: inner_gen,
                            } => Ok(FirValue::GenRef {
                                slot: *inner_slot,
                                generation: *inner_gen,
                            }),
                            other => {
                                let (new_slot, new_gen) = self.heap.alloc(other.clone());
                                Ok(FirValue::GenRef {
                                    slot: new_slot,
                                    generation: new_gen,
                                })
                            }
                        }
                    }
                    _ => {
                        let (slot, generation) = self.heap.alloc(v.clone());
                        Ok(FirValue::GenRef { slot, generation })
                    }
                }
            }
            ValueExpr::GenCheck { ref_val, redundant } => {
                if !*redundant {
                    let v = env
                        .get(ref_val)
                        .ok_or(InterpError::UndefinedValue(*ref_val))?;
                    match v {
                        FirValue::GenRef { slot, generation }
                        | FirValue::HeapFieldPointer {
                            slot, generation, ..
                        } => {
                            self.heap.check(*slot, *generation)?;
                        }
                        FirValue::Pointer(addr) => {
                            if let Some(FirValue::GenRef { slot, generation }) =
                                self.stack_memory.get(addr)
                            {
                                self.heap.check(*slot, *generation)?;
                            }
                        }
                        _ => {}
                    }
                }
                Ok(FirValue::Unit)
            }
            ValueExpr::BoundsCheck {
                base,
                index,
                redundant,
            } => {
                if !*redundant {
                    let base_val = env.get(base).ok_or(InterpError::UndefinedValue(*base))?;
                    let idx_val = env.get(index).ok_or(InterpError::UndefinedValue(*index))?;
                    let idx = match idx_val {
                        FirValue::Int(i) => *i,
                        _ => {
                            return Err(InterpError::TypeMismatch(
                                "Index must be an integer".into(),
                            ))
                        }
                    };
                    let len = match base_val {
                        FirValue::Array(elements) => elements.len() as i128,
                        FirValue::String(s) => s.len() as i128,
                        FirValue::Pointer(addr) => {
                            if let Some(target) = self.stack_memory.get(addr) {
                                match target {
                                    FirValue::Array(elements) => elements.len() as i128,
                                    FirValue::String(s) => s.len() as i128,
                                    _ => 0,
                                }
                            } else {
                                0
                            }
                        }
                        _ => 0,
                    };
                    if len > 0 && (idx < 0 || idx >= len) {
                        return Err(InterpError::Panic(format!(
                            "Out of bounds check failure: index {} with length {}",
                            idx, len
                        )));
                    }
                }
                Ok(FirValue::Unit)
            }
            ValueExpr::SliceBoundsCheck {
                base,
                start,
                end,
                redundant,
            } => {
                if !*redundant {
                    let base_val = env.get(base).ok_or(InterpError::UndefinedValue(*base))?;
                    let start_val = env.get(start).ok_or(InterpError::UndefinedValue(*start))?;
                    let end_val = env.get(end).ok_or(InterpError::UndefinedValue(*end))?;
                    let s_idx = match start_val {
                        FirValue::Int(i) => *i,
                        _ => {
                            return Err(InterpError::TypeMismatch(
                                "Slice start must be an integer".into(),
                            ))
                        }
                    };
                    let e_idx = match end_val {
                        FirValue::Int(i) => *i,
                        _ => {
                            return Err(InterpError::TypeMismatch(
                                "Slice end must be an integer".into(),
                            ))
                        }
                    };
                    let len = match base_val {
                        FirValue::Array(elements) => elements.len() as i128,
                        FirValue::String(s) => s.len() as i128,
                        FirValue::Pointer(addr) => {
                            if let Some(target) = self.stack_memory.get(addr) {
                                match target {
                                    FirValue::Array(elements) => elements.len() as i128,
                                    FirValue::String(s) => s.len() as i128,
                                    _ => 0,
                                }
                            } else {
                                0
                            }
                        }
                        _ => 0,
                    };
                    if s_idx < 0 || s_idx > e_idx || (len > 0 && e_idx > len) {
                        return Err(InterpError::Panic(format!(
                            "Out of bounds slice check failure: range [{}..{}] exceeds length {}",
                            s_idx, e_idx, len
                        )));
                    }
                }
                Ok(FirValue::Unit)
            }
            ValueExpr::GenDeref { ref_val } => {
                let v = env
                    .get(ref_val)
                    .ok_or(InterpError::UndefinedValue(*ref_val))?;
                match v {
                    FirValue::GenRef { slot, generation } => {
                        self.heap.check(*slot, *generation)?;
                        let val = self.heap.deref(*slot)?.clone();
                        Ok(val)
                    }
                    FirValue::HeapFieldPointer {
                        slot,
                        generation,
                        path,
                    } => {
                        self.heap.check(*slot, *generation)?;
                        let target = self.heap.deref(*slot)?;
                        let leaf = navigate_value(target, path)?;
                        Ok(leaf.clone())
                    }
                    FirValue::FieldPointer { base_addr, path } => {
                        let target = self
                            .stack_memory
                            .get(base_addr)
                            .ok_or(InterpError::InvalidPointer(*base_addr))?;
                        let leaf = navigate_value(target, path)?;
                        Ok(leaf.clone())
                    }
                    FirValue::Pointer(addr) => {
                        if let Some(target) = self.stack_memory.get(addr) {
                            if let FirValue::GenRef { slot, generation } = target {
                                self.heap.check(*slot, *generation)?;
                                let val = self.heap.deref(*slot)?.clone();
                                Ok(val)
                            } else {
                                Ok(target.clone())
                            }
                        } else {
                            Err(InterpError::InvalidPointer(*addr))
                        }
                    }
                    other => Ok(other.clone()),
                }
            }

            ValueExpr::CallArenaAlloc { .. } => {
                let (slot, generation) = self.heap.alloc(FirValue::Unit);
                Ok(FirValue::GenRef { slot, generation })
            }
            ValueExpr::CallArenaMark => Ok(FirValue::Int(0)),
            ValueExpr::CallArenaRewind { .. } => Ok(FirValue::Unit),

            ValueExpr::Yield => Ok(FirValue::Unit),
            ValueExpr::YieldValue { val } => Ok(env.get(val).cloned().unwrap_or(FirValue::Unit)),
            ValueExpr::Spawn { .. } => Ok(FirValue::Unit),

            ValueExpr::ChanCreate { .. } => {
                let id = self.next_chan_id;
                self.next_chan_id += 1;
                self.channels.insert(id, VecDeque::new());
                Ok(FirValue::Int(id as i128))
            }
            ValueExpr::ChanSend { chan, val } => {
                let cid = match env.get(chan) {
                    Some(FirValue::Int(id)) => *id as u64,
                    _ => 0,
                };
                if let Some(v) = env.get(val) {
                    if let Some(q) = self.channels.get_mut(&cid) {
                        q.push_back(v.clone());
                    }
                }
                Ok(FirValue::Unit)
            }
            ValueExpr::ChanRecv { chan } | ValueExpr::ChanTryRecv { chan } => {
                let cid = match env.get(chan) {
                    Some(FirValue::Int(id)) => *id as u64,
                    _ => 0,
                };
                if let Some(q) = self.channels.get_mut(&cid) {
                    if let Some(v) = q.pop_front() {
                        return Ok(v);
                    }
                }
                Ok(FirValue::Unit)
            }
            ValueExpr::ChanClose { chan } => {
                let cid = match env.get(chan) {
                    Some(FirValue::Int(id)) => *id as u64,
                    _ => 0,
                };
                self.channels.remove(&cid);
                Ok(FirValue::Unit)
            }
            ValueExpr::ChanSelect {
                channels,
                has_default,
            } => {
                for (idx, c) in channels.iter().enumerate() {
                    let cid = match env.get(c) {
                        Some(FirValue::Int(id)) => *id as u64,
                        _ => 0,
                    };
                    if let Some(q) = self.channels.get_mut(&cid) {
                        if !q.is_empty() {
                            return Ok(FirValue::Int(idx as i128));
                        }
                    }
                }
                if *has_default {
                    Ok(FirValue::Int(channels.len() as i128))
                } else {
                    Ok(FirValue::Int(0))
                }
            }
            ValueExpr::EnumInit {
                enum_name,
                variant,
                discriminant,
                payload,
            } => {
                let p_val = payload
                    .as_ref()
                    .map(|p_id| Box::new(env.get(p_id).cloned().unwrap_or(FirValue::Unit)));
                Ok(FirValue::Enum {
                    enum_name: *enum_name,
                    variant: *variant,
                    discriminant: *discriminant,
                    payload: p_val,
                })
            }
            ValueExpr::EnumGetDiscriminant { base } => match env.get(base) {
                Some(FirValue::Enum { discriminant, .. }) => {
                    Ok(FirValue::Int(*discriminant as i128))
                }
                Some(FirValue::Int(i)) => Ok(FirValue::Int(*i)),
                _ => Ok(FirValue::Int(0)),
            },
            ValueExpr::EnumGetPayload { base, .. } => match env.get(base) {
                Some(FirValue::Enum {
                    payload: Some(p), ..
                }) => Ok((**p).clone()),
                _ => Ok(FirValue::Unit),
            },
            ValueExpr::FormatString(parts) => {
                let mut out = String::new();
                for part in parts {
                    let v = env.get(part).ok_or(InterpError::UndefinedValue(*part))?;
                    match v {
                        FirValue::String(s) => out.push_str(s),
                        FirValue::Int(i) => out.push_str(&i.to_string()),
                        FirValue::Float(f) => out.push_str(&f.to_string()),
                        FirValue::Bool(b) => out.push_str(&b.to_string()),
                        other => out.push_str(&other.to_string()),
                    }
                }
                Ok(FirValue::String(out))
            }
        }
    }

    /// Evaluate binary operators.
    fn evaluate_binary_op(
        &self,
        op: BinaryOp,
        lhs: &FirValue,
        rhs: &FirValue,
    ) -> Result<FirValue, InterpError> {
        let deref_lhs = if let FirValue::GenRef { slot, generation } = lhs {
            if !matches!(rhs, FirValue::Null) {
                self.heap.check(*slot, *generation)?;
                Some(self.heap.deref(*slot)?)
            } else {
                None
            }
        } else {
            None
        };
        let effective_lhs = deref_lhs.unwrap_or(lhs);

        let deref_rhs = if let FirValue::GenRef { slot, generation } = rhs {
            if !matches!(effective_lhs, FirValue::Null) {
                self.heap.check(*slot, *generation)?;
                Some(self.heap.deref(*slot)?)
            } else {
                None
            }
        } else {
            None
        };
        let effective_rhs = deref_rhs.unwrap_or(rhs);

        match (effective_lhs, effective_rhs) {
            (FirValue::Int(a), FirValue::Int(b)) => match op {
                BinaryOp::Add => Ok(FirValue::Int(a.wrapping_add(*b))),
                BinaryOp::Sub => Ok(FirValue::Int(a.wrapping_sub(*b))),
                BinaryOp::Mul => Ok(FirValue::Int(a.wrapping_mul(*b))),
                BinaryOp::Div => {
                    if *b == 0 {
                        Err(InterpError::DivisionByZero)
                    } else {
                        Ok(FirValue::Int(a.wrapping_div(*b)))
                    }
                }
                BinaryOp::Rem => {
                    if *b == 0 {
                        Err(InterpError::DivisionByZero)
                    } else {
                        Ok(FirValue::Int(a.wrapping_rem(*b)))
                    }
                }
                BinaryOp::BitAnd => Ok(FirValue::Int(a & b)),
                BinaryOp::BitOr => Ok(FirValue::Int(a | b)),
                BinaryOp::BitXor => Ok(FirValue::Int(a ^ b)),
                BinaryOp::Shl => Ok(FirValue::Int(a << (b & 127))),
                BinaryOp::Shr => Ok(FirValue::Int(a >> (b & 127))),
                BinaryOp::Eq => Ok(FirValue::Bool(a == b)),
                BinaryOp::Ne => Ok(FirValue::Bool(a != b)),
                BinaryOp::Lt => Ok(FirValue::Bool(a < b)),
                BinaryOp::Le => Ok(FirValue::Bool(a <= b)),
                BinaryOp::Gt => Ok(FirValue::Bool(a > b)),
                BinaryOp::Ge => Ok(FirValue::Bool(a >= b)),
                _ => Err(InterpError::TypeMismatch(format!(
                    "Unsupported binary op {:?} on integers",
                    op
                ))),
            },
            (FirValue::Float(a), FirValue::Float(b)) => match op {
                BinaryOp::Add => Ok(FirValue::Float(a + b)),
                BinaryOp::Sub => Ok(FirValue::Float(a - b)),
                BinaryOp::Mul => Ok(FirValue::Float(a * b)),
                BinaryOp::Div => Ok(FirValue::Float(a / b)),
                BinaryOp::Eq => Ok(FirValue::Bool((a - b).abs() < f64::EPSILON)),
                BinaryOp::Ne => Ok(FirValue::Bool((a - b).abs() >= f64::EPSILON)),
                BinaryOp::Lt => Ok(FirValue::Bool(a < b)),
                BinaryOp::Le => Ok(FirValue::Bool(a <= b)),
                BinaryOp::Gt => Ok(FirValue::Bool(a > b)),
                BinaryOp::Ge => Ok(FirValue::Bool(a >= b)),
                _ => Err(InterpError::TypeMismatch(format!(
                    "Unsupported op {:?} on floats",
                    op
                ))),
            },
            (FirValue::Bool(a), FirValue::Bool(b)) => match op {
                BinaryOp::And => Ok(FirValue::Bool(*a && *b)),
                BinaryOp::Or => Ok(FirValue::Bool(*a || *b)),
                BinaryOp::BitAnd => Ok(FirValue::Bool(*a && *b)),
                BinaryOp::BitOr => Ok(FirValue::Bool(*a || *b)),
                BinaryOp::Eq => Ok(FirValue::Bool(a == b)),
                BinaryOp::Ne => Ok(FirValue::Bool(a != b)),
                _ => Err(InterpError::TypeMismatch(format!(
                    "Unsupported op {:?} on bools",
                    op
                ))),
            },
            (FirValue::String(a), FirValue::String(b)) => match op {
                BinaryOp::Add => Ok(FirValue::String(format!("{}{}", a, b))),
                BinaryOp::Eq => Ok(FirValue::Bool(a == b)),
                BinaryOp::Ne => Ok(FirValue::Bool(a != b)),
                _ => Err(InterpError::TypeMismatch(format!(
                    "Unsupported op {:?} on strings",
                    op
                ))),
            },
            (FirValue::Null, FirValue::GenRef { slot, generation })
            | (FirValue::GenRef { slot, generation }, FirValue::Null) => match op {
                BinaryOp::Eq => Ok(FirValue::Bool(*slot == 0 && *generation == 0)),
                BinaryOp::Ne => Ok(FirValue::Bool(*slot != 0 || *generation != 0)),
                _ => Err(InterpError::TypeMismatch(format!(
                    "Incompatible types for {:?}: {} and {}",
                    op, lhs, rhs
                ))),
            },
            (FirValue::Null, FirValue::Pointer(addr))
            | (FirValue::Pointer(addr), FirValue::Null) => match op {
                BinaryOp::Eq => Ok(FirValue::Bool(*addr == 0)),
                BinaryOp::Ne => Ok(FirValue::Bool(*addr != 0)),
                _ => Err(InterpError::TypeMismatch(format!(
                    "Incompatible types for {:?}: {} and {}",
                    op, lhs, rhs
                ))),
            },
            _ => match op {
                BinaryOp::Eq => Ok(FirValue::Bool(lhs == rhs)),
                BinaryOp::Ne => Ok(FirValue::Bool(lhs != rhs)),
                _ => Err(InterpError::TypeMismatch(format!(
                    "Incompatible types for {:?}: {} and {}",
                    op, lhs, rhs
                ))),
            },
        }
    }
}

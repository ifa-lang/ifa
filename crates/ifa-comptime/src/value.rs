use crate::error::{ComptimeError, ComptimeErrorKind};
use ifa_ast::{Expr, ExprKind, Lit};
use ifa_span::{Span, Symbol, INTERNER};
use std::fmt;

/// Represents any runtime or compile-time value manipulable inside the IFA comptime VM.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Unit,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    Char(char),
    String(String),
    Array(Vec<Value>),
    Tuple(Vec<Value>),
    Struct {
        name: Symbol,
        fields: Vec<(Symbol, Value)>,
    },
    EnumVariant {
        enum_name: Symbol,
        variant: Symbol,
        payload: Option<Box<Value>>,
    },
    Error(Box<Value>),
    Option(Option<Box<Value>>),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Unit => write!(f, "()"),
            Value::Bool(b) => write!(f, "{}", b),
            Value::Int(i) => write!(f, "{}", i),
            Value::UInt(u) => write!(f, "{}", u),
            Value::Float(fl) => write!(f, "{}", fl),
            Value::Char(c) => write!(f, "'{}'", c),
            Value::String(s) => write!(f, "\"{}\"", s),
            Value::Array(arr) => {
                write!(f, "[")?;
                for (i, val) in arr.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", val)?;
                }
                write!(f, "]")
            }
            Value::Tuple(tup) => {
                write!(f, "(")?;
                for (i, val) in tup.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", val)?;
                }
                write!(f, ")")
            }
            Value::Struct { name, fields } => {
                let name_str = INTERNER.resolve(name);
                write!(f, "{} {{ ", name_str)?;
                for (i, (fname, val)) in fields.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", INTERNER.resolve(fname), val)?;
                }
                write!(f, " }}")
            }
            Value::EnumVariant {
                variant, payload, ..
            } => {
                let var_str = INTERNER.resolve(variant);
                if let Some(p) = payload {
                    write!(f, "{}({})", var_str, p)
                } else {
                    write!(f, "{}", var_str)
                }
            }
            Value::Error(err) => write!(f, "!({})", err),
            Value::Option(opt) => match opt {
                Some(val) => write!(f, "Some({})", val),
                None => write!(f, "None"),
            },
        }
    }
}

impl Value {
    /// Returns a human-readable name of the value's type.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Unit => "()",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::UInt(_) => "uint",
            Value::Float(_) => "float",
            Value::Char(_) => "char",
            Value::String(_) => "str",
            Value::Array(_) => "array",
            Value::Tuple(_) => "tuple",
            Value::Struct { .. } => "struct",
            Value::EnumVariant { .. } => "enum",
            Value::Error(_) => "error",
            Value::Option(_) => "option",
        }
    }

    /// Evaluates the truthiness of the value in boolean contexts.
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            Value::Int(i) => *i != 0,
            Value::UInt(u) => *u != 0,
            Value::Float(f) => *f != 0.0,
            Value::Char(_) => true,
            Value::String(s) => !s.is_empty(),
            Value::Array(a) => !a.is_empty(),
            Value::Tuple(t) => !t.is_empty(),
            Value::Unit => false,
            Value::Struct { .. } => true,
            Value::EnumVariant { .. } => true,
            Value::Error(_) => false,
            Value::Option(opt) => opt.is_some(),
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::UInt(u) => Some(*u as i64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Converts a comptime value back into an AST expression node.
    pub fn to_ast_expr(&self, span: Span) -> Expr {
        match self {
            Value::Unit => Expr::new(ExprKind::Unit, span),
            Value::Bool(b) => Expr::new(ExprKind::Lit(Lit::Bool(*b)), span),
            Value::Int(i) => {
                let sym = INTERNER.intern(&i.to_string());
                Expr::new(ExprKind::Lit(Lit::Int(sym)), span)
            }
            Value::UInt(u) => {
                let sym = INTERNER.intern(&u.to_string());
                Expr::new(ExprKind::Lit(Lit::Int(sym)), span)
            }
            Value::Float(f) => {
                let sym = INTERNER.intern(&f.to_string());
                Expr::new(ExprKind::Lit(Lit::Float(sym)), span)
            }
            Value::Char(c) => Expr::new(ExprKind::Lit(Lit::Char(*c)), span),
            Value::String(s) => {
                let sym = INTERNER.intern(s);
                Expr::new(ExprKind::Lit(Lit::String(sym)), span)
            }
            Value::Array(elems) => {
                let ast_elems = elems.iter().map(|e| e.to_ast_expr(span)).collect();
                Expr::new(ExprKind::Array(ast_elems), span)
            }
            Value::Tuple(items) => {
                let ast_items = items.iter().map(|e| e.to_ast_expr(span)).collect();
                Expr::new(ExprKind::Tuple(ast_items), span)
            }
            Value::Struct { name, fields } => {
                let ast_fields = fields
                    .iter()
                    .map(|(k, v)| (*k, v.to_ast_expr(span)))
                    .collect();
                Expr::new(
                    ExprKind::StructInit {
                        name: vec![*name],
                        fields: ast_fields,
                    },
                    span,
                )
            }
            Value::EnumVariant { .. } => Expr::new(ExprKind::Unit, span),
            Value::Error(inner) => inner.to_ast_expr(span),
            Value::Option(opt) => match opt {
                Some(inner) => inner.to_ast_expr(span),
                None => Expr::new(ExprKind::Unit, span),
            },
        }
    }

    // =========================================================================
    // Arithmetic operations
    // =========================================================================

    pub fn add(&self, other: &Self, span: Span) -> Result<Value, ComptimeError> {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a.wrapping_add(*b))),
            (Value::UInt(a), Value::UInt(b)) => Ok(Value::UInt(a.wrapping_add(*b))),
            (Value::Float(a), Value::Float(b)) => Ok(Value::Float(a + b)),
            (Value::String(a), Value::String(b)) => Ok(Value::String(format!("{}{}", a, b))),
            (Value::String(a), other) => Ok(Value::String(format!("{}{}", a, other))),
            (other, Value::String(b)) => Ok(Value::String(format!("{}{}", other, b))),
            (Value::Array(a), Value::Array(b)) => {
                let mut concat = a.clone();
                concat.extend(b.clone());
                Ok(Value::Array(concat))
            }
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::InvalidBinaryOp {
                    op: "+".to_string(),
                    left: self.type_name().to_string(),
                    right: other.type_name().to_string(),
                },
                span,
            )),
        }
    }

    pub fn sub(&self, other: &Self, span: Span) -> Result<Value, ComptimeError> {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a.wrapping_sub(*b))),
            (Value::UInt(a), Value::UInt(b)) => Ok(Value::UInt(a.wrapping_sub(*b))),
            (Value::Float(a), Value::Float(b)) => Ok(Value::Float(a - b)),
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::InvalidBinaryOp {
                    op: "-".to_string(),
                    left: self.type_name().to_string(),
                    right: other.type_name().to_string(),
                },
                span,
            )),
        }
    }

    pub fn mul(&self, other: &Self, span: Span) -> Result<Value, ComptimeError> {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a.wrapping_mul(*b))),
            (Value::UInt(a), Value::UInt(b)) => Ok(Value::UInt(a.wrapping_mul(*b))),
            (Value::Float(a), Value::Float(b)) => Ok(Value::Float(a * b)),
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::InvalidBinaryOp {
                    op: "*".to_string(),
                    left: self.type_name().to_string(),
                    right: other.type_name().to_string(),
                },
                span,
            )),
        }
    }

    pub fn div(&self, other: &Self, span: Span) -> Result<Value, ComptimeError> {
        match (self, other) {
            (Value::Int(_), Value::Int(0)) | (Value::UInt(_), Value::UInt(0)) => {
                Err(ComptimeError::new(ComptimeErrorKind::DivisionByZero, span))
            }
            (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a / b)),
            (Value::UInt(a), Value::UInt(b)) => Ok(Value::UInt(a / b)),
            (Value::Float(a), Value::Float(b)) => {
                if *b == 0.0 {
                    Err(ComptimeError::new(ComptimeErrorKind::DivisionByZero, span))
                } else {
                    Ok(Value::Float(a / b))
                }
            }
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::InvalidBinaryOp {
                    op: "/".to_string(),
                    left: self.type_name().to_string(),
                    right: other.type_name().to_string(),
                },
                span,
            )),
        }
    }

    pub fn rem(&self, other: &Self, span: Span) -> Result<Value, ComptimeError> {
        match (self, other) {
            (Value::Int(_), Value::Int(0)) | (Value::UInt(_), Value::UInt(0)) => {
                Err(ComptimeError::new(ComptimeErrorKind::ModuloByZero, span))
            }
            (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a % b)),
            (Value::UInt(a), Value::UInt(b)) => Ok(Value::UInt(a % b)),
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::InvalidBinaryOp {
                    op: "%".to_string(),
                    left: self.type_name().to_string(),
                    right: other.type_name().to_string(),
                },
                span,
            )),
        }
    }

    pub fn neg(&self, span: Span) -> Result<Value, ComptimeError> {
        match self {
            Value::Int(i) => Ok(Value::Int(-i)),
            Value::Float(f) => Ok(Value::Float(-f)),
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::InvalidUnaryOp {
                    op: "-".to_string(),
                    operand: self.type_name().to_string(),
                },
                span,
            )),
        }
    }

    pub fn not(&self, _span: Span) -> Result<Value, ComptimeError> {
        Ok(Value::Bool(!self.is_truthy()))
    }

    // =========================================================================
    // Bitwise operations
    // =========================================================================

    pub fn bit_and(&self, other: &Self, span: Span) -> Result<Value, ComptimeError> {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a & b)),
            (Value::UInt(a), Value::UInt(b)) => Ok(Value::UInt(a & b)),
            (Value::Bool(a), Value::Bool(b)) => Ok(Value::Bool(*a && *b)),
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::InvalidBinaryOp {
                    op: "&".to_string(),
                    left: self.type_name().to_string(),
                    right: other.type_name().to_string(),
                },
                span,
            )),
        }
    }

    pub fn bit_or(&self, other: &Self, span: Span) -> Result<Value, ComptimeError> {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a | b)),
            (Value::UInt(a), Value::UInt(b)) => Ok(Value::UInt(a | b)),
            (Value::Bool(a), Value::Bool(b)) => Ok(Value::Bool(*a || *b)),
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::InvalidBinaryOp {
                    op: "|".to_string(),
                    left: self.type_name().to_string(),
                    right: other.type_name().to_string(),
                },
                span,
            )),
        }
    }

    pub fn bit_xor(&self, other: &Self, span: Span) -> Result<Value, ComptimeError> {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a ^ b)),
            (Value::UInt(a), Value::UInt(b)) => Ok(Value::UInt(a ^ b)),
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::InvalidBinaryOp {
                    op: "^".to_string(),
                    left: self.type_name().to_string(),
                    right: other.type_name().to_string(),
                },
                span,
            )),
        }
    }

    pub fn bit_not(&self, span: Span) -> Result<Value, ComptimeError> {
        match self {
            Value::Int(i) => Ok(Value::Int(!i)),
            Value::UInt(u) => Ok(Value::UInt(!u)),
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::InvalidUnaryOp {
                    op: "~".to_string(),
                    operand: self.type_name().to_string(),
                },
                span,
            )),
        }
    }

    pub fn shl(&self, other: &Self, span: Span) -> Result<Value, ComptimeError> {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) if *b >= 0 => Ok(Value::Int(a.wrapping_shl(*b as u32))),
            (Value::UInt(a), Value::Int(b)) if *b >= 0 => {
                Ok(Value::UInt(a.wrapping_shl(*b as u32)))
            }
            (Value::UInt(a), Value::UInt(b)) => Ok(Value::UInt(a.wrapping_shl(*b as u32))),
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::InvalidBinaryOp {
                    op: "<<".to_string(),
                    left: self.type_name().to_string(),
                    right: other.type_name().to_string(),
                },
                span,
            )),
        }
    }

    pub fn shr(&self, other: &Self, span: Span) -> Result<Value, ComptimeError> {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) if *b >= 0 => Ok(Value::Int(a.wrapping_shr(*b as u32))),
            (Value::UInt(a), Value::Int(b)) if *b >= 0 => {
                Ok(Value::UInt(a.wrapping_shr(*b as u32)))
            }
            (Value::UInt(a), Value::UInt(b)) => Ok(Value::UInt(a.wrapping_shr(*b as u32))),
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::InvalidBinaryOp {
                    op: ">>".to_string(),
                    left: self.type_name().to_string(),
                    right: other.type_name().to_string(),
                },
                span,
            )),
        }
    }

    // =========================================================================
    // Comparison operations
    // =========================================================================

    pub fn val_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::UInt(a), Value::UInt(b)) => a == b,
            (Value::Int(a), Value::UInt(b)) if *a >= 0 => (*a as u64) == *b,
            (Value::UInt(a), Value::Int(b)) if *b >= 0 => *a == (*b as u64),
            (Value::Float(a), Value::Float(b)) => a == b,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Char(a), Value::Char(b)) => a == b,
            (Value::String(a), Value::String(b)) => a == b,
            (Value::Array(a), Value::Array(b)) => a == b,
            (Value::Tuple(a), Value::Tuple(b)) => a == b,
            (Value::Unit, Value::Unit) => true,
            _ => false,
        }
    }

    pub fn lt(&self, other: &Self, span: Span) -> Result<Value, ComptimeError> {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => Ok(Value::Bool(a < b)),
            (Value::UInt(a), Value::UInt(b)) => Ok(Value::Bool(a < b)),
            (Value::Float(a), Value::Float(b)) => Ok(Value::Bool(a < b)),
            (Value::Char(a), Value::Char(b)) => Ok(Value::Bool(a < b)),
            (Value::String(a), Value::String(b)) => Ok(Value::Bool(a < b)),
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::InvalidBinaryOp {
                    op: "<".to_string(),
                    left: self.type_name().to_string(),
                    right: other.type_name().to_string(),
                },
                span,
            )),
        }
    }

    pub fn lte(&self, other: &Self, span: Span) -> Result<Value, ComptimeError> {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => Ok(Value::Bool(a <= b)),
            (Value::UInt(a), Value::UInt(b)) => Ok(Value::Bool(a <= b)),
            (Value::Float(a), Value::Float(b)) => Ok(Value::Bool(a <= b)),
            (Value::Char(a), Value::Char(b)) => Ok(Value::Bool(a <= b)),
            (Value::String(a), Value::String(b)) => Ok(Value::Bool(a <= b)),
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::InvalidBinaryOp {
                    op: "<=".to_string(),
                    left: self.type_name().to_string(),
                    right: other.type_name().to_string(),
                },
                span,
            )),
        }
    }

    pub fn gt(&self, other: &Self, span: Span) -> Result<Value, ComptimeError> {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => Ok(Value::Bool(a > b)),
            (Value::UInt(a), Value::UInt(b)) => Ok(Value::Bool(a > b)),
            (Value::Float(a), Value::Float(b)) => Ok(Value::Bool(a > b)),
            (Value::Char(a), Value::Char(b)) => Ok(Value::Bool(a > b)),
            (Value::String(a), Value::String(b)) => Ok(Value::Bool(a > b)),
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::InvalidBinaryOp {
                    op: ">".to_string(),
                    left: self.type_name().to_string(),
                    right: other.type_name().to_string(),
                },
                span,
            )),
        }
    }

    pub fn gte(&self, other: &Self, span: Span) -> Result<Value, ComptimeError> {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => Ok(Value::Bool(a >= b)),
            (Value::UInt(a), Value::UInt(b)) => Ok(Value::Bool(a >= b)),
            (Value::Float(a), Value::Float(b)) => Ok(Value::Bool(a >= b)),
            (Value::Char(a), Value::Char(b)) => Ok(Value::Bool(a >= b)),
            (Value::String(a), Value::String(b)) => Ok(Value::Bool(a >= b)),
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::InvalidBinaryOp {
                    op: ">=".to_string(),
                    left: self.type_name().to_string(),
                    right: other.type_name().to_string(),
                },
                span,
            )),
        }
    }

    // =========================================================================
    // Indexing and Member access
    // =========================================================================

    pub fn get_index(&self, index: i64, span: Span) -> Result<Value, ComptimeError> {
        match self {
            Value::Array(arr) => {
                if index < 0 || (index as usize) >= arr.len() {
                    Err(ComptimeError::new(
                        ComptimeErrorKind::IndexOutOfBounds {
                            index,
                            len: arr.len(),
                        },
                        span,
                    ))
                } else {
                    Ok(arr[index as usize].clone())
                }
            }
            Value::String(s) => {
                let chars: Vec<char> = s.chars().collect();
                if index < 0 || (index as usize) >= chars.len() {
                    Err(ComptimeError::new(
                        ComptimeErrorKind::IndexOutOfBounds {
                            index,
                            len: chars.len(),
                        },
                        span,
                    ))
                } else {
                    Ok(Value::Char(chars[index as usize]))
                }
            }
            Value::Tuple(tup) => {
                if index < 0 || (index as usize) >= tup.len() {
                    Err(ComptimeError::new(
                        ComptimeErrorKind::IndexOutOfBounds {
                            index,
                            len: tup.len(),
                        },
                        span,
                    ))
                } else {
                    Ok(tup[index as usize].clone())
                }
            }
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::TypeMismatch {
                    expected: "array, str ou tuple".to_string(),
                    found: self.type_name().to_string(),
                },
                span,
            )),
        }
    }

    pub fn set_index(&mut self, index: i64, value: Value, span: Span) -> Result<(), ComptimeError> {
        match self {
            Value::Array(arr) => {
                if index < 0 || (index as usize) >= arr.len() {
                    Err(ComptimeError::new(
                        ComptimeErrorKind::IndexOutOfBounds {
                            index,
                            len: arr.len(),
                        },
                        span,
                    ))
                } else {
                    arr[index as usize] = value;
                    Ok(())
                }
            }
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::TypeMismatch {
                    expected: "array".to_string(),
                    found: self.type_name().to_string(),
                },
                span,
            )),
        }
    }

    pub fn get_field(&self, field: Symbol, span: Span) -> Result<Value, ComptimeError> {
        match self {
            Value::Struct { name, fields } => {
                for (fname, val) in fields {
                    if *fname == field {
                        return Ok(val.clone());
                    }
                }
                Err(ComptimeError::new(
                    ComptimeErrorKind::FieldNotFound {
                        struct_name: INTERNER.resolve(name).to_string(),
                        field: INTERNER.resolve(&field).to_string(),
                    },
                    span,
                ))
            }
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::TypeMismatch {
                    expected: "struct".to_string(),
                    found: self.type_name().to_string(),
                },
                span,
            )),
        }
    }

    pub fn set_field(
        &mut self,
        field: Symbol,
        value: Value,
        span: Span,
    ) -> Result<(), ComptimeError> {
        match self {
            Value::Struct { name, fields } => {
                for (fname, val) in fields.iter_mut() {
                    if *fname == field {
                        *val = value;
                        return Ok(());
                    }
                }
                Err(ComptimeError::new(
                    ComptimeErrorKind::FieldNotFound {
                        struct_name: INTERNER.resolve(name).to_string(),
                        field: INTERNER.resolve(&field).to_string(),
                    },
                    span,
                ))
            }
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::TypeMismatch {
                    expected: "struct".to_string(),
                    found: self.type_name().to_string(),
                },
                span,
            )),
        }
    }

    pub fn len(&self, span: Span) -> Result<usize, ComptimeError> {
        match self {
            Value::Array(a) => Ok(a.len()),
            Value::String(s) => Ok(s.chars().count()),
            Value::Tuple(t) => Ok(t.len()),
            _ => Err(ComptimeError::new(
                ComptimeErrorKind::TypeMismatch {
                    expected: "array, str ou tuple".to_string(),
                    found: self.type_name().to_string(),
                },
                span,
            )),
        }
    }
}

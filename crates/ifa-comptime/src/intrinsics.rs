use crate::error::{ComptimeError, ComptimeErrorKind};
use crate::value::Value;
use ifa_span::{Span, Symbol, INTERNER};

/// Dispatcher for built-in comptime intrinsic functions.
pub fn call_intrinsic(name: Symbol, args: &[Value], span: Span) -> Result<Value, ComptimeError> {
    let name_str = INTERNER.resolve(&name);
    match name_str.as_str() {
        "assert" => {
            if args.is_empty() {
                return Err(ComptimeError::new(
                    ComptimeErrorKind::ArityMismatch {
                        expected: 1,
                        found: 0,
                    },
                    span,
                ));
            }
            let cond = args[0].is_truthy();
            let msg = if args.len() > 1 {
                match &args[1] {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                }
            } else {
                "assertion comptime échouée".to_string()
            };

            if !cond {
                Err(ComptimeError::new(
                    ComptimeErrorKind::AssertionFailed(msg),
                    span,
                ))
            } else {
                Ok(Value::Unit)
            }
        }
        "compile_error" => {
            let msg = if let Some(arg) = args.first() {
                match arg {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                }
            } else {
                "erreur de compilation statique".to_string()
            };
            Err(ComptimeError::new(
                ComptimeErrorKind::CompileError(msg),
                span,
            ))
        }
        "len" => {
            if args.len() != 1 {
                return Err(ComptimeError::new(
                    ComptimeErrorKind::ArityMismatch {
                        expected: 1,
                        found: args.len(),
                    },
                    span,
                ));
            }
            let length = args[0].len(span)?;
            Ok(Value::Int(length as i64))
        }
        "type_of" => {
            if args.len() != 1 {
                return Err(ComptimeError::new(
                    ComptimeErrorKind::ArityMismatch {
                        expected: 1,
                        found: args.len(),
                    },
                    span,
                ));
            }
            Ok(Value::String(args[0].type_name().to_string()))
        }
        "crc32" => {
            if args.len() != 1 {
                return Err(ComptimeError::new(
                    ComptimeErrorKind::ArityMismatch {
                        expected: 1,
                        found: args.len(),
                    },
                    span,
                ));
            }
            let bytes: Vec<u8> = match &args[0] {
                Value::String(s) => s.as_bytes().to_vec(),
                Value::Array(arr) => {
                    let mut b = Vec::new();
                    for item in arr {
                        if let Some(i) = item.as_int() {
                            b.push((i & 0xFF) as u8);
                        } else {
                            return Err(ComptimeError::new(
                                ComptimeErrorKind::TypeMismatch {
                                    expected: "u8".to_string(),
                                    found: item.type_name().to_string(),
                                },
                                span,
                            ));
                        }
                    }
                    b
                }
                other => {
                    return Err(ComptimeError::new(
                        ComptimeErrorKind::TypeMismatch {
                            expected: "str ou array".to_string(),
                            found: other.type_name().to_string(),
                        },
                        span,
                    ));
                }
            };
            let crc = compute_crc32(&bytes);
            Ok(Value::UInt(crc as u64))
        }
        "hex_encode" => {
            if args.len() != 1 {
                return Err(ComptimeError::new(
                    ComptimeErrorKind::ArityMismatch {
                        expected: 1,
                        found: args.len(),
                    },
                    span,
                ));
            }
            let mut hex_str = String::new();
            match &args[0] {
                Value::Array(arr) => {
                    for item in arr {
                        if let Some(i) = item.as_int() {
                            use std::fmt::Write;
                            let _ = write!(hex_str, "{:02x}", (i & 0xFF) as u8);
                        }
                    }
                }
                Value::String(s) => {
                    for b in s.as_bytes() {
                        use std::fmt::Write;
                        let _ = write!(hex_str, "{:02x}", b);
                    }
                }
                other => {
                    return Err(ComptimeError::new(
                        ComptimeErrorKind::TypeMismatch {
                            expected: "array ou str".to_string(),
                            found: other.type_name().to_string(),
                        },
                        span,
                    ));
                }
            }
            Ok(Value::String(hex_str))
        }
        "json_validate" => {
            if args.len() != 1 {
                return Err(ComptimeError::new(
                    ComptimeErrorKind::ArityMismatch {
                        expected: 1,
                        found: args.len(),
                    },
                    span,
                ));
            }
            let text = match &args[0] {
                Value::String(s) => s.as_str(),
                other => {
                    return Err(ComptimeError::new(
                        ComptimeErrorKind::TypeMismatch {
                            expected: "str".to_string(),
                            found: other.type_name().to_string(),
                        },
                        span,
                    ));
                }
            };
            let is_valid = validate_json_syntax(text);
            Ok(Value::Bool(is_valid))
        }
        "abs" => {
            if args.len() != 1 {
                return Err(ComptimeError::new(
                    ComptimeErrorKind::ArityMismatch {
                        expected: 1,
                        found: args.len(),
                    },
                    span,
                ));
            }
            match &args[0] {
                Value::Int(i) => Ok(Value::Int(i.abs())),
                Value::UInt(u) => Ok(Value::UInt(*u)),
                Value::Float(f) => Ok(Value::Float(f.abs())),
                other => Err(ComptimeError::new(
                    ComptimeErrorKind::TypeMismatch {
                        expected: "numérique".to_string(),
                        found: other.type_name().to_string(),
                    },
                    span,
                )),
            }
        }
        "sqrt" => {
            if args.len() != 1 {
                return Err(ComptimeError::new(
                    ComptimeErrorKind::ArityMismatch {
                        expected: 1,
                        found: args.len(),
                    },
                    span,
                ));
            }
            let f = match &args[0] {
                Value::Float(f) => *f,
                Value::Int(i) => *i as f64,
                Value::UInt(u) => *u as f64,
                other => {
                    return Err(ComptimeError::new(
                        ComptimeErrorKind::TypeMismatch {
                            expected: "float".to_string(),
                            found: other.type_name().to_string(),
                        },
                        span,
                    ));
                }
            };
            if f < 0.0 {
                return Err(ComptimeError::new(
                    ComptimeErrorKind::InvalidUnaryOp {
                        op: "sqrt".to_string(),
                        operand: format!("{}", f),
                    },
                    span,
                ));
            }
            Ok(Value::Float(f.sqrt()))
        }
        "sin" => {
            if args.len() != 1 {
                return Err(ComptimeError::new(
                    ComptimeErrorKind::ArityMismatch {
                        expected: 1,
                        found: args.len(),
                    },
                    span,
                ));
            }
            let f = match &args[0] {
                Value::Float(f) => *f,
                Value::Int(i) => *i as f64,
                Value::UInt(u) => *u as f64,
                other => {
                    return Err(ComptimeError::new(
                        ComptimeErrorKind::TypeMismatch {
                            expected: "float".to_string(),
                            found: other.type_name().to_string(),
                        },
                        span,
                    ));
                }
            };
            Ok(Value::Float(f.sin()))
        }
        "cos" => {
            if args.len() != 1 {
                return Err(ComptimeError::new(
                    ComptimeErrorKind::ArityMismatch {
                        expected: 1,
                        found: args.len(),
                    },
                    span,
                ));
            }
            let f = match &args[0] {
                Value::Float(f) => *f,
                Value::Int(i) => *i as f64,
                Value::UInt(u) => *u as f64,
                other => {
                    return Err(ComptimeError::new(
                        ComptimeErrorKind::TypeMismatch {
                            expected: "float".to_string(),
                            found: other.type_name().to_string(),
                        },
                        span,
                    ));
                }
            };
            Ok(Value::Float(f.cos()))
        }
        "floor" => {
            if args.len() != 1 {
                return Err(ComptimeError::new(
                    ComptimeErrorKind::ArityMismatch {
                        expected: 1,
                        found: args.len(),
                    },
                    span,
                ));
            }
            let f = match &args[0] {
                Value::Float(f) => *f,
                Value::Int(i) => *i as f64,
                Value::UInt(u) => *u as f64,
                other => {
                    return Err(ComptimeError::new(
                        ComptimeErrorKind::TypeMismatch {
                            expected: "float".to_string(),
                            found: other.type_name().to_string(),
                        },
                        span,
                    ));
                }
            };
            Ok(Value::Float(f.floor()))
        }
        "ceil" => {
            if args.len() != 1 {
                return Err(ComptimeError::new(
                    ComptimeErrorKind::ArityMismatch {
                        expected: 1,
                        found: args.len(),
                    },
                    span,
                ));
            }
            let f = match &args[0] {
                Value::Float(f) => *f,
                Value::Int(i) => *i as f64,
                Value::UInt(u) => *u as f64,
                other => {
                    return Err(ComptimeError::new(
                        ComptimeErrorKind::TypeMismatch {
                            expected: "float".to_string(),
                            found: other.type_name().to_string(),
                        },
                        span,
                    ));
                }
            };
            Ok(Value::Float(f.ceil()))
        }
        "min" => {
            if args.len() != 2 {
                return Err(ComptimeError::new(
                    ComptimeErrorKind::ArityMismatch {
                        expected: 2,
                        found: args.len(),
                    },
                    span,
                ));
            }
            match (&args[0], &args[1]) {
                (Value::Int(a), Value::Int(b)) => Ok(Value::Int(*a.min(b))),
                (Value::UInt(a), Value::UInt(b)) => Ok(Value::UInt(*a.min(b))),
                (Value::Float(a), Value::Float(b)) => Ok(Value::Float(a.min(*b))),
                (Value::Int(a), Value::Float(b)) => Ok(Value::Float((*a as f64).min(*b))),
                (Value::Float(a), Value::Int(b)) => Ok(Value::Float(a.min(*b as f64))),
                (other1, other2) => Err(ComptimeError::new(
                    ComptimeErrorKind::InvalidBinaryOp {
                        op: "min".to_string(),
                        left: other1.type_name().to_string(),
                        right: other2.type_name().to_string(),
                    },
                    span,
                )),
            }
        }
        "max" => {
            if args.len() != 2 {
                return Err(ComptimeError::new(
                    ComptimeErrorKind::ArityMismatch {
                        expected: 2,
                        found: args.len(),
                    },
                    span,
                ));
            }
            match (&args[0], &args[1]) {
                (Value::Int(a), Value::Int(b)) => Ok(Value::Int(*a.max(b))),
                (Value::UInt(a), Value::UInt(b)) => Ok(Value::UInt(*a.max(b))),
                (Value::Float(a), Value::Float(b)) => Ok(Value::Float(a.max(*b))),
                (Value::Int(a), Value::Float(b)) => Ok(Value::Float((*a as f64).max(*b))),
                (Value::Float(a), Value::Int(b)) => Ok(Value::Float(a.max(*b as f64))),
                (other1, other2) => Err(ComptimeError::new(
                    ComptimeErrorKind::InvalidBinaryOp {
                        op: "max".to_string(),
                        left: other1.type_name().to_string(),
                        right: other2.type_name().to_string(),
                    },
                    span,
                )),
            }
        }
        "pow" => {
            if args.len() != 2 {
                return Err(ComptimeError::new(
                    ComptimeErrorKind::ArityMismatch {
                        expected: 2,
                        found: args.len(),
                    },
                    span,
                ));
            }
            match (&args[0], &args[1]) {
                (Value::Int(base), Value::Int(exp)) if *exp >= 0 && *exp <= u32::MAX as i64 => {
                    match base.checked_pow(*exp as u32) {
                        Some(res) => Ok(Value::Int(res)),
                        None => {
                            let base_f = *base as f64;
                            let exp_f = *exp as f64;
                            Ok(Value::Float(base_f.powf(exp_f)))
                        }
                    }
                }
                (Value::Float(base), Value::Float(exp)) => Ok(Value::Float(base.powf(*exp))),
                (Value::Int(base), Value::Float(exp)) => {
                    Ok(Value::Float((*base as f64).powf(*exp)))
                }
                (Value::Float(base), Value::Int(exp)) => Ok(Value::Float(base.powf(*exp as f64))),
                (other1, other2) => Err(ComptimeError::new(
                    ComptimeErrorKind::InvalidBinaryOp {
                        op: "pow".to_string(),
                        left: other1.type_name().to_string(),
                        right: other2.type_name().to_string(),
                    },
                    span,
                )),
            }
        }
        _ => Err(ComptimeError::new(
            ComptimeErrorKind::UndefinedFunction(name_str),
            span,
        )),
    }
}

/// Computes the IEEE 802.3 CRC32 checksum.
pub fn compute_crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = ((crc & 1) != 0) as u32;
            crc = (crc >> 1) ^ (0xEDB8_8320 & (!mask).wrapping_add(1));
        }
    }
    !crc
}

/// Static JSON validation check without requiring external parser crates.
fn validate_json_syntax(text: &str) -> bool {
    let text = text.trim();
    if text.is_empty() {
        return false;
    }
    let mut stack = Vec::new();
    let mut in_string = false;
    let mut escape = false;

    for ch in text.chars() {
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' | '[' => stack.push(ch),
            '}' if stack.pop() != Some('{') => return false,
            ']' if stack.pop() != Some('[') => return false,
            _ => {}
        }
    }

    !in_string && stack.is_empty()
}

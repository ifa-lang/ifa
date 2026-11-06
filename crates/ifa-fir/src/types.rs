use ifa_sema::types::{FloatType, IntType, Type as SemaType};
use ifa_span::Symbol;
use std::fmt;

/// Intermediate representation types for FIR SSA.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FirType {
    Unit,
    Bool,
    Int(IntType),
    Float(FloatType),
    Char,
    Str,
    String,
    Pointer(Box<FirType>),
    GenerationalRef(Box<FirType>),
    Struct(Symbol, Vec<(Symbol, FirType)>),
    Enum(Symbol, Vec<(Symbol, Option<FirType>)>),
    Array(Box<FirType>, u32),
    Slice(Box<FirType>),
    Optional(Box<FirType>),
    ErrorUnion {
        err: Box<FirType>,
        ok: Box<FirType>,
    },
    Function {
        params: Vec<FirType>,
        ret: Box<FirType>,
    },
}

impl FirType {
    /// Convert semantic analyzer Type into FIR intermediate type.
    pub fn from_sema_type(ty: &SemaType) -> Self {
        match ty {
            SemaType::Unit => FirType::Unit,
            SemaType::Bool => FirType::Bool,
            SemaType::Int(i) => FirType::Int(*i),
            SemaType::Float(f) => FirType::Float(*f),
            SemaType::Char => FirType::Char,
            SemaType::Str => FirType::Str,
            SemaType::String => FirType::String,
            SemaType::Ref(inner) => FirType::GenerationalRef(Box::new(Self::from_sema_type(inner))),
            SemaType::Struct { name, fields } => {
                let fir_fields = fields
                    .iter()
                    .map(|(s, t)| (*s, Self::from_sema_type(t)))
                    .collect();
                FirType::Struct(*name, fir_fields)
            }
            SemaType::Enum { name, variants } => {
                let fir_variants = variants
                    .iter()
                    .map(|(s, opt_t)| (*s, opt_t.as_ref().map(Self::from_sema_type)))
                    .collect();
                FirType::Enum(*name, fir_variants)
            }
            SemaType::Array(inner, size) => {
                FirType::Array(Box::new(Self::from_sema_type(inner)), *size)
            }
            SemaType::Slice(inner) => FirType::Slice(Box::new(Self::from_sema_type(inner))),
            SemaType::Optional(inner) => FirType::Optional(Box::new(Self::from_sema_type(inner))),
            SemaType::ErrorUnion { err, ok } => FirType::ErrorUnion {
                err: Box::new(Self::from_sema_type(err)),
                ok: Box::new(Self::from_sema_type(ok)),
            },
            SemaType::Fn { params, ret } => FirType::Function {
                params: params
                    .iter()
                    .map(|(_, t)| Self::from_sema_type(t))
                    .collect(),
                ret: Box::new(Self::from_sema_type(ret)),
            },
            SemaType::Tuple(fields) => {
                let fir_fields = fields
                    .iter()
                    .enumerate()
                    .map(|(i, t)| {
                        let name_str = format!("_{}", i);
                        let sym = ifa_span::INTERNER.intern(&name_str);
                        (sym, Self::from_sema_type(t))
                    })
                    .collect();
                let tuple_sym = ifa_span::INTERNER.intern("Tuple");
                FirType::Struct(tuple_sym, fir_fields)
            }
            SemaType::Generic { name, args } => {
                let sym_str = format!("{}_{}", name.as_str(), args.len());
                let gen_sym = ifa_span::INTERNER.intern(&sym_str);
                FirType::Struct(gen_sym, Vec::new())
            }
            SemaType::IntegerLiteral(_) => FirType::Int(IntType::I64),
            SemaType::FloatLiteral => FirType::Float(FloatType::F64),
            SemaType::Never | SemaType::Unknown => FirType::Unit,
        }
    }

    /// Returns true if this is a generational reference (requiring 128-bit fat pointer).
    pub fn is_generational_ref(&self) -> bool {
        matches!(self, FirType::GenerationalRef(_))
    }

    /// Returns true if this is a heap-allocated or reference-counted CoW candidate.
    pub fn is_cow_candidate(&self) -> bool {
        matches!(
            self,
            FirType::String | FirType::Slice(_) | FirType::Struct(_, _) | FirType::Array(_, _)
        )
    }
}

impl fmt::Display for FirType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FirType::Unit => write!(f, "()"),
            FirType::Bool => write!(f, "bool"),
            FirType::Int(i) => write!(f, "{}", i),
            FirType::Float(fl) => write!(f, "{}", fl),
            FirType::Char => write!(f, "char"),
            FirType::Str => write!(f, "str"),
            FirType::String => write!(f, "String"),
            FirType::Pointer(inner) => write!(f, "*{}", inner),
            FirType::GenerationalRef(inner) => write!(f, "ref {}", inner),
            FirType::Struct(name, _) => write!(f, "{}", name.as_str()),
            FirType::Enum(name, _) => write!(f, "{}", name.as_str()),
            FirType::Array(inner, size) => write!(f, "[{}; {}]", inner, size),
            FirType::Slice(inner) => write!(f, "Slice<{}>", inner),
            FirType::Optional(inner) => write!(f, "?{}", inner),
            FirType::ErrorUnion { err, ok } => write!(f, "{}!{}", err, ok),
            FirType::Function { params, ret } => {
                write!(f, "fn(")?;
                for (i, p) in params.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", p)?;
                }
                write!(f, ") -> {}", ret)
            }
        }
    }
}

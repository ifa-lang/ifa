use ifa_sema::types::Type as SemaType;
pub use ifa_sema::types::{FloatType, IntType};
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
    Range {
        elem: Box<FirType>,
        inclusive: bool,
    },
    Optional(Box<FirType>),
    ErrorUnion {
        err: Box<FirType>,
        ok: Box<FirType>,
    },
    Channel(Box<FirType>),
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
            SemaType::Range { elem, inclusive } => FirType::Range {
                elem: Box::new(Self::from_sema_type(elem)),
                inclusive: *inclusive,
            },
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
                if args.is_empty() {
                    FirType::Struct(*name, Vec::new())
                } else {
                    let mangled_sym =
                        mangle_instantiation_symbol(&ifa_span::INTERNER.resolve(name), args);
                    FirType::Struct(mangled_sym, Vec::new())
                }
            }
            SemaType::TypeParam(_) => FirType::Int(IntType::I64),
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

    /// Returns the concrete memory footprint size in bytes for this type.
    pub fn byte_size(&self) -> usize {
        match self {
            FirType::Unit => 0,
            FirType::Bool | FirType::Char => 1,
            FirType::Int(i) => match i {
                IntType::I8 | IntType::U8 => 1,
                IntType::I16 | IntType::U16 => 2,
                IntType::I32 | IntType::U32 => 4,
                IntType::I64 | IntType::U64 | IntType::ISize | IntType::USize => 8,
            },
            FirType::Float(f) => match f {
                FloatType::F32 => 4,
                FloatType::F64 => 8,
            },
            FirType::Str | FirType::Slice(_) => 16,
            FirType::String => 24,
            FirType::Pointer(_) | FirType::Channel(_) => 8,
            FirType::GenerationalRef(_) => 16,
            FirType::Struct(_, fields) => {
                let size: usize = fields.iter().map(|(_, ty)| ty.byte_size().max(8)).sum();
                size.max(8)
            }
            FirType::Enum(_, variants) => {
                let payload_max: usize = variants
                    .iter()
                    .filter_map(|(_, opt)| opt.as_ref().map(|t| t.byte_size()))
                    .max()
                    .unwrap_or(0);
                payload_max + 8
            }
            FirType::Array(elem, len) => elem.byte_size() * (*len as usize),
            FirType::Range { elem, .. } => elem.byte_size() * 2 + 8,
            FirType::Optional(inner) => inner.byte_size() + 1,
            FirType::ErrorUnion { ok, .. } => ok.byte_size() + 8,
            FirType::Function { .. } => 16,
        }
    }

    /// Returns the natural memory alignment requirement in bytes for this type.
    pub fn alignment(&self) -> usize {
        match self {
            FirType::Unit => 1,
            FirType::Bool | FirType::Char => 1,
            FirType::Int(i) => match i {
                IntType::I8 | IntType::U8 => 1,
                IntType::I16 | IntType::U16 => 2,
                IntType::I32 | IntType::U32 => 4,
                IntType::I64 | IntType::U64 | IntType::ISize | IntType::USize => 8,
            },
            FirType::Float(f) => match f {
                FloatType::F32 => 4,
                FloatType::F64 => 8,
            },
            FirType::Str | FirType::Slice(_) => 8,
            FirType::String => 8,
            FirType::Pointer(_) | FirType::Channel(_) => 8,
            FirType::GenerationalRef(_) => 8,
            FirType::Struct(_, fields) => fields
                .iter()
                .map(|(_, ty)| ty.alignment())
                .max()
                .unwrap_or(8)
                .max(1),
            FirType::Enum(_, variants) => {
                let payload_align = variants
                    .iter()
                    .filter_map(|(_, opt)| opt.as_ref().map(|t| t.alignment()))
                    .max()
                    .unwrap_or(1);
                payload_align.max(8)
            }
            FirType::Array(elem, _) => elem.alignment(),
            FirType::Range { elem, .. } => elem.alignment().max(8),
            FirType::Optional(inner) => inner.alignment(),
            FirType::ErrorUnion { ok, .. } => ok.alignment().max(8),
            FirType::Function { .. } => 8,
        }
    }

    /// Recursively checks if this type references a specified struct symbol.
    pub fn is_recursive_with_name(&self, struct_name: Symbol) -> bool {
        match self {
            FirType::GenerationalRef(inner)
            | FirType::Pointer(inner)
            | FirType::Optional(inner)
            | FirType::Slice(inner) => inner.is_recursive_with_name(struct_name),
            FirType::Array(inner, _) => inner.is_recursive_with_name(struct_name),
            FirType::Struct(name, fields) => {
                if *name == struct_name {
                    true
                } else {
                    fields
                        .iter()
                        .any(|(_, t)| t.is_recursive_with_name(struct_name))
                }
            }
            FirType::Enum(name, variants) => {
                if *name == struct_name {
                    true
                } else {
                    variants.iter().any(|(_, opt)| {
                        opt.as_ref()
                            .is_some_and(|t| t.is_recursive_with_name(struct_name))
                    })
                }
            }
            _ => false,
        }
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
            FirType::Range { elem, inclusive } => {
                write!(f, "Range<{}{}>", if *inclusive { "=" } else { "" }, elem)
            }
            FirType::Optional(inner) => write!(f, "?{}", inner),
            FirType::ErrorUnion { err, ok } => write!(f, "{}!{}", err, ok),
            FirType::Channel(inner) => write!(f, "chan<{}>", inner),
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

pub use ifa_sema::types::{mangle_instantiation_symbol, mangle_sema_type};

use ifa_ast::{GenericParam, ParamMode, Type as AstType, TypeKind as AstTypeKind};
use ifa_diagnostics::Diagnostic;
use ifa_span::{Symbol, INTERNER};
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntType {
    I8,
    I16,
    I32,
    I64,
    ISize,
    U8,
    U16,
    U32,
    U64,
    USize,
}

impl IntType {
    pub fn is_signed(self) -> bool {
        matches!(
            self,
            IntType::I8 | IntType::I16 | IntType::I32 | IntType::I64 | IntType::ISize
        )
    }

    pub fn is_unsigned(self) -> bool {
        !self.is_signed()
    }

    pub fn bit_width(self) -> u32 {
        match self {
            IntType::I8 | IntType::U8 => 8,
            IntType::I16 | IntType::U16 => 16,
            IntType::I32 | IntType::U32 => 32,
            IntType::I64 | IntType::U64 => 64,
            IntType::ISize | IntType::USize => 64,
        }
    }
}

impl fmt::Display for IntType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IntType::I8 => write!(f, "i8"),
            IntType::I16 => write!(f, "i16"),
            IntType::I32 => write!(f, "i32"),
            IntType::I64 => write!(f, "i64"),
            IntType::ISize => write!(f, "isize"),
            IntType::U8 => write!(f, "u8"),
            IntType::U16 => write!(f, "u16"),
            IntType::U32 => write!(f, "u32"),
            IntType::U64 => write!(f, "u64"),
            IntType::USize => write!(f, "usize"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FloatType {
    F32,
    F64,
}

impl fmt::Display for FloatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FloatType::F32 => write!(f, "f32"),
            FloatType::F64 => write!(f, "f64"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Type {
    Unit,
    Bool,
    Int(IntType),
    Float(FloatType),
    Char,
    Str,
    String,
    Ref(Box<Type>),
    Optional(Box<Type>),
    Slice(Box<Type>),
    Array(Box<Type>, u32),
    Range {
        elem: Box<Type>,
        inclusive: bool,
    },
    ErrorUnion {
        err: Box<Type>,
        ok: Box<Type>,
    },
    Struct {
        name: Symbol,
        fields: Vec<(Symbol, Type)>,
    },
    Enum {
        name: Symbol,
        variants: Vec<(Symbol, Option<Type>)>,
    },
    Tuple(Vec<Type>),
    Fn {
        params: Vec<(ParamMode, Type)>,
        ret: Box<Type>,
    },
    Generic {
        name: Symbol,
        args: Vec<Type>,
    },
    /// Unconstrained integer literal waiting for bidirectional inference or default (i64/u64)
    IntegerLiteral(u64),
    /// Unconstrained float literal waiting for bidirectional inference or default (f64)
    FloatLiteral,
    /// Type for expressions that never return normally (return, fail, infinite loop)
    Never,
    /// Generic type parameter placeholder (e.g. T in struct Box<T>)
    TypeParam(Symbol),
    /// Unknown / error sentinel to avoid cascading errors
    Unknown,
}

impl Type {
    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            Type::Int(_) | Type::Float(_) | Type::IntegerLiteral(_) | Type::FloatLiteral
        )
    }

    pub fn is_integer(&self) -> bool {
        matches!(self, Type::Int(_) | Type::IntegerLiteral(_))
    }

    pub fn is_float(&self) -> bool {
        matches!(self, Type::Float(_) | Type::FloatLiteral)
    }

    pub fn is_unit(&self) -> bool {
        matches!(self, Type::Unit)
    }

    pub fn is_never(&self) -> bool {
        matches!(self, Type::Never)
    }

    pub fn is_ref(&self) -> bool {
        matches!(self, Type::Ref(_))
    }

    pub fn is_optional(&self) -> bool {
        matches!(self, Type::Optional(_))
    }

    pub fn is_error_union(&self) -> bool {
        matches!(self, Type::ErrorUnion { .. })
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self, Type::Unknown)
    }

    pub fn parse_int_literal(text: &str, expected: Option<&Type>) -> Type {
        if text.ends_with("u8") {
            Type::Int(IntType::U8)
        } else if text.ends_with("u16") {
            Type::Int(IntType::U16)
        } else if text.ends_with("u32") {
            Type::Int(IntType::U32)
        } else if text.ends_with("u64") {
            Type::Int(IntType::U64)
        } else if text.ends_with("usize") {
            Type::Int(IntType::USize)
        } else if text.ends_with("i8") {
            Type::Int(IntType::I8)
        } else if text.ends_with("i16") {
            Type::Int(IntType::I16)
        } else if text.ends_with("i32") {
            Type::Int(IntType::I32)
        } else if text.ends_with("i64") {
            Type::Int(IntType::I64)
        } else if text.ends_with("isize") {
            Type::Int(IntType::ISize)
        } else if let Some(Type::Int(expected_int)) = expected {
            Type::Int(*expected_int)
        } else {
            Type::IntegerLiteral(0)
        }
    }

    pub fn parse_float_literal(text: &str, expected: Option<&Type>) -> Type {
        if text.ends_with("f32") {
            Type::Float(FloatType::F32)
        } else if text.ends_with("f64") {
            Type::Float(FloatType::F64)
        } else if let Some(Type::Float(expected_fl)) = expected {
            Type::Float(*expected_fl)
        } else {
            Type::FloatLiteral
        }
    }

    /// Resolves an integer or float literal into its concrete type, or leaves other types intact.
    pub fn resolve_defaults(&self) -> Type {
        match self {
            Type::IntegerLiteral(_) => Type::Int(IntType::I64),
            Type::FloatLiteral => Type::Float(FloatType::F64),
            Type::Ref(inner) => Type::Ref(Box::new(inner.resolve_defaults())),
            Type::Optional(inner) => Type::Optional(Box::new(inner.resolve_defaults())),
            Type::Slice(inner) => Type::Slice(Box::new(inner.resolve_defaults())),
            Type::Array(inner, n) => Type::Array(Box::new(inner.resolve_defaults()), *n),
            Type::Range { elem, inclusive } => Type::Range {
                elem: Box::new(elem.resolve_defaults()),
                inclusive: *inclusive,
            },
            Type::ErrorUnion { err, ok } => Type::ErrorUnion {
                err: Box::new(err.resolve_defaults()),
                ok: Box::new(ok.resolve_defaults()),
            },
            Type::Tuple(elems) => Type::Tuple(elems.iter().map(|e| e.resolve_defaults()).collect()),
            _ => self.clone(),
        }
    }

    /// Checks if a value of type `self` can be assigned or coerced to `target`.
    pub fn is_assignable_to(&self, target: &Type) -> bool {
        if self == target {
            return true;
        }

        // Never can satisfy any expected return/value type
        if matches!(self, Type::Never) {
            return true;
        }

        // Unknown suppresses cascading errors
        if matches!(self, Type::Unknown) || matches!(target, Type::Unknown) {
            return true;
        }

        // Integer literal can coerce to any concrete integer type
        if let Type::IntegerLiteral(_) = self {
            if matches!(target, Type::Int(_)) {
                return true;
            }
        }

        // Float literal can coerce to any concrete float type
        if let Type::FloatLiteral = self {
            if matches!(target, Type::Float(_)) {
                return true;
            }
        }

        // Optional to Optional compatibility
        if let (Type::Optional(src_inner), Type::Optional(target_inner)) = (self, target) {
            return src_inner.is_assignable_to(target_inner);
        }

        // T can coerce to Optional(T)
        if let Type::Optional(inner_target) = target {
            if self.is_assignable_to(inner_target) {
                return true;
            }
            // None / Unit can assign to Optional
            if matches!(self, Type::Unit) {
                return true;
            }
        }

        // Array [T; N] to Array [U; N] compatibility
        if let (Type::Array(src_elem, src_n), Type::Array(target_elem, target_n)) = (self, target) {
            if src_n == target_n && src_elem.is_assignable_to(target_elem) {
                return true;
            }
        }

        // Array [T; N] can coerce to Slice<T>
        if let (Type::Array(src_elem, _), Type::Slice(target_elem)) = (self, target) {
            if src_elem.is_assignable_to(target_elem) {
                return true;
            }
        }

        if let (
            Type::Range {
                elem: s_elem,
                inclusive: s_inc,
            },
            Type::Range {
                elem: t_elem,
                inclusive: t_inc,
            },
        ) = (self, target)
        {
            if s_inc == t_inc && s_elem.is_assignable_to(t_elem) {
                return true;
            }
        }

        // Tuple to Tuple compatibility
        if let (Type::Tuple(src_elems), Type::Tuple(target_elems)) = (self, target) {
            if src_elems.len() == target_elems.len() {
                return src_elems
                    .iter()
                    .zip(target_elems.iter())
                    .all(|(s, t)| s.is_assignable_to(t));
            }
        }

        // Ref(T) assignable to Ref(T)
        if let (Type::Ref(src_inner), Type::Ref(target_inner)) = (self, target) {
            return src_inner.is_assignable_to(target_inner);
        }

        // Ref(T) can coerce to T for projection / read-only access
        if let Type::Ref(src_inner) = self {
            if src_inner.is_assignable_to(target) {
                return true;
            }
        }

        // Str and String compatibility for string parameters
        if (matches!(self, Type::Str) && matches!(target, Type::String))
            || (matches!(self, Type::String) && matches!(target, Type::Str))
        {
            return true;
        }

        // Error union compatibility: T can coerce to ErrorUnion<E, T>
        if let Type::ErrorUnion { ok, .. } = target {
            if self.is_assignable_to(ok) {
                return true;
            }
        }

        // Generic structs like List<T> or custom Box<T>
        if let (Type::Generic { name: n1, args: a1 }, Type::Generic { name: n2, args: a2 }) =
            (self, target)
        {
            if n1 == n2 && a1.len() == a2.len() {
                return a1
                    .iter()
                    .zip(a2.iter())
                    .all(|(t1, t2)| t1.is_assignable_to(t2));
            }
        }

        // Generic struct compatible with base Struct symbol and vice versa
        if let (Type::Generic { name: n1, .. }, Type::Struct { name: n2, .. }) = (self, target) {
            if n1 == n2 {
                return true;
            }
        }
        if let (Type::Struct { name: n1, .. }, Type::Generic { name: n2, .. }) = (self, target) {
            if n1 == n2 {
                return true;
            }
        }

        // Struct by name
        if let (Type::Struct { name: n1, .. }, Type::Struct { name: n2, .. }) = (self, target) {
            return n1 == n2;
        }

        // Generic type parameter equality
        if let (Type::TypeParam(s1), Type::TypeParam(s2)) = (self, target) {
            return s1 == s2;
        }

        // Enum by name
        if let (Type::Enum { name: n1, .. }, Type::Enum { name: n2, .. }) = (self, target) {
            return n1 == n2;
        }

        // First-class functions and closures compatibility
        if let (
            Type::Fn {
                params: p1,
                ret: r1,
            },
            Type::Fn {
                params: p2,
                ret: r2,
            },
        ) = (self, target)
        {
            if p1.len() == p2.len() {
                let params_match = p1.iter().zip(p2.iter()).all(|((m1, t1), (m2, t2))| {
                    m1 == m2 && (t2.is_assignable_to(t1) || t1.is_assignable_to(t2))
                });
                return params_match && r1.is_assignable_to(r2);
            }
        }

        false
    }

    /// Substitutes generic type parameters according to the provided mapping.
    pub fn substitute(&self, mapping: &HashMap<Symbol, Type>) -> Type {
        match self {
            Type::TypeParam(sym) => mapping.get(sym).cloned().unwrap_or_else(|| self.clone()),
            Type::Ref(inner) => Type::Ref(Box::new(inner.substitute(mapping))),
            Type::Optional(inner) => Type::Optional(Box::new(inner.substitute(mapping))),
            Type::Slice(inner) => Type::Slice(Box::new(inner.substitute(mapping))),
            Type::Array(inner, n) => Type::Array(Box::new(inner.substitute(mapping)), *n),
            Type::Range { elem, inclusive } => Type::Range {
                elem: Box::new(elem.substitute(mapping)),
                inclusive: *inclusive,
            },
            Type::ErrorUnion { err, ok } => Type::ErrorUnion {
                err: Box::new(err.substitute(mapping)),
                ok: Box::new(ok.substitute(mapping)),
            },
            Type::Tuple(elems) => {
                Type::Tuple(elems.iter().map(|e| e.substitute(mapping)).collect())
            }
            Type::Generic { name, args } => Type::Generic {
                name: *name,
                args: args.iter().map(|a| a.substitute(mapping)).collect(),
            },
            Type::Struct { name, fields } => Type::Struct {
                name: *name,
                fields: fields
                    .iter()
                    .map(|(n, t)| (*n, t.substitute(mapping)))
                    .collect(),
            },
            Type::Fn { params, ret } => Type::Fn {
                params: params
                    .iter()
                    .map(|(m, t)| (*m, t.substitute(mapping)))
                    .collect(),
                ret: Box::new(ret.substitute(mapping)),
            },
            _ => self.clone(),
        }
    }

    /// Unifies any generic type parameters in `self` against concrete types in `concrete`.
    pub fn unify_type_params(&self, concrete: &Type, mapping: &mut HashMap<Symbol, Type>) {
        match (self, concrete) {
            (Type::TypeParam(sym), c) => match mapping.get(sym) {
                None => {
                    mapping.insert(*sym, c.resolve_defaults());
                }
                Some(Type::Unknown) if !matches!(c, Type::Unknown) => {
                    mapping.insert(*sym, c.resolve_defaults());
                }
                _ => {}
            },
            (Type::Ref(inner), Type::Ref(c_inner)) => {
                inner.unify_type_params(c_inner, mapping);
            }
            (Type::Ref(inner), c) => {
                inner.unify_type_params(c, mapping);
            }
            (p, Type::Ref(c_inner)) if !matches!(p, Type::Ref(_)) => {
                p.unify_type_params(c_inner, mapping);
            }
            (Type::Optional(inner), Type::Optional(c_inner)) => {
                inner.unify_type_params(c_inner, mapping);
            }
            (Type::Optional(inner), c) => {
                // T coercing to ?T
                inner.unify_type_params(c, mapping);
            }
            (Type::Slice(inner), Type::Slice(c_inner)) => {
                inner.unify_type_params(c_inner, mapping);
            }
            (Type::Array(inner, _), Type::Array(c_inner, _)) => {
                inner.unify_type_params(c_inner, mapping);
            }
            (
                Type::Range {
                    elem: inner,
                    inclusive: inc1,
                },
                Type::Range {
                    elem: c_inner,
                    inclusive: inc2,
                },
            ) if inc1 == inc2 => {
                inner.unify_type_params(c_inner, mapping);
            }
            (Type::Generic { name: n1, args: a1 }, Type::Generic { name: n2, args: a2 })
                if n1 == n2 =>
            {
                for (a, c) in a1.iter().zip(a2.iter()) {
                    a.unify_type_params(c, mapping);
                }
            }
            (Type::Tuple(elems1), Type::Tuple(elems2)) => {
                for (e1, e2) in elems1.iter().zip(elems2.iter()) {
                    e1.unify_type_params(e2, mapping);
                }
            }
            _ => {}
        }
    }

    /// Resolves an AST Type into a semantic Type using known declarations.
    pub fn from_ast(
        ast_ty: &AstType,
        known_structs: &HashMap<Symbol, Type>,
        known_enums: &HashMap<Symbol, Type>,
    ) -> Result<Type, Diagnostic> {
        Self::from_ast_with_generics(ast_ty, known_structs, known_enums, &[])
    }

    /// Resolves an AST Type into a semantic Type with awareness of in-scope generic parameters.
    pub fn from_ast_with_generics(
        ast_ty: &AstType,
        known_structs: &HashMap<Symbol, Type>,
        known_enums: &HashMap<Symbol, Type>,
        generics: &[GenericParam],
    ) -> Result<Type, Diagnostic> {
        match &ast_ty.kind {
            AstTypeKind::Unit => Ok(Type::Unit),
            AstTypeKind::Named(sym) => {
                if generics.iter().any(|g| g.name == *sym) {
                    return Ok(Type::TypeParam(*sym));
                }
                let name = INTERNER.resolve(sym);
                match name.as_str() {
                    "bool" => Ok(Type::Bool),
                    "u8" => Ok(Type::Int(IntType::U8)),
                    "u16" => Ok(Type::Int(IntType::U16)),
                    "u32" => Ok(Type::Int(IntType::U32)),
                    "u64" => Ok(Type::Int(IntType::U64)),
                    "usize" => Ok(Type::Int(IntType::USize)),
                    "i8" => Ok(Type::Int(IntType::I8)),
                    "i16" => Ok(Type::Int(IntType::I16)),
                    "i32" => Ok(Type::Int(IntType::I32)),
                    "i64" => Ok(Type::Int(IntType::I64)),
                    "isize" => Ok(Type::Int(IntType::ISize)),
                    "f32" => Ok(Type::Float(FloatType::F32)),
                    "f64" => Ok(Type::Float(FloatType::F64)),
                    "char" => Ok(Type::Char),
                    "str" => Ok(Type::Str),
                    "String" => Ok(Type::String),
                    "void" => Ok(Type::Unit),
                    _ => {
                        if let Some(st) = known_structs.get(sym) {
                            Ok(st.clone())
                        } else if let Some(en) = known_enums.get(sym) {
                            Ok(en.clone())
                        } else {
                            // Forward reference or generic type parameter
                            Ok(Type::Struct {
                                name: *sym,
                                fields: Vec::new(),
                            })
                        }
                    }
                }
            }
            AstTypeKind::Path(path) => {
                if let Some(last) = path.last() {
                    if let Some(st) = known_structs.get(last) {
                        return Ok(st.clone());
                    } else if let Some(en) = known_enums.get(last) {
                        return Ok(en.clone());
                    }
                    Ok(Type::Struct {
                        name: *last,
                        fields: Vec::new(),
                    })
                } else {
                    Ok(Type::Unknown)
                }
            }
            AstTypeKind::Generic(sym, args) => {
                let resolved_args: Result<Vec<Type>, Diagnostic> = args
                    .iter()
                    .map(|a| Type::from_ast_with_generics(a, known_structs, known_enums, generics))
                    .collect();
                let args = resolved_args?;
                let name = INTERNER.resolve(sym);
                if name == "Slice" && args.len() == 1 {
                    Ok(Type::Slice(Box::new(args[0].clone())))
                } else {
                    Ok(Type::Generic { name: *sym, args })
                }
            }
            AstTypeKind::Ref(inner) => {
                let resolved =
                    Type::from_ast_with_generics(inner, known_structs, known_enums, generics)?;
                Ok(Type::Ref(Box::new(resolved)))
            }
            AstTypeKind::Optional(inner) => {
                let resolved =
                    Type::from_ast_with_generics(inner, known_structs, known_enums, generics)?;
                Ok(Type::Optional(Box::new(resolved)))
            }
            AstTypeKind::Slice(inner) => {
                let resolved =
                    Type::from_ast_with_generics(inner, known_structs, known_enums, generics)?;
                Ok(Type::Slice(Box::new(resolved)))
            }
            AstTypeKind::Array(inner, size) => {
                let resolved =
                    Type::from_ast_with_generics(inner, known_structs, known_enums, generics)?;
                Ok(Type::Array(Box::new(resolved), *size))
            }
            AstTypeKind::ErrorUnion(err_ty, ok_ty) => {
                let err =
                    Type::from_ast_with_generics(err_ty, known_structs, known_enums, generics)?;
                let ok = Type::from_ast_with_generics(ok_ty, known_structs, known_enums, generics)?;
                Ok(Type::ErrorUnion {
                    err: Box::new(err),
                    ok: Box::new(ok),
                })
            }
            AstTypeKind::Tuple(types) => {
                let resolved: Result<Vec<Type>, Diagnostic> = types
                    .iter()
                    .map(|t| Type::from_ast_with_generics(t, known_structs, known_enums, generics))
                    .collect();
                Ok(Type::Tuple(resolved?))
            }
            AstTypeKind::Fn { params, ret } => {
                let resolved_params: Result<Vec<(ParamMode, Type)>, Diagnostic> = params
                    .iter()
                    .map(|(mode, t)| {
                        Type::from_ast_with_generics(t, known_structs, known_enums, generics)
                            .map(|res| (*mode, res))
                    })
                    .collect();
                let resolved_ret =
                    Type::from_ast_with_generics(ret, known_structs, known_enums, generics)?;
                Ok(Type::Fn {
                    params: resolved_params?,
                    ret: Box::new(resolved_ret),
                })
            }
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Unit => write!(f, "()"),
            Type::Bool => write!(f, "bool"),
            Type::Int(i) => write!(f, "{}", i),
            Type::Float(fl) => write!(f, "{}", fl),
            Type::Char => write!(f, "char"),
            Type::Str => write!(f, "str"),
            Type::String => write!(f, "String"),
            Type::Ref(inner) => write!(f, "ref {}", inner),
            Type::Optional(inner) => write!(f, "?{}", inner),
            Type::Slice(inner) => write!(f, "Slice<{}>", inner),
            Type::Array(inner, n) => write!(f, "[{}; {}]", inner, n),
            Type::Range { elem, inclusive } => {
                write!(f, "Range<{}{}>", if *inclusive { "=" } else { "" }, elem)
            }
            Type::ErrorUnion { err, ok } => write!(f, "{}!{}", err, ok),
            Type::Struct { name, .. } => write!(f, "{}", INTERNER.resolve(name)),
            Type::Enum { name, .. } => write!(f, "{}", INTERNER.resolve(name)),
            Type::Tuple(elems) => {
                write!(f, "(")?;
                for (i, elem) in elems.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", elem)?;
                }
                write!(f, ")")
            }
            Type::Fn { params, ret } => {
                write!(f, "fn(")?;
                for (i, (mode, pty)) in params.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    if *mode != ParamMode::In {
                        write!(f, "{} ", mode)?;
                    }
                    write!(f, "{}", pty)?;
                }
                write!(f, ") -> {}", ret)
            }
            Type::Generic { name, args } => {
                write!(f, "{}<", INTERNER.resolve(name))?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", arg)?;
                }
                write!(f, ">")
            }
            Type::IntegerLiteral(_) => write!(f, "{{integer}}"),
            Type::FloatLiteral => write!(f, "{{float}}"),
            Type::Never => write!(f, "!"),
            Type::TypeParam(sym) => write!(f, "{}", INTERNER.resolve(sym)),
            Type::Unknown => write!(f, "{{unknown}}"),
        }
    }
}

/// Mangles a semantic type into a deterministic, valid identifier token for monomorphization.
pub fn mangle_sema_type(ty: &Type) -> String {
    match ty {
        Type::Unit => "unit".to_string(),
        Type::Bool => "bool".to_string(),
        Type::Int(int_ty) => match int_ty {
            IntType::I8 => "i8".to_string(),
            IntType::I16 => "i16".to_string(),
            IntType::I32 => "i32".to_string(),
            IntType::I64 => "i64".to_string(),
            IntType::U8 => "u8".to_string(),
            IntType::U16 => "u16".to_string(),
            IntType::U32 => "u32".to_string(),
            IntType::U64 => "u64".to_string(),
            IntType::ISize => "isize".to_string(),
            IntType::USize => "usize".to_string(),
        },
        Type::Float(float_ty) => match float_ty {
            FloatType::F32 => "f32".to_string(),
            FloatType::F64 => "f64".to_string(),
        },
        Type::Char => "char".to_string(),
        Type::Str => "str".to_string(),
        Type::String => "string".to_string(),
        Type::Ref(inner) => format!("ref_{}", mangle_sema_type(inner)),
        Type::Array(inner, n) => format!("arr{}_{}", n, mangle_sema_type(inner)),
        Type::Slice(inner) => format!("slice_{}", mangle_sema_type(inner)),
        Type::Optional(inner) => format!("opt_{}", mangle_sema_type(inner)),
        Type::ErrorUnion { err, ok } => {
            format!("err_{}_{}", mangle_sema_type(err), mangle_sema_type(ok))
        }
        Type::Struct { name, .. } | Type::Enum { name, .. } => INTERNER.resolve(name),
        Type::Generic { name, args } => {
            let base = INTERNER.resolve(name);
            let args_str: Vec<String> = args.iter().map(mangle_sema_type).collect();
            format!("{}_{}", base, args_str.join("_"))
        }
        Type::TypeParam(sym) => INTERNER.resolve(sym),
        _ => "val".to_string(),
    }
}

/// Computes the specialized symbol name for a monomorphized function or struct.
pub fn mangle_instantiation_symbol(base: &str, type_args: &[Type]) -> Symbol {
    if type_args.is_empty() {
        return INTERNER.intern(base);
    }
    let mangled_args: Vec<String> = type_args.iter().map(mangle_sema_type).collect();
    let full = format!("{}__{}", base, mangled_args.join("_"));
    INTERNER.intern(&full)
}

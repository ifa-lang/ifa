use crate::error::KoriError;
use ifa_ast::ParamMode;
use ifa_fir::{format_module, FirModule};
use ifa_sema::symbol_table::{
    ConstSymbol, EnumSymbol, FieldSymbol, FunctionSymbol, ModuleSymbol, ParamSymbol, StructSymbol,
    SymbolTable,
};
use ifa_sema::types::{FloatType, IntType, Type};
use ifa_span::{Span, Symbol, INTERNER};
use serde::{Deserialize, Serialize};

/// Standard binary header for IFA compiled module metadata (`IFAM`).
pub const IFAM_MAGIC: [u8; 4] = *b"IFAM";

/// Current binary specification version for module metadata.
pub const IFAM_VERSION: u32 = 1;

/// Serializable mirror of the IFA semantic type system for cross-compilation caching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SerializableType {
    Unit,
    Bool,
    Int(String),
    Float(String),
    Char,
    Str,
    String,
    Ref(Box<SerializableType>),
    Optional(Box<SerializableType>),
    Slice(Box<SerializableType>),
    Array(Box<SerializableType>, u32),
    Range {
        elem: Box<SerializableType>,
        inclusive: bool,
    },
    ErrorUnion {
        err: Box<SerializableType>,
        ok: Box<SerializableType>,
    },
    Struct {
        name: String,
        fields: Vec<(String, SerializableType)>,
    },
    Enum {
        name: String,
        variants: Vec<(String, Option<SerializableType>)>,
    },
    Tuple(Vec<SerializableType>),
    Fn {
        params: Vec<(String, SerializableType)>,
        ret: Box<SerializableType>,
    },
    Generic {
        name: String,
        args: Vec<SerializableType>,
    },
    Custom(String),
    Unknown,
}

impl From<&Type> for SerializableType {
    fn from(ty: &Type) -> Self {
        match ty {
            Type::Unit => SerializableType::Unit,
            Type::Bool => SerializableType::Bool,
            Type::Int(it) => SerializableType::Int(format!("{}", it)),
            Type::Float(ft) => SerializableType::Float(format!("{}", ft)),
            Type::Char => SerializableType::Char,
            Type::Str => SerializableType::Str,
            Type::String => SerializableType::String,
            Type::Ref(inner) => SerializableType::Ref(Box::new(Self::from(inner.as_ref()))),
            Type::Optional(inner) => {
                SerializableType::Optional(Box::new(Self::from(inner.as_ref())))
            }
            Type::Slice(inner) => SerializableType::Slice(Box::new(Self::from(inner.as_ref()))),
            Type::Array(inner, sz) => {
                SerializableType::Array(Box::new(Self::from(inner.as_ref())), *sz)
            }
            Type::Range { elem, inclusive } => SerializableType::Range {
                elem: Box::new(Self::from(elem.as_ref())),
                inclusive: *inclusive,
            },
            Type::ErrorUnion { err, ok } => SerializableType::ErrorUnion {
                err: Box::new(Self::from(err.as_ref())),
                ok: Box::new(Self::from(ok.as_ref())),
            },
            Type::Struct { name, fields } => SerializableType::Struct {
                name: INTERNER.resolve(name).to_string(),
                fields: fields
                    .iter()
                    .map(|(f_name, f_ty)| (INTERNER.resolve(f_name).to_string(), Self::from(f_ty)))
                    .collect(),
            },
            Type::Enum { name, variants } => SerializableType::Enum {
                name: INTERNER.resolve(name).to_string(),
                variants: variants
                    .iter()
                    .map(|(v_name, v_ty)| {
                        (
                            INTERNER.resolve(v_name).to_string(),
                            v_ty.as_ref().map(Self::from),
                        )
                    })
                    .collect(),
            },
            Type::Tuple(elems) => SerializableType::Tuple(elems.iter().map(Self::from).collect()),
            Type::Fn { params, ret } => SerializableType::Fn {
                params: params
                    .iter()
                    .map(|(mode, t)| (format!("{:?}", mode), Self::from(t)))
                    .collect(),
                ret: Box::new(Self::from(ret.as_ref())),
            },
            Type::Generic { name, args } => SerializableType::Generic {
                name: INTERNER.resolve(name).to_string(),
                args: args.iter().map(Self::from).collect(),
            },
            Type::TypeParam(sym) => SerializableType::Custom(INTERNER.resolve(sym).to_string()),
            _ => SerializableType::Unknown,
        }
    }
}

impl SerializableType {
    /// Convert back to semantic `Type`.
    pub fn to_type(&self) -> Type {
        match self {
            SerializableType::Unit => Type::Unit,
            SerializableType::Bool => Type::Bool,
            SerializableType::Int(s) => match s.as_str() {
                "i8" => Type::Int(IntType::I8),
                "i16" => Type::Int(IntType::I16),
                "i32" => Type::Int(IntType::I32),
                "i64" => Type::Int(IntType::I64),
                "isize" => Type::Int(IntType::ISize),
                "u8" => Type::Int(IntType::U8),
                "u16" => Type::Int(IntType::U16),
                "u32" => Type::Int(IntType::U32),
                "u64" => Type::Int(IntType::U64),
                "usize" => Type::Int(IntType::USize),
                _ => Type::Int(IntType::I64),
            },
            SerializableType::Float(s) => match s.as_str() {
                "f32" => Type::Float(FloatType::F32),
                "f64" => Type::Float(FloatType::F64),
                _ => Type::Float(FloatType::F64),
            },
            SerializableType::Char => Type::Char,
            SerializableType::Str => Type::Str,
            SerializableType::String => Type::String,
            SerializableType::Ref(inner) => Type::Ref(Box::new(inner.to_type())),
            SerializableType::Optional(inner) => Type::Optional(Box::new(inner.to_type())),
            SerializableType::Slice(inner) => Type::Slice(Box::new(inner.to_type())),
            SerializableType::Array(inner, sz) => Type::Array(Box::new(inner.to_type()), *sz),
            SerializableType::Range { elem, inclusive } => Type::Range {
                elem: Box::new(elem.to_type()),
                inclusive: *inclusive,
            },
            SerializableType::ErrorUnion { err, ok } => Type::ErrorUnion {
                err: Box::new(err.to_type()),
                ok: Box::new(ok.to_type()),
            },
            SerializableType::Struct { name, fields } => {
                let name_sym = INTERNER.intern(name);
                let flds = fields
                    .iter()
                    .map(|(fn_name, fn_ty)| (INTERNER.intern(fn_name), fn_ty.to_type()))
                    .collect();
                Type::Struct {
                    name: name_sym,
                    fields: flds,
                }
            }
            SerializableType::Enum { name, variants } => {
                let name_sym = INTERNER.intern(name);
                let vars = variants
                    .iter()
                    .map(|(vn, vt)| (INTERNER.intern(vn), vt.as_ref().map(|t| t.to_type())))
                    .collect();
                Type::Enum {
                    name: name_sym,
                    variants: vars,
                }
            }
            SerializableType::Tuple(elems) => {
                Type::Tuple(elems.iter().map(|e| e.to_type()).collect())
            }
            SerializableType::Fn { params, ret } => {
                let p = params
                    .iter()
                    .map(|(m_str, t)| {
                        let mode = if m_str.contains("InOut") {
                            ParamMode::InOut
                        } else if m_str.contains("Sink") {
                            ParamMode::Sink
                        } else if m_str.contains("Mut") {
                            ParamMode::Mut
                        } else if m_str.contains("Comptime") {
                            ParamMode::Comptime
                        } else {
                            ParamMode::In
                        };
                        (mode, t.to_type())
                    })
                    .collect();
                Type::Fn {
                    params: p,
                    ret: Box::new(ret.to_type()),
                }
            }
            SerializableType::Generic { name, args } => {
                let name_sym = INTERNER.intern(name);
                let parsed_args = args.iter().map(|a| a.to_type()).collect();
                Type::Generic {
                    name: name_sym,
                    args: parsed_args,
                }
            }
            SerializableType::Custom(name) => Type::TypeParam(INTERNER.intern(name)),
            SerializableType::Unknown => Type::Unknown,
        }
    }
}

/// Metadata for an exported parameter in a module function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedParamMetadata {
    pub name: String,
    pub mode: String,
    pub ty: SerializableType,
}

/// Metadata for an exported function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedFunctionMetadata {
    pub name: String,
    pub is_pub: bool,
    pub is_strict: bool,
    pub is_comptime: bool,
    pub is_extern: Option<String>,
    pub params: Vec<ExportedParamMetadata>,
    pub ret_ty: SerializableType,
}

/// Metadata for an exported struct field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedFieldMetadata {
    pub name: String,
    pub is_pub: bool,
    pub ty: SerializableType,
}

/// Metadata for an exported struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedStructMetadata {
    pub name: String,
    pub is_pub: bool,
    pub fields: Vec<ExportedFieldMetadata>,
}

/// Metadata for an exported enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedEnumMetadata {
    pub name: String,
    pub is_pub: bool,
    pub variants: Vec<(String, Option<SerializableType>)>,
}

/// Metadata for an exported constant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedConstMetadata {
    pub name: String,
    pub is_pub: bool,
    pub ty: SerializableType,
    pub value_repr: Option<String>,
}

/// Complete compiled binary module metadata for fast incremental re-use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMetadata {
    pub module_name: String,
    pub package_name: String,
    pub fingerprint: String,
    pub timestamp_unix: u64,
    pub functions: Vec<ExportedFunctionMetadata>,
    pub structs: Vec<ExportedStructMetadata>,
    pub enums: Vec<ExportedEnumMetadata>,
    pub consts: Vec<ExportedConstMetadata>,
    pub fir_payload: Option<String>,
    pub dependencies: Vec<String>,
}

impl ModuleMetadata {
    /// Create new module metadata container.
    pub fn new(module_name: &str, package_name: &str, fingerprint: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            module_name: module_name.to_string(),
            package_name: package_name.to_string(),
            fingerprint: fingerprint.to_string(),
            timestamp_unix: now,
            functions: Vec::new(),
            structs: Vec::new(),
            enums: Vec::new(),
            consts: Vec::new(),
            fir_payload: None,
            dependencies: Vec::new(),
        }
    }

    /// Extract exported module metadata from a analyzed symbol table and compiled FIR module.
    pub fn from_symbols_and_fir(
        module_name: &str,
        package_name: &str,
        fingerprint: &str,
        symbols: &SymbolTable,
        fir_module: &FirModule,
    ) -> Self {
        let mut meta = Self::new(module_name, package_name, fingerprint);

        // 1. Export functions
        for f in symbols.functions.values() {
            if f.is_pub {
                let params = f
                    .params
                    .iter()
                    .map(|p| ExportedParamMetadata {
                        name: INTERNER.resolve(&p.name).to_string(),
                        mode: match p.mode {
                            ParamMode::In => "in".to_string(),
                            ParamMode::InOut => "inout".to_string(),
                            ParamMode::Sink => "sink".to_string(),
                            ParamMode::Mut => "mut".to_string(),
                            ParamMode::Comptime => "comptime".to_string(),
                        },
                        ty: SerializableType::from(&p.ty),
                    })
                    .collect();

                meta.functions.push(ExportedFunctionMetadata {
                    name: INTERNER.resolve(&f.name).to_string(),
                    is_pub: f.is_pub,
                    is_strict: f.is_strict,
                    is_comptime: f.is_comptime,
                    is_extern: f.is_extern.clone(),
                    params,
                    ret_ty: SerializableType::from(&f.ret_ty),
                });
            }
        }

        // 2. Export structs
        for s in symbols.structs.values() {
            if s.is_pub {
                let fields = s
                    .fields
                    .iter()
                    .map(|fld| ExportedFieldMetadata {
                        name: INTERNER.resolve(&fld.name).to_string(),
                        is_pub: fld.is_pub,
                        ty: SerializableType::from(&fld.ty),
                    })
                    .collect();

                meta.structs.push(ExportedStructMetadata {
                    name: INTERNER.resolve(&s.name).to_string(),
                    is_pub: s.is_pub,
                    fields,
                });
            }
        }

        // 3. Export enums
        for e in symbols.enums.values() {
            if e.is_pub {
                let variants = e
                    .variants
                    .iter()
                    .map(|(v_sym, v_ty)| {
                        (
                            INTERNER.resolve(v_sym).to_string(),
                            v_ty.as_ref().map(SerializableType::from),
                        )
                    })
                    .collect();

                meta.enums.push(ExportedEnumMetadata {
                    name: INTERNER.resolve(&e.name).to_string(),
                    is_pub: e.is_pub,
                    variants,
                });
            }
        }

        // 4. Export consts
        for c in symbols.consts.values() {
            if c.is_pub {
                meta.consts.push(ExportedConstMetadata {
                    name: INTERNER.resolve(&c.name).to_string(),
                    is_pub: c.is_pub,
                    ty: SerializableType::from(&c.ty),
                    value_repr: None,
                });
            }
        }

        // 5. Store formatted FIR payload
        meta.fir_payload = Some(format_module(fir_module));

        meta
    }

    /// Convert exported metadata back into a `ModuleSymbol` usable during parent module type-checking.
    pub fn to_module_symbol(&self, alias: Symbol, path: &[Symbol], span: Span) -> ModuleSymbol {
        let mut mod_sym = ModuleSymbol::new(alias, path.to_vec(), true, span);

        for f in &self.functions {
            let fn_name_sym = INTERNER.intern(&f.name);
            let ret_ty = f.ret_ty.to_type();
            let params = f
                .params
                .iter()
                .map(|p| {
                    let mode = match p.mode.as_str() {
                        "inout" => ParamMode::InOut,
                        "sink" => ParamMode::Sink,
                        "mut" => ParamMode::Mut,
                        "comptime" => ParamMode::Comptime,
                        _ => ParamMode::In,
                    };
                    ParamSymbol {
                        mode,
                        name: INTERNER.intern(&p.name),
                        ty: p.ty.to_type(),
                        span,
                    }
                })
                .collect();

            let func_sym = FunctionSymbol {
                name: fn_name_sym,
                is_pub: f.is_pub,
                is_strict: f.is_strict,
                is_comptime: f.is_comptime,
                is_extern: f.is_extern.clone(),
                generics: Vec::new(),
                params,
                ret_ty,
                span,
            };
            mod_sym.add_function(func_sym);
        }

        for s in &self.structs {
            let st_name_sym = INTERNER.intern(&s.name);
            let fields: Vec<FieldSymbol> = s
                .fields
                .iter()
                .map(|fld| FieldSymbol {
                    is_pub: fld.is_pub,
                    name: INTERNER.intern(&fld.name),
                    ty: fld.ty.to_type(),
                    span,
                })
                .collect();
            let struct_sym = StructSymbol::new(st_name_sym, s.is_pub, Vec::new(), fields, span);
            mod_sym.add_struct(struct_sym);
        }

        for e in &self.enums {
            let enum_name_sym = INTERNER.intern(&e.name);
            let variants = e
                .variants
                .iter()
                .map(|(var_name, ty_opt)| {
                    let v_sym = INTERNER.intern(var_name);
                    let v_ty = ty_opt.as_ref().map(|t| t.to_type());
                    (v_sym, v_ty)
                })
                .collect();
            let enum_sym = EnumSymbol {
                name: enum_name_sym,
                is_pub: e.is_pub,
                variants,
                span,
            };
            mod_sym.add_enum(enum_sym);
        }

        for c in &self.consts {
            let c_name_sym = INTERNER.intern(&c.name);
            let const_sym = ConstSymbol {
                name: c_name_sym,
                is_pub: c.is_pub,
                ty: c.ty.to_type(),
                value: None,
                span,
            };
            mod_sym.add_const(const_sym);
        }

        mod_sym
    }

    /// Serializes metadata into a binary format with standard `IFAM` header and BLAKE3 integrity checksum.
    pub fn serialize_to_binary(&self) -> Result<Vec<u8>, KoriError> {
        let payload_json = serde_json::to_vec(self).map_err(|e| {
            KoriError::Codegen(format!(
                "Failed to serialize module metadata payload: {}",
                e
            ))
        })?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(&payload_json);
        let checksum = hasher.finalize();

        let mut binary = Vec::with_capacity(52 + payload_json.len());
        // 1. Magic bytes: 4 bytes "IFAM"
        binary.extend_from_slice(&IFAM_MAGIC);
        // 2. Version: u32 (little endian)
        binary.extend_from_slice(&IFAM_VERSION.to_le_bytes());
        // 3. Flags: u32 (0)
        binary.extend_from_slice(&0u32.to_le_bytes());
        // 4. Payload length: u64 (little endian)
        binary.extend_from_slice(&(payload_json.len() as u64).to_le_bytes());
        // 5. BLAKE3 payload checksum: 32 bytes
        binary.extend_from_slice(checksum.as_bytes());
        // 6. Payload data
        binary.extend_from_slice(&payload_json);

        Ok(binary)
    }

    /// Deserializes metadata from binary data verifying `IFAM` magic, format version, and BLAKE3 checksum.
    pub fn deserialize_from_binary(bytes: &[u8]) -> Result<Self, KoriError> {
        const HEADER_LEN: usize = 4 + 4 + 4 + 8 + 32; // 52 bytes
        if bytes.len() < HEADER_LEN {
            return Err(KoriError::Codegen(
                "Corrupted module metadata: file truncated".to_string(),
            ));
        }

        // Validate magic
        if bytes[0..4] != IFAM_MAGIC {
            return Err(KoriError::Codegen(format!(
                "Invalid module metadata magic header: expected IFAM, got {:?}",
                &bytes[0..4]
            )));
        }

        // Validate version
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        if version != IFAM_VERSION {
            return Err(KoriError::Codegen(format!(
                "Unsupported module metadata format version: {}",
                version
            )));
        }

        let _flags = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let payload_len = u64::from_le_bytes(bytes[12..20].try_into().unwrap()) as usize;
        let expected_checksum = &bytes[20..52];

        let payload_bytes = &bytes[52..];
        if payload_bytes.len() != payload_len {
            return Err(KoriError::Codegen(format!(
                "Corrupted module metadata payload: expected {} bytes, got {}",
                payload_len,
                payload_bytes.len()
            )));
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(payload_bytes);
        let actual_checksum = hasher.finalize();

        if actual_checksum.as_bytes() != expected_checksum {
            return Err(KoriError::Codegen(
                "Module metadata integrity check failed: BLAKE3 checksum mismatch".to_string(),
            ));
        }

        let metadata: ModuleMetadata = serde_json::from_slice(payload_bytes).map_err(|e| {
            KoriError::Codegen(format!("Failed to deserialize module metadata: {}", e))
        })?;

        Ok(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ifa_span::Span;

    #[test]
    fn test_binary_module_metadata_roundtrip() {
        let mut meta = ModuleMetadata::new("math", "std", "deadbeef0123456789abcdef");
        meta.functions.push(ExportedFunctionMetadata {
            name: "add".to_string(),
            is_pub: true,
            is_strict: true,
            is_comptime: false,
            is_extern: None,
            params: vec![
                ExportedParamMetadata {
                    name: "a".to_string(),
                    mode: "in".to_string(),
                    ty: SerializableType::Int("i64".to_string()),
                },
                ExportedParamMetadata {
                    name: "b".to_string(),
                    mode: "inout".to_string(),
                    ty: SerializableType::Int("i64".to_string()),
                },
            ],
            ret_ty: SerializableType::Int("i64".to_string()),
        });

        meta.structs.push(ExportedStructMetadata {
            name: "Point".to_string(),
            is_pub: true,
            fields: vec![
                ExportedFieldMetadata {
                    name: "x".to_string(),
                    is_pub: true,
                    ty: SerializableType::Float("f64".to_string()),
                },
                ExportedFieldMetadata {
                    name: "y".to_string(),
                    is_pub: true,
                    ty: SerializableType::Float("f64".to_string()),
                },
            ],
        });

        // Binary serialization
        let binary_bytes = meta.serialize_to_binary().expect("Serialization succeeded");
        assert_eq!(&binary_bytes[0..4], &IFAM_MAGIC);

        // Binary deserialization
        let deserialized =
            ModuleMetadata::deserialize_from_binary(&binary_bytes).expect("Deserialization ok");
        assert_eq!(deserialized.module_name, "math");
        assert_eq!(deserialized.package_name, "std");
        assert_eq!(deserialized.functions.len(), 1);
        assert_eq!(deserialized.functions[0].name, "add");
        assert!(deserialized.functions[0].is_strict);
        assert_eq!(deserialized.structs.len(), 1);
        assert_eq!(deserialized.structs[0].name, "Point");

        // Convert to ModuleSymbol
        let dummy_span = Span::dummy();
        let mod_sym = deserialized.to_module_symbol(
            INTERNER.intern("math"),
            &[INTERNER.intern("math")],
            dummy_span,
        );
        assert_eq!(mod_sym.functions.len(), 1);
        assert_eq!(mod_sym.structs.len(), 1);
    }

    #[test]
    fn test_binary_module_tampering_detection() {
        let meta = ModuleMetadata::new("crypto", "ifa", "1122334455667788");
        let mut bytes = meta.serialize_to_binary().unwrap();

        // 1. Corrupt magic
        bytes[0] = b'X';
        assert!(ModuleMetadata::deserialize_from_binary(&bytes).is_err());
        bytes[0] = b'I';

        // 2. Corrupt checksum
        bytes[25] ^= 0xFF;
        assert!(ModuleMetadata::deserialize_from_binary(&bytes).is_err());
        bytes[25] ^= 0xFF;

        // 3. Corrupt payload
        let last = bytes.len() - 1;
        bytes[last] ^= 0xAA;
        assert!(ModuleMetadata::deserialize_from_binary(&bytes).is_err());
    }
}

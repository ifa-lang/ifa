//! WebAssembly Interface Types (WIT) and WASI 0.2 toolchain for IFA.
//!
//! Provides AST definitions, parsing of `.wit` files, and bi-directional code generation
//! between IFA native types and WIT component interfaces.

use serde::{Deserialize, Serialize};
use std::fmt::Write as FmtWrite;

/// Unique package identifier according to WIT specification (e.g. `wasi:cli/stdout@0.2.0`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WitPackageId {
    pub namespace: String,
    pub name: String,
    pub version: Option<String>,
}

impl WitPackageId {
    pub fn new(
        namespace: impl Into<String>,
        name: impl Into<String>,
        version: Option<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
            version,
        }
    }

    pub fn to_string_repr(&self) -> String {
        match &self.version {
            Some(ver) => format!("{}:{}@{}", self.namespace, self.name, ver),
            None => format!("{}:{}", self.namespace, self.name),
        }
    }
}

/// Primitive and composite types supported by WIT and the Canonical ABI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitType {
    Bool,
    U8,
    U16,
    U32,
    U64,
    S8,
    S16,
    S32,
    S64,
    F32,
    F64,
    Char,
    String,
    List(Box<WitType>),
    Record(Vec<WitField>),
    Variant(Vec<WitVariantCase>),
    Enum(Vec<String>),
    Flags(Vec<String>),
    OptionType(Box<WitType>),
    ResultType {
        ok: Option<Box<WitType>>,
        err: Option<Box<WitType>>,
    },
    Resource {
        name: String,
    },
    Own(String),
    Borrow(String),
    TypeRef(String),
}

impl WitType {
    /// Return the Canonical ABI byte size and alignment (size, align).
    pub fn cabi_layout(&self) -> (usize, usize) {
        match self {
            WitType::Bool | WitType::U8 | WitType::S8 => (1, 1),
            WitType::U16 | WitType::S16 => (2, 2),
            WitType::U32 | WitType::S32 | WitType::F32 | WitType::Char => (4, 4),
            WitType::U64 | WitType::S64 | WitType::F64 => (8, 8),
            // (ptr: u32, len: u32)
            WitType::String | WitType::List(_) => (8, 4),
            WitType::Own(_) | WitType::Borrow(_) | WitType::Resource { .. } => (4, 4),
            WitType::Record(fields) => {
                let mut offset = 0;
                let mut max_align = 1;
                for field in fields {
                    let (sz, al) = field.ty.cabi_layout();
                    if al > max_align {
                        max_align = al;
                    }
                    offset = align_to(offset, al) + sz;
                }
                (align_to(offset, max_align), max_align)
            }
            WitType::Variant(cases) => {
                let (disc_sz, disc_al) = if cases.len() <= 256 {
                    (1, 1)
                } else if cases.len() <= 65536 {
                    (2, 2)
                } else {
                    (4, 4)
                };
                let mut max_payload_sz = 0;
                let mut max_payload_al = 1;
                for case in cases {
                    if let Some(payload) = &case.ty {
                        let (sz, al) = payload.cabi_layout();
                        if sz > max_payload_sz {
                            max_payload_sz = sz;
                        }
                        if al > max_payload_al {
                            max_payload_al = al;
                        }
                    }
                }
                let total_al = disc_al.max(max_payload_al);
                let payload_offset = align_to(disc_sz, max_payload_al);
                (
                    align_to(payload_offset + max_payload_sz, total_al),
                    total_al,
                )
            }
            WitType::Enum(cases) => {
                if cases.len() <= 256 {
                    (1, 1)
                } else if cases.len() <= 65536 {
                    (2, 2)
                } else {
                    (4, 4)
                }
            }
            WitType::Flags(flags) => {
                if flags.len() <= 8 {
                    (1, 1)
                } else if flags.len() <= 16 {
                    (2, 2)
                } else {
                    let count = flags.len().div_ceil(32);
                    (count * 4, 4)
                }
            }
            WitType::OptionType(inner) => {
                let (sz, al) = inner.cabi_layout();
                let total_al = al.max(1);
                let payload_offset = align_to(1, al);
                (align_to(payload_offset + sz, total_al), total_al)
            }
            WitType::ResultType { ok, err } => {
                let mut max_sz = 0;
                let mut max_al = 1;
                if let Some(ok_ty) = ok {
                    let (sz, al) = ok_ty.cabi_layout();
                    max_sz = max_sz.max(sz);
                    max_al = max_al.max(al);
                }
                if let Some(err_ty) = err {
                    let (sz, al) = err_ty.cabi_layout();
                    max_sz = max_sz.max(sz);
                    max_al = max_al.max(al);
                }
                let total_al = max_al.max(1);
                let payload_offset = align_to(1, max_al);
                (align_to(payload_offset + max_sz, total_al), total_al)
            }
            WitType::TypeRef(_) => (8, 4),
        }
    }

    /// Render WIT syntax for this type.
    pub fn to_wit(&self) -> String {
        match self {
            WitType::Bool => "bool".to_string(),
            WitType::U8 => "u8".to_string(),
            WitType::U16 => "u16".to_string(),
            WitType::U32 => "u32".to_string(),
            WitType::U64 => "u64".to_string(),
            WitType::S8 => "s8".to_string(),
            WitType::S16 => "s16".to_string(),
            WitType::S32 => "s32".to_string(),
            WitType::S64 => "s64".to_string(),
            WitType::F32 => "f32".to_string(),
            WitType::F64 => "f64".to_string(),
            WitType::Char => "char".to_string(),
            WitType::String => "string".to_string(),
            WitType::List(inner) => format!("list<{}>", inner.to_wit()),
            WitType::OptionType(inner) => format!("option<{}>", inner.to_wit()),
            WitType::ResultType { ok, err } => match (ok, err) {
                (Some(o), Some(e)) => format!("result<{}, {}>", o.to_wit(), e.to_wit()),
                (Some(o), None) => format!("result<{}>", o.to_wit()),
                (None, Some(e)) => format!("result<_, {}>", e.to_wit()),
                (None, None) => "result".to_string(),
            },
            WitType::Resource { name } => format!("resource {}", name),
            WitType::Own(name) => format!("own<{}>", name),
            WitType::Borrow(name) => format!("borrow<{}>", name),
            WitType::TypeRef(name) => name.clone(),
            WitType::Record(fields) => {
                let mut s = "record {\n".to_string();
                for f in fields {
                    let _ = writeln!(s, "    {}: {},", f.name, f.ty.to_wit());
                }
                s.push('}');
                s
            }
            WitType::Variant(cases) => {
                let mut s = "variant {\n".to_string();
                for c in cases {
                    match &c.ty {
                        Some(t) => {
                            let _ = writeln!(s, "    {}({}),", c.name, t.to_wit());
                        }
                        None => {
                            let _ = writeln!(s, "    {},", c.name);
                        }
                    }
                }
                s.push('}');
                s
            }
            WitType::Enum(cases) => {
                format!("enum {{ {} }}", cases.join(", "))
            }
            WitType::Flags(flags) => {
                format!("flags {{ {} }}", flags.join(", "))
            }
        }
    }

    /// Convert into idiomatic IFA type declaration string.
    pub fn to_ifa_type(&self) -> String {
        match self {
            WitType::Bool => "bool".to_string(),
            WitType::U8 => "u8".to_string(),
            WitType::U16 => "u16".to_string(),
            WitType::U32 => "u32".to_string(),
            WitType::U64 => "u64".to_string(),
            WitType::S8 => "i8".to_string(),
            WitType::S16 => "i16".to_string(),
            WitType::S32 => "i32".to_string(),
            WitType::S64 => "i64".to_string(),
            WitType::F32 => "f32".to_string(),
            WitType::F64 => "f64".to_string(),
            WitType::Char => "u32".to_string(),
            WitType::String => "string".to_string(),
            WitType::List(inner) => format!("[{}]", inner.to_ifa_type()),
            WitType::OptionType(inner) => format!("option<{}>", inner.to_ifa_type()),
            WitType::ResultType { ok, err } => {
                let ok_str = ok
                    .as_ref()
                    .map(|t| t.to_ifa_type())
                    .unwrap_or_else(|| "()".to_string());
                let err_str = err
                    .as_ref()
                    .map(|t| t.to_ifa_type())
                    .unwrap_or_else(|| "string".to_string());
                format!("result<{}, {}>", ok_str, err_str)
            }
            WitType::Resource { name } => name.clone(),
            WitType::Own(name) => format!("sink {}", name),
            WitType::Borrow(name) => format!("ref {}", name),
            WitType::TypeRef(name) => name.clone(),
            _ => "/* composite type */".to_string(),
        }
    }
}

fn align_to(offset: usize, align: usize) -> usize {
    (offset + align - 1) & !(align - 1)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitField {
    pub name: String,
    pub ty: WitType,
    pub docs: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitVariantCase {
    pub name: String,
    pub ty: Option<WitType>,
    pub docs: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitFunction {
    pub name: String,
    pub params: Vec<(String, WitType)>,
    pub results: Vec<(Option<String>, WitType)>,
    pub docs: Option<String>,
}

impl WitFunction {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            params: Vec::new(),
            results: Vec::new(),
            docs: None,
        }
    }

    pub fn with_param(mut self, name: impl Into<String>, ty: WitType) -> Self {
        self.params.push((name.into(), ty));
        self
    }

    pub fn with_result(mut self, ty: WitType) -> Self {
        self.results.push((None, ty));
        self
    }

    pub fn with_named_result(mut self, name: impl Into<String>, ty: WitType) -> Self {
        self.results.push((Some(name.into()), ty));
        self
    }

    pub fn to_wit(&self) -> String {
        let mut s = String::new();
        if let Some(doc) = &self.docs {
            let _ = writeln!(s, "    /// {}", doc);
        }
        let _ = write!(s, "    {}: func(", self.name);
        for (i, (p_name, p_ty)) in self.params.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            let _ = write!(s, "{}: {}", p_name, p_ty.to_wit());
        }
        s.push(')');
        match self.results.len() {
            0 => {}
            1 => {
                let _ = write!(s, " -> {}", self.results[0].1.to_wit());
            }
            _ => {
                s.push_str(" -> (");
                for (i, (r_name, r_ty)) in self.results.iter().enumerate() {
                    if i > 0 {
                        s.push_str(", ");
                    }
                    if let Some(rn) = r_name {
                        let _ = write!(s, "{}: {}", rn, r_ty.to_wit());
                    } else {
                        s.push_str(&r_ty.to_wit());
                    }
                }
                s.push(')');
            }
        }
        s.push(';');
        s
    }

    pub fn to_ifa_signature(&self) -> String {
        let mut s = format!("pub fn {}(", self.name);
        for (i, (p_name, p_ty)) in self.params.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            let _ = write!(s, "{}: {}", p_name, p_ty.to_ifa_type());
        }
        s.push(')');
        match self.results.len() {
            0 => {}
            1 => {
                let _ = write!(s, " -> {}", self.results[0].1.to_ifa_type());
            }
            _ => {
                s.push_str(" -> (");
                for (i, (_, r_ty)) in self.results.iter().enumerate() {
                    if i > 0 {
                        s.push_str(", ");
                    }
                    s.push_str(&r_ty.to_ifa_type());
                }
                s.push(')');
            }
        }
        s
    }
}

/// A standalone interface in a WIT document (`interface <name> { ... }`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitInterface {
    pub name: String,
    pub types: Vec<(String, WitType)>,
    pub functions: Vec<WitFunction>,
    pub docs: Option<String>,
}

impl WitInterface {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            types: Vec::new(),
            functions: Vec::new(),
            docs: None,
        }
    }

    pub fn to_wit(&self) -> String {
        let mut s = String::new();
        if let Some(doc) = &self.docs {
            let _ = writeln!(s, "/// {}", doc);
        }
        let _ = writeln!(s, "interface {} {{", self.name);

        for (t_name, t_val) in &self.types {
            match t_val {
                WitType::Record(fields) => {
                    let _ = writeln!(s, "    record {} {{", t_name);
                    for f in fields {
                        let _ = writeln!(s, "        {}: {},", f.name, f.ty.to_wit());
                    }
                    let _ = writeln!(s, "    }}");
                }
                WitType::Variant(cases) => {
                    let _ = writeln!(s, "    variant {} {{", t_name);
                    for c in cases {
                        match &c.ty {
                            Some(ty) => {
                                let _ = writeln!(s, "        {}({}),", c.name, ty.to_wit());
                            }
                            None => {
                                let _ = writeln!(s, "        {},", c.name);
                            }
                        }
                    }
                    let _ = writeln!(s, "    }}");
                }
                WitType::Enum(cases) => {
                    let _ = writeln!(s, "    enum {} {{ {} }}", t_name, cases.join(", "));
                }
                WitType::Flags(flags) => {
                    let _ = writeln!(s, "    flags {} {{ {} }}", t_name, flags.join(", "));
                }
                other => {
                    let _ = writeln!(s, "    type {} = {};", t_name, other.to_wit());
                }
            }
        }

        for func in &self.functions {
            let _ = writeln!(s, "{}", func.to_wit());
        }

        s.push_str("}\n");
        s
    }

    /// Generate an IFA interface and related data types.
    pub fn to_ifa_module(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(
            s,
            "// IFA Interface Bindings for WIT interface `{}`",
            self.name
        );
        let _ = writeln!(s, "// Auto-generated by ifa-wasm v0.1.1\n");

        for (t_name, t_val) in &self.types {
            match t_val {
                WitType::Record(fields) => {
                    let _ = writeln!(s, "pub struct {} {{", t_name);
                    for f in fields {
                        let _ = writeln!(s, "    pub {}: {},", f.name, f.ty.to_ifa_type());
                    }
                    let _ = writeln!(s, "}}\n");
                }
                WitType::Variant(cases) => {
                    let _ = writeln!(s, "pub enum {} {{", t_name);
                    for c in cases {
                        match &c.ty {
                            Some(ty) => {
                                let _ = writeln!(s, "    {}({}),", c.name, ty.to_ifa_type());
                            }
                            None => {
                                let _ = writeln!(s, "    {},", c.name);
                            }
                        }
                    }
                    let _ = writeln!(s, "}}\n");
                }
                WitType::Enum(cases) => {
                    let _ = writeln!(s, "pub enum {} {{", t_name);
                    for c in cases {
                        let _ = writeln!(s, "    {},", c);
                    }
                    let _ = writeln!(s, "}}\n");
                }
                _ => {}
            }
        }

        let _ = writeln!(s, "pub interface {} {{", self.name);
        for func in &self.functions {
            let _ = writeln!(s, "    {};", func.to_ifa_signature());
        }
        let _ = writeln!(s, "}}");
        s
    }
}

/// A WIT World definition describing component imports and exports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitWorld {
    pub name: String,
    pub imports: Vec<WitWorldItem>,
    pub exports: Vec<WitWorldItem>,
    pub docs: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitWorldItem {
    Interface(WitInterface),
    InterfaceRef(String),
    Function(WitFunction),
}

impl WitWorld {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            imports: Vec::new(),
            exports: Vec::new(),
            docs: None,
        }
    }

    pub fn to_wit(&self) -> String {
        let mut s = String::new();
        if let Some(doc) = &self.docs {
            let _ = writeln!(s, "/// {}", doc);
        }
        let _ = writeln!(s, "world {} {{", self.name);

        for imp in &self.imports {
            match imp {
                WitWorldItem::InterfaceRef(id) => {
                    let _ = writeln!(s, "    import {};", id);
                }
                WitWorldItem::Interface(iface) => {
                    let _ = writeln!(s, "    import {}: interface {{", iface.name);
                    for f in &iface.functions {
                        let _ = writeln!(s, "    {}", f.to_wit());
                    }
                    let _ = writeln!(s, "    }};");
                }
                WitWorldItem::Function(f) => {
                    let _ = writeln!(s, "    import {}", f.to_wit().trim());
                }
            }
        }

        for exp in &self.exports {
            match exp {
                WitWorldItem::InterfaceRef(id) => {
                    let _ = writeln!(s, "    export {};", id);
                }
                WitWorldItem::Interface(iface) => {
                    let _ = writeln!(s, "    export {}: interface {{", iface.name);
                    for f in &iface.functions {
                        let _ = writeln!(s, "    {}", f.to_wit());
                    }
                    let _ = writeln!(s, "    }};");
                }
                WitWorldItem::Function(f) => {
                    let _ = writeln!(s, "    export {}", f.to_wit().trim());
                }
            }
        }

        s.push_str("}\n");
        s
    }
}

/// Complete WIT Document or Package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitPackage {
    pub id: WitPackageId,
    pub interfaces: Vec<WitInterface>,
    pub worlds: Vec<WitWorld>,
}

impl WitPackage {
    pub fn new(id: WitPackageId) -> Self {
        Self {
            id,
            interfaces: Vec::new(),
            worlds: Vec::new(),
        }
    }

    pub fn to_wit(&self) -> String {
        let mut s = format!("package {};\n\n", self.id.to_string_repr());
        for iface in &self.interfaces {
            s.push_str(&iface.to_wit());
            s.push('\n');
        }
        for world in &self.worlds {
            s.push_str(&world.to_wit());
            s.push('\n');
        }
        s
    }

    /// Basic WIT Parser that parses simple packages, interfaces, records, and functions.
    #[allow(clippy::while_let_on_iterator)]
    pub fn parse(input: &str) -> Result<Self, String> {
        let mut lines = input.lines().map(|l| l.trim()).peekable();
        let mut pkg_id = WitPackageId::new("ifa", "unnamed", None);
        let mut interfaces = Vec::new();
        let mut worlds = Vec::new();

        while let Some(line) = lines.next() {
            if line.is_empty() || line.starts_with("//") {
                continue;
            }

            if line.starts_with("package ") {
                let rest = line
                    .trim_start_matches("package ")
                    .trim_end_matches(';')
                    .trim();
                if let Some((ns_name, ver)) = rest.split_once('@') {
                    if let Some((ns, name)) = ns_name.split_once(':') {
                        pkg_id = WitPackageId::new(ns, name, Some(ver.to_string()));
                    }
                } else if let Some((ns, name)) = rest.split_once(':') {
                    pkg_id = WitPackageId::new(ns, name, None);
                }
            } else if line.starts_with("interface ") {
                let iface_name = line
                    .trim_start_matches("interface ")
                    .trim_end_matches('{')
                    .trim();
                let mut iface = WitInterface::new(iface_name);

                while let Some(inner) = lines.next() {
                    let inner = inner.trim();
                    if inner == "}" || inner.starts_with('}') {
                        break;
                    }
                    if inner.is_empty() || inner.starts_with("//") {
                        continue;
                    }
                    if inner.starts_with("record ") {
                        let rec_name = inner
                            .trim_start_matches("record ")
                            .trim_end_matches('{')
                            .trim();
                        let mut fields = Vec::new();
                        while let Some(fl) = lines.next() {
                            let fl = fl.trim();
                            if fl == "}" || fl.starts_with('}') {
                                break;
                            }
                            if let Some((f_name, f_ty)) = fl.trim_end_matches(',').split_once(':') {
                                fields.push(WitField {
                                    name: f_name.trim().to_string(),
                                    ty: parse_wit_type(f_ty.trim()),
                                    docs: None,
                                });
                            }
                        }
                        iface
                            .types
                            .push((rec_name.to_string(), WitType::Record(fields)));
                    } else if let Some((fn_name, fn_body)) = inner.split_once(": func(") {
                        let fn_body = fn_body.trim_end_matches(';');
                        let (param_str, ret_str) = if let Some((p, r)) = fn_body.split_once(") -> ")
                        {
                            (p, Some(r.trim()))
                        } else {
                            (fn_body.trim_end_matches(')'), None)
                        };

                        let mut func = WitFunction::new(fn_name.trim());
                        if !param_str.trim().is_empty() {
                            for part in param_str.split(',') {
                                if let Some((p_name, p_ty)) = part.split_once(':') {
                                    func =
                                        func.with_param(p_name.trim(), parse_wit_type(p_ty.trim()));
                                }
                            }
                        }
                        if let Some(ret) = ret_str {
                            func = func.with_result(parse_wit_type(ret));
                        }
                        iface.functions.push(func);
                    }
                }
                interfaces.push(iface);
            } else if line.starts_with("world ") {
                let world_name = line
                    .trim_start_matches("world ")
                    .trim_end_matches('{')
                    .trim();
                let mut world = WitWorld::new(world_name);

                while let Some(inner) = lines.next() {
                    let inner = inner.trim();
                    if inner == "}" || inner.starts_with('}') {
                        break;
                    }
                    if inner.is_empty() || inner.starts_with("//") {
                        continue;
                    }
                    if inner.starts_with("import ") {
                        let item = inner
                            .trim_start_matches("import ")
                            .trim_end_matches(';')
                            .trim();
                        world
                            .imports
                            .push(WitWorldItem::InterfaceRef(item.to_string()));
                    } else if inner.starts_with("export ") {
                        let item = inner
                            .trim_start_matches("export ")
                            .trim_end_matches(';')
                            .trim();
                        world
                            .exports
                            .push(WitWorldItem::InterfaceRef(item.to_string()));
                    }
                }
                worlds.push(world);
            }
        }

        Ok(WitPackage {
            id: pkg_id,
            interfaces,
            worlds,
        })
    }
}

fn parse_wit_type(s: &str) -> WitType {
    match s {
        "bool" => WitType::Bool,
        "u8" => WitType::U8,
        "u16" => WitType::U16,
        "u32" => WitType::U32,
        "u64" => WitType::U64,
        "s8" => WitType::S8,
        "s16" => WitType::S16,
        "s32" => WitType::S32,
        "s64" => WitType::S64,
        "f32" => WitType::F32,
        "f64" => WitType::F64,
        "char" => WitType::Char,
        "string" => WitType::String,
        _ if s.starts_with("list<") && s.ends_with('>') => {
            let inner = &s[5..s.len() - 1];
            WitType::List(Box::new(parse_wit_type(inner.trim())))
        }
        _ if s.starts_with("option<") && s.ends_with('>') => {
            let inner = &s[7..s.len() - 1];
            WitType::OptionType(Box::new(parse_wit_type(inner.trim())))
        }
        _ if s.starts_with("result<") && s.ends_with('>') => {
            let inner = &s[7..s.len() - 1];
            if let Some((ok, err)) = inner.split_once(',') {
                WitType::ResultType {
                    ok: if ok.trim() == "_" {
                        None
                    } else {
                        Some(Box::new(parse_wit_type(ok.trim())))
                    },
                    err: Some(Box::new(parse_wit_type(err.trim()))),
                }
            } else {
                WitType::ResultType {
                    ok: Some(Box::new(parse_wit_type(inner.trim()))),
                    err: None,
                }
            }
        }
        _ if s.starts_with("own<") && s.ends_with('>') => {
            WitType::Own(s[4..s.len() - 1].trim().to_string())
        }
        _ if s.starts_with("borrow<") && s.ends_with('>') => {
            WitType::Borrow(s[7..s.len() - 1].trim().to_string())
        }
        named => WitType::TypeRef(named.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wit_cabi_layout_calculations() {
        assert_eq!(WitType::Bool.cabi_layout(), (1, 1));
        assert_eq!(WitType::U32.cabi_layout(), (4, 4));
        assert_eq!(WitType::U64.cabi_layout(), (8, 8));
        assert_eq!(WitType::String.cabi_layout(), (8, 4));
        assert_eq!(WitType::List(Box::new(WitType::U8)).cabi_layout(), (8, 4));

        let rec = WitType::Record(vec![
            WitField {
                name: "id".to_string(),
                ty: WitType::U64,
                docs: None,
            },
            WitField {
                name: "tag".to_string(),
                ty: WitType::U8,
                docs: None,
            },
        ]);
        // Size: 8 (u64) + 1 (u8) padded to align 8 => 16 bytes, align 8
        assert_eq!(rec.cabi_layout(), (16, 8));
    }

    #[test]
    fn test_wit_roundtrip_parsing_and_generation() {
        let wit_source = r#"package ifa:service@0.2.0;

interface kv-store {
    record entry {
        key: string,
        val: list<u8>,
        version: u64,
    }

    get: func(key: string) -> option<entry>;
    set: func(key: string, val: list<u8>) -> result;
}

world server {
    import wasi:logging/logging@0.2.0;
    export kv-store;
}
"#;

        let pkg = WitPackage::parse(wit_source).expect("Failed to parse WIT");
        assert_eq!(pkg.id.to_string_repr(), "ifa:service@0.2.0");
        assert_eq!(pkg.interfaces.len(), 1);
        let iface = &pkg.interfaces[0];
        assert_eq!(iface.name, "kv-store");
        assert_eq!(iface.functions.len(), 2);
        assert_eq!(iface.functions[0].name, "get");
        assert_eq!(iface.functions[1].name, "set");

        let ifa_code = iface.to_ifa_module();
        assert!(ifa_code.contains("pub struct entry"));
        assert!(ifa_code.contains("pub interface kv-store"));
        assert!(ifa_code.contains("pub fn get(key: string) -> option<entry>;"));
    }
}

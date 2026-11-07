use crate::types::Type;
use ifa_ast::{GenericParam, ParamMode};
use ifa_diagnostics::Diagnostic;
use ifa_span::{Span, Symbol, INTERNER};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct VariableSymbol {
    pub id: u32,
    pub name: Symbol,
    pub ty: Type,
    pub is_mut: bool,
    pub is_initialized: bool,
    pub mode: Option<ParamMode>,
    pub span: Span,
    pub scope_depth: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParamSymbol {
    pub mode: ParamMode,
    pub name: Symbol,
    pub ty: Type,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FunctionSymbol {
    pub name: Symbol,
    pub is_pub: bool,
    pub is_strict: bool,
    pub is_comptime: bool,
    pub is_extern: Option<String>,
    pub generics: Vec<GenericParam>,
    pub params: Vec<ParamSymbol>,
    pub ret_ty: Type,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FieldSymbol {
    pub is_pub: bool,
    pub name: Symbol,
    pub ty: Type,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StructSymbol {
    pub name: Symbol,
    pub is_pub: bool,
    pub generics: Vec<GenericParam>,
    pub fields: Vec<FieldSymbol>,
    pub field_indices: HashMap<Symbol, usize>,
    pub span: Span,
}

impl StructSymbol {
    pub fn new(
        name: Symbol,
        is_pub: bool,
        generics: Vec<GenericParam>,
        fields: Vec<FieldSymbol>,
        span: Span,
    ) -> Self {
        let mut field_indices = HashMap::new();
        for (idx, field) in fields.iter().enumerate() {
            field_indices.insert(field.name, idx);
        }
        Self {
            name,
            is_pub,
            generics,
            fields,
            field_indices,
            span,
        }
    }

    pub fn get_field(&self, name: &Symbol) -> Option<&FieldSymbol> {
        self.field_indices.get(name).map(|&idx| &self.fields[idx])
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TraitMethodSymbol {
    pub name: Symbol,
    pub params: Vec<ParamSymbol>,
    pub ret_ty: Type,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TraitSymbol {
    pub name: Symbol,
    pub is_pub: bool,
    pub methods: Vec<TraitMethodSymbol>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EnumSymbol {
    pub name: Symbol,
    pub is_pub: bool,
    pub variants: Vec<(Symbol, Option<Type>)>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConstSymbol {
    pub name: Symbol,
    pub is_pub: bool,
    pub ty: Type,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModuleSymbol {
    pub name: Symbol,
    pub path: Vec<Symbol>,
    pub is_pub: bool,
    pub span: Span,
    pub functions: HashMap<Symbol, FunctionSymbol>,
    pub structs: HashMap<Symbol, StructSymbol>,
    pub enums: HashMap<Symbol, EnumSymbol>,
    pub consts: HashMap<Symbol, ConstSymbol>,
}

impl ModuleSymbol {
    pub fn new(name: Symbol, path: Vec<Symbol>, is_pub: bool, span: Span) -> Self {
        Self {
            name,
            path,
            is_pub,
            span,
            functions: HashMap::new(),
            structs: HashMap::new(),
            enums: HashMap::new(),
            consts: HashMap::new(),
        }
    }

    pub fn add_function(&mut self, func: FunctionSymbol) {
        self.functions.insert(func.name, func);
    }

    pub fn add_struct(&mut self, st: StructSymbol) {
        self.structs.insert(st.name, st);
    }

    pub fn add_enum(&mut self, en: EnumSymbol) {
        self.enums.insert(en.name, en);
    }

    pub fn add_const(&mut self, c: ConstSymbol) {
        self.consts.insert(c.name, c);
    }
}

#[derive(Debug, Clone)]
pub struct Scope {
    pub depth: usize,
    pub is_loop: bool,
    pub is_function_root: bool,
    pub variables: HashMap<Symbol, VariableSymbol>,
}

impl Scope {
    pub fn new(depth: usize, is_loop: bool, is_function_root: bool) -> Self {
        Self {
            depth,
            is_loop,
            is_function_root,
            variables: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SymbolTable {
    pub scopes: Vec<Scope>,
    pub functions: HashMap<Symbol, FunctionSymbol>,
    pub structs: HashMap<Symbol, StructSymbol>,
    pub enums: HashMap<Symbol, EnumSymbol>,
    pub consts: HashMap<Symbol, ConstSymbol>,
    pub traits: HashMap<Symbol, TraitSymbol>,
    pub trait_impls: HashMap<Symbol, Vec<Type>>,
    pub modules: HashMap<Symbol, ModuleSymbol>,
    pub imports: Vec<(Vec<Symbol>, Option<Symbol>, Span)>,
    pub expr_types: HashMap<Span, Type>,
    pub generic_function_instances: HashMap<Symbol, Vec<Vec<Type>>>,
    pub generic_struct_instances: HashMap<Symbol, Vec<Vec<Type>>>,
    pub call_instantiations: HashMap<Span, Vec<Type>>,
    next_var_id: u32,
}

impl SymbolTable {
    pub fn new() -> Self {
        let mut table = Self {
            scopes: vec![Scope::new(0, false, false)],
            functions: HashMap::new(),
            structs: HashMap::new(),
            enums: HashMap::new(),
            consts: HashMap::new(),
            traits: HashMap::new(),
            trait_impls: HashMap::new(),
            modules: HashMap::new(),
            imports: Vec::new(),
            expr_types: HashMap::new(),
            generic_function_instances: HashMap::new(),
            generic_struct_instances: HashMap::new(),
            call_instantiations: HashMap::new(),
            next_var_id: 1,
        };
        table.init_builtins();
        table
    }

    /// Define a module namespace in the symbol table.
    pub fn define_module(&mut self, module: ModuleSymbol) -> Result<(), Diagnostic> {
        if let Some(existing) = self.modules.get(&module.name) {
            let mod_name = INTERNER.resolve(&module.name);
            return Err(
                Diagnostic::error(format!("module '{}' déjà défini", mod_name))
                    .with_code("E0008")
                    .with_primary_label(module.span, "redéfinition du module")
                    .with_secondary_label(existing.span, "première définition ici"),
            );
        }
        self.modules.insert(module.name, module);
        Ok(())
    }

    /// Lookup a module by its local name or alias.
    pub fn lookup_module(&self, name: &Symbol) -> Option<&ModuleSymbol> {
        self.modules.get(name)
    }

    /// Lookup a mutable module by its local name or alias.
    pub fn lookup_module_mut(&mut self, name: &Symbol) -> Option<&mut ModuleSymbol> {
        self.modules.get_mut(name)
    }

    /// Lookup a qualified function in a module (returns the symbol and its `is_pub` visibility).
    pub fn lookup_qualified_function(
        &self,
        module_name: &Symbol,
        fn_name: &Symbol,
    ) -> Option<(&FunctionSymbol, bool)> {
        let module = self.lookup_module(module_name)?;
        let func = module.functions.get(fn_name)?;
        Some((func, func.is_pub))
    }

    /// Lookup a qualified struct in a module (returns the symbol and its `is_pub` visibility).
    pub fn lookup_qualified_struct(
        &self,
        module_name: &Symbol,
        st_name: &Symbol,
    ) -> Option<(&StructSymbol, bool)> {
        let module = self.lookup_module(module_name)?;
        let st = module.structs.get(st_name)?;
        Some((st, st.is_pub))
    }

    /// Lookup a qualified enum in a module (returns the symbol and its `is_pub` visibility).
    pub fn lookup_qualified_enum(
        &self,
        module_name: &Symbol,
        en_name: &Symbol,
    ) -> Option<(&EnumSymbol, bool)> {
        let module = self.lookup_module(module_name)?;
        let en = module.enums.get(en_name)?;
        Some((en, en.is_pub))
    }

    /// Lookup a qualified constant in a module (returns the symbol and its `is_pub` visibility).
    pub fn lookup_qualified_const(
        &self,
        module_name: &Symbol,
        c_name: &Symbol,
    ) -> Option<(&ConstSymbol, bool)> {
        let module = self.lookup_module(module_name)?;
        let c = module.consts.get(c_name)?;
        Some((c, c.is_pub))
    }

    /// Records a concrete generic function instantiation for monomorphization.
    pub fn record_generic_function_instance(&mut self, name: Symbol, type_args: Vec<Type>) {
        let instances = self.generic_function_instances.entry(name).or_default();
        if !instances.iter().any(|existing| existing == &type_args) {
            instances.push(type_args);
        }
    }

    /// Records a concrete generic struct instantiation for monomorphization.
    pub fn record_generic_struct_instance(&mut self, name: Symbol, type_args: Vec<Type>) {
        let instances = self.generic_struct_instances.entry(name).or_default();
        if !instances.iter().any(|existing| existing == &type_args) {
            instances.push(type_args);
        }
    }

    /// Traverses a semantic type and records any concrete generic struct instantiations.
    pub fn register_type_if_generic_instance(&mut self, ty: &Type) {
        match ty {
            Type::Generic { name, args } => {
                if !args.is_empty()
                    && args
                        .iter()
                        .all(|a| !matches!(a, Type::Unknown | Type::TypeParam(_)))
                {
                    self.record_generic_struct_instance(*name, args.clone());
                }
                for a in args {
                    self.register_type_if_generic_instance(a);
                }
            }
            Type::Ref(inner)
            | Type::Array(inner, _)
            | Type::Slice(inner)
            | Type::Optional(inner) => {
                self.register_type_if_generic_instance(inner);
            }
            Type::ErrorUnion { err, ok } => {
                self.register_type_if_generic_instance(err);
                self.register_type_if_generic_instance(ok);
            }
            Type::Tuple(elems) => {
                for e in elems {
                    self.register_type_if_generic_instance(e);
                }
            }
            _ => {}
        }
    }

    fn init_builtins(&mut self) {
        let dummy = Span::dummy();

        // 1. Module `std::io` / `io`
        let io_name = INTERNER.intern("io");
        let std_io_name = INTERNER.intern("std::io");
        let mut io_mod =
            ModuleSymbol::new(io_name, vec![INTERNER.intern("std"), io_name], true, dummy);
        let msg_sym = INTERNER.intern("msg");
        io_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("println"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: vec![ParamSymbol {
                mode: ParamMode::In,
                name: msg_sym,
                ty: Type::String,
                span: dummy,
            }],
            ret_ty: Type::Unit,
            span: dummy,
        });
        io_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("print"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: vec![ParamSymbol {
                mode: ParamMode::In,
                name: msg_sym,
                ty: Type::String,
                span: dummy,
            }],
            ret_ty: Type::Unit,
            span: dummy,
        });
        io_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("read_line"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: Vec::new(),
            ret_ty: Type::String,
            span: dummy,
        });
        io_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("flush"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: Vec::new(),
            ret_ty: Type::Unit,
            span: dummy,
        });
        self.modules.insert(io_name, io_mod.clone());
        self.modules.insert(std_io_name, io_mod);

        // 2. Module `std::fs` / `fs`
        let fs_name = INTERNER.intern("fs");
        let std_fs_name = INTERNER.intern("std::fs");
        let mut fs_mod =
            ModuleSymbol::new(fs_name, vec![INTERNER.intern("std"), fs_name], true, dummy);
        let path_sym = INTERNER.intern("path");
        let content_sym = INTERNER.intern("content");
        fs_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("read_to_string"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: vec![ParamSymbol {
                mode: ParamMode::In,
                name: path_sym,
                ty: Type::String,
                span: dummy,
            }],
            ret_ty: Type::String,
            span: dummy,
        });
        fs_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("write_string"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: vec![
                ParamSymbol {
                    mode: ParamMode::In,
                    name: path_sym,
                    ty: Type::String,
                    span: dummy,
                },
                ParamSymbol {
                    mode: ParamMode::In,
                    name: content_sym,
                    ty: Type::String,
                    span: dummy,
                },
            ],
            ret_ty: Type::Bool,
            span: dummy,
        });
        fs_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("exists"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: vec![ParamSymbol {
                mode: ParamMode::In,
                name: path_sym,
                ty: Type::String,
                span: dummy,
            }],
            ret_ty: Type::Bool,
            span: dummy,
        });
        fs_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("file_size"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: vec![ParamSymbol {
                mode: ParamMode::In,
                name: path_sym,
                ty: Type::String,
                span: dummy,
            }],
            ret_ty: Type::Int(crate::types::IntType::U64),
            span: dummy,
        });
        self.modules.insert(fs_name, fs_mod.clone());
        self.modules.insert(std_fs_name, fs_mod);

        // 3. Module `net::http` / `http`
        let http_name = INTERNER.intern("http");
        let net_http_name = INTERNER.intern("net::http");
        let mut http_mod = ModuleSymbol::new(
            http_name,
            vec![INTERNER.intern("net"), http_name],
            true,
            dummy,
        );
        let port_sym = INTERNER.intern("port");
        let url_sym = INTERNER.intern("url");
        let body_sym = INTERNER.intern("body");
        let http_server_ty = Type::Struct {
            name: INTERNER.intern("HttpServer"),
            fields: Vec::new(),
        };
        let http_client_ty = Type::Struct {
            name: INTERNER.intern("HttpClient"),
            fields: Vec::new(),
        };
        let http_resp_ty = Type::Struct {
            name: INTERNER.intern("HttpResponse"),
            fields: Vec::new(),
        };
        http_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("Server"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: vec![ParamSymbol {
                mode: ParamMode::In,
                name: port_sym,
                ty: Type::Int(crate::types::IntType::U16),
                span: dummy,
            }],
            ret_ty: http_server_ty,
            span: dummy,
        });
        http_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("Client"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: Vec::new(),
            ret_ty: http_client_ty,
            span: dummy,
        });
        http_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("get"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: vec![ParamSymbol {
                mode: ParamMode::In,
                name: url_sym,
                ty: Type::String,
                span: dummy,
            }],
            ret_ty: http_resp_ty.clone(),
            span: dummy,
        });
        http_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("post"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: vec![
                ParamSymbol {
                    mode: ParamMode::In,
                    name: url_sym,
                    ty: Type::String,
                    span: dummy,
                },
                ParamSymbol {
                    mode: ParamMode::In,
                    name: body_sym,
                    ty: Type::String,
                    span: dummy,
                },
            ],
            ret_ty: http_resp_ty,
            span: dummy,
        });
        self.modules.insert(http_name, http_mod.clone());
        self.modules.insert(net_http_name, http_mod);

        // 4. Module `encoding::json` / `json`
        let json_name = INTERNER.intern("json");
        let enc_json_name = INTERNER.intern("encoding::json");
        let mut json_mod = ModuleSymbol::new(
            json_name,
            vec![INTERNER.intern("encoding"), json_name],
            true,
            dummy,
        );
        json_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("decode"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: vec![ParamSymbol {
                mode: ParamMode::In,
                name: INTERNER.intern("input"),
                ty: Type::String,
                span: dummy,
            }],
            ret_ty: Type::Unknown,
            span: dummy,
        });
        json_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("encode"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: vec![ParamSymbol {
                mode: ParamMode::In,
                name: INTERNER.intern("val"),
                ty: Type::Unknown,
                span: dummy,
            }],
            ret_ty: Type::String,
            span: dummy,
        });
        self.modules.insert(json_name, json_mod.clone());
        self.modules.insert(enc_json_name, json_mod);

        // 5. Module `encoding::csv` / `csv`
        let csv_name = INTERNER.intern("csv");
        let enc_csv_name = INTERNER.intern("encoding::csv");
        let mut csv_mod = ModuleSymbol::new(
            csv_name,
            vec![INTERNER.intern("encoding"), csv_name],
            true,
            dummy,
        );
        let csv_table_ty = Type::Struct {
            name: INTERNER.intern("CsvTable"),
            fields: Vec::new(),
        };
        csv_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("decode"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: vec![ParamSymbol {
                mode: ParamMode::In,
                name: INTERNER.intern("input"),
                ty: Type::String,
                span: dummy,
            }],
            ret_ty: csv_table_ty.clone(),
            span: dummy,
        });
        csv_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("encode"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: vec![ParamSymbol {
                mode: ParamMode::In,
                name: INTERNER.intern("table"),
                ty: csv_table_ty,
                span: dummy,
            }],
            ret_ty: Type::String,
            span: dummy,
        });
        self.modules.insert(csv_name, csv_mod.clone());
        self.modules.insert(enc_csv_name, csv_mod);

        // 6. Module `crypto`
        let crypto_name = INTERNER.intern("crypto");
        let mut crypto_mod = ModuleSymbol::new(crypto_name, vec![crypto_name], true, dummy);
        crypto_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("sha256_hex"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: vec![ParamSymbol {
                mode: ParamMode::In,
                name: INTERNER.intern("data"),
                ty: Type::String,
                span: dummy,
            }],
            ret_ty: Type::String,
            span: dummy,
        });
        crypto_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("blake3_hex"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: vec![ParamSymbol {
                mode: ParamMode::In,
                name: INTERNER.intern("data"),
                ty: Type::String,
                span: dummy,
            }],
            ret_ty: Type::String,
            span: dummy,
        });
        self.modules.insert(crypto_name, crypto_mod);

        // 7. Module `sync`
        let sync_name = INTERNER.intern("sync");
        let mut sync_mod = ModuleSymbol::new(sync_name, vec![sync_name], true, dummy);
        sync_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("channel"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: Vec::new(),
            ret_ty: Type::Unknown,
            span: dummy,
        });
        sync_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("WaitGroup"),
            is_pub: true,
            is_strict: false,
            is_comptime: false,
            is_extern: None,
            generics: Vec::new(),
            params: Vec::new(),
            ret_ty: Type::Struct {
                name: INTERNER.intern("WaitGroup"),
                fields: Vec::new(),
            },
            span: dummy,
        });
        self.modules.insert(sync_name, sync_mod);

        // 8. Module `math`
        let math_name = INTERNER.intern("math");
        let mut math_mod = ModuleSymbol::new(math_name, vec![math_name], true, dummy);
        let x_sym = INTERNER.intern("x");
        let a_sym = INTERNER.intern("a");
        let b_sym = INTERNER.intern("b");
        let f64_ty = Type::Float(crate::types::FloatType::F64);
        math_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("abs"),
            is_pub: true,
            is_strict: true,
            is_comptime: true,
            is_extern: None,
            generics: Vec::new(),
            params: vec![ParamSymbol {
                mode: ParamMode::In,
                name: x_sym,
                ty: f64_ty.clone(),
                span: dummy,
            }],
            ret_ty: f64_ty.clone(),
            span: dummy,
        });
        math_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("sqrt"),
            is_pub: true,
            is_strict: true,
            is_comptime: true,
            is_extern: None,
            generics: Vec::new(),
            params: vec![ParamSymbol {
                mode: ParamMode::In,
                name: x_sym,
                ty: f64_ty.clone(),
                span: dummy,
            }],
            ret_ty: f64_ty.clone(),
            span: dummy,
        });
        math_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("min"),
            is_pub: true,
            is_strict: true,
            is_comptime: true,
            is_extern: None,
            generics: Vec::new(),
            params: vec![
                ParamSymbol {
                    mode: ParamMode::In,
                    name: a_sym,
                    ty: f64_ty.clone(),
                    span: dummy,
                },
                ParamSymbol {
                    mode: ParamMode::In,
                    name: b_sym,
                    ty: f64_ty.clone(),
                    span: dummy,
                },
            ],
            ret_ty: f64_ty.clone(),
            span: dummy,
        });
        math_mod.add_function(FunctionSymbol {
            name: INTERNER.intern("max"),
            is_pub: true,
            is_strict: true,
            is_comptime: true,
            is_extern: None,
            generics: Vec::new(),
            params: vec![
                ParamSymbol {
                    mode: ParamMode::In,
                    name: a_sym,
                    ty: f64_ty.clone(),
                    span: dummy,
                },
                ParamSymbol {
                    mode: ParamMode::In,
                    name: b_sym,
                    ty: f64_ty.clone(),
                    span: dummy,
                },
            ],
            ret_ty: f64_ty.clone(),
            span: dummy,
        });
        math_mod.add_const(ConstSymbol {
            name: INTERNER.intern("PI"),
            is_pub: true,
            ty: f64_ty,
            span: dummy,
        });
        self.modules.insert(math_name, math_mod);
    }

    pub fn enter_scope(&mut self, is_loop: bool, is_function_root: bool) {
        let depth = self.scopes.len();
        self.scopes
            .push(Scope::new(depth, is_loop, is_function_root));
    }

    pub fn exit_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
        }
    }

    pub fn current_depth(&self) -> usize {
        self.scopes.len().saturating_sub(1)
    }

    pub fn is_inside_loop(&self) -> bool {
        self.scopes.iter().rev().any(|s| s.is_loop)
    }

    pub fn define_variable(
        &mut self,
        name: Symbol,
        ty: Type,
        is_mut: bool,
        is_initialized: bool,
        mode: Option<ParamMode>,
        span: Span,
    ) -> Result<u32, Diagnostic> {
        let current_scope = self
            .scopes
            .last_mut()
            .expect("At least one scope must exist");
        if let Some(existing) = current_scope.variables.get(&name) {
            let var_name = INTERNER.resolve(&name);
            return Err(Diagnostic::error(format!(
                "variable '{}' déjà définie dans cette portée",
                var_name
            ))
            .with_code("E0002")
            .with_primary_label(span, "redéfinition de la variable")
            .with_secondary_label(existing.span, "première définition ici"));
        }

        let id = self.next_var_id;
        self.next_var_id += 1;
        let depth = current_scope.depth;

        let var_sym = VariableSymbol {
            id,
            name,
            ty,
            is_mut,
            is_initialized,
            mode,
            span,
            scope_depth: depth,
        };

        current_scope.variables.insert(name, var_sym);
        Ok(id)
    }

    pub fn lookup_variable(&self, name: &Symbol) -> Option<&VariableSymbol> {
        for scope in self.scopes.iter().rev() {
            if let Some(var) = scope.variables.get(name) {
                return Some(var);
            }
        }
        None
    }

    pub fn lookup_variable_mut(&mut self, name: &Symbol) -> Option<&mut VariableSymbol> {
        for scope in self.scopes.iter_mut().rev() {
            if let Some(var) = scope.variables.get_mut(name) {
                return Some(var);
            }
        }
        None
    }

    pub fn define_function(&mut self, func: FunctionSymbol) -> Result<(), Diagnostic> {
        if let Some(existing) = self.functions.get(&func.name) {
            let fn_name = INTERNER.resolve(&func.name);
            return Err(
                Diagnostic::error(format!("fonction '{}' déjà définie", fn_name))
                    .with_code("E0003")
                    .with_primary_label(func.span, "redéfinition de la fonction")
                    .with_secondary_label(existing.span, "première définition ici"),
            );
        }
        self.functions.insert(func.name, func);
        Ok(())
    }

    pub fn lookup_function(&self, name: &Symbol) -> Option<&FunctionSymbol> {
        self.functions.get(name)
    }

    pub fn define_struct(&mut self, st: StructSymbol) -> Result<(), Diagnostic> {
        if let Some(existing) = self.structs.get(&st.name) {
            let st_name = INTERNER.resolve(&st.name);
            return Err(
                Diagnostic::error(format!("structure '{}' déjà définie", st_name))
                    .with_code("E0004")
                    .with_primary_label(st.span, "redéfinition de la structure")
                    .with_secondary_label(existing.span, "première définition ici"),
            );
        }
        self.structs.insert(st.name, st);
        Ok(())
    }

    pub fn lookup_struct(&self, name: &Symbol) -> Option<&StructSymbol> {
        self.structs.get(name)
    }

    pub fn define_enum(&mut self, en: EnumSymbol) -> Result<(), Diagnostic> {
        if let Some(existing) = self.enums.get(&en.name) {
            let en_name = INTERNER.resolve(&en.name);
            return Err(
                Diagnostic::error(format!("énumération '{}' déjà définie", en_name))
                    .with_code("E0005")
                    .with_primary_label(en.span, "redéfinition de l'énumération")
                    .with_secondary_label(existing.span, "première définition ici"),
            );
        }
        self.enums.insert(en.name, en);
        Ok(())
    }

    pub fn lookup_enum(&self, name: &Symbol) -> Option<&EnumSymbol> {
        self.enums.get(name)
    }

    pub fn define_const(&mut self, c: ConstSymbol) -> Result<(), Diagnostic> {
        if let Some(existing) = self.consts.get(&c.name) {
            let c_name = INTERNER.resolve(&c.name);
            return Err(
                Diagnostic::error(format!("constante '{}' déjà définie", c_name))
                    .with_code("E0006")
                    .with_primary_label(c.span, "redéfinition de la constante")
                    .with_secondary_label(existing.span, "première définition ici"),
            );
        }
        self.consts.insert(c.name, c);
        Ok(())
    }

    pub fn lookup_const(&self, name: &Symbol) -> Option<&ConstSymbol> {
        self.consts.get(name)
    }

    pub fn define_trait(&mut self, tr: TraitSymbol) -> Result<(), Diagnostic> {
        if let Some(existing) = self.traits.get(&tr.name) {
            let tr_name = INTERNER.resolve(&tr.name);
            return Err(
                Diagnostic::error(format!("trait '{}' déjà défini", tr_name))
                    .with_code("E0007")
                    .with_primary_label(tr.span, "redéfinition du trait")
                    .with_secondary_label(existing.span, "première définition ici"),
            );
        }
        self.traits.insert(tr.name, tr);
        Ok(())
    }

    pub fn lookup_trait(&self, name: &Symbol) -> Option<&TraitSymbol> {
        self.traits.get(name)
    }

    pub fn register_trait_impl(&mut self, trait_name: Symbol, ty: Type) {
        self.trait_impls.entry(trait_name).or_default().push(ty);
    }

    pub fn type_implements_trait(&self, ty: &Type, trait_name: &Symbol) -> bool {
        // Unknown suppresses cascading errors
        if matches!(ty, Type::Unknown) {
            return true;
        }

        // Direct explicit registration
        if let Some(types) = self.trait_impls.get(trait_name) {
            for impl_ty in types {
                if ty.is_assignable_to(impl_ty) || ty == impl_ty {
                    return true;
                }
            }
        }

        // If trait definition exists, check structural / method conformity
        if let Some(tr) = self.traits.get(trait_name) {
            if tr.methods.is_empty() {
                return true;
            }

            for req_m in &tr.methods {
                let mut found = false;
                if let Some(f) = self.lookup_function(&req_m.name) {
                    if let Some(first_p) = f.params.first() {
                        if ty.is_assignable_to(&first_p.ty)
                            || matches!(&first_p.ty, Type::Ref(inner) if ty.is_assignable_to(inner))
                            || matches!(&first_p.ty, Type::TypeParam(_))
                        {
                            found = true;
                        }
                    }
                }
                if !found {
                    return false;
                }
            }
            return true;
        }

        false
    }
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}

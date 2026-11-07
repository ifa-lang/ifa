use crate::types::Type;
use ifa_ast::ParamMode;
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
    pub generics: Vec<Symbol>,
    pub fields: Vec<FieldSymbol>,
    pub field_indices: HashMap<Symbol, usize>,
    pub span: Span,
}

impl StructSymbol {
    pub fn new(
        name: Symbol,
        is_pub: bool,
        generics: Vec<Symbol>,
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
            next_var_id: 1,
        };
        table.init_builtins();
        table
    }

    fn init_builtins(&mut self) {
        // Builtin functions could be registered here
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
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}

#![allow(clippy::result_large_err)]

use ifa_ast::*;
use ifa_diagnostics::Diagnostic;
use ifa_lexer::token::{Token, TokenKind};
use ifa_span::{sym, BytePos, FileId, Span, INTERNER};

pub struct Parser {
    file_id: FileId,
    tokens: Vec<Token>,
    cursor: usize,
    diagnostics: Vec<Diagnostic>,
}

impl Parser {
    pub fn new(file_id: FileId, tokens: Vec<Token>) -> Self {
        Self {
            file_id,
            tokens,
            cursor: 0,
            diagnostics: Vec::new(),
        }
    }

    // --- Cursor & Token Helpers ---

    fn current(&self) -> Token {
        if self.cursor < self.tokens.len() {
            self.tokens[self.cursor]
        } else {
            let last_pos = self.tokens.last().map(|t| t.span.end).unwrap_or(BytePos(0));
            Token::new(TokenKind::Eof, Span::new(self.file_id, last_pos, last_pos))
        }
    }

    #[allow(dead_code)]
    fn peek(&self) -> Token {
        if self.cursor + 1 < self.tokens.len() {
            self.tokens[self.cursor + 1]
        } else {
            self.current()
        }
    }

    fn advance(&mut self) -> Token {
        let tok = self.current();
        if self.cursor < self.tokens.len() {
            self.cursor += 1;
        }
        tok
    }

    fn check(&self, expected: &TokenKind) -> bool {
        std::mem::discriminant(&self.current().kind) == std::mem::discriminant(expected)
    }

    fn match_token(&mut self, expected: &TokenKind) -> bool {
        if self.check(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: TokenKind) -> Result<Token, Diagnostic> {
        let cur = self.current();
        if std::mem::discriminant(&cur.kind) == std::mem::discriminant(&expected) {
            Ok(self.advance())
        } else {
            let diag = Diagnostic::error(format!(
                "attendu '{}', mais trouvé '{}'",
                expected, cur.kind
            ))
            .with_primary_label(cur.span, format!("attendu '{}'", expected));
            self.diagnostics.push(diag.clone());
            Err(diag)
        }
    }

    fn eat_semicolons(&mut self) {
        while self.match_token(&TokenKind::Semicolon) {}
    }

    // --- Top-level Program Parsing ---

    pub fn parse_program(&mut self) -> (Program, Vec<Diagnostic>) {
        let start_pos = self.current().span.start;
        let mut items = Vec::new();

        while !self.check(&TokenKind::Eof) {
            self.eat_semicolons();
            if self.check(&TokenKind::Eof) {
                break;
            }
            match self.parse_item() {
                Ok(item) => items.push(item),
                Err(_) => {
                    self.synchronize_item();
                }
            }
            self.eat_semicolons();
        }

        let end_pos = self.current().span.end;
        let prog = Program {
            items,
            span: Span::new(self.file_id, start_pos, end_pos),
        };
        (prog, std::mem::take(&mut self.diagnostics))
    }

    fn synchronize_item(&mut self) {
        self.advance();
        while !self.check(&TokenKind::Eof) {
            if self.check(&TokenKind::Semicolon) {
                self.advance();
                return;
            }
            match self.current().kind {
                TokenKind::Fn
                | TokenKind::Struct
                | TokenKind::Enum
                | TokenKind::Import
                | TokenKind::Const => return,
                _ => {
                    self.advance();
                }
            }
        }
    }

    fn parse_item(&mut self) -> Result<Item, Diagnostic> {
        let is_pub = self.match_token(&TokenKind::Pub);
        let mut is_strict = false;
        let mut is_comptime = false;
        let mut is_extern = None;

        loop {
            if self.match_token(&TokenKind::Strict) {
                is_strict = true;
            } else if self.match_token(&TokenKind::Comptime) {
                is_comptime = true;
            } else if self.match_token(&TokenKind::Extern) {
                if let TokenKind::StringLiteral(s) = self.current().kind {
                    self.advance();
                    is_extern = Some(s.to_string());
                } else {
                    is_extern = Some("C".to_string());
                }
            } else {
                break;
            }
        }

        match self.current().kind {
            TokenKind::Fn => self
                .parse_function(is_pub, is_strict, is_comptime, is_extern)
                .map(Item::Function),
            TokenKind::Struct => self.parse_struct(is_pub).map(Item::Struct),
            TokenKind::Enum => self.parse_enum(is_pub).map(Item::Enum),
            TokenKind::Import => self.parse_import().map(Item::Import),
            TokenKind::Const => self.parse_const(is_pub).map(Item::Const),
            TokenKind::Trait | TokenKind::Interface => self.parse_trait(is_pub).map(Item::Trait),
            TokenKind::Impl => self.parse_impl().map(Item::Impl),
            _ => {
                let cur = self.current();
                let diag = Diagnostic::error(format!("déclaration inattendue '{}'", cur.kind))
                    .with_primary_label(
                        cur.span,
                        "déclaration attendue (fn, struct, enum, import, const, trait, interface, impl)",
                    );
                self.diagnostics.push(diag.clone());
                Err(diag)
            }
        }
    }

    fn parse_function(
        &mut self,
        is_pub: bool,
        is_strict: bool,
        is_comptime: bool,
        is_extern: Option<String>,
    ) -> Result<Function, Diagnostic> {
        let fn_tok = self.expect(TokenKind::Fn)?;
        let name_tok = match self.current().kind {
            TokenKind::Ident(s) => {
                self.advance();
                s
            }
            _ => {
                let cur = self.current();
                let diag = Diagnostic::error("nom de fonction attendu après 'fn'")
                    .with_primary_label(cur.span, "identifiant attendu");
                self.diagnostics.push(diag.clone());
                return Err(diag);
            }
        };

        // Generics <T, U> or <T: Trait1 + Trait2>
        let generics = self.parse_generic_params()?;

        // Parameters (inout a: T, sink b: U)
        self.expect(TokenKind::OpenParen)?;
        let mut params = Vec::new();
        while !self.check(&TokenKind::CloseParen) && !self.check(&TokenKind::Eof) {
            let start_param = self.current().span.start;
            let mut mode = ParamMode::In;
            if self.match_token(&TokenKind::InOut) {
                mode = ParamMode::InOut;
            } else if self.match_token(&TokenKind::Sink) {
                mode = ParamMode::Sink;
            } else if self.match_token(&TokenKind::Comptime) {
                mode = ParamMode::Comptime;
            } else if self.match_token(&TokenKind::In) {
                mode = ParamMode::In;
            } else if self.match_token(&TokenKind::Mut) {
                mode = ParamMode::Mut;
            }

            let param_name = match self.current().kind {
                TokenKind::Ident(s) => {
                    self.advance();
                    s
                }
                _ => {
                    let cur = self.current();
                    let diag = Diagnostic::error("nom de paramètre attendu")
                        .with_primary_label(cur.span, "identifiant attendu");
                    self.diagnostics.push(diag.clone());
                    return Err(diag);
                }
            };

            let ty = if self.match_token(&TokenKind::Colon) {
                self.parse_type()?
            } else {
                Type {
                    kind: TypeKind::Named(sym("auto")),
                    span: self.current().span,
                }
            };

            let end_param = ty.span.end;
            params.push(Param {
                mode,
                name: param_name,
                ty,
                span: Span::new(self.file_id, start_param, end_param),
            });

            if !self.match_token(&TokenKind::Comma) {
                break;
            }
        }
        self.expect(TokenKind::CloseParen)?;

        // Return type -> Type
        let ret_ty = if self.match_token(&TokenKind::Arrow) {
            Some(self.parse_type()?)
        } else {
            None
        };

        // Body or semicolon (for extern/signatures)
        let (body, end_pos) = if self.check(&TokenKind::OpenBrace) {
            let b = self.parse_block()?;
            let end = b.span.end;
            (Some(b), end)
        } else {
            self.expect(TokenKind::Semicolon)?;
            (None, self.current().span.end)
        };

        Ok(Function {
            is_pub,
            is_strict,
            is_comptime,
            is_extern,
            name: name_tok,
            generics,
            params,
            ret_ty,
            body,
            span: Span::new(self.file_id, fn_tok.span.start, end_pos),
        })
    }

    fn parse_struct(&mut self, is_pub: bool) -> Result<Struct, Diagnostic> {
        let struct_tok = self.expect(TokenKind::Struct)?;
        let name = match self.current().kind {
            TokenKind::Ident(s) => {
                self.advance();
                s
            }
            _ => {
                let cur = self.current();
                let diag = Diagnostic::error("nom de structure attendu après 'struct'")
                    .with_primary_label(cur.span, "identifiant attendu");
                self.diagnostics.push(diag.clone());
                return Err(diag);
            }
        };

        // Optional generics <T, U> or <T: Trait1 + Trait2>
        let generics = self.parse_generic_params()?;

        self.expect(TokenKind::OpenBrace)?;
        let mut fields = Vec::new();
        while !self.check(&TokenKind::CloseBrace) && !self.check(&TokenKind::Eof) {
            let field_pub = self.match_token(&TokenKind::Pub);
            let field_name = match self.current().kind {
                TokenKind::Ident(s) => {
                    self.advance();
                    s
                }
                _ => {
                    let cur = self.current();
                    let diag = Diagnostic::error("nom de champ attendu")
                        .with_primary_label(cur.span, "identifiant attendu");
                    self.diagnostics.push(diag.clone());
                    return Err(diag);
                }
            };
            self.expect(TokenKind::Colon)?;
            let field_ty = self.parse_type()?;
            let span = Span::new(self.file_id, self.current().span.start, field_ty.span.end);
            fields.push(StructField {
                is_pub: field_pub,
                name: field_name,
                ty: field_ty,
                span,
            });

            self.match_token(&TokenKind::Comma);
            self.eat_semicolons();
        }
        let close = self.expect(TokenKind::CloseBrace)?;

        Ok(Struct {
            is_pub,
            name,
            generics,
            fields,
            span: Span::new(self.file_id, struct_tok.span.start, close.span.end),
        })
    }

    fn parse_enum(&mut self, is_pub: bool) -> Result<Enum, Diagnostic> {
        let enum_tok = self.expect(TokenKind::Enum)?;
        let name = match self.current().kind {
            TokenKind::Ident(s) => {
                self.advance();
                s
            }
            _ => {
                let cur = self.current();
                let diag = Diagnostic::error("nom d'énumération attendu après 'enum'")
                    .with_primary_label(cur.span, "identifiant attendu");
                self.diagnostics.push(diag.clone());
                return Err(diag);
            }
        };

        self.expect(TokenKind::OpenBrace)?;
        let mut variants = Vec::new();
        while !self.check(&TokenKind::CloseBrace) && !self.check(&TokenKind::Eof) {
            let start = self.current().span.start;
            let v_name = match self.current().kind {
                TokenKind::Ident(s) => {
                    self.advance();
                    s
                }
                _ => break,
            };

            let mut payload = None;
            let mut end = self.current().span.end;
            if self.match_token(&TokenKind::OpenParen) {
                let ty = self.parse_type()?;
                let close_p = self.expect(TokenKind::CloseParen)?;
                end = close_p.span.end;
                payload = Some(ty);
            }

            variants.push(Variant {
                name: v_name,
                payload,
                span: Span::new(self.file_id, start, end),
            });

            self.match_token(&TokenKind::Comma);
            self.eat_semicolons();
        }
        let close = self.expect(TokenKind::CloseBrace)?;

        Ok(Enum {
            is_pub,
            name,
            variants,
            span: Span::new(self.file_id, enum_tok.span.start, close.span.end),
        })
    }

    fn parse_import(&mut self) -> Result<Import, Diagnostic> {
        let import_tok = self.expect(TokenKind::Import)?;
        let mut path = Vec::new();

        loop {
            match self.current().kind {
                TokenKind::Ident(s) => {
                    self.advance();
                    path.push(s);
                }
                _ => {
                    let cur = self.current();
                    let diag = Diagnostic::error("segment de chemin attendu après 'import'")
                        .with_primary_label(cur.span, "identifiant attendu");
                    self.diagnostics.push(diag.clone());
                    return Err(diag);
                }
            }

            if self.match_token(&TokenKind::ColonColon) || self.match_token(&TokenKind::Slash) {
                continue;
            } else {
                break;
            }
        }

        let alias = if self.match_token(&TokenKind::As) {
            match self.current().kind {
                TokenKind::Ident(s) => {
                    self.advance();
                    Some(s)
                }
                _ => None,
            }
        } else {
            None
        };

        let end_pos = self.current().span.end;
        self.match_token(&TokenKind::Semicolon);

        Ok(Import {
            path,
            alias,
            span: Span::new(self.file_id, import_tok.span.start, end_pos),
        })
    }

    fn parse_const(&mut self, is_pub: bool) -> Result<Const, Diagnostic> {
        let const_tok = self.expect(TokenKind::Const)?;
        let name = match self.current().kind {
            TokenKind::Ident(s) => {
                self.advance();
                s
            }
            _ => {
                let cur = self.current();
                let diag = Diagnostic::error("nom de constante attendu")
                    .with_primary_label(cur.span, "identifiant attendu");
                self.diagnostics.push(diag.clone());
                return Err(diag);
            }
        };

        let ty = if self.match_token(&TokenKind::Colon) {
            Some(self.parse_type()?)
        } else {
            None
        };

        self.expect(TokenKind::Eq)?;
        let value = self.parse_expr()?;
        self.match_token(&TokenKind::Semicolon);

        let end_pos = value.span.end;
        Ok(Const {
            is_pub,
            name,
            ty,
            value,
            span: Span::new(self.file_id, const_tok.span.start, end_pos),
        })
    }

    fn parse_generic_params(&mut self) -> Result<Vec<GenericParam>, Diagnostic> {
        let mut generics = Vec::new();
        if self.match_token(&TokenKind::Lt) {
            while !self.check(&TokenKind::Gt) && !self.check(&TokenKind::Eof) {
                let start = self.current().span.start;
                let name = match self.current().kind {
                    TokenKind::Ident(g) => {
                        self.advance();
                        g
                    }
                    _ => {
                        let cur = self.current();
                        let diag = Diagnostic::error("nom de paramètre générique attendu")
                            .with_primary_label(cur.span, "identifiant attendu");
                        self.diagnostics.push(diag.clone());
                        return Err(diag);
                    }
                };

                let mut bounds = Vec::new();
                let mut end = self.current().span.end;
                if self.match_token(&TokenKind::Colon) {
                    while !self.check(&TokenKind::Comma)
                        && !self.check(&TokenKind::Gt)
                        && !self.check(&TokenKind::Eof)
                    {
                        match self.current().kind {
                            TokenKind::Ident(b) => {
                                let b_tok = self.advance();
                                bounds.push(b);
                                end = b_tok.span.end;
                            }
                            _ => {
                                let cur = self.current();
                                let diag = Diagnostic::error(
                                    "nom de trait ou interface attendu pour la contrainte générique",
                                )
                                .with_primary_label(cur.span, "identifiant attendu");
                                self.diagnostics.push(diag.clone());
                                return Err(diag);
                            }
                        }
                        if !self.match_token(&TokenKind::Plus) {
                            break;
                        }
                    }
                }

                generics.push(GenericParam {
                    name,
                    bounds,
                    span: Span::new(self.file_id, start, end),
                });

                if !self.match_token(&TokenKind::Comma) {
                    break;
                }
            }
            self.expect(TokenKind::Gt)?;
        }
        Ok(generics)
    }

    fn parse_trait(&mut self, is_pub: bool) -> Result<Trait, Diagnostic> {
        let kw_tok = self.advance(); // consume 'trait' or 'interface'
        let name = match self.current().kind {
            TokenKind::Ident(s) => {
                self.advance();
                s
            }
            _ => {
                let cur = self.current();
                let diag = Diagnostic::error("nom de trait ou interface attendu")
                    .with_primary_label(cur.span, "identifiant attendu");
                self.diagnostics.push(diag.clone());
                return Err(diag);
            }
        };

        self.expect(TokenKind::OpenBrace)?;
        let mut methods = Vec::new();
        while !self.check(&TokenKind::CloseBrace) && !self.check(&TokenKind::Eof) {
            let fn_tok = self.expect(TokenKind::Fn)?;
            let method_name = match self.current().kind {
                TokenKind::Ident(s) => {
                    self.advance();
                    s
                }
                _ => {
                    let cur = self.current();
                    let diag = Diagnostic::error("nom de méthode attendu dans le contrat de trait")
                        .with_primary_label(cur.span, "identifiant attendu");
                    self.diagnostics.push(diag.clone());
                    return Err(diag);
                }
            };

            self.expect(TokenKind::OpenParen)?;
            let mut params = Vec::new();
            while !self.check(&TokenKind::CloseParen) && !self.check(&TokenKind::Eof) {
                let start_param = self.current().span.start;
                let mut mode = ParamMode::In;
                if self.match_token(&TokenKind::InOut) {
                    mode = ParamMode::InOut;
                } else if self.match_token(&TokenKind::Sink) {
                    mode = ParamMode::Sink;
                } else if self.match_token(&TokenKind::Comptime) {
                    mode = ParamMode::Comptime;
                } else if self.match_token(&TokenKind::In) {
                    mode = ParamMode::In;
                } else if self.match_token(&TokenKind::Mut) {
                    mode = ParamMode::Mut;
                }

                let param_name = match self.current().kind {
                    TokenKind::Ident(s) => {
                        self.advance();
                        s
                    }
                    _ => {
                        let cur = self.current();
                        let diag = Diagnostic::error("nom de paramètre attendu dans la méthode")
                            .with_primary_label(cur.span, "identifiant attendu");
                        self.diagnostics.push(diag.clone());
                        return Err(diag);
                    }
                };

                let ty = if self.match_token(&TokenKind::Colon) {
                    self.parse_type()?
                } else {
                    Type {
                        kind: TypeKind::Named(sym("auto")),
                        span: self.current().span,
                    }
                };

                let end_param = ty.span.end;
                params.push(Param {
                    mode,
                    name: param_name,
                    ty,
                    span: Span::new(self.file_id, start_param, end_param),
                });

                if !self.match_token(&TokenKind::Comma) {
                    break;
                }
            }
            self.expect(TokenKind::CloseParen)?;

            let ret_ty = if self.match_token(&TokenKind::Arrow) {
                Some(self.parse_type()?)
            } else {
                None
            };

            let end_pos = ret_ty
                .as_ref()
                .map(|t| t.span.end)
                .unwrap_or(self.current().span.end);
            self.eat_semicolons();

            methods.push(TraitMethod {
                name: method_name,
                params,
                ret_ty,
                span: Span::new(self.file_id, fn_tok.span.start, end_pos),
            });
        }
        let close = self.expect(TokenKind::CloseBrace)?;

        Ok(Trait {
            is_pub,
            name,
            methods,
            span: Span::new(self.file_id, kw_tok.span.start, close.span.end),
        })
    }

    fn parse_impl(&mut self) -> Result<Impl, Diagnostic> {
        let impl_tok = self.expect(TokenKind::Impl)?;
        let first_ty = self.parse_type()?;
        let (trait_name, target_ty) = if self.match_token(&TokenKind::For) {
            let tr_name = match &first_ty.kind {
                TypeKind::Named(s) => *s,
                _ => {
                    let diag = Diagnostic::error("nom de trait simple attendu avant 'for'")
                        .with_primary_label(first_ty.span, "identifiant de trait attendu");
                    self.diagnostics.push(diag.clone());
                    return Err(diag);
                }
            };
            let target = self.parse_type()?;
            (Some(tr_name), target)
        } else {
            (None, first_ty)
        };

        self.expect(TokenKind::OpenBrace)?;
        let mut methods = Vec::new();
        while !self.check(&TokenKind::CloseBrace) && !self.check(&TokenKind::Eof) {
            let m_pub = self.match_token(&TokenKind::Pub);
            methods.push(self.parse_function(m_pub, false, false, None)?);
        }
        let close = self.expect(TokenKind::CloseBrace)?;

        Ok(Impl {
            trait_name,
            target_ty,
            methods,
            span: Span::new(self.file_id, impl_tok.span.start, close.span.end),
        })
    }

    // --- Type Parsing ---

    pub fn parse_type(&mut self) -> Result<Type, Diagnostic> {
        let start = self.current().span.start;

        let mut base_type = if self.match_token(&TokenKind::Ref) {
            // ref T: Generational Reference
            let inner = self.parse_type()?;
            let span = Span::new(self.file_id, start, inner.span.end);
            Type {
                kind: TypeKind::Ref(Box::new(inner)),
                span,
            }
        } else if self.match_token(&TokenKind::Question) {
            // ?T: Optional
            let inner = self.parse_type()?;
            let span = Span::new(self.file_id, start, inner.span.end);
            Type {
                kind: TypeKind::Optional(Box::new(inner)),
                span,
            }
        } else if self.match_token(&TokenKind::OpenBracket) {
            // [T; N] or [T]
            let inner = self.parse_type()?;
            if self.match_token(&TokenKind::Semicolon) {
                let len = match self.current().kind {
                    TokenKind::IntLiteral(s) => {
                        self.advance();
                        s.to_string().parse::<u32>().unwrap_or(0)
                    }
                    _ => 0,
                };
                let close = self.expect(TokenKind::CloseBracket)?;
                Type {
                    kind: TypeKind::Array(Box::new(inner), len),
                    span: Span::new(self.file_id, start, close.span.end),
                }
            } else {
                let close = self.expect(TokenKind::CloseBracket)?;
                Type {
                    kind: TypeKind::Slice(Box::new(inner)),
                    span: Span::new(self.file_id, start, close.span.end),
                }
            }
        } else if self.match_token(&TokenKind::OpenParen) {
            // Unit () or Tuple (T1, T2)
            if self.match_token(&TokenKind::CloseParen) {
                Type {
                    kind: TypeKind::Unit,
                    span: Span::new(self.file_id, start, self.current().span.end),
                }
            } else {
                let mut tuple_types = Vec::new();
                while !self.check(&TokenKind::CloseParen) && !self.check(&TokenKind::Eof) {
                    tuple_types.push(self.parse_type()?);
                    if !self.match_token(&TokenKind::Comma) {
                        break;
                    }
                }
                let close = self.expect(TokenKind::CloseParen)?;
                Type {
                    kind: TypeKind::Tuple(tuple_types),
                    span: Span::new(self.file_id, start, close.span.end),
                }
            }
        } else {
            // Named or Path or Generic
            let mut path = Vec::new();
            match self.current().kind {
                TokenKind::Ident(s) => {
                    self.advance();
                    path.push(s);
                }
                _ => {
                    let cur = self.current();
                    let diag = Diagnostic::error("type attendu")
                        .with_primary_label(cur.span, "nom de type attendu");
                    self.diagnostics.push(diag.clone());
                    return Err(diag);
                }
            }

            while self.match_token(&TokenKind::ColonColon) || self.match_token(&TokenKind::Dot) {
                if let TokenKind::Ident(s) = self.current().kind {
                    self.advance();
                    path.push(s);
                }
            }

            // Generic arguments: Name<T, U>
            if self.match_token(&TokenKind::Lt) {
                let mut type_args = Vec::new();
                while !self.check(&TokenKind::Gt) && !self.check(&TokenKind::Eof) {
                    type_args.push(self.parse_type()?);
                    if !self.match_token(&TokenKind::Comma) {
                        break;
                    }
                }
                let close = self.expect(TokenKind::Gt)?;
                let name = *path.last().unwrap();
                Type {
                    kind: TypeKind::Generic(name, type_args),
                    span: Span::new(self.file_id, start, close.span.end),
                }
            } else if path.len() == 1 {
                Type {
                    kind: TypeKind::Named(path[0]),
                    span: Span::new(self.file_id, start, self.current().span.end),
                }
            } else {
                Type {
                    kind: TypeKind::Path(path),
                    span: Span::new(self.file_id, start, self.current().span.end),
                }
            }
        };

        // Check for Error Union ! Operator: TypeErreur!TypeSucces (e.g. IoError!String)
        if self.match_token(&TokenKind::Bang) {
            let success_type = self.parse_type()?;
            let end_span = success_type.span.end;
            base_type = Type {
                kind: TypeKind::ErrorUnion(Box::new(base_type), Box::new(success_type)),
                span: Span::new(self.file_id, start, end_span),
            };
        }

        Ok(base_type)
    }

    // --- Block & Statement Parsing ---

    fn synchronize_block(&mut self) {
        while !self.check(&TokenKind::CloseBrace) && !self.check(&TokenKind::Eof) {
            if self.check(&TokenKind::Semicolon) {
                self.advance();
                return;
            }
            match self.current().kind {
                TokenKind::Let
                | TokenKind::Mut
                | TokenKind::If
                | TokenKind::While
                | TokenKind::For
                | TokenKind::Return
                | TokenKind::Defer
                | TokenKind::Fn => return,
                _ => {
                    self.advance();
                }
            }
        }
    }

    pub fn parse_block(&mut self) -> Result<Block, Diagnostic> {
        let open = self.expect(TokenKind::OpenBrace)?;
        let mut stmts = Vec::new();
        let mut expr = None;

        while !self.check(&TokenKind::CloseBrace) && !self.check(&TokenKind::Eof) {
            self.eat_semicolons();
            if self.check(&TokenKind::CloseBrace) {
                break;
            }

            let stmt = match self.parse_stmt() {
                Ok(s) => s,
                Err(_) => {
                    self.synchronize_block();
                    continue;
                }
            };
            // Check if final expression of the block
            if let Stmt::Expr(e) = stmt {
                if self.check(&TokenKind::CloseBrace) {
                    expr = Some(Box::new(e));
                    break;
                } else {
                    stmts.push(Stmt::Expr(e));
                }
            } else {
                stmts.push(stmt);
            }
            self.eat_semicolons();
        }
        let close = self.expect(TokenKind::CloseBrace)?;

        Ok(Block {
            stmts,
            expr,
            span: Span::new(self.file_id, open.span.start, close.span.end),
        })
    }

    fn parse_stmt(&mut self) -> Result<Stmt, Diagnostic> {
        let cur = self.current();
        match cur.kind {
            TokenKind::Let | TokenKind::Mut => {
                let is_mut = cur.kind == TokenKind::Mut;
                self.advance();
                let name = match self.current().kind {
                    TokenKind::Ident(s) => {
                        self.advance();
                        s
                    }
                    _ => {
                        let c = self.current();
                        let diag = Diagnostic::error("nom de variable attendu")
                            .with_primary_label(c.span, "identifiant attendu");
                        self.diagnostics.push(diag.clone());
                        return Err(diag);
                    }
                };

                let ty = if self.match_token(&TokenKind::Colon) {
                    Some(self.parse_type()?)
                } else {
                    None
                };

                let init = if self.match_token(&TokenKind::Eq) {
                    Some(self.parse_expr()?)
                } else {
                    None
                };

                self.match_token(&TokenKind::Semicolon);
                let end = init
                    .as_ref()
                    .map(|e| e.span.end)
                    .unwrap_or(self.current().span.end);
                Ok(Stmt::Let {
                    is_mut,
                    name,
                    ty,
                    init,
                    span: Span::new(self.file_id, cur.span.start, end),
                })
            }
            TokenKind::Defer => {
                let defer_tok = self.advance();
                let blk = self.parse_block()?;
                let end = blk.span.end;
                Ok(Stmt::Defer(
                    blk,
                    Span::new(self.file_id, defer_tok.span.start, end),
                ))
            }
            TokenKind::Return => {
                let ret_tok = self.advance();
                let expr =
                    if !self.check(&TokenKind::Semicolon) && !self.check(&TokenKind::CloseBrace) {
                        Some(self.parse_expr()?)
                    } else {
                        None
                    };
                self.match_token(&TokenKind::Semicolon);
                let end = expr
                    .as_ref()
                    .map(|e| e.span.end)
                    .unwrap_or(ret_tok.span.end);
                Ok(Stmt::Return(
                    expr,
                    Span::new(self.file_id, ret_tok.span.start, end),
                ))
            }
            TokenKind::Fail => {
                let fail_tok = self.advance();
                let expr = self.parse_expr()?;
                self.match_token(&TokenKind::Semicolon);
                let end = expr.span.end;
                Ok(Stmt::Fail(
                    expr,
                    Span::new(self.file_id, fail_tok.span.start, end),
                ))
            }
            TokenKind::While => {
                let while_tok = self.advance();
                let cond = self.parse_expr()?;
                let body = self.parse_block()?;
                let end = body.span.end;
                Ok(Stmt::While {
                    cond,
                    body,
                    span: Span::new(self.file_id, while_tok.span.start, end),
                })
            }
            TokenKind::For => {
                let for_tok = self.advance();
                let var = match self.current().kind {
                    TokenKind::Ident(s) => {
                        self.advance();
                        s
                    }
                    _ => {
                        let c = self.current();
                        let diag = Diagnostic::error("nom de variable attendu après 'for'")
                            .with_primary_label(c.span, "identifiant attendu");
                        self.diagnostics.push(diag.clone());
                        return Err(diag);
                    }
                };
                self.expect(TokenKind::In)?;
                let iterable = self.parse_expr()?;
                let body = self.parse_block()?;
                let end = body.span.end;
                Ok(Stmt::For {
                    var,
                    iterable,
                    body,
                    span: Span::new(self.file_id, for_tok.span.start, end),
                })
            }
            TokenKind::Loop => {
                let loop_tok = self.advance();
                let body = self.parse_block()?;
                let end = body.span.end;
                Ok(Stmt::Loop(
                    body,
                    Span::new(self.file_id, loop_tok.span.start, end),
                ))
            }
            TokenKind::Break => {
                let tok = self.advance();
                self.match_token(&TokenKind::Semicolon);
                Ok(Stmt::Break(tok.span))
            }
            TokenKind::Continue => {
                let tok = self.advance();
                self.match_token(&TokenKind::Semicolon);
                Ok(Stmt::Continue(tok.span))
            }
            _ => {
                // Expression or Assignment
                let expr = self.parse_expr()?;

                let assign_op = if self.match_token(&TokenKind::Eq) {
                    Some(None)
                } else if self.match_token(&TokenKind::PlusEq) {
                    Some(Some(AssignOp::Add))
                } else if self.match_token(&TokenKind::MinusEq) {
                    Some(Some(AssignOp::Sub))
                } else if self.match_token(&TokenKind::StarEq) {
                    Some(Some(AssignOp::Mul))
                } else if self.match_token(&TokenKind::SlashEq) {
                    Some(Some(AssignOp::Div))
                } else if self.match_token(&TokenKind::PercentEq) {
                    Some(Some(AssignOp::Rem))
                } else if self.match_token(&TokenKind::CaretEq) {
                    Some(Some(AssignOp::BitXor))
                } else if self.match_token(&TokenKind::AmpersandEq) {
                    Some(Some(AssignOp::BitAnd))
                } else if self.match_token(&TokenKind::PipeEq) {
                    Some(Some(AssignOp::BitOr))
                } else if self.match_token(&TokenKind::ShlEq) {
                    Some(Some(AssignOp::Shl))
                } else if self.match_token(&TokenKind::ShrEq) {
                    Some(Some(AssignOp::Shr))
                } else {
                    None
                };

                if let Some(op) = assign_op {
                    let val = self.parse_expr()?;
                    self.match_token(&TokenKind::Semicolon);
                    let span = Span::new(self.file_id, expr.span.start, val.span.end);
                    Ok(Stmt::Assign {
                        target: expr,
                        op,
                        val,
                        span,
                    })
                } else {
                    self.match_token(&TokenKind::Semicolon);
                    Ok(Stmt::Expr(expr))
                }
            }
        }
    }

    // --- Expression Pratt Parsing ---

    pub fn parse_expr(&mut self) -> Result<Expr, Diagnostic> {
        self.parse_expr_precedence(0)
    }

    fn parse_expr_precedence(&mut self, min_prec: u8) -> Result<Expr, Diagnostic> {
        let mut left = self.parse_prefix()?;

        loop {
            let cur = self.current();
            let prec = match cur.kind {
                // Suffixes (100)
                TokenKind::Dot
                | TokenKind::QuestionDot
                | TokenKind::OpenParen
                | TokenKind::OpenBracket
                | TokenKind::Question => 100,

                // Multiplicative (80)
                TokenKind::Star | TokenKind::Slash | TokenKind::Percent => 80,

                // Additive (70)
                TokenKind::Plus | TokenKind::Minus => 70,

                // Shifts (60)
                TokenKind::Shl | TokenKind::Shr => 60,

                // Relational (50)
                TokenKind::EqEq
                | TokenKind::NotEq
                | TokenKind::Lt
                | TokenKind::LtEq
                | TokenKind::Gt
                | TokenKind::GtEq => 50,

                // Bitwise (40)
                TokenKind::Ampersand | TokenKind::Pipe | TokenKind::Caret => 40,

                // Logical (30 / 20)
                TokenKind::AndAnd => 30,
                TokenKind::OrOr => 20,

                // Coalescing & Catch (10)
                TokenKind::QuestionQuestion | TokenKind::Catch => 10,

                _ => break,
            };

            if prec < min_prec {
                break;
            }

            left = self.parse_infix(left, prec)?;
        }

        Ok(left)
    }

    fn parse_prefix(&mut self) -> Result<Expr, Diagnostic> {
        let cur = self.current();
        match cur.kind {
            TokenKind::IntLiteral(s) => {
                self.advance();
                Ok(Expr::new(ExprKind::Lit(Lit::Int(s)), cur.span))
            }
            TokenKind::FloatLiteral(s) => {
                self.advance();
                Ok(Expr::new(ExprKind::Lit(Lit::Float(s)), cur.span))
            }
            TokenKind::StringLiteral(s) => {
                self.advance();
                Ok(Expr::new(ExprKind::Lit(Lit::String(s)), cur.span))
            }
            TokenKind::CharLiteral(c) => {
                self.advance();
                Ok(Expr::new(ExprKind::Lit(Lit::Char(c)), cur.span))
            }
            TokenKind::True => {
                self.advance();
                Ok(Expr::new(ExprKind::Lit(Lit::Bool(true)), cur.span))
            }
            TokenKind::False => {
                self.advance();
                Ok(Expr::new(ExprKind::Lit(Lit::Bool(false)), cur.span))
            }
            TokenKind::Null => {
                self.advance();
                Ok(Expr::new(ExprKind::Lit(Lit::Null), cur.span))
            }
            TokenKind::OpenParen => {
                let open = self.advance();
                if self.match_token(&TokenKind::CloseParen) {
                    let span = Span::new(self.file_id, open.span.start, self.current().span.end);
                    Ok(Expr::new(ExprKind::Unit, span))
                } else {
                    let first = self.parse_expr()?;
                    if self.match_token(&TokenKind::Comma) {
                        let mut tuple_items = vec![first];
                        while !self.check(&TokenKind::CloseParen) && !self.check(&TokenKind::Eof) {
                            tuple_items.push(self.parse_expr()?);
                            if !self.match_token(&TokenKind::Comma) {
                                break;
                            }
                        }
                        let close = self.expect(TokenKind::CloseParen)?;
                        let span = Span::new(self.file_id, open.span.start, close.span.end);
                        Ok(Expr::new(ExprKind::Tuple(tuple_items), span))
                    } else {
                        let close = self.expect(TokenKind::CloseParen)?;
                        let span = Span::new(self.file_id, open.span.start, close.span.end);
                        Ok(Expr::new(first.kind, span))
                    }
                }
            }
            TokenKind::OpenBracket => {
                let open = self.advance();
                if self.match_token(&TokenKind::CloseBracket) {
                    let span = Span::new(self.file_id, open.span.start, self.current().span.end);
                    Ok(Expr::new(ExprKind::Array(Vec::new()), span))
                } else {
                    let first = self.parse_expr()?;
                    if self.match_token(&TokenKind::Semicolon) {
                        let count = self.parse_expr()?;
                        let close = self.expect(TokenKind::CloseBracket)?;
                        let span = Span::new(self.file_id, open.span.start, close.span.end);
                        Ok(Expr::new(
                            ExprKind::ArrayRepeat(Box::new(first), Box::new(count)),
                            span,
                        ))
                    } else {
                        let mut elems = vec![first];
                        while self.match_token(&TokenKind::Comma) {
                            if self.check(&TokenKind::CloseBracket) {
                                break;
                            }
                            elems.push(self.parse_expr()?);
                        }
                        let close = self.expect(TokenKind::CloseBracket)?;
                        let span = Span::new(self.file_id, open.span.start, close.span.end);
                        Ok(Expr::new(ExprKind::Array(elems), span))
                    }
                }
            }
            TokenKind::OpenBrace => {
                let is_record = if self.cursor + 2 < self.tokens.len() {
                    let next1 = &self.tokens[self.cursor + 1];
                    let next2 = &self.tokens[self.cursor + 2];
                    matches!(
                        next1.kind,
                        TokenKind::Ident(_) | TokenKind::StringLiteral(_)
                    ) && matches!(next2.kind, TokenKind::Colon)
                } else {
                    false
                };

                if is_record {
                    let open = self.advance();
                    let mut entries = Vec::new();
                    while !self.check(&TokenKind::CloseBrace) && !self.check(&TokenKind::Eof) {
                        let key = match self.current().kind {
                            TokenKind::Ident(s) | TokenKind::StringLiteral(s) => {
                                self.advance();
                                s
                            }
                            _ => break,
                        };
                        self.expect(TokenKind::Colon)?;
                        let val = self.parse_expr()?;
                        entries.push((key, val));
                        if !self.match_token(&TokenKind::Comma) {
                            break;
                        }
                    }
                    let close = self.expect(TokenKind::CloseBrace)?;
                    let span = Span::new(self.file_id, open.span.start, close.span.end);
                    Ok(Expr::new(ExprKind::Record(entries), span))
                } else {
                    let blk = self.parse_block()?;
                    let span = blk.span;
                    Ok(Expr::new(ExprKind::Block(blk), span))
                }
            }
            TokenKind::If => {
                let if_tok = self.advance();
                let cond = self.parse_expr()?;
                let then_branch = self.parse_block()?;
                let mut else_branch = None;
                let mut end_pos = then_branch.span.end;

                if self.match_token(&TokenKind::Else) {
                    if self.check(&TokenKind::If) {
                        let else_if = self.parse_expr()?;
                        end_pos = else_if.span.end;
                        else_branch = Some(Box::new(else_if));
                    } else {
                        let else_blk = self.parse_block()?;
                        end_pos = else_blk.span.end;
                        else_branch = Some(Box::new(Expr::new(
                            ExprKind::Block(else_blk),
                            Span::new(self.file_id, then_branch.span.end, end_pos),
                        )));
                    }
                }

                Ok(Expr::new(
                    ExprKind::If {
                        cond: Box::new(cond),
                        then_branch,
                        else_branch,
                    },
                    Span::new(self.file_id, if_tok.span.start, end_pos),
                ))
            }
            TokenKind::Match => {
                let match_tok = self.advance();
                let expr = self.parse_expr()?;
                self.expect(TokenKind::OpenBrace)?;
                let mut arms = Vec::new();

                while !self.check(&TokenKind::CloseBrace) && !self.check(&TokenKind::Eof) {
                    let pat_start = self.current().span.start;
                    let pattern = self.parse_pattern()?;

                    let guard = if self.match_token(&TokenKind::If) {
                        Some(self.parse_expr()?)
                    } else {
                        None
                    };

                    self.expect(TokenKind::FatArrow)?;
                    let body = self.parse_expr()?;
                    let arm_span = Span::new(self.file_id, pat_start, body.span.end);
                    arms.push(MatchArm {
                        pattern,
                        guard,
                        body,
                        span: arm_span,
                    });

                    self.match_token(&TokenKind::Comma);
                }

                let close = self.expect(TokenKind::CloseBrace)?;
                Ok(Expr::new(
                    ExprKind::Match {
                        expr: Box::new(expr),
                        arms,
                    },
                    Span::new(self.file_id, match_tok.span.start, close.span.end),
                ))
            }
            TokenKind::Select => {
                let select_tok = self.advance();
                self.expect(TokenKind::OpenBrace)?;
                let mut arms = Vec::new();

                while !self.check(&TokenKind::CloseBrace) && !self.check(&TokenKind::Eof) {
                    let arm_start = self.current().span.start;

                    // Optional 'case' keyword
                    if let TokenKind::Ident(s) = self.current().kind {
                        if s.as_str() == "case" {
                            self.advance();
                        }
                    }

                    if self.match_token(&TokenKind::Default) {
                        self.expect(TokenKind::FatArrow)?;
                        let body = self.parse_expr()?;
                        let arm_span = Span::new(self.file_id, arm_start, body.span.end);
                        arms.push(SelectArm {
                            pattern: None,
                            channel: None,
                            is_default: true,
                            body,
                            span: arm_span,
                        });
                    } else if self.match_token(&TokenKind::Let) {
                        let pattern = self.parse_pattern()?;
                        self.expect(TokenKind::Eq)?;
                        let channel = self.parse_expr()?;
                        self.expect(TokenKind::FatArrow)?;
                        let body = self.parse_expr()?;
                        let arm_span = Span::new(self.file_id, arm_start, body.span.end);
                        arms.push(SelectArm {
                            pattern: Some(pattern),
                            channel: Some(channel),
                            is_default: false,
                            body,
                            span: arm_span,
                        });
                    } else {
                        let expr = self.parse_expr()?;
                        if self.match_token(&TokenKind::Eq) {
                            let channel = self.parse_expr()?;
                            self.expect(TokenKind::FatArrow)?;
                            let body = self.parse_expr()?;
                            let arm_span = Span::new(self.file_id, arm_start, body.span.end);
                            let pat = match expr.kind {
                                ExprKind::Ident(sym) => Pattern::Ident(sym, expr.span),
                                _ => Pattern::Wildcard(expr.span),
                            };
                            arms.push(SelectArm {
                                pattern: Some(pat),
                                channel: Some(channel),
                                is_default: false,
                                body,
                                span: arm_span,
                            });
                        } else {
                            self.expect(TokenKind::FatArrow)?;
                            let body = self.parse_expr()?;
                            let arm_span = Span::new(self.file_id, arm_start, body.span.end);
                            arms.push(SelectArm {
                                pattern: None,
                                channel: Some(expr),
                                is_default: false,
                                body,
                                span: arm_span,
                            });
                        }
                    }

                    self.match_token(&TokenKind::Comma);
                }

                let close = self.expect(TokenKind::CloseBrace)?;
                Ok(Expr::new(
                    ExprKind::Select { arms },
                    Span::new(self.file_id, select_tok.span.start, close.span.end),
                ))
            }
            TokenKind::Spawn => {
                let spawn_tok = self.advance();
                let expr = self.parse_expr()?;
                let span = Span::new(self.file_id, spawn_tok.span.start, expr.span.end);
                Ok(Expr::new(ExprKind::Spawn(Box::new(expr)), span))
            }
            TokenKind::Comptime => {
                let comptime_tok = self.advance();
                let expr = self.parse_expr()?;
                let span = Span::new(self.file_id, comptime_tok.span.start, expr.span.end);
                Ok(Expr::new(ExprKind::Comptime(Box::new(expr)), span))
            }
            TokenKind::Fn => {
                // Anonymous lambda: fn(args) { body }
                let fn_tok = self.advance();
                self.expect(TokenKind::OpenParen)?;
                let mut params = Vec::new();
                while !self.check(&TokenKind::CloseParen) && !self.check(&TokenKind::Eof) {
                    if let TokenKind::Ident(s) = self.current().kind {
                        self.advance();
                        let ty = if self.match_token(&TokenKind::Colon) {
                            self.parse_type()?
                        } else {
                            Type {
                                kind: TypeKind::Named(sym("auto")),
                                span: cur.span,
                            }
                        };
                        params.push(Param {
                            mode: ParamMode::In,
                            name: s,
                            ty,
                            span: cur.span,
                        });
                    }
                    if !self.match_token(&TokenKind::Comma) {
                        break;
                    }
                }
                self.expect(TokenKind::CloseParen)?;
                let body = self.parse_block()?;
                let span = Span::new(self.file_id, fn_tok.span.start, body.span.end);
                Ok(Expr::new(ExprKind::Lambda { params, body }, span))
            }
            // Unary Prefix Ops: -, !, try, ref, inout, sink
            TokenKind::Minus
            | TokenKind::Bang
            | TokenKind::Try
            | TokenKind::Ref
            | TokenKind::InOut
            | TokenKind::Sink => {
                let op_tok = self.advance();
                let op = match op_tok.kind {
                    TokenKind::Minus => UnaryOp::Neg,
                    TokenKind::Bang => UnaryOp::Not,
                    TokenKind::Try => UnaryOp::Try,
                    TokenKind::Ref => UnaryOp::Ref,
                    TokenKind::InOut => UnaryOp::InOut,
                    TokenKind::Sink => UnaryOp::Sink,
                    _ => unreachable!(),
                };
                let operand = self.parse_expr_precedence(90)?;
                let span = Span::new(self.file_id, op_tok.span.start, operand.span.end);
                Ok(Expr::new(
                    ExprKind::Unary {
                        op,
                        expr: Box::new(operand),
                    },
                    span,
                ))
            }
            TokenKind::Ident(s) => {
                self.advance();
                // Check if path: Ident::Ident or StructInit Ident { ... }
                let mut path = vec![s];
                while self.match_token(&TokenKind::ColonColon) {
                    if let TokenKind::Ident(next_id) = self.current().kind {
                        self.advance();
                        path.push(next_id);
                    }
                }

                if path.len() > 1 {
                    Ok(Expr::new(ExprKind::Path(path), cur.span))
                } else {
                    Ok(Expr::new(ExprKind::Ident(s), cur.span))
                }
            }
            _ => {
                let diag =
                    Diagnostic::error(format!("expression attendue, mais trouvé '{}'", cur.kind))
                        .with_primary_label(cur.span, "expression attendue");
                self.diagnostics.push(diag.clone());
                Err(diag)
            }
        }
    }

    pub fn parse_pattern(&mut self) -> Result<Pattern, Diagnostic> {
        let _ = self.match_token(&TokenKind::Pipe);
        let first = self.parse_range_pattern()?;
        if self.check(&TokenKind::Pipe) {
            let mut pats = vec![first];
            while self.match_token(&TokenKind::Pipe) {
                pats.push(self.parse_range_pattern()?);
            }
            let span = Span::new(
                self.file_id,
                pats[0].span().start,
                pats.last().unwrap().span().end,
            );
            Ok(Pattern::Or(pats, span))
        } else {
            Ok(first)
        }
    }

    pub fn parse_range_pattern(&mut self) -> Result<Pattern, Diagnostic> {
        let cur = self.current();
        if self.match_token(&TokenKind::DotDotEq) {
            let end = self.parse_primary_pattern()?;
            let span = Span::new(self.file_id, cur.span.start, end.span().end);
            Ok(Pattern::Range {
                start: None,
                end: Some(Box::new(end)),
                inclusive: true,
                span,
            })
        } else if self.match_token(&TokenKind::DotDot) {
            let end = self.parse_primary_pattern()?;
            let span = Span::new(self.file_id, cur.span.start, end.span().end);
            Ok(Pattern::Range {
                start: None,
                end: Some(Box::new(end)),
                inclusive: false,
                span,
            })
        } else {
            let start = self.parse_primary_pattern()?;
            if self.match_token(&TokenKind::DotDotEq) {
                let end = self.parse_primary_pattern()?;
                let span = Span::new(self.file_id, start.span().start, end.span().end);
                Ok(Pattern::Range {
                    start: Some(Box::new(start)),
                    end: Some(Box::new(end)),
                    inclusive: true,
                    span,
                })
            } else if self.match_token(&TokenKind::DotDot) {
                let span_start = start.span().start;
                let has_end = !self.check(&TokenKind::FatArrow)
                    && !self.check(&TokenKind::Pipe)
                    && !self.check(&TokenKind::Comma)
                    && !self.check(&TokenKind::If)
                    && !self.check(&TokenKind::CloseBrace)
                    && !self.check(&TokenKind::CloseParen)
                    && !self.check(&TokenKind::Eof);
                if has_end {
                    let end = self.parse_primary_pattern()?;
                    let span = Span::new(self.file_id, span_start, end.span().end);
                    Ok(Pattern::Range {
                        start: Some(Box::new(start)),
                        end: Some(Box::new(end)),
                        inclusive: false,
                        span,
                    })
                } else {
                    let span = Span::new(
                        self.file_id,
                        span_start,
                        self.tokens[self.cursor - 1].span.end,
                    );
                    Ok(Pattern::Range {
                        start: Some(Box::new(start)),
                        end: None,
                        inclusive: false,
                        span,
                    })
                }
            } else {
                Ok(start)
            }
        }
    }

    pub fn parse_primary_pattern(&mut self) -> Result<Pattern, Diagnostic> {
        let cur = self.current();
        let pat_start = cur.span.start;
        match cur.kind {
            TokenKind::OpenBracket => {
                self.advance();
                if self.match_token(&TokenKind::CloseBracket) {
                    let span = Span::new(
                        self.file_id,
                        pat_start,
                        self.tokens[self.cursor - 1].span.end,
                    );
                    Ok(Pattern::Slice {
                        prefix: Vec::new(),
                        rest: None,
                        suffix: Vec::new(),
                        span,
                    })
                } else {
                    let mut prefix = Vec::new();
                    let mut rest: Option<Option<Box<Pattern>>> = None;
                    let mut suffix = Vec::new();

                    while !self.check(&TokenKind::CloseBracket) && !self.check(&TokenKind::Eof) {
                        if self.match_token(&TokenKind::DotDot) {
                            let dotdot_span = self.tokens[self.cursor - 1].span;
                            if rest.is_some() {
                                let diag = Diagnostic::error(
                                    "plus d'un motif de reste '..' dans un motif de tranche",
                                )
                                .with_code("E0046")
                                .with_primary_label(dotdot_span, "motif de reste en double");
                                self.diagnostics.push(diag.clone());
                                return Err(diag);
                            }

                            if !self.check(&TokenKind::Comma)
                                && !self.check(&TokenKind::CloseBracket)
                            {
                                let rest_pat = self.parse_primary_pattern()?;
                                rest = Some(Some(Box::new(rest_pat)));
                            } else {
                                rest = Some(None);
                            }
                        } else {
                            let elem_pat = self.parse_pattern()?;
                            if rest.is_some() {
                                suffix.push(elem_pat);
                            } else {
                                prefix.push(elem_pat);
                            }
                        }

                        if !self.match_token(&TokenKind::Comma) {
                            break;
                        }
                    }

                    let close = self.expect(TokenKind::CloseBracket)?;
                    let span = Span::new(self.file_id, pat_start, close.span.end);
                    Ok(Pattern::Slice {
                        prefix,
                        rest,
                        suffix,
                        span,
                    })
                }
            }
            TokenKind::OpenParen => {
                self.advance();
                if self.match_token(&TokenKind::CloseParen) {
                    let span = Span::new(
                        self.file_id,
                        pat_start,
                        self.tokens[self.cursor - 1].span.end,
                    );
                    Ok(Pattern::Tuple(Vec::new(), span))
                } else {
                    let mut elems = Vec::new();
                    elems.push(self.parse_pattern()?);
                    let mut has_trailing_comma = false;
                    while self.match_token(&TokenKind::Comma) {
                        has_trailing_comma = true;
                        if self.check(&TokenKind::CloseParen) {
                            break;
                        }
                        elems.push(self.parse_pattern()?);
                    }
                    let close = self.expect(TokenKind::CloseParen)?;
                    let span = Span::new(self.file_id, pat_start, close.span.end);
                    if elems.len() == 1 && !has_trailing_comma {
                        Ok(elems.into_iter().next().unwrap())
                    } else {
                        Ok(Pattern::Tuple(elems, span))
                    }
                }
            }
            TokenKind::Ident(s) => {
                self.advance();
                if s.as_str() == "_" {
                    Ok(Pattern::Wildcard(Span::new(
                        self.file_id,
                        pat_start,
                        cur.span.end,
                    )))
                } else {
                    let mut path = vec![s];
                    while self.match_token(&TokenKind::ColonColon) {
                        let next_tok = self.current();
                        match next_tok.kind {
                            TokenKind::Ident(next_sym) => {
                                self.advance();
                                path.push(next_sym);
                            }
                            _ => {
                                let diag = Diagnostic::error(
                                    "nom de variant ou de structure attendu après '::'",
                                )
                                .with_primary_label(next_tok.span, "identifiant attendu");
                                self.diagnostics.push(diag.clone());
                                return Err(diag);
                            }
                        }
                    }

                    if self.match_token(&TokenKind::OpenBrace) {
                        let mut fields = Vec::new();
                        let mut has_rest = false;
                        while !self.check(&TokenKind::CloseBrace) && !self.check(&TokenKind::Eof) {
                            if self.match_token(&TokenKind::DotDot) {
                                has_rest = true;
                                let _ = self.match_token(&TokenKind::Comma);
                                break;
                            }
                            let f_tok = self.current();
                            let f_name = match f_tok.kind {
                                TokenKind::Ident(name) => {
                                    self.advance();
                                    name
                                }
                                _ => {
                                    let diag = Diagnostic::error(
                                        "nom de champ ou '..' attendu dans le motif de structure",
                                    )
                                    .with_primary_label(f_tok.span, "nom de champ attendu");
                                    self.diagnostics.push(diag.clone());
                                    return Err(diag);
                                }
                            };
                            let (f_pat, f_end) = if self.match_token(&TokenKind::Colon) {
                                let pat = self.parse_pattern()?;
                                let end = pat.span().end;
                                (pat, end)
                            } else {
                                (Pattern::Ident(f_name, f_tok.span), f_tok.span.end)
                            };
                            fields.push(StructPatternField {
                                name: f_name,
                                pattern: f_pat,
                                span: Span::new(self.file_id, f_tok.span.start, f_end),
                            });
                            if !self.match_token(&TokenKind::Comma) {
                                break;
                            }
                        }
                        let close = self.expect(TokenKind::CloseBrace)?;
                        Ok(Pattern::Struct {
                            name: path,
                            fields,
                            has_rest,
                            span: Span::new(self.file_id, pat_start, close.span.end),
                        })
                    } else if self.match_token(&TokenKind::OpenParen) {
                        let inner_pat = self.parse_pattern()?;
                        let close = self.expect(TokenKind::CloseParen)?;
                        let (enum_name, variant) = if path.len() > 1 {
                            let v = path.pop().unwrap();
                            let e = path.pop();
                            (e, v)
                        } else {
                            (None, path[0])
                        };
                        Ok(Pattern::Variant {
                            enum_name,
                            variant,
                            inner: Some(Box::new(inner_pat)),
                            span: Span::new(self.file_id, pat_start, close.span.end),
                        })
                    } else if path.len() > 1 {
                        let v = path.pop().unwrap();
                        let e = path.pop();
                        let last_end = self.tokens[self.cursor - 1].span.end;
                        Ok(Pattern::Variant {
                            enum_name: e,
                            variant: v,
                            inner: None,
                            span: Span::new(self.file_id, pat_start, last_end),
                        })
                    } else {
                        Ok(Pattern::Ident(
                            s,
                            Span::new(self.file_id, pat_start, cur.span.end),
                        ))
                    }
                }
            }
            TokenKind::IntLiteral(s) => {
                self.advance();
                Ok(Pattern::Lit(
                    Lit::Int(s),
                    Span::new(self.file_id, pat_start, cur.span.end),
                ))
            }
            TokenKind::FloatLiteral(s) => {
                self.advance();
                Ok(Pattern::Lit(
                    Lit::Float(s),
                    Span::new(self.file_id, pat_start, cur.span.end),
                ))
            }
            TokenKind::StringLiteral(s) => {
                self.advance();
                Ok(Pattern::Lit(
                    Lit::String(s),
                    Span::new(self.file_id, pat_start, cur.span.end),
                ))
            }
            TokenKind::True => {
                self.advance();
                Ok(Pattern::Lit(
                    Lit::Bool(true),
                    Span::new(self.file_id, pat_start, cur.span.end),
                ))
            }
            TokenKind::False => {
                self.advance();
                Ok(Pattern::Lit(
                    Lit::Bool(false),
                    Span::new(self.file_id, pat_start, cur.span.end),
                ))
            }
            TokenKind::Null => {
                self.advance();
                Ok(Pattern::Lit(
                    Lit::Null,
                    Span::new(self.file_id, pat_start, cur.span.end),
                ))
            }
            TokenKind::Minus => {
                self.advance();
                let next_tok = self.current();
                match next_tok.kind {
                    TokenKind::IntLiteral(s) => {
                        self.advance();
                        let neg_s = INTERNER.intern(&format!("-{}", s.as_str()));
                        Ok(Pattern::Lit(
                            Lit::Int(neg_s),
                            Span::new(self.file_id, pat_start, next_tok.span.end),
                        ))
                    }
                    TokenKind::FloatLiteral(s) => {
                        self.advance();
                        let neg_s = INTERNER.intern(&format!("-{}", s.as_str()));
                        Ok(Pattern::Lit(
                            Lit::Float(neg_s),
                            Span::new(self.file_id, pat_start, next_tok.span.end),
                        ))
                    }
                    _ => {
                        let diag = Diagnostic::error("littéral numérique attendu après '-'")
                            .with_primary_label(next_tok.span, "littéral attendu");
                        self.diagnostics.push(diag.clone());
                        Err(diag)
                    }
                }
            }
            _ => {
                let diag = Diagnostic::error(format!("motif attendu, mais trouvé '{}'", cur.kind))
                    .with_primary_label(cur.span, "motif attendu");
                self.diagnostics.push(diag.clone());
                Err(diag)
            }
        }
    }

    fn parse_call_args(&mut self) -> Result<Vec<Arg>, Diagnostic> {
        self.expect(TokenKind::OpenParen)?;
        let mut args = Vec::new();
        while !self.check(&TokenKind::CloseParen) && !self.check(&TokenKind::Eof) {
            let start = self.current().span.start;
            let arg = if let TokenKind::Ident(name) = self.current().kind {
                if self.peek().kind == TokenKind::Colon {
                    self.advance(); // name
                    self.advance(); // ':'
                    let val = self.parse_expr()?;
                    let span = Span::new(self.file_id, start, val.span.end);
                    Arg::named(name, val, span)
                } else {
                    let val = self.parse_expr()?;
                    Arg::positional(val)
                }
            } else {
                let val = self.parse_expr()?;
                Arg::positional(val)
            };
            args.push(arg);
            if !self.match_token(&TokenKind::Comma) {
                break;
            }
        }
        self.expect(TokenKind::CloseParen)?;
        Ok(args)
    }

    fn parse_infix(&mut self, left: Expr, min_prec: u8) -> Result<Expr, Diagnostic> {
        let cur = self.current();
        match cur.kind {
            // Function Call: callee(args)
            TokenKind::OpenParen => {
                let args = self.parse_call_args()?;
                let end = self
                    .tokens
                    .get(self.cursor.saturating_sub(1))
                    .map(|t| t.span.end)
                    .unwrap_or(left.span.end);
                let span = Span::new(self.file_id, left.span.start, end);
                Ok(Expr::new(
                    ExprKind::Call {
                        callee: Box::new(left),
                        args,
                    },
                    span,
                ))
            }
            // Method Call or Field Access: expr.field, expr?.field, expr.method(args), expr?.method(args)
            TokenKind::Dot | TokenKind::QuestionDot => {
                let is_safe = cur.kind == TokenKind::QuestionDot;
                self.advance();
                let member = match self.current().kind {
                    TokenKind::Ident(s) => {
                        self.advance();
                        s
                    }
                    _ => {
                        let c = self.current();
                        let op_str = if is_safe { "?." } else { "." };
                        let diag =
                            Diagnostic::error(format!("nom de membre attendu après '{}'", op_str))
                                .with_primary_label(c.span, "identifiant attendu");
                        self.diagnostics.push(diag.clone());
                        return Err(diag);
                    }
                };

                if self.check(&TokenKind::OpenParen) {
                    let args = self.parse_call_args()?;
                    let end = self
                        .tokens
                        .get(self.cursor.saturating_sub(1))
                        .map(|t| t.span.end)
                        .unwrap_or(left.span.end);
                    let span = Span::new(self.file_id, left.span.start, end);
                    Ok(Expr::new(
                        ExprKind::MethodCall {
                            receiver: Box::new(left),
                            method: member,
                            args,
                            safe: is_safe,
                        },
                        span,
                    ))
                } else {
                    let end_pos = self.current().span.end;
                    let span = Span::new(self.file_id, left.span.start, end_pos);
                    Ok(Expr::new(
                        ExprKind::FieldAccess {
                            receiver: Box::new(left),
                            field: member,
                            safe: is_safe,
                        },
                        span,
                    ))
                }
            }
            // Array Index: expr[index]
            TokenKind::OpenBracket => {
                self.advance();
                let index = self.parse_expr()?;
                let close = self.expect(TokenKind::CloseBracket)?;
                let span = Span::new(self.file_id, left.span.start, close.span.end);
                Ok(Expr::new(
                    ExprKind::Index {
                        receiver: Box::new(left),
                        index: Box::new(index),
                    },
                    span,
                ))
            }
            // Postfix Try / Error Propagation Operator: expr?
            TokenKind::Question => {
                let q_tok = self.advance();
                let span = Span::new(self.file_id, left.span.start, q_tok.span.end);
                Ok(Expr::new(
                    ExprKind::Unary {
                        op: UnaryOp::Try,
                        expr: Box::new(left),
                    },
                    span,
                ))
            }
            // Catch Operator: expr catch err { ... }
            TokenKind::Catch => {
                self.advance();
                let err_var = if let TokenKind::Ident(s) = self.current().kind {
                    self.advance();
                    Some(s)
                } else {
                    None
                };
                let body = self.parse_block()?;
                let span = Span::new(self.file_id, left.span.start, body.span.end);
                Ok(Expr::new(
                    ExprKind::Catch {
                        expr: Box::new(left),
                        err_var,
                        body,
                    },
                    span,
                ))
            }
            // Binary Operators
            _ => {
                let op = match cur.kind {
                    TokenKind::Plus => BinOp::Add,
                    TokenKind::Minus => BinOp::Sub,
                    TokenKind::Star => BinOp::Mul,
                    TokenKind::Slash => BinOp::Div,
                    TokenKind::Percent => BinOp::Rem,
                    TokenKind::EqEq => BinOp::Eq,
                    TokenKind::NotEq => BinOp::NotEq,
                    TokenKind::Lt => BinOp::Lt,
                    TokenKind::LtEq => BinOp::LtEq,
                    TokenKind::Gt => BinOp::Gt,
                    TokenKind::GtEq => BinOp::GtEq,
                    TokenKind::AndAnd => BinOp::And,
                    TokenKind::OrOr => BinOp::Or,
                    TokenKind::Ampersand => BinOp::BitAnd,
                    TokenKind::Pipe => BinOp::BitOr,
                    TokenKind::Caret => BinOp::BitXor,
                    TokenKind::Shl => BinOp::Shl,
                    TokenKind::Shr => BinOp::Shr,
                    TokenKind::QuestionQuestion => BinOp::Coalesce,
                    _ => unreachable!(),
                };
                self.advance();
                let right = self.parse_expr_precedence(min_prec + 1)?;
                let span = Span::new(self.file_id, left.span.start, right.span.end);
                Ok(Expr::new(
                    ExprKind::Binary {
                        op,
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    span,
                ))
            }
        }
    }
}

pub fn parse(file_id: FileId, tokens: Vec<Token>) -> (Program, Vec<Diagnostic>) {
    let mut parser = Parser::new(file_id, tokens);
    parser.parse_program()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ifa_lexer::tokenize;

    #[test]
    fn test_parse_simple_function() {
        let src = r#"
            pub fn add(a: u32, inout b: u32) -> u32 {
                mut sum = a + b;
                return sum;
            }
        "#;
        let fid = FileId(0);
        let tokens = tokenize(fid, src);
        let (prog, diags) = parse(fid, tokens);

        assert!(diags.is_empty(), "Diagnostics: {:?}", diags);
        assert_eq!(prog.items.len(), 1);
        if let Item::Function(f) = &prog.items[0] {
            assert!(f.is_pub);
            assert_eq!(f.name, sym("add"));
            assert_eq!(f.params.len(), 2);
            assert_eq!(f.params[0].mode, ParamMode::In);
            assert_eq!(f.params[1].mode, ParamMode::InOut);
        } else {
            panic!("expected Function");
        }
    }

    #[test]
    fn test_parse_http_server_from_spec() {
        let src = r#"
            import std::io;
            import net::http;

            struct WindowNode {
                id: String,
                parent: ?ref WindowNode,
                children: List<WindowNode>
            }

            fn main() -> Result<(), io::Error> {
                let server = http::Server::bind("127.0.0.1:8080");
                return Ok(());
            }
        "#;
        let fid = FileId(0);
        let tokens = tokenize(fid, src);
        let (prog, diags) = parse(fid, tokens);

        assert!(diags.is_empty(), "Diagnostics: {:?}", diags);
        assert_eq!(prog.items.len(), 4); // 2 imports, 1 struct, 1 function
    }

    #[test]
    fn test_parse_catch_and_fail() {
        let src = r#"
            fn process() -> IoError!String {
                let payload = json::decode(req.body()) catch err {
                    fail "Invalid payload";
                };
                return payload;
            }
        "#;
        let fid = FileId(0);
        let tokens = tokenize(fid, src);
        let (prog, diags) = parse(fid, tokens);

        assert!(diags.is_empty(), "Diagnostics: {:?}", diags);
        assert_eq!(prog.items.len(), 1);
    }

    #[test]
    fn test_parse_try_and_question_operator() {
        let src = r#"
            fn process() -> IoError!String {
                let a = try read_file("a.txt");
                let b = read_file("b.txt")?;
                return a + b;
            }
        "#;
        let fid = FileId(0);
        let tokens = tokenize(fid, src);
        let (prog, diags) = parse(fid, tokens);

        assert!(diags.is_empty(), "Diagnostics: {:?}", diags);
        assert_eq!(prog.items.len(), 1);
    }

    #[test]
    fn test_parse_select_statement() {
        let src = r#"
            fn monitor(ch1: Channel, ch2: Channel) {
                select {
                    msg = ch1 => {
                        handle(msg);
                    },
                    let data = ch2 => {
                        process(data);
                    },
                    default => {
                        idle();
                    }
                }
            }
        "#;
        let fid = FileId(0);
        let tokens = tokenize(fid, src);
        let (prog, diags) = parse(fid, tokens);

        assert!(diags.is_empty(), "Diagnostics: {:?}", diags);
        assert_eq!(prog.items.len(), 1);
        if let Item::Function(f) = &prog.items[0] {
            let body = f.body.as_ref().unwrap();
            let expr = body
                .expr
                .as_deref()
                .or_else(|| {
                    body.stmts.first().and_then(|s| match s {
                        Stmt::Expr(e) => Some(e),
                        _ => None,
                    })
                })
                .expect("expected select expression");
            if let ExprKind::Select { arms } = &expr.kind {
                assert_eq!(arms.len(), 3);
                assert!(!arms[0].is_default);
                assert!(!arms[1].is_default);
                assert!(arms[2].is_default);
            } else {
                panic!("expected ExprKind::Select");
            }
        }
    }

    #[test]
    fn test_parse_safe_navigation_operator() {
        let src = r#"
            fn test_safe_nav(node: ?ref Node) {
                let v = node?.val;
                let child = node?.next?.child;
                let res = node?.compute(10);
            }
        "#;
        let fid = FileId(0);
        let tokens = tokenize(fid, src);
        let (prog, diags) = parse(fid, tokens);

        assert!(diags.is_empty(), "Diagnostics: {:?}", diags);
        assert_eq!(prog.items.len(), 1);
        if let Item::Function(f) = &prog.items[0] {
            let body = f.body.as_ref().unwrap();
            assert_eq!(body.stmts.len(), 3);
            if let Stmt::Let {
                init: Some(init_expr),
                ..
            } = &body.stmts[0]
            {
                assert!(matches!(
                    init_expr.kind,
                    ExprKind::FieldAccess { safe: true, .. }
                ));
            } else {
                panic!("expected let with safe FieldAccess");
            }
            if let Stmt::Let {
                init: Some(init_expr),
                ..
            } = &body.stmts[1]
            {
                if let ExprKind::FieldAccess {
                    safe: true,
                    receiver,
                    ..
                } = &init_expr.kind
                {
                    assert!(matches!(
                        receiver.kind,
                        ExprKind::FieldAccess { safe: true, .. }
                    ));
                } else {
                    panic!("expected nested safe FieldAccess");
                }
            } else {
                panic!("expected let with chained FieldAccess");
            }
            if let Stmt::Let {
                init: Some(init_expr),
                ..
            } = &body.stmts[2]
            {
                assert!(matches!(
                    init_expr.kind,
                    ExprKind::MethodCall { safe: true, .. }
                ));
            } else {
                panic!("expected let with safe MethodCall");
            }
        }
    }
}

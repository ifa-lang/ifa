//! Semantic Tokens provider (LSP 3.16 / 3.17) for rich syntax highlighting.

use crate::document::Document;
use crate::protocol::{SemanticTokens, SemanticTokensLegend};
use ifa_lexer::{tokenize, TokenKind};
use ifa_span::FileId;

pub fn get_semantic_tokens_legend() -> SemanticTokensLegend {
    SemanticTokensLegend {
        token_types: vec![
            "keyword".to_string(),   // 0
            "type".to_string(),      // 1
            "struct".to_string(),    // 2
            "enum".to_string(),      // 3
            "function".to_string(),  // 4
            "method".to_string(),    // 5
            "parameter".to_string(), // 6
            "variable".to_string(),  // 7
            "property".to_string(),  // 8
            "string".to_string(),    // 9
            "number".to_string(),    // 10
            "operator".to_string(),  // 11
            "comment".to_string(),   // 12
        ],
        token_modifiers: vec![
            "declaration".to_string(),    // 1
            "definition".to_string(),     // 2
            "readonly".to_string(),       // 4
            "defaultLibrary".to_string(), // 8
        ],
    }
}

struct RawSemanticToken {
    line: u32,
    character: u32,
    length: u32,
    token_type: u32,
    token_modifiers: u32,
}

pub fn handle_semantic_tokens(doc: &Document) -> SemanticTokens {
    let mut raw_tokens = Vec::new();
    let file_id = FileId(0);
    let tokens = tokenize(file_id, &doc.text);

    for tok in tokens {
        let range = doc.span_to_range(tok.span);
        let length = tok.span.len();
        if length == 0 {
            continue;
        }

        let (token_type, token_modifiers) = match tok.kind {
            // Keywords
            TokenKind::Fn
            | TokenKind::Let
            | TokenKind::Mut
            | TokenKind::Struct
            | TokenKind::Enum
            | TokenKind::Import
            | TokenKind::As
            | TokenKind::Pub
            | TokenKind::Type
            | TokenKind::Const
            | TokenKind::If
            | TokenKind::Else
            | TokenKind::Match
            | TokenKind::For
            | TokenKind::In
            | TokenKind::InOut
            | TokenKind::Sink
            | TokenKind::Strict
            | TokenKind::Comptime
            | TokenKind::Extern
            | TokenKind::Ref
            | TokenKind::While
            | TokenKind::Loop
            | TokenKind::Return
            | TokenKind::Defer
            | TokenKind::Break
            | TokenKind::Continue
            | TokenKind::Fail
            | TokenKind::Try
            | TokenKind::Catch
            | TokenKind::Spawn
            | TokenKind::Select
            | TokenKind::Default
            | TokenKind::Trait
            | TokenKind::Interface
            | TokenKind::Impl
            | TokenKind::True
            | TokenKind::False => (0, 0),

            // Number literals
            TokenKind::IntLiteral(_) | TokenKind::FloatLiteral(_) => (10, 0),

            // Strings and chars
            TokenKind::StringLiteral(_) | TokenKind::CharLiteral(_) => (9, 0),

            // Operators
            TokenKind::Arrow
            | TokenKind::FatArrow
            | TokenKind::QuestionQuestion
            | TokenKind::ColonColon
            | TokenKind::EqEq
            | TokenKind::NotEq
            | TokenKind::LtEq
            | TokenKind::GtEq
            | TokenKind::PlusEq
            | TokenKind::MinusEq
            | TokenKind::StarEq
            | TokenKind::SlashEq
            | TokenKind::PercentEq
            | TokenKind::CaretEq
            | TokenKind::AmpersandEq
            | TokenKind::PipeEq
            | TokenKind::ShlEq
            | TokenKind::ShrEq
            | TokenKind::AndAnd
            | TokenKind::OrOr
            | TokenKind::Shl
            | TokenKind::Shr
            | TokenKind::Plus
            | TokenKind::Minus
            | TokenKind::Star
            | TokenKind::Slash
            | TokenKind::Percent
            | TokenKind::Eq
            | TokenKind::Lt
            | TokenKind::Gt
            | TokenKind::Bang
            | TokenKind::Ampersand
            | TokenKind::Pipe
            | TokenKind::Caret
            | TokenKind::Question
            | TokenKind::Colon => (11, 0),

            // Identifiers: disambiguate using semantic analysis
            TokenKind::Ident(symbol) => {
                let name = symbol.resolve();
                if is_primitive_type(&name) {
                    (1, 8) // Type with defaultLibrary modifier
                } else if let Some(analysis) = &doc.analysis {
                    if analysis.symbols.functions.contains_key(&symbol) {
                        (4, 0) // Function
                    } else if analysis.symbols.structs.contains_key(&symbol) {
                        (2, 0) // Struct
                    } else if analysis.symbols.enums.contains_key(&symbol) {
                        (3, 0) // Enum
                    } else if analysis
                        .symbols
                        .structs
                        .values()
                        .any(|s| s.get_field(&symbol).is_some())
                    {
                        (8, 0) // Field/property
                    } else {
                        (7, 0) // Variable
                    }
                } else {
                    (7, 0) // Variable fallback
                }
            }

            TokenKind::OpenParen
            | TokenKind::CloseParen
            | TokenKind::OpenBracket
            | TokenKind::CloseBracket
            | TokenKind::OpenBrace
            | TokenKind::CloseBrace
            | TokenKind::Semicolon
            | TokenKind::Comma
            | TokenKind::Dot
            | TokenKind::Error
            | TokenKind::Eof => continue,
        };

        raw_tokens.push(RawSemanticToken {
            line: range.start.line,
            character: range.start.character,
            length,
            token_type,
            token_modifiers,
        });
    }

    // Sort tokens by (line, character)
    raw_tokens.sort_by_key(|a| (a.line, a.character));

    // Relative delta-encoding: [deltaLine, deltaStartChar, length, tokenType, tokenModifiers]
    let mut data = Vec::with_capacity(raw_tokens.len() * 5);
    let mut prev_line = 0;
    let mut prev_char = 0;

    for tok in raw_tokens {
        let delta_line = tok.line - prev_line;
        let delta_char = if delta_line == 0 {
            tok.character.saturating_sub(prev_char)
        } else {
            tok.character
        };

        data.push(delta_line);
        data.push(delta_char);
        data.push(tok.length);
        data.push(tok.token_type);
        data.push(tok.token_modifiers);

        prev_line = tok.line;
        prev_char = tok.character;
    }

    SemanticTokens {
        result_id: None,
        data,
    }
}

fn is_primitive_type(name: &str) -> bool {
    matches!(
        name,
        "int"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "float"
            | "f32"
            | "f64"
            | "bool"
            | "string"
            | "char"
            | "void"
            | "ref"
    )
}

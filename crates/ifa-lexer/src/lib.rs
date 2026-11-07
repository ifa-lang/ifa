pub mod token;

use ifa_span::{sym, BytePos, FileId, Span};
use logos::Logos;
pub use token::{RawToken, Token, TokenKind};

pub struct Lexer<'a> {
    file_id: FileId,
    src: &'a str,
    logos: logos::Lexer<'a, RawToken>,
}

impl<'a> Lexer<'a> {
    pub fn new(file_id: FileId, src: &'a str) -> Self {
        Self {
            file_id,
            src,
            logos: RawToken::lexer(src),
        }
    }

    pub fn tokenize(&mut self) -> Vec<Token> {
        let mut tokens = Vec::new();
        while let Some(res) = self.logos.next() {
            let span_range = self.logos.span();
            let start = BytePos(span_range.start as u32);
            let end = BytePos(span_range.end as u32);
            let span = Span::new(self.file_id, start, end);
            let slice = self.logos.slice();

            let kind = match res {
                Ok(raw) => match raw {
                    RawToken::Fn => TokenKind::Fn,
                    RawToken::Let => TokenKind::Let,
                    RawToken::Mut => TokenKind::Mut,
                    RawToken::Struct => TokenKind::Struct,
                    RawToken::Enum => TokenKind::Enum,
                    RawToken::Import => TokenKind::Import,
                    RawToken::As => TokenKind::As,
                    RawToken::Pub => TokenKind::Pub,
                    RawToken::Type => TokenKind::Type,
                    RawToken::Const => TokenKind::Const,
                    RawToken::If => TokenKind::If,
                    RawToken::Else => TokenKind::Else,
                    RawToken::Match => TokenKind::Match,
                    RawToken::For => TokenKind::For,
                    RawToken::In => TokenKind::In,
                    RawToken::InOut => TokenKind::InOut,
                    RawToken::Sink => TokenKind::Sink,
                    RawToken::Strict => TokenKind::Strict,
                    RawToken::Comptime => TokenKind::Comptime,
                    RawToken::Extern => TokenKind::Extern,
                    RawToken::Ref => TokenKind::Ref,
                    RawToken::While => TokenKind::While,
                    RawToken::Loop => TokenKind::Loop,
                    RawToken::Return => TokenKind::Return,
                    RawToken::Defer => TokenKind::Defer,
                    RawToken::Break => TokenKind::Break,
                    RawToken::Continue => TokenKind::Continue,
                    RawToken::Fail => TokenKind::Fail,
                    RawToken::Try => TokenKind::Try,
                    RawToken::Catch => TokenKind::Catch,
                    RawToken::Spawn => TokenKind::Spawn,
                    RawToken::Select => TokenKind::Select,
                    RawToken::Default => TokenKind::Default,
                    RawToken::Trait => TokenKind::Trait,
                    RawToken::Interface => TokenKind::Interface,
                    RawToken::Impl => TokenKind::Impl,
                    RawToken::True => TokenKind::True,
                    RawToken::False => TokenKind::False,
                    RawToken::Null => TokenKind::Null,

                    RawToken::Ident => TokenKind::Ident(sym(slice)),
                    RawToken::IntLiteral => TokenKind::IntLiteral(sym(slice)),
                    RawToken::FloatLiteral => TokenKind::FloatLiteral(sym(slice)),
                    RawToken::StringLiteral => {
                        let inner = if slice.len() >= 2 {
                            &slice[1..slice.len() - 1]
                        } else {
                            slice
                        };
                        TokenKind::StringLiteral(sym(inner))
                    }
                    RawToken::CharLiteral => {
                        let c = slice.chars().nth(1).unwrap_or('\0');
                        TokenKind::CharLiteral(c)
                    }

                    RawToken::Arrow => TokenKind::Arrow,
                    RawToken::FatArrow => TokenKind::FatArrow,
                    RawToken::QuestionQuestion => TokenKind::QuestionQuestion,
                    RawToken::QuestionDot => TokenKind::QuestionDot,
                    RawToken::ColonColon => TokenKind::ColonColon,
                    RawToken::EqEq => TokenKind::EqEq,
                    RawToken::NotEq => TokenKind::NotEq,
                    RawToken::LtEq => TokenKind::LtEq,
                    RawToken::GtEq => TokenKind::GtEq,
                    RawToken::PlusEq => TokenKind::PlusEq,
                    RawToken::MinusEq => TokenKind::MinusEq,
                    RawToken::StarEq => TokenKind::StarEq,
                    RawToken::SlashEq => TokenKind::SlashEq,
                    RawToken::PercentEq => TokenKind::PercentEq,
                    RawToken::CaretEq => TokenKind::CaretEq,
                    RawToken::AmpersandEq => TokenKind::AmpersandEq,
                    RawToken::PipeEq => TokenKind::PipeEq,
                    RawToken::ShlEq => TokenKind::ShlEq,
                    RawToken::ShrEq => TokenKind::ShrEq,
                    RawToken::AndAnd => TokenKind::AndAnd,
                    RawToken::OrOr => TokenKind::OrOr,
                    RawToken::Shl => TokenKind::Shl,
                    RawToken::Shr => TokenKind::Shr,

                    RawToken::Plus => TokenKind::Plus,
                    RawToken::Minus => TokenKind::Minus,
                    RawToken::Star => TokenKind::Star,
                    RawToken::Slash => TokenKind::Slash,
                    RawToken::Percent => TokenKind::Percent,
                    RawToken::Eq => TokenKind::Eq,
                    RawToken::Lt => TokenKind::Lt,
                    RawToken::Gt => TokenKind::Gt,
                    RawToken::Bang => TokenKind::Bang,
                    RawToken::Ampersand => TokenKind::Ampersand,
                    RawToken::Pipe => TokenKind::Pipe,
                    RawToken::Caret => TokenKind::Caret,
                    RawToken::Question => TokenKind::Question,
                    RawToken::Colon => TokenKind::Colon,
                    RawToken::Semicolon => TokenKind::Semicolon,
                    RawToken::Comma => TokenKind::Comma,
                    RawToken::DotDotEq => TokenKind::DotDotEq,
                    RawToken::DotDot => TokenKind::DotDot,
                    RawToken::Dot => TokenKind::Dot,

                    RawToken::OpenParen => TokenKind::OpenParen,
                    RawToken::CloseParen => TokenKind::CloseParen,
                    RawToken::OpenBracket => TokenKind::OpenBracket,
                    RawToken::CloseBracket => TokenKind::CloseBracket,
                    RawToken::OpenBrace => TokenKind::OpenBrace,
                    RawToken::CloseBrace => TokenKind::CloseBrace,
                },
                Err(_) => TokenKind::Error,
            };

            tokens.push(Token::new(kind, span));
        }

        let eof_pos = BytePos(self.src.len() as u32);
        tokens.push(Token::new(
            TokenKind::Eof,
            Span::new(self.file_id, eof_pos, eof_pos),
        ));
        tokens
    }
}

pub fn tokenize(file_id: FileId, src: &str) -> Vec<Token> {
    let mut lexer = Lexer::new(file_id, src);
    lexer.tokenize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use token::TokenKind;

    #[test]
    fn test_lex_keywords_and_modifiers() {
        let src = "fn let mut in inout sink ref strict comptime fail try catch spawn";
        let tokens = tokenize(FileId(0), src);
        let kinds: Vec<_> = tokens.iter().map(|t| t.kind).collect();

        assert_eq!(
            kinds,
            vec![
                TokenKind::Fn,
                TokenKind::Let,
                TokenKind::Mut,
                TokenKind::In,
                TokenKind::InOut,
                TokenKind::Sink,
                TokenKind::Ref,
                TokenKind::Strict,
                TokenKind::Comptime,
                TokenKind::Fail,
                TokenKind::Try,
                TokenKind::Catch,
                TokenKind::Spawn,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_lex_operators() {
        let src = "-> => ?? ?. :: == != <= >= && ||";
        let tokens = tokenize(FileId(0), src);
        let kinds: Vec<_> = tokens.iter().map(|t| t.kind).collect();

        assert_eq!(
            kinds,
            vec![
                TokenKind::Arrow,
                TokenKind::FatArrow,
                TokenKind::QuestionQuestion,
                TokenKind::QuestionDot,
                TokenKind::ColonColon,
                TokenKind::EqEq,
                TokenKind::NotEq,
                TokenKind::LtEq,
                TokenKind::GtEq,
                TokenKind::AndAnd,
                TokenKind::OrOr,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_lex_literals() {
        let src = r#"42 0xFF 3.14 "hello world" 'x'"#;
        let tokens = tokenize(FileId(0), src);
        assert_eq!(tokens[0].kind, TokenKind::IntLiteral(sym("42")));
        assert_eq!(tokens[1].kind, TokenKind::IntLiteral(sym("0xFF")));
        assert_eq!(tokens[2].kind, TokenKind::FloatLiteral(sym("3.14")));
        assert_eq!(tokens[3].kind, TokenKind::StringLiteral(sym("hello world")));
        assert_eq!(tokens[4].kind, TokenKind::CharLiteral('x'));
    }

    #[test]
    fn test_lex_ifa_spec_snippet() {
        let src = r#"
            // Server example
            strict fn compute(inout p: Payload, sink secret: Key) -> u32 {
                mut x = 10;
                return x;
            }
        "#;
        let tokens = tokenize(FileId(0), src);
        assert_eq!(tokens[0].kind, TokenKind::Strict);
        assert_eq!(tokens[1].kind, TokenKind::Fn);
        assert_eq!(tokens[2].kind, TokenKind::Ident(sym("compute")));
        assert_eq!(tokens[3].kind, TokenKind::OpenParen);
        assert_eq!(tokens[4].kind, TokenKind::InOut);
    }
}

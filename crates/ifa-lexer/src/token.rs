use ifa_span::{Span, Symbol};
use logos::Logos;
use std::fmt;

#[derive(Logos, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[logos(skip r"[ \t\r\n]+")]
#[logos(skip r"//[^\n]*")]
#[logos(skip r"/\*([^*]|\*[^/])*\*/")]
pub enum RawToken {
    // Keywords
    #[token("fn")]
    Fn,
    #[token("let")]
    Let,
    #[token("mut")]
    Mut,
    #[token("struct")]
    Struct,
    #[token("enum")]
    Enum,
    #[token("import")]
    Import,
    #[token("as")]
    As,
    #[token("pub")]
    Pub,
    #[token("type")]
    Type,
    #[token("const")]
    Const,
    #[token("if")]
    If,
    #[token("else")]
    Else,
    #[token("match")]
    Match,
    #[token("for")]
    For,
    #[token("in")]
    In,
    #[token("inout")]
    InOut,
    #[token("sink")]
    Sink,
    #[token("strict")]
    Strict,
    #[token("comptime")]
    Comptime,
    #[token("extern")]
    Extern,
    #[token("ref")]
    Ref,
    #[token("while")]
    While,
    #[token("loop")]
    Loop,
    #[token("return")]
    Return,
    #[token("defer")]
    Defer,
    #[token("break")]
    Break,
    #[token("continue")]
    Continue,
    #[token("fail")]
    Fail,
    #[token("try")]
    Try,
    #[token("catch")]
    Catch,
    #[token("spawn")]
    Spawn,
    #[token("trait")]
    Trait,
    #[token("interface")]
    Interface,
    #[token("impl")]
    Impl,
    #[token("true")]
    True,
    #[token("false")]
    False,

    // Identifiers
    #[regex(r"[a-zA-Z_][a-zA-Z0-9_]*")]
    Ident,

    // Numeric Literals
    #[regex(r"0x[0-9a-fA-F_]+([uif](8|16|32|64|size))?")]
    #[regex(r"0b[01_]+([uif](8|16|32|64|size))?")]
    #[regex(r"0o[0-7_]+([uif](8|16|32|64|size))?")]
    #[regex(r"[0-9][0-9_]*([uif](8|16|32|64|size))?")]
    IntLiteral,

    #[regex(r"[0-9][0-9_]*\.[0-9][0-9_]*([eE][+-]?[0-9_]+)?(f32|f64)?")]
    FloatLiteral,

    // String & Char Literals
    #[regex(r#""([^"\\]|\\.)*""#)]
    StringLiteral,

    #[regex(r"'([^'\\]|\\.)'")]
    CharLiteral,

    // Multi-char Operators
    #[token("->")]
    Arrow,
    #[token("=>")]
    FatArrow,
    #[token("??")]
    QuestionQuestion,
    #[token("::")]
    ColonColon,
    #[token("==")]
    EqEq,
    #[token("!=")]
    NotEq,
    #[token("<=")]
    LtEq,
    #[token(">=")]
    GtEq,
    #[token("+=")]
    PlusEq,
    #[token("-=")]
    MinusEq,
    #[token("*=")]
    StarEq,
    #[token("/=")]
    SlashEq,
    #[token("%=")]
    PercentEq,
    #[token("^=")]
    CaretEq,
    #[token("&=")]
    AmpersandEq,
    #[token("|=")]
    PipeEq,
    #[token("<<=")]
    ShlEq,
    #[token(">>=")]
    ShrEq,
    #[token("&&")]
    AndAnd,
    #[token("||")]
    OrOr,
    #[token("<<")]
    Shl,
    #[token(">>")]
    Shr,

    // Single-char Operators
    #[token("+")]
    Plus,
    #[token("-")]
    Minus,
    #[token("*")]
    Star,
    #[token("/")]
    Slash,
    #[token("%")]
    Percent,
    #[token("=")]
    Eq,
    #[token("<")]
    Lt,
    #[token(">")]
    Gt,
    #[token("!")]
    Bang,
    #[token("&")]
    Ampersand,
    #[token("|")]
    Pipe,
    #[token("^")]
    Caret,
    #[token("?")]
    Question,
    #[token(":")]
    Colon,
    #[token(";")]
    Semicolon,
    #[token(",")]
    Comma,
    #[token(".")]
    Dot,

    // Delimiters
    #[token("(")]
    OpenParen,
    #[token(")")]
    CloseParen,
    #[token("[")]
    OpenBracket,
    #[token("]")]
    CloseBracket,
    #[token("{")]
    OpenBrace,
    #[token("}")]
    CloseBrace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenKind {
    // Keywords
    Fn,
    Let,
    Mut,
    Struct,
    Enum,
    Import,
    As,
    Pub,
    Type,
    Const,
    If,
    Else,
    Match,
    For,
    In,
    InOut,
    Sink,
    Strict,
    Comptime,
    Extern,
    Ref,
    While,
    Loop,
    Return,
    Defer,
    Break,
    Continue,
    Fail,
    Try,
    Catch,
    Spawn,
    Trait,
    Interface,
    Impl,
    True,
    False,

    // Identifiers & Literals
    Ident(Symbol),
    IntLiteral(Symbol),
    FloatLiteral(Symbol),
    StringLiteral(Symbol),
    CharLiteral(char),

    // Multi-char Operators
    Arrow,
    FatArrow,
    QuestionQuestion,
    ColonColon,
    EqEq,
    NotEq,
    LtEq,
    GtEq,
    PlusEq,
    MinusEq,
    StarEq,
    SlashEq,
    PercentEq,
    CaretEq,
    AmpersandEq,
    PipeEq,
    ShlEq,
    ShrEq,
    AndAnd,
    OrOr,
    Shl,
    Shr,

    // Single-char Operators
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Eq,
    Lt,
    Gt,
    Bang,
    Ampersand,
    Pipe,
    Caret,
    Question,
    Colon,
    Semicolon,
    Comma,
    Dot,

    // Delimiters
    OpenParen,
    CloseParen,
    OpenBracket,
    CloseBracket,
    OpenBrace,
    CloseBrace,

    // Error & EOF
    Error,
    Eof,
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenKind::Fn => write!(f, "fn"),
            TokenKind::Let => write!(f, "let"),
            TokenKind::Mut => write!(f, "mut"),
            TokenKind::Struct => write!(f, "struct"),
            TokenKind::Enum => write!(f, "enum"),
            TokenKind::Import => write!(f, "import"),
            TokenKind::As => write!(f, "as"),
            TokenKind::Pub => write!(f, "pub"),
            TokenKind::Type => write!(f, "type"),
            TokenKind::Const => write!(f, "const"),
            TokenKind::If => write!(f, "if"),
            TokenKind::Else => write!(f, "else"),
            TokenKind::Match => write!(f, "match"),
            TokenKind::For => write!(f, "for"),
            TokenKind::In => write!(f, "in"),
            TokenKind::InOut => write!(f, "inout"),
            TokenKind::Sink => write!(f, "sink"),
            TokenKind::Strict => write!(f, "strict"),
            TokenKind::Comptime => write!(f, "comptime"),
            TokenKind::Extern => write!(f, "extern"),
            TokenKind::Ref => write!(f, "ref"),
            TokenKind::While => write!(f, "while"),
            TokenKind::Loop => write!(f, "loop"),
            TokenKind::Return => write!(f, "return"),
            TokenKind::Defer => write!(f, "defer"),
            TokenKind::Break => write!(f, "break"),
            TokenKind::Continue => write!(f, "continue"),
            TokenKind::Fail => write!(f, "fail"),
            TokenKind::Try => write!(f, "try"),
            TokenKind::Catch => write!(f, "catch"),
            TokenKind::Spawn => write!(f, "spawn"),
            TokenKind::Trait => write!(f, "trait"),
            TokenKind::Interface => write!(f, "interface"),
            TokenKind::Impl => write!(f, "impl"),
            TokenKind::True => write!(f, "true"),
            TokenKind::False => write!(f, "false"),

            TokenKind::Ident(s) => write!(f, "identifier '{}'", s),
            TokenKind::IntLiteral(s) => write!(f, "integer '{}'", s),
            TokenKind::FloatLiteral(s) => write!(f, "float '{}'", s),
            TokenKind::StringLiteral(s) => write!(f, "string '{}'", s),
            TokenKind::CharLiteral(c) => write!(f, "char '{}'", c),

            TokenKind::Arrow => write!(f, "->"),
            TokenKind::FatArrow => write!(f, "=>"),
            TokenKind::QuestionQuestion => write!(f, "??"),
            TokenKind::ColonColon => write!(f, "::"),
            TokenKind::EqEq => write!(f, "=="),
            TokenKind::NotEq => write!(f, "!="),
            TokenKind::LtEq => write!(f, "<="),
            TokenKind::GtEq => write!(f, ">="),
            TokenKind::PlusEq => write!(f, "+="),
            TokenKind::MinusEq => write!(f, "-="),
            TokenKind::StarEq => write!(f, "*="),
            TokenKind::SlashEq => write!(f, "/="),
            TokenKind::PercentEq => write!(f, "%="),
            TokenKind::CaretEq => write!(f, "^="),
            TokenKind::AmpersandEq => write!(f, "&="),
            TokenKind::PipeEq => write!(f, "|="),
            TokenKind::ShlEq => write!(f, "<<="),
            TokenKind::ShrEq => write!(f, ">>="),
            TokenKind::AndAnd => write!(f, "&&"),
            TokenKind::OrOr => write!(f, "||"),
            TokenKind::Shl => write!(f, "<<"),
            TokenKind::Shr => write!(f, ">>"),

            TokenKind::Plus => write!(f, "+"),
            TokenKind::Minus => write!(f, "-"),
            TokenKind::Star => write!(f, "*"),
            TokenKind::Slash => write!(f, "/"),
            TokenKind::Percent => write!(f, "%"),
            TokenKind::Eq => write!(f, "="),
            TokenKind::Lt => write!(f, "<"),
            TokenKind::Gt => write!(f, ">"),
            TokenKind::Bang => write!(f, "!"),
            TokenKind::Ampersand => write!(f, "&"),
            TokenKind::Pipe => write!(f, "|"),
            TokenKind::Caret => write!(f, "^"),
            TokenKind::Question => write!(f, "?"),
            TokenKind::Colon => write!(f, ":"),
            TokenKind::Semicolon => write!(f, ";"),
            TokenKind::Comma => write!(f, ","),
            TokenKind::Dot => write!(f, "."),

            TokenKind::OpenParen => write!(f, "("),
            TokenKind::CloseParen => write!(f, ")"),
            TokenKind::OpenBracket => write!(f, "["),
            TokenKind::CloseBracket => write!(f, "]"),
            TokenKind::OpenBrace => write!(f, "{{"),
            TokenKind::CloseBrace => write!(f, "}}"),

            TokenKind::Error => write!(f, "<error>"),
            TokenKind::Eof => write!(f, "<eof>"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

impl Token {
    pub fn new(kind: TokenKind, span: Span) -> Self {
        Self { kind, span }
    }

    pub fn dummy() -> Self {
        Self {
            kind: TokenKind::Eof,
            span: Span::DUMMY,
        }
    }
}

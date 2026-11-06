use lasso::{Spur, ThreadedRodeo};
use std::fmt;
use std::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct BytePos(pub u32);

impl BytePos {
    pub const ZERO: BytePos = BytePos(0);

    pub fn to_usize(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for BytePos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FileId(pub u32);

impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Span {
    pub file_id: FileId,
    pub start: BytePos,
    pub end: BytePos,
}

impl Span {
    pub const DUMMY: Span = Span {
        file_id: FileId(0),
        start: BytePos(0),
        end: BytePos(0),
    };

    pub fn new(file_id: FileId, start: BytePos, end: BytePos) -> Self {
        Self {
            file_id,
            start,
            end,
        }
    }

    pub fn len(self) -> u32 {
        self.end.0.saturating_sub(self.start.0)
    }

    pub fn is_empty(self) -> bool {
        self.start >= self.end
    }

    pub fn contains(self, pos: BytePos) -> bool {
        self.start <= pos && pos < self.end
    }

    pub fn merge(self, other: Span) -> Span {
        if self.file_id != other.file_id {
            return self;
        }
        let start = std::cmp::min(self.start, other.start);
        let end = std::cmp::max(self.end, other.end);
        Span {
            file_id: self.file_id,
            start,
            end,
        }
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..{}", self.start.0, self.end.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spanned<T> {
    pub node: T,
    pub span: Span,
}

impl<T> Spanned<T> {
    pub fn new(node: T, span: Span) -> Self {
        Self { node, span }
    }

    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Spanned<U> {
        Spanned {
            node: f(self.node),
            span: self.span,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SourceFile {
    pub id: FileId,
    pub name: String,
    pub src: String,
    pub line_starts: Vec<usize>,
}

impl SourceFile {
    pub fn new(id: FileId, name: String, src: String) -> Self {
        let mut line_starts = vec![0];
        for (idx, byte) in src.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(idx + 1);
            }
        }
        Self {
            id,
            name,
            src,
            line_starts,
        }
    }

    pub fn lookup_line_col(&self, pos: BytePos) -> (usize, usize) {
        let offset = pos.to_usize();
        let line_idx = match self.line_starts.binary_search(&offset) {
            Ok(idx) => idx,
            Err(idx) => idx.saturating_sub(1),
        };
        let line_start = self.line_starts.get(line_idx).copied().unwrap_or(0);
        let col = offset.saturating_sub(line_start) + 1;
        (line_idx + 1, col)
    }

    pub fn get_line_slice(&self, line: usize) -> Option<&str> {
        if line == 0 || line > self.line_starts.len() {
            return None;
        }
        let start = self.line_starts[line - 1];
        let end = if line < self.line_starts.len() {
            self.line_starts[line].saturating_sub(1)
        } else {
            self.src.len()
        };
        self.src.get(start..end)
    }
}

#[derive(Debug, Default)]
pub struct SourceMap {
    files: Vec<SourceFile>,
}

impl SourceMap {
    pub fn new() -> Self {
        Self { files: Vec::new() }
    }

    pub fn add_file(&mut self, name: impl Into<String>, src: impl Into<String>) -> FileId {
        let id = FileId(self.files.len() as u32);
        let file = SourceFile::new(id, name.into(), src.into());
        self.files.push(file);
        id
    }

    pub fn get_file(&self, id: FileId) -> Option<&SourceFile> {
        self.files.get(id.0 as usize)
    }

    pub fn lookup_line_col(&self, span: Span) -> Option<(usize, usize)> {
        let file = self.get_file(span.file_id)?;
        Some(file.lookup_line_col(span.start))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Symbol(pub Spur);

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", INTERNER.resolve(self))
    }
}

pub struct Interner {
    rodeo: RwLock<ThreadedRodeo>,
}

impl Interner {
    pub fn new() -> Self {
        Self {
            rodeo: RwLock::new(ThreadedRodeo::new()),
        }
    }

    pub fn intern(&self, text: &str) -> Symbol {
        let rodeo = self.rodeo.read().unwrap();
        Symbol(rodeo.get_or_intern(text))
    }

    pub fn resolve(&self, symbol: &Symbol) -> String {
        let rodeo = self.rodeo.read().unwrap();
        rodeo.resolve(&symbol.0).to_string()
    }
}

impl Default for Interner {
    fn default() -> Self {
        Self::new()
    }
}

lazy_static::lazy_static! {
    pub static ref INTERNER: Interner = Interner::new();
}

pub fn sym(text: &str) -> Symbol {
    INTERNER.intern(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_span_merge() {
        let f = FileId(1);
        let s1 = Span::new(f, BytePos(5), BytePos(10));
        let s2 = Span::new(f, BytePos(8), BytePos(20));
        let merged = s1.merge(s2);
        assert_eq!(merged.start, BytePos(5));
        assert_eq!(merged.end, BytePos(20));
        assert_eq!(merged.len(), 15);
    }

    #[test]
    fn test_source_map_lines() {
        let mut sm = SourceMap::new();
        let src = "fn main() {\n    let a = 42;\n}\n";
        let fid = sm.add_file("test.ifa", src);
        let file = sm.get_file(fid).unwrap();

        // Start of second line: "    let..."
        let (line, col) = file.lookup_line_col(BytePos(12));
        assert_eq!(line, 2);
        assert_eq!(col, 1);
    }

    #[test]
    fn test_symbol_interning() {
        let s1 = sym("my_identifier");
        let s2 = sym("my_identifier");
        let s3 = sym("other_identifier");
        assert_eq!(s1, s2);
        assert_ne!(s1, s3);
        assert_eq!(s1.to_string(), "my_identifier");
    }
}

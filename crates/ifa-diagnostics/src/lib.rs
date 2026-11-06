use ariadne::{Color, Label as AriadneLabel, Report, ReportKind, Source};
use ifa_span::{SourceMap, Span};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    Note,
    Help,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Error => write!(f, "error"),
            Severity::Warning => write!(f, "warning"),
            Severity::Note => write!(f, "note"),
            Severity::Help => write!(f, "help"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub span: Span,
    pub message: String,
    pub is_primary: bool,
}

impl Label {
    pub fn primary(span: Span, message: impl Into<String>) -> Self {
        Self {
            span,
            message: message.into(),
            is_primary: true,
        }
    }

    pub fn secondary(span: Span, message: impl Into<String>) -> Self {
        Self {
            span,
            message: message.into(),
            is_primary: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: Option<String>,
    pub message: String,
    pub labels: Vec<Label>,
    pub notes: Vec<String>,
    pub helps: Vec<String>,
}

impl Diagnostic {
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            code: None,
            message: message.into(),
            labels: Vec::new(),
            notes: Vec::new(),
            helps: Vec::new(),
        }
    }

    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            code: None,
            message: message.into(),
            labels: Vec::new(),
            notes: Vec::new(),
            helps: Vec::new(),
        }
    }

    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }

    pub fn with_label(mut self, label: Label) -> Self {
        self.labels.push(label);
        self
    }

    pub fn with_primary_label(self, span: Span, message: impl Into<String>) -> Self {
        self.with_label(Label::primary(span, message))
    }

    pub fn with_secondary_label(self, span: Span, message: impl Into<String>) -> Self {
        self.with_label(Label::secondary(span, message))
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.helps.push(help.into());
        self
    }

    pub fn render_to_string(&self, source_map: &SourceMap) -> String {
        let first_label = self.labels.first();
        let (file_name, file_src, start_offset) = if let Some(lbl) = first_label {
            if let Some(src_file) = source_map.get_file(lbl.span.file_id) {
                (
                    src_file.name.clone(),
                    src_file.src.clone(),
                    lbl.span.start.to_usize(),
                )
            } else {
                ("<unknown>".to_string(), String::new(), 0)
            }
        } else {
            ("<unknown>".to_string(), String::new(), 0)
        };

        let kind = match self.severity {
            Severity::Error => ReportKind::Error,
            Severity::Warning => ReportKind::Warning,
            Severity::Note => ReportKind::Advice,
            Severity::Help => ReportKind::Advice,
        };

        let mut builder = Report::build(kind, &file_name, start_offset).with_message(&self.message);

        if let Some(code) = &self.code {
            builder = builder.with_code(code);
        }

        for lbl in &self.labels {
            if let Some(src_file) = source_map.get_file(lbl.span.file_id) {
                let range = (
                    &src_file.name,
                    lbl.span.start.to_usize()..lbl.span.end.to_usize(),
                );
                let color = if lbl.is_primary {
                    match self.severity {
                        Severity::Error => Color::Red,
                        Severity::Warning => Color::Yellow,
                        _ => Color::Cyan,
                    }
                } else {
                    Color::Blue
                };

                let ariadne_label = AriadneLabel::new(range)
                    .with_message(&lbl.message)
                    .with_color(color);

                builder = builder.with_label(ariadne_label);
            }
        }

        for note in &self.notes {
            builder = builder.with_note(note);
        }

        for help in &self.helps {
            builder = builder.with_help(help);
        }

        let report = builder.finish();
        let mut buffer = Vec::new();
        let source = Source::from(&file_src);
        let _ = report.write((&file_name, source), &mut buffer);
        String::from_utf8_lossy(&buffer).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ifa_span::{BytePos, FileId, Span};

    #[test]
    fn test_diagnostic_creation() {
        let span = Span::new(FileId(0), BytePos(0), BytePos(10));
        let diag = Diagnostic::error("syntax error: unexpected token")
            .with_code("E001")
            .with_primary_label(span, "expected ';' here")
            .with_note("declarations must end with semicolon");

        assert_eq!(diag.severity, Severity::Error);
        assert_eq!(diag.code.as_deref(), Some("E001"));
        assert_eq!(diag.labels.len(), 1);
        assert_eq!(diag.notes.len(), 1);
    }
}

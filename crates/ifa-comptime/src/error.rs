use ifa_diagnostics::Diagnostic;
use ifa_span::Span;
use std::fmt;

/// Categories of errors that can occur during compile-time evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum ComptimeErrorKind {
    DivisionByZero,
    ModuloByZero,
    IndexOutOfBounds {
        index: i64,
        len: usize,
    },
    FieldNotFound {
        struct_name: String,
        field: String,
    },
    UndefinedVariable(String),
    UndefinedFunction(String),
    TypeMismatch {
        expected: String,
        found: String,
    },
    InvalidUnaryOp {
        op: String,
        operand: String,
    },
    InvalidBinaryOp {
        op: String,
        left: String,
        right: String,
    },
    GasLimitExceeded {
        limit: u64,
    },
    MemoryLimitExceeded {
        limit_bytes: usize,
        requested_bytes: usize,
    },
    CallStackOverflow {
        max_depth: usize,
    },
    AssertionFailed(String),
    CompileError(String),
    EmptyStack,
    NotAFunction(String),
    ArityMismatch {
        expected: usize,
        found: usize,
    },
    InvalidAssignmentTarget,
    ArrayRepeatNegativeCount(i64),
    RecursiveStructureEscape {
        struct_name: String,
    },
    MutableClosureArenaEscape {
        closure_name: String,
        arena_name: String,
    },
}

impl fmt::Display for ComptimeErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComptimeErrorKind::DivisionByZero => {
                write!(f, "division par zéro lors de l'évaluation comptime")
            }
            ComptimeErrorKind::ModuloByZero => {
                write!(f, "modulo par zéro lors de l'évaluation comptime")
            }
            ComptimeErrorKind::IndexOutOfBounds { index, len } => {
                write!(
                    f,
                    "index hors limites lors de l'évaluation comptime : index {} pour une taille de {}",
                    index, len
                )
            }
            ComptimeErrorKind::FieldNotFound { struct_name, field } => {
                write!(
                    f,
                    "champ '{}' introuvable dans la structure '{}' lors de l'évaluation comptime",
                    field, struct_name
                )
            }
            ComptimeErrorKind::UndefinedVariable(name) => {
                write!(f, "variable inconnue '{}' dans le contexte comptime", name)
            }
            ComptimeErrorKind::UndefinedFunction(name) => {
                write!(f, "fonction inconnue '{}' dans le contexte comptime", name)
            }
            ComptimeErrorKind::TypeMismatch { expected, found } => {
                write!(
                    f,
                    "incompatibilité de type comptime : attendu {}, trouvé {}",
                    expected, found
                )
            }
            ComptimeErrorKind::InvalidUnaryOp { op, operand } => {
                write!(
                    f,
                    "opération unaire '{}' non supportée sur le type '{}' en comptime",
                    op, operand
                )
            }
            ComptimeErrorKind::InvalidBinaryOp { op, left, right } => {
                write!(
                    f,
                    "opération binaire '{}' non supportée entre '{}' et '{}' en comptime",
                    op, left, right
                )
            }
            ComptimeErrorKind::GasLimitExceeded { limit } => {
                write!(
                    f,
                    "dépassement du quota d'instructions comptime (limite: {} étapes, boucle infinie suspectée)",
                    limit
                )
            }
            ComptimeErrorKind::MemoryLimitExceeded {
                limit_bytes,
                requested_bytes,
            } => {
                write!(
                    f,
                    "dépassement du quota de mémoire comptime (limite: {} octets, demandé: {} octets)",
                    limit_bytes, requested_bytes
                )
            }
            ComptimeErrorKind::CallStackOverflow { max_depth } => {
                write!(
                    f,
                    "débordement de pile d'appels comptime (profondeur maximale de {} atteinte)",
                    max_depth
                )
            }
            ComptimeErrorKind::AssertionFailed(msg) => {
                write!(f, "échec de l'assertion comptime : {}", msg)
            }
            ComptimeErrorKind::CompileError(msg) => {
                write!(
                    f,
                    "erreur explicite lors de l'évaluation comptime : {}",
                    msg
                )
            }
            ComptimeErrorKind::EmptyStack => {
                write!(
                    f,
                    "pile de la machine virtuelle comptime vide de manière inattendue"
                )
            }
            ComptimeErrorKind::NotAFunction(name) => {
                write!(f, "'{}' n'est pas une fonction appelable en comptime", name)
            }
            ComptimeErrorKind::ArityMismatch { expected, found } => {
                write!(
                    f,
                    "nombre d'arguments incorrect : {} attendu(s), {} fourni(s)",
                    expected, found
                )
            }
            ComptimeErrorKind::InvalidAssignmentTarget => {
                write!(f, "cible d'affectation invalide dans l'expression comptime")
            }
            ComptimeErrorKind::ArrayRepeatNegativeCount(c) => {
                write!(
                    f,
                    "taille de répétition de tableau négative ({}) en comptime",
                    c
                )
            }
            ComptimeErrorKind::RecursiveStructureEscape { struct_name } => {
                write!(
                    f,
                    "violation d'évasion comptime : tentative d'évasion de la structure récursive '{}' allouée dans l'arène isolée hors du contexte comptime",
                    struct_name
                )
            }
            ComptimeErrorKind::MutableClosureArenaEscape {
                closure_name,
                arena_name,
            } => {
                write!(
                    f,
                    "violation d'évasion comptime : tentative d'évasion d'une fermeture mutable '{}' capturant l'arène isolée '{}' hors du contexte comptime",
                    closure_name, arena_name
                )
            }
        }
    }
}

/// Represents an error produced by the compile-time bytecode VM, tagged with a source span.
#[derive(Debug, Clone, PartialEq)]
pub struct ComptimeError {
    pub kind: ComptimeErrorKind,
    pub span: Span,
}

impl ComptimeError {
    pub fn new(kind: ComptimeErrorKind, span: Span) -> Self {
        Self { kind, span }
    }

    /// Converts this compile-time evaluation error into an Ariadne diagnostic report.
    pub fn to_diagnostic(&self) -> Diagnostic {
        let code = match &self.kind {
            ComptimeErrorKind::RecursiveStructureEscape { .. } => "E0028",
            ComptimeErrorKind::MutableClosureArenaEscape { .. } => "E0029",
            ComptimeErrorKind::DivisionByZero | ComptimeErrorKind::ModuloByZero => "E0030",
            ComptimeErrorKind::IndexOutOfBounds { .. } => "E0031",
            ComptimeErrorKind::FieldNotFound { .. } => "E0032",
            ComptimeErrorKind::UndefinedVariable(_) => "E0033",
            ComptimeErrorKind::UndefinedFunction(_) => "E0034",
            ComptimeErrorKind::TypeMismatch { .. } => "E0035",
            ComptimeErrorKind::GasLimitExceeded { .. } => "E0036",
            ComptimeErrorKind::MemoryLimitExceeded { .. } => "E0041",
            ComptimeErrorKind::CallStackOverflow { .. } => "E0037",
            ComptimeErrorKind::AssertionFailed(_) => "E0038",
            ComptimeErrorKind::CompileError(_) => "E0039",
            _ => "E0040",
        };

        let msg = self.kind.to_string();
        Diagnostic::error(&msg)
            .with_code(code)
            .with_primary_label(self.span, &msg)
    }
}

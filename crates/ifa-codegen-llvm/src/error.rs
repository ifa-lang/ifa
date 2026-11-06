use thiserror::Error;

/// Errors that can occur during LLVM IR generation and compilation.
#[derive(Debug, Error)]
pub enum LlvmCodegenError {
    #[error("I/O error during LLVM code generation: {0}")]
    Io(#[from] std::io::Error),

    #[error("Target configuration error: {0}")]
    Target(String),

    #[error("Type translation error: {0}")]
    Type(String),

    #[error("Translation error in function `{function}`: {message}")]
    Translation { function: String, message: String },

    #[error("External LLVM toolchain error: {0}")]
    Toolchain(String),
}

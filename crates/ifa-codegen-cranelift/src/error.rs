use thiserror::Error;

/// Errors arising during Cranelift code generation, JIT compilation, or native object linking.
#[derive(Debug, Error)]
pub enum CodegenError {
    #[error("Cranelift module error: {0}")]
    Module(String),

    #[error("Cranelift codegen error: {0}")]
    Codegen(String),

    #[error("Function not found: {0}")]
    FunctionNotFound(String),

    #[error("Type unsupported in native code generation: {0}")]
    UnsupportedType(String),

    #[error("Instruction unsupported in native code generation: {0}")]
    UnsupportedInstruction(String),

    #[error("Native link error: {0}")]
    LinkError(String),

    #[error("I/O error during artifact generation: {0}")]
    Io(#[from] std::io::Error),
}

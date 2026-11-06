//! LLVM production optimizing code generation backend for the IFA programming language.

pub mod compiler;
pub mod error;
pub mod ir_emitter;
pub mod target;
pub mod types;

pub use compiler::LlvmCompiler;
pub use error::LlvmCodegenError;
pub use ir_emitter::LlvmIrEmitter;
pub use target::{LlvmTargetConfig, TargetArch};
pub use types::fir_to_llvm_type;

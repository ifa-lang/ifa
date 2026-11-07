//! Cranelift code generation backend for the IFA compiler.
//!
//! Provides both fast In-Memory JIT execution (`ifa run --native`) and
//! Ahead-of-Time native object compilation (`ifa build`).

pub mod aot;
pub mod error;
pub mod jit;
pub mod translator;
pub mod types;

pub use aot::{AotCompiler, RUNTIME_STUB_C};
pub use error::CodegenError;
pub use jit::JitEngine;
pub use translator::FunctionTranslator;
pub use types::{fir_signature_to_cranelift, fir_type_to_cranelift};

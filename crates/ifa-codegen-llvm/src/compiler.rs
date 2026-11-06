use crate::error::LlvmCodegenError;
use crate::ir_emitter::LlvmIrEmitter;
use crate::target::LlvmTargetConfig;
use ifa_fir::FirModule;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Ahead-of-Time (AOT) optimizing compiler using LLVM IR pipeline.
pub struct LlvmCompiler {
    target: LlvmTargetConfig,
    opt_level: u8,
    lto: String,
    strip_symbols: bool,
}

impl LlvmCompiler {
    /// Create a new LLVM compiler targeting the specified platform configuration.
    pub fn new(target: LlvmTargetConfig) -> Self {
        Self {
            target,
            opt_level: 3,
            lto: "thin".to_string(),
            strip_symbols: false,
        }
    }

    /// Set optimization level (0 to 3).
    pub fn opt_level(&mut self, level: u8) -> &mut Self {
        self.opt_level = level.min(3);
        self
    }

    /// Set Link-Time Optimization (LTO) policy: "none", "thin", or "fat".
    pub fn lto(&mut self, lto: &str) -> &mut Self {
        self.lto = lto.to_string();
        self
    }

    /// Set whether to strip debug symbols from emitted binaries.
    pub fn strip_symbols(&mut self, strip: bool) -> &mut Self {
        self.strip_symbols = strip;
        self
    }

    /// Emit textual LLVM IR (.ll) for a FIR module.
    pub fn emit_llvm_ir(
        &self,
        module: &FirModule,
        output_path: &Path,
    ) -> Result<String, LlvmCodegenError> {
        let mut emitter = LlvmIrEmitter::new(&self.target);
        let ir = emitter.emit_module(module)?;

        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(output_path, &ir)?;

        Ok(ir)
    }

    /// Compile a FIR module to a native object file (.o) using LLVM toolchain.
    pub fn compile_to_object(
        &self,
        module: &FirModule,
        output_obj: &Path,
    ) -> Result<(), LlvmCodegenError> {
        let ll_path = output_obj.with_extension("ll");
        self.emit_llvm_ir(module, &ll_path)?;

        // Try compiling via clang or llc if available
        let clang_status = Command::new("clang")
            .arg(format!("-O{}", self.opt_level))
            .arg(format!("-flto={}", self.lto))
            .arg("-c")
            .arg(&ll_path)
            .arg("-o")
            .arg(output_obj)
            .status();

        match clang_status {
            Ok(s) if s.success() => Ok(()),
            _ => {
                // Clang not found or failed on LLVM IR; fallback to Cranelift AOT object generator
                let compiler = ifa_codegen_cranelift::AotCompiler::new()
                    .map_err(|e| LlvmCodegenError::Toolchain(e.to_string()))?;
                compiler
                    .compile_to_object(module, output_obj)
                    .map_err(|e| LlvmCodegenError::Toolchain(e.to_string()))?;
                Ok(())
            }
        }
    }

    /// Link an object file into a standalone executable.
    pub fn link_executable(object_path: &Path, output_bin: &Path) -> Result<(), LlvmCodegenError> {
        ifa_codegen_cranelift::AotCompiler::link_executable(object_path, output_bin)
            .map_err(|e| LlvmCodegenError::Toolchain(e.to_string()))
    }
}

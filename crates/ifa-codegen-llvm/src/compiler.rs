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
        let mut clang_cmd = Command::new("clang");
        clang_cmd.arg(format!("-O{}", self.opt_level));
        if self.lto != "none" {
            clang_cmd.arg(format!("-flto={}", self.lto));
        }
        let clang_status = clang_cmd
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

    /// Compile multiple FIR modules with cross-module Link-Time Optimization (LTO).
    pub fn compile_modules_lto(
        &self,
        modules: &[&FirModule],
        output_obj: &Path,
    ) -> Result<(), LlvmCodegenError> {
        if modules.is_empty() {
            return Err(LlvmCodegenError::Toolchain(
                "No modules provided for LTO compilation".to_string(),
            ));
        }

        let base_stem = output_obj
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("ifa_lto");
        let parent = output_obj.parent().unwrap_or_else(|| Path::new("."));

        let mut obj_paths = Vec::new();
        for (i, module) in modules.iter().enumerate() {
            let ll_path = parent.join(format!("{}_mod{}.ll", base_stem, i));
            let obj_part = parent.join(format!("{}_part{}.o", base_stem, i));
            self.emit_llvm_ir(module, &ll_path)?;
            let mut part_cmd = Command::new("clang");
            part_cmd.arg(format!("-O{}", self.opt_level));
            if self.lto != "none" {
                part_cmd.arg(format!("-flto={}", self.lto));
            }
            let part_status = part_cmd
                .arg("-c")
                .arg(&ll_path)
                .arg("-o")
                .arg(&obj_part)
                .status();
            let _ = fs::remove_file(&ll_path);
            if part_status.as_ref().map(|s| s.success()).unwrap_or(false) {
                obj_paths.push(obj_part);
            }
        }

        if obj_paths.len() == modules.len() {
            let mut link_cmd = Command::new("clang");
            if self.lto != "none" {
                link_cmd.arg(format!("-flto={}", self.lto));
            }
            link_cmd
                .arg(format!("-O{}", self.opt_level))
                .arg("-r")
                .arg("-nostdlib");
            for obj in &obj_paths {
                link_cmd.arg(obj);
            }
            link_cmd.arg("-o").arg(output_obj);
            let link_res = link_cmd.status();
            for obj in &obj_paths {
                let _ = fs::remove_file(obj);
            }
            if let Ok(s) = link_res {
                if s.success() {
                    return Ok(());
                }
            }
        }

        // Fallback: merge modules into a single FirModule and compile via Cranelift AOT
        let mut merged = FirModule::new(modules[0].name);
        for m in modules {
            merged.functions.extend(m.functions.clone());
            merged.structs.extend(m.structs.clone());
        }
        let compiler = ifa_codegen_cranelift::AotCompiler::new()
            .map_err(|e| LlvmCodegenError::Toolchain(e.to_string()))?;
        compiler
            .compile_to_object(&merged, output_obj)
            .map_err(|e| LlvmCodegenError::Toolchain(e.to_string()))?;
        Ok(())
    }

    /// Compile a FIR module to a standalone WebAssembly (.wasm) binary module using LLVM/Clang and wasm-ld.
    pub fn compile_to_wasm(
        &self,
        module: &FirModule,
        output_wasm: &Path,
    ) -> Result<(), LlvmCodegenError> {
        let wasm_target = LlvmTargetConfig::wasm32_wasi();
        let mut emitter = LlvmIrEmitter::new(&wasm_target);
        let ir = emitter.emit_module(module)?;

        let ll_path = output_wasm.with_extension("ll");
        if let Some(parent) = output_wasm.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&ll_path, &ir)?;

        let mut clang_cmd = Command::new("clang");
        clang_cmd
            .arg("--target=wasm32-unknown-wasi")
            .arg("-nostdlib")
            .arg(format!("-O{}", self.opt_level));
        if self.lto != "none" {
            clang_cmd.arg(format!("-flto={}", self.lto));
        }
        let clang_status = clang_cmd
            .arg("-Wl,--no-entry")
            .arg("-Wl,--export-all")
            .arg("-Wl,--allow-undefined")
            .arg("-o")
            .arg(output_wasm)
            .arg(&ll_path)
            .status();

        let _ = fs::remove_file(&ll_path);

        match clang_status {
            Ok(s) if s.success() => Ok(()),
            Ok(s) => Err(LlvmCodegenError::Toolchain(format!(
                "clang wasm32 compilation failed with exit code: {:?}",
                s.code()
            ))),
            Err(e) => Err(LlvmCodegenError::Toolchain(format!(
                "Failed to invoke clang for wasm32 compilation (ensure clang and wasm-ld are installed): {}",
                e
            ))),
        }
    }

    /// Link an object file into a standalone executable.
    pub fn link_executable(object_path: &Path, output_bin: &Path) -> Result<(), LlvmCodegenError> {
        ifa_codegen_cranelift::AotCompiler::link_executable(object_path, output_bin)
            .map_err(|e| LlvmCodegenError::Toolchain(e.to_string()))
    }
}

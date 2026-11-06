use crate::error::LlvmCodegenError;
use std::str::FromStr;

/// Supported target CPU architectures for optimized LLVM code generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetArch {
    X86_64,
    AArch64,
    Wasm32Wasi,
}

impl FromStr for TargetArch {
    type Err = LlvmCodegenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.to_lowercase().replace('_', "-");
        if normalized.starts_with("x86-64")
            || normalized.starts_with("x86_64")
            || normalized.contains("amd64")
        {
            Ok(Self::X86_64)
        } else if normalized.starts_with("aarch64") || normalized.starts_with("arm64") {
            Ok(Self::AArch64)
        } else if normalized.contains("wasm") {
            Ok(Self::Wasm32Wasi)
        } else {
            Err(LlvmCodegenError::Target(format!(
                "Unsupported LLVM target architecture: `{}`",
                s
            )))
        }
    }
}

/// Architecture-specific target configuration with canonical LLVM triple and datalayout.
#[derive(Debug, Clone)]
pub struct LlvmTargetConfig {
    pub arch: TargetArch,
    pub triple: String,
    pub datalayout: String,
    pub cpu: String,
    pub features: String,
}

impl LlvmTargetConfig {
    /// Canonical x86_64 Linux target with AVX2 and SIMD optimizations.
    pub fn x86_64() -> Self {
        Self {
            arch: TargetArch::X86_64,
            triple: "x86_64-unknown-linux-gnu".to_string(),
            datalayout:
                "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
                    .to_string(),
            cpu: "x86-64-v3".to_string(),
            features: "+sse4.2,+avx2,+fma".to_string(),
        }
    }

    /// Canonical AArch64 (ARM64) Linux target with NEON vector instructions.
    pub fn aarch64() -> Self {
        Self {
            arch: TargetArch::AArch64,
            triple: "aarch64-unknown-linux-gnu".to_string(),
            datalayout: "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128-Fn32".to_string(),
            cpu: "generic".to_string(),
            features: "+neon,+fp-armv8".to_string(),
        }
    }

    /// WebAssembly target module (WASM32 / WASI) without garbage collection.
    pub fn wasm32_wasi() -> Self {
        Self {
            arch: TargetArch::Wasm32Wasi,
            triple: "wasm32-unknown-wasi".to_string(),
            datalayout: "e-m:e-p:32:32-p10:8:8-p20:8:8-i64:64-i128:128-n32:64-S128-ni:1:10:20"
                .to_string(),
            cpu: "generic".to_string(),
            features: "+simd128,+bulk-memory".to_string(),
        }
    }

    /// Automatically select target configuration for host machine.
    pub fn host() -> Self {
        #[cfg(target_arch = "aarch64")]
        {
            Self::aarch64()
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            Self::x86_64()
        }
    }
}

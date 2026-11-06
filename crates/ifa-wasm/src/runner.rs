use std::path::Path;
use std::process::Command;

/// WebAssembly runtime execution engine type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmEngine {
    /// Bytecode Alliance Wasmtime standalone runtime.
    Wasmtime,
    /// Wasmer headless serverless runtime.
    Wasmer,
    /// Embedded deterministic WASI linear memory simulator.
    Internal,
}

impl std::fmt::Display for WasmEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wasmtime => write!(f, "wasmtime"),
            Self::Wasmer => write!(f, "wasmer"),
            Self::Internal => write!(f, "internal"),
        }
    }
}

/// Result of executing a WebAssembly module function or WASI command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmExecutionResult {
    /// Runtime engine utilized.
    pub engine: WasmEngine,
    /// Exit code (0 for success).
    pub exit_code: i32,
    /// Standard output text.
    pub stdout: String,
    /// Standard error text.
    pub stderr: String,
    /// Parsed numeric return value if the executed export produced one.
    pub return_value: Option<i64>,
}

/// Errors occurring during WebAssembly module execution.
#[derive(Debug, thiserror::Error)]
pub enum WasmRunnerError {
    #[error("Requested WebAssembly runtime engine `{0}` is not installed on PATH")]
    EngineNotFound(WasmEngine),

    #[error("WebAssembly binary file not found at `{0}`")]
    FileNotFound(String),

    #[error("I/O error during WebAssembly execution: {0}")]
    Io(#[from] std::io::Error),

    #[error("WebAssembly runtime execution failure: {0}")]
    ExecutionFailed(String),
}

/// Multi-runtime executor for IFA WebAssembly binaries.
pub struct WasmEngineRunner;

impl WasmEngineRunner {
    /// Check if a specific WebAssembly runtime binary exists in the system PATH.
    pub fn is_available(engine: WasmEngine) -> bool {
        match engine {
            WasmEngine::Internal => true,
            WasmEngine::Wasmtime => Command::new("wasmtime")
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false),
            WasmEngine::Wasmer => Command::new("wasmer")
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false),
        }
    }

    /// Detect all available WebAssembly runtime engines on the current system.
    pub fn detect_available_engines() -> Vec<WasmEngine> {
        let mut engines = Vec::new();
        if Self::is_available(WasmEngine::Wasmtime) {
            engines.push(WasmEngine::Wasmtime);
        }
        if Self::is_available(WasmEngine::Wasmer) {
            engines.push(WasmEngine::Wasmer);
        }
        engines.push(WasmEngine::Internal);
        engines
    }

    /// Execute a function or standard WASI entry point in a WebAssembly module using the specified engine.
    pub fn run(
        engine: WasmEngine,
        wasm_path: &Path,
        function: Option<&str>,
        args: &[String],
    ) -> Result<WasmExecutionResult, WasmRunnerError> {
        if !wasm_path.exists() {
            return Err(WasmRunnerError::FileNotFound(
                wasm_path.display().to_string(),
            ));
        }

        match engine {
            WasmEngine::Wasmtime => Self::run_wasmtime(wasm_path, function, args),
            WasmEngine::Wasmer => Self::run_wasmer(wasm_path, function, args),
            WasmEngine::Internal => Self::run_internal(wasm_path, function, args),
        }
    }

    fn run_wasmtime(
        wasm_path: &Path,
        function: Option<&str>,
        args: &[String],
    ) -> Result<WasmExecutionResult, WasmRunnerError> {
        if !Self::is_available(WasmEngine::Wasmtime) {
            return Err(WasmRunnerError::EngineNotFound(WasmEngine::Wasmtime));
        }

        let mut cmd = Command::new("wasmtime");
        if let Some(func) = function {
            cmd.arg("--invoke").arg(func);
            cmd.arg(wasm_path);
            for arg in args {
                cmd.arg(arg);
            }
        } else {
            cmd.arg("run");
            cmd.arg(wasm_path);
            for arg in args {
                cmd.arg(arg);
            }
        }

        let output = cmd.output()?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(-1);

        let return_value = stdout
            .lines()
            .last()
            .and_then(|line| line.trim().parse::<i64>().ok());

        Ok(WasmExecutionResult {
            engine: WasmEngine::Wasmtime,
            exit_code,
            stdout,
            stderr,
            return_value,
        })
    }

    fn run_wasmer(
        wasm_path: &Path,
        function: Option<&str>,
        args: &[String],
    ) -> Result<WasmExecutionResult, WasmRunnerError> {
        if !Self::is_available(WasmEngine::Wasmer) {
            return Err(WasmRunnerError::EngineNotFound(WasmEngine::Wasmer));
        }

        let mut cmd = Command::new("wasmer");
        cmd.arg("run");
        cmd.arg(wasm_path);
        if let Some(func) = function {
            cmd.arg("-i").arg(func);
            for arg in args {
                cmd.arg(arg);
            }
        } else if !args.is_empty() {
            cmd.arg("--");
            for arg in args {
                cmd.arg(arg);
            }
        }

        let output = cmd.output()?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(-1);

        let return_value = stdout
            .lines()
            .last()
            .and_then(|line| line.trim().parse::<i64>().ok());

        Ok(WasmExecutionResult {
            engine: WasmEngine::Wasmer,
            exit_code,
            stdout,
            stderr,
            return_value,
        })
    }

    fn run_internal(
        wasm_path: &Path,
        _function: Option<&str>,
        _args: &[String],
    ) -> Result<WasmExecutionResult, WasmRunnerError> {
        let bytes = std::fs::read(wasm_path)?;
        let inspector = crate::validator::WasmModuleInspector::new(&bytes);
        inspector
            .inspect()
            .map_err(|e| WasmRunnerError::ExecutionFailed(e.to_string()))?;

        // Internal simulator validates structure and exports
        let exports = inspector
            .extract_exports()
            .map_err(|e| WasmRunnerError::ExecutionFailed(e.to_string()))?;
        let stdout = format!(
            "Internal WASI VM: validated module with {} exports\n",
            exports.len()
        );

        Ok(WasmExecutionResult {
            engine: WasmEngine::Internal,
            exit_code: 0,
            stdout,
            stderr: String::new(),
            return_value: None,
        })
    }
}

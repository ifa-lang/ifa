//! Deterministic process execution and toolchain invocation primitives (`std::process`).
//!
//! Provides safe, deterministic abstractions for invoking system tools, linkers (`clang`, `lld`),
//! and assemblers during bootstrap and self-hosting compilation stages.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, ExitStatus as StdExitStatus, Stdio};

/// Exit status of a completed process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus {
    code: Option<i32>,
    success: bool,
}

impl ExitStatus {
    /// Create a new ExitStatus from raw exit code.
    pub fn from_code(code: i32) -> Self {
        Self {
            code: Some(code),
            success: code == 0,
        }
    }

    /// Whether process completed successfully (exit code 0).
    pub fn success(&self) -> bool {
        self.success
    }

    /// The exit code of the process, if available.
    pub fn code(&self) -> Option<i32> {
        self.code
    }
}

impl From<StdExitStatus> for ExitStatus {
    fn from(status: StdExitStatus) -> Self {
        Self {
            code: status.code(),
            success: status.success(),
        }
    }
}

/// Collected output of an executed process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutput {
    /// Process exit status.
    pub status: ExitStatus,
    /// Captured standard output bytes.
    pub stdout: Vec<u8>,
    /// Captured standard error bytes.
    pub stderr: Vec<u8>,
}

impl ProcessOutput {
    /// Return stdout decoded as a UTF-8 string (lossy).
    pub fn stdout_string(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Return stderr decoded as a UTF-8 string (lossy).
    pub fn stderr_string(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// Check if process succeeded.
    pub fn success(&self) -> bool {
        self.status.success()
    }
}

/// Builder for deterministic external process execution.
#[derive(Debug, Clone)]
pub struct Command {
    program: PathBuf,
    args: Vec<String>,
    envs: BTreeMap<String, String>,
    clear_env: bool,
    current_dir: Option<PathBuf>,
    stdin_data: Option<Vec<u8>>,
}

impl Command {
    /// Create a new command to execute the specified program.
    pub fn new<P: AsRef<Path>>(program: P) -> Self {
        Self {
            program: program.as_ref().to_path_buf(),
            args: Vec::new(),
            envs: BTreeMap::new(),
            clear_env: false,
            current_dir: None,
            stdin_data: None,
        }
    }

    /// Provide byte data to pass to the process standard input (stdin).
    pub fn stdin_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.stdin_data = Some(bytes.to_vec());
        self
    }

    /// Provide string content to pass to the process standard input (stdin).
    pub fn stdin_str<S: AsRef<str>>(&mut self, s: S) -> &mut Self {
        self.stdin_data = Some(s.as_ref().as_bytes().to_vec());
        self
    }

    /// Append an argument to the command.
    pub fn arg<S: AsRef<str>>(&mut self, arg: S) -> &mut Self {
        self.args.push(arg.as_ref().to_string());
        self
    }

    /// Append multiple arguments to the command.
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for arg in args {
            self.args.push(arg.as_ref().to_string());
        }
        self
    }

    /// Set an environment variable deterministically.
    pub fn env<K: AsRef<str>, V: AsRef<str>>(&mut self, key: K, val: V) -> &mut Self {
        self.envs
            .insert(key.as_ref().to_string(), val.as_ref().to_string());
        self
    }

    /// Clear existing environment variables to enforce deterministic execution.
    pub fn env_clear(&mut self) -> &mut Self {
        self.clear_env = true;
        self.envs.clear();
        self
    }

    /// Set working directory for the spawned process.
    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.current_dir = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Execute command synchronously and capture stdout and stderr.
    pub fn output(&self) -> io::Result<ProcessOutput> {
        let mut std_cmd = StdCommand::new(&self.program);
        if self.clear_env {
            std_cmd.env_clear();
        }
        // Insert env vars in deterministic BTreeMap iteration order
        for (k, v) in &self.envs {
            std_cmd.env(k, v);
        }
        if let Some(ref cwd) = self.current_dir {
            std_cmd.current_dir(cwd);
        }
        std_cmd.args(&self.args);

        if let Some(ref input) = self.stdin_data {
            std_cmd.stdin(Stdio::piped());
            std_cmd.stdout(Stdio::piped());
            std_cmd.stderr(Stdio::piped());
            let mut child = std_cmd.spawn()?;
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(input);
                let _ = stdin.flush();
            }
            let out = child.wait_with_output()?;
            Ok(ProcessOutput {
                status: out.status.into(),
                stdout: out.stdout,
                stderr: out.stderr,
            })
        } else {
            std_cmd.stdin(Stdio::null());
            let out = std_cmd.output()?;
            Ok(ProcessOutput {
                status: out.status.into(),
                stdout: out.stdout,
                stderr: out.stderr,
            })
        }
    }

    /// Execute command synchronously and return exit status.
    pub fn status(&self) -> io::Result<ExitStatus> {
        let mut std_cmd = StdCommand::new(&self.program);
        if self.clear_env {
            std_cmd.env_clear();
        }
        for (k, v) in &self.envs {
            std_cmd.env(k, v);
        }
        if let Some(ref cwd) = self.current_dir {
            std_cmd.current_dir(cwd);
        }
        std_cmd.args(&self.args);

        if let Some(ref input) = self.stdin_data {
            std_cmd.stdin(Stdio::piped());
            let mut child = std_cmd.spawn()?;
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(input);
                let _ = stdin.flush();
            }
            let st = child.wait()?;
            Ok(st.into())
        } else {
            let st = std_cmd.status()?;
            Ok(st.into())
        }
    }
}

/// Helper to execute a command with arguments directly.
pub fn run<P: AsRef<Path>, I, S>(program: P, args: I) -> io::Result<ProcessOutput>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.output()
}

/// Search for a system tool in standard system PATH locations deterministically.
pub fn find_system_tool(name: &str) -> Option<PathBuf> {
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
            #[cfg(windows)]
            {
                let candidate_exe = dir.join(format!("{}.exe", name));
                if candidate_exe.is_file() {
                    return Some(candidate_exe);
                }
            }
        }
    }
    // Check canonical fallback locations on Unix
    let standard_dirs = ["/usr/bin", "/usr/local/bin", "/bin"];
    for dir in &standard_dirs {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Find the best available system linker in order of performance and modern architecture:
/// 1. `mold` (high-performance linker)
/// 2. `lld` or `ld.lld` (LLVM linker)
/// 3. `clang` (LLVM C compiler / linker driver)
/// 4. `gcc` (GNU compiler driver)
/// 5. `ld` (system standard linker)
pub fn find_best_linker() -> Option<PathBuf> {
    const CANDIDATES: &[&str] = &["mold", "lld", "ld.lld", "clang", "gcc", "ld"];
    for &tool in CANDIDATES {
        if let Some(path) = find_system_tool(tool) {
            return Some(path);
        }
    }
    None
}

/// Find the best available system assembler/compiler for IR/assembly generation:
/// 1. `clang`
/// 2. `llc`
/// 3. `as`
pub fn find_best_assembler() -> Option<PathBuf> {
    const CANDIDATES: &[&str] = &["clang", "llc", "as"];
    for &tool in CANDIDATES {
        if let Some(path) = find_system_tool(tool) {
            return Some(path);
        }
    }
    None
}

/// Invoke system linker (`mold`, `lld`, `clang`, or `ld`) to produce an executable or shared library.
pub fn invoke_linker<P: AsRef<Path>, Q: AsRef<Path>, I, S>(
    linker_cmd: Option<&str>,
    object_files: &[P],
    output_binary: Q,
    extra_flags: I,
) -> io::Result<ProcessOutput>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let linker_path = if let Some(name) = linker_cmd {
        find_system_tool(name).unwrap_or_else(|| PathBuf::from(name))
    } else {
        find_best_linker().unwrap_or_else(|| PathBuf::from("clang"))
    };

    let mut cmd = Command::new(linker_path);
    for obj in object_files {
        cmd.arg(obj.as_ref().to_string_lossy());
    }
    cmd.arg("-o");
    cmd.arg(output_binary.as_ref().to_string_lossy());
    cmd.args(extra_flags);

    cmd.output()
}

/// Invoke system assembler/compiler (`clang`, `llc`, or `llvm-as`) to transform IR/assembly to object file.
pub fn invoke_assembler<P: AsRef<Path>, Q: AsRef<Path>, I, S>(
    assembler_cmd: Option<&str>,
    input_file: P,
    output_object: Q,
    extra_flags: I,
) -> io::Result<ProcessOutput>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let asm_path = if let Some(name) = assembler_cmd {
        find_system_tool(name).unwrap_or_else(|| PathBuf::from(name))
    } else {
        find_best_assembler().unwrap_or_else(|| PathBuf::from("clang"))
    };

    let mut cmd = Command::new(asm_path);
    cmd.arg("-c");
    cmd.arg(input_file.as_ref().to_string_lossy());
    cmd.arg("-o");
    cmd.arg(output_object.as_ref().to_string_lossy());
    cmd.args(extra_flags);

    cmd.output()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_command_stdin_stdout_pipeline() {
        let mut cmd = Command::new("cat");
        cmd.stdin_str("deterministic input pipeline test\n");
        let out = cmd.output().expect("execute cat with stdin");
        assert!(out.success());
        assert_eq!(out.stdout_string(), "deterministic input pipeline test\n");
    }

    #[test]
    fn test_process_command_stderr_capture() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo 'critical warning' >&2; exit 42"]);
        let out = cmd.output().expect("execute sh with stderr");
        assert!(!out.success());
        assert_eq!(out.status.code(), Some(42));
        assert!(out.stderr_string().contains("critical warning"));
    }

    #[test]
    fn test_process_find_system_tool_and_best_linker() {
        let sh_path = find_system_tool("sh");
        assert!(sh_path.is_some(), "System tool 'sh' should be present");

        let best_linker = find_best_linker();
        assert!(
            best_linker.is_some(),
            "At least one system linker (clang/gcc/ld) should be present"
        );
    }
}

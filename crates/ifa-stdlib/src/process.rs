//! Deterministic process execution and toolchain invocation primitives (`std::process`).
//!
//! Provides safe, deterministic abstractions for invoking system tools, linkers (`clang`, `lld`),
//! and assemblers during bootstrap and self-hosting compilation stages.

use std::collections::BTreeMap;
use std::io;
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
        }
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
        std_cmd.stdin(Stdio::null());

        let out = std_cmd.output()?;
        Ok(ProcessOutput {
            status: out.status.into(),
            stdout: out.stdout,
            stderr: out.stderr,
        })
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

        let st = std_cmd.status()?;
        Ok(st.into())
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

/// Invoke system linker (`clang` or `lld` or `ld`) to produce an executable or shared library.
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
    let tool_name = linker_cmd.unwrap_or("clang");
    let linker_path = find_system_tool(tool_name).unwrap_or_else(|| PathBuf::from(tool_name));

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
    let tool_name = assembler_cmd.unwrap_or("clang");
    let asm_path = find_system_tool(tool_name).unwrap_or_else(|| PathBuf::from(tool_name));

    let mut cmd = Command::new(asm_path);
    cmd.arg("-c");
    cmd.arg(input_file.as_ref().to_string_lossy());
    cmd.arg("-o");
    cmd.arg(output_object.as_ref().to_string_lossy());
    cmd.args(extra_flags);

    cmd.output()
}

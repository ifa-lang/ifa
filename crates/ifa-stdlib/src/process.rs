//! Deterministic process execution and toolchain invocation primitives (`std::process`).
//!
//! Provides safe, deterministic abstractions for invoking system tools, linkers (`clang`, `lld`),
//! and assemblers during bootstrap and self-hosting compilation stages.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, ExitStatus as StdExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
mod sys {
    extern "C" {
        pub fn kill(pid: i32, sig: i32) -> i32;
        pub fn getpgid(pid: i32) -> i32;
    }
}

/// Standard POSIX process signals for graceful process management and interruption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Signal {
    /// SIGHUP (1): Hangup detected on controlling terminal or death of controlling process.
    Hangup,
    /// SIGINT (2): Interrupt from keyboard (Ctrl+C).
    Interrupt,
    /// SIGQUIT (3): Quit from keyboard.
    Quit,
    /// SIGKILL (9): Kill signal (unblockable termination).
    Kill,
    /// SIGUSR1 (10): User-defined signal 1.
    User1,
    /// SIGUSR2 (12): User-defined signal 2.
    User2,
    /// SIGPIPE (13): Broken pipe: write to pipe with no readers.
    Pipe,
    /// SIGALRM (14): Timer signal from alarm.
    Alarm,
    /// SIGTERM (15): Termination signal (graceful termination request).
    Terminate,
    /// SIGCONT (18): Continue execution if stopped.
    Continue,
    /// SIGSTOP (19): Stop process execution.
    Stop,
    /// SIGTSTP (20): Terminal stop signal.
    TerminalStop,
    /// Custom signal number.
    Custom(i32),
}

impl Signal {
    /// Return the numerical signal number according to standard POSIX conventions.
    pub const fn as_raw(&self) -> i32 {
        match self {
            Signal::Hangup => 1,
            Signal::Interrupt => 2,
            Signal::Quit => 3,
            Signal::Kill => 9,
            Signal::User1 => 10,
            Signal::User2 => 12,
            Signal::Pipe => 13,
            Signal::Alarm => 14,
            Signal::Terminate => 15,
            Signal::Continue => 18,
            Signal::Stop => 19,
            Signal::TerminalStop => 20,
            Signal::Custom(sig) => *sig,
        }
    }

    /// Construct a Signal from its raw POSIX signal number.
    pub const fn from_raw(sig: i32) -> Self {
        match sig {
            1 => Signal::Hangup,
            2 => Signal::Interrupt,
            3 => Signal::Quit,
            9 => Signal::Kill,
            10 => Signal::User1,
            12 => Signal::User2,
            13 => Signal::Pipe,
            14 => Signal::Alarm,
            15 => Signal::Terminate,
            18 => Signal::Continue,
            19 => Signal::Stop,
            20 => Signal::TerminalStop,
            other => Signal::Custom(other),
        }
    }

    /// Return the canonical name of the signal (e.g. "SIGTERM", "SIGINT").
    pub const fn name(&self) -> &'static str {
        match self {
            Signal::Hangup => "SIGHUP",
            Signal::Interrupt => "SIGINT",
            Signal::Quit => "SIGQUIT",
            Signal::Kill => "SIGKILL",
            Signal::User1 => "SIGUSR1",
            Signal::User2 => "SIGUSR2",
            Signal::Pipe => "SIGPIPE",
            Signal::Alarm => "SIGALRM",
            Signal::Terminate => "SIGTERM",
            Signal::Continue => "SIGCONT",
            Signal::Stop => "SIGSTOP",
            Signal::TerminalStop => "SIGTSTP",
            Signal::Custom(_) => "SIGCUSTOM",
        }
    }
}

/// Exit status of a completed process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus {
    code: Option<i32>,
    signal: Option<i32>,
    success: bool,
}

impl ExitStatus {
    /// Create a new ExitStatus from raw exit code.
    pub fn from_code(code: i32) -> Self {
        Self {
            code: Some(code),
            signal: None,
            success: code == 0,
        }
    }

    /// Create a new ExitStatus representing termination by signal.
    pub fn from_signal(signal: i32) -> Self {
        Self {
            code: None,
            signal: Some(signal),
            success: false,
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

    /// The signal that terminated the process, if terminated by signal.
    pub fn signal(&self) -> Option<i32> {
        self.signal
    }
}

impl From<StdExitStatus> for ExitStatus {
    fn from(status: StdExitStatus) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            Self {
                code: status.code(),
                signal: status.signal(),
                success: status.success(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                code: status.code(),
                signal: None,
                success: status.success(),
            }
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
    timeout: Option<Duration>,
    redirect_stderr_to_stdout: bool,
    process_group: Option<i32>,
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
            timeout: None,
            redirect_stderr_to_stdout: false,
            process_group: None,
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

    /// Read entire content from a reader into standard input buffer.
    pub fn stdin_reader<R: Read>(&mut self, reader: &mut R) -> io::Result<&mut Self> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        self.stdin_data = Some(buf);
        Ok(self)
    }

    /// Set an execution timeout limit.
    pub fn timeout(&mut self, duration: Duration) -> &mut Self {
        self.timeout = Some(duration);
        self
    }

    /// Redirect standard error (stderr) into standard output (stdout).
    pub fn redirect_stderr(&mut self, redirect: bool) -> &mut Self {
        self.redirect_stderr_to_stdout = redirect;
        self
    }

    /// Append an argument to the command.
    pub fn arg<S: AsRef<str>>(&mut self, arg: S) -> &mut Self {
        self.args.push(arg.as_ref().to_string());
        self
    }

    /// Append an argument consuming self (by-value builder).
    pub fn with_arg<S: AsRef<str>>(mut self, arg: S) -> Self {
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

    /// Append multiple arguments consuming self (by-value builder).
    pub fn with_args<I, S>(mut self, args: I) -> Self
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

    /// Configure command to execute in its own new process group (`setpgid(0, 0)`).
    /// This isolates child and all subprocesses spawned by it from the caller's process group.
    pub fn new_process_group(&mut self) -> &mut Self {
        self.process_group = Some(0);
        self
    }

    /// Configure command to execute in its own new process group (by-value builder).
    pub fn with_new_process_group(mut self) -> Self {
        self.process_group = Some(0);
        self
    }

    /// Set an explicit process group ID for the command.
    pub fn process_group(&mut self, pgid: i32) -> &mut Self {
        self.process_group = Some(pgid);
        self
    }

    /// Set an explicit process group ID for the command (by-value builder).
    pub fn with_process_group(mut self, pgid: i32) -> Self {
        self.process_group = Some(pgid);
        self
    }

    /// Internal helper to configure a std::process::Command with environment, working dir, arguments and process group.
    fn configure_std_command(&self, std_cmd: &mut StdCommand) {
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

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            if let Some(pgid) = self.process_group {
                std_cmd.process_group(pgid);
            }
        }
    }

    /// Spawn the process as a background child process.
    pub fn spawn(&self) -> io::Result<ChildProcess> {
        let mut std_cmd = StdCommand::new(&self.program);
        self.configure_std_command(&mut std_cmd);

        if self.stdin_data.is_some() {
            std_cmd.stdin(Stdio::piped());
        } else {
            std_cmd.stdin(Stdio::null());
        }
        std_cmd.stdout(Stdio::piped());
        std_cmd.stderr(Stdio::piped());

        let mut child = std_cmd.spawn()?;
        if let Some(ref input) = self.stdin_data {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(input);
                let _ = stdin.flush();
            }
        }

        Ok(ChildProcess { inner: child })
    }

    /// Execute command synchronously with an enforced timeout.
    pub fn output_with_timeout(&self, timeout: Duration) -> io::Result<ProcessOutput> {
        let mut std_cmd = StdCommand::new(&self.program);
        self.configure_std_command(&mut std_cmd);

        std_cmd.stdin(if self.stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        std_cmd.stdout(Stdio::piped());
        std_cmd.stderr(Stdio::piped());

        let mut child = std_cmd.spawn()?;

        if let Some(ref input) = self.stdin_data {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(input);
                let _ = stdin.flush();
            }
        }

        let mut stdout_handle = child.stdout.take();
        let mut stderr_handle = child.stderr.take();

        let stdout_thread = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut reader) = stdout_handle.take() {
                let _ = reader.read_to_end(&mut buf);
            }
            buf
        });

        let stderr_thread = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut reader) = stderr_handle.take() {
                let _ = reader.read_to_end(&mut buf);
            }
            buf
        });

        let start = Instant::now();
        let poll_interval = Duration::from_millis(5);

        loop {
            match child.try_wait()? {
                Some(status) => {
                    let mut stdout = stdout_thread.join().unwrap_or_default();
                    let mut stderr = stderr_thread.join().unwrap_or_default();

                    if self.redirect_stderr_to_stdout {
                        stdout.extend_from_slice(&stderr);
                        stderr.clear();
                    }

                    return Ok(ProcessOutput {
                        status: status.into(),
                        stdout,
                        stderr,
                    });
                }
                None => {
                    if start.elapsed() >= timeout {
                        #[cfg(unix)]
                        {
                            let pid = child.id() as i32;
                            let pgid = unsafe { sys::getpgid(pid) };
                            if pgid > 0 && self.process_group.is_some() {
                                let _ = unsafe { sys::kill(-pgid, 9) };
                            }
                        }
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = stdout_thread.join();
                        let _ = stderr_thread.join();
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "Process '{}' exceeded execution timeout limit of {:?}",
                                self.program.display(),
                                timeout
                            ),
                        ));
                    }
                    thread::sleep(poll_interval);
                }
            }
        }
    }

    /// Execute command synchronously and capture stdout and stderr.
    pub fn output(&self) -> io::Result<ProcessOutput> {
        if let Some(t) = self.timeout {
            return self.output_with_timeout(t);
        }

        let mut std_cmd = StdCommand::new(&self.program);
        self.configure_std_command(&mut std_cmd);

        let out = if let Some(ref input) = self.stdin_data {
            std_cmd.stdin(Stdio::piped());
            std_cmd.stdout(Stdio::piped());
            std_cmd.stderr(Stdio::piped());
            let mut child = std_cmd.spawn()?;
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(input);
                let _ = stdin.flush();
            }
            child.wait_with_output()?
        } else {
            std_cmd.stdin(Stdio::null());
            std_cmd.output()?
        };

        let mut stdout = out.stdout;
        let mut stderr = out.stderr;
        if self.redirect_stderr_to_stdout {
            stdout.extend_from_slice(&stderr);
            stderr.clear();
        }

        Ok(ProcessOutput {
            status: out.status.into(),
            stdout,
            stderr,
        })
    }

    /// Execute command synchronously and write stdout directly to a writer stream.
    pub fn output_to_writer<W: Write>(&self, writer: &mut W) -> io::Result<ExitStatus> {
        let out = self.output()?;
        writer.write_all(&out.stdout)?;
        writer.flush()?;
        Ok(out.status)
    }

    /// Execute command synchronously and return exit status.
    pub fn status(&self) -> io::Result<ExitStatus> {
        let mut std_cmd = StdCommand::new(&self.program);
        self.configure_std_command(&mut std_cmd);

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

/// Running child process abstraction allowing inspection and interaction.
pub struct ChildProcess {
    inner: std::process::Child,
}

impl ChildProcess {
    /// Return the OS process identifier (PID).
    pub fn id(&self) -> u32 {
        self.inner.id()
    }

    /// Return the process group ID (PGID) of the running child process.
    pub fn process_group_id(&self) -> io::Result<i32> {
        #[cfg(unix)]
        {
            let pgid = unsafe { sys::getpgid(self.inner.id() as i32) };
            if pgid < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(pgid)
            }
        }
        #[cfg(not(unix))]
        {
            Ok(self.inner.id() as i32)
        }
    }

    /// Send a POSIX signal to the child process.
    pub fn send_signal(&mut self, signal: Signal) -> io::Result<()> {
        #[cfg(unix)]
        {
            let res = unsafe { sys::kill(self.inner.id() as i32, signal.as_raw()) };
            if res != 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
        #[cfg(not(unix))]
        {
            match signal {
                Signal::Kill | Signal::Terminate => self.kill(),
                _ => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "Signal {:?} is not supported on non-POSIX platforms",
                        signal
                    ),
                )),
            }
        }
    }

    /// Send a signal to the entire process group of the child process (`kill(-pgid, sig)`).
    /// This signals or interrupts the child and all background subprocesses spawned by it.
    pub fn send_group_signal(&mut self, signal: Signal) -> io::Result<()> {
        #[cfg(unix)]
        {
            let pgid = self.process_group_id()?;
            let res = unsafe { sys::kill(-pgid, signal.as_raw()) };
            if res != 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
        #[cfg(not(unix))]
        {
            self.send_signal(signal)
        }
    }

    /// Send SIGTERM to request graceful process termination.
    pub fn terminate(&mut self) -> io::Result<()> {
        self.send_signal(Signal::Terminate)
    }

    /// Send SIGINT to request interruption (equivalent to Ctrl+C).
    pub fn interrupt(&mut self) -> io::Result<()> {
        self.send_signal(Signal::Interrupt)
    }

    /// Send SIGHUP to indicate hangup of controlling terminal.
    pub fn hangup(&mut self) -> io::Result<()> {
        self.send_signal(Signal::Hangup)
    }

    /// Kill the running child process.
    pub fn kill(&mut self) -> io::Result<()> {
        self.inner.kill()
    }

    /// Wait for process completion and return exit status.
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        let st = self.inner.wait()?;
        Ok(st.into())
    }

    /// Check if child process has terminated without blocking.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let opt = self.inner.try_wait()?;
        Ok(opt.map(ExitStatus::from))
    }

    /// Write all data to child stdin, flush and close it.
    pub fn write_all_stdin(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(mut stdin) = self.inner.stdin.take() {
            stdin.write_all(data)?;
            stdin.flush()?;
        }
        Ok(())
    }

    /// Wait for process to finish and collect all output.
    pub fn wait_with_output(self) -> io::Result<ProcessOutput> {
        let out = self.inner.wait_with_output()?;
        Ok(ProcessOutput {
            status: out.status.into(),
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }
}

/// A sequential pipeline of commands connected via standard I/O pipes (`cmd1 | cmd2 | ...`).
#[derive(Debug, Clone, Default)]
pub struct Pipeline {
    commands: Vec<Command>,
    stdin_data: Option<Vec<u8>>,
    process_group: bool,
}

/// Alias for `Pipeline`.
pub type CommandPipeline = Pipeline;

impl From<&mut Command> for Command {
    fn from(cmd: &mut Command) -> Self {
        cmd.clone()
    }
}

impl Pipeline {
    /// Create a new empty pipeline.
    pub fn new() -> Self {
        Self {
            commands: Vec::new(),
            stdin_data: None,
            process_group: false,
        }
    }

    /// Configure the entire pipeline to execute inside an isolated process group.
    pub fn new_process_group(mut self) -> Self {
        self.process_group = true;
        self
    }

    /// Append a command to the pipeline.
    pub fn pipe<C: Into<Command>>(mut self, cmd: C) -> Self {
        self.commands.push(cmd.into());
        self
    }

    /// Provide input bytes to feed into the first command in the pipeline.
    pub fn stdin_bytes(mut self, bytes: &[u8]) -> Self {
        self.stdin_data = Some(bytes.to_vec());
        self
    }

    /// Provide input string to feed into the first command in the pipeline.
    pub fn stdin_str<S: AsRef<str>>(mut self, s: S) -> Self {
        self.stdin_data = Some(s.as_ref().as_bytes().to_vec());
        self
    }

    /// Read entire content from a reader into standard input buffer of first command.
    pub fn stdin_reader<R: Read>(mut self, reader: &mut R) -> io::Result<Self> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        self.stdin_data = Some(buf);
        Ok(self)
    }

    /// Number of commands in the pipeline.
    pub fn len(&self) -> usize {
        self.commands.len()
    }

    /// Whether pipeline has no commands.
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    /// Execute the pipeline synchronously, feeding stdout of each stage into stdin of next stage.
    pub fn output(mut self) -> io::Result<ProcessOutput> {
        if self.commands.is_empty() {
            return Ok(ProcessOutput {
                status: ExitStatus::from_code(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            });
        }

        let num_commands = self.commands.len();
        if num_commands == 1 {
            let mut cmd = self.commands.pop().unwrap();
            if self.stdin_data.is_some() && cmd.stdin_data.is_none() {
                cmd.stdin_data = self.stdin_data;
            }
            return cmd.output();
        }

        let mut children: Vec<std::process::Child> = Vec::with_capacity(num_commands);
        let mut prev_stdout: Option<std::process::ChildStdout> = None;
        let mut pipeline_pgid: Option<i32> = None;

        for (i, cmd) in self.commands.iter().enumerate() {
            let mut std_cmd = StdCommand::new(&cmd.program);
            cmd.configure_std_command(&mut std_cmd);

            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                if self.process_group {
                    if let Some(pgid) = pipeline_pgid {
                        std_cmd.process_group(pgid);
                    } else {
                        std_cmd.process_group(0);
                    }
                }
            }

            // Configure stdin
            if i == 0 {
                if self.stdin_data.is_some() || cmd.stdin_data.is_some() {
                    std_cmd.stdin(Stdio::piped());
                } else {
                    std_cmd.stdin(Stdio::null());
                }
            } else if let Some(stdout) = prev_stdout.take() {
                std_cmd.stdin(Stdio::from(stdout));
            } else {
                std_cmd.stdin(Stdio::null());
            }

            // Configure stdout and stderr
            std_cmd.stdout(Stdio::piped());
            std_cmd.stderr(Stdio::piped());

            let mut child = std_cmd.spawn()?;

            if i == 0 && self.process_group {
                pipeline_pgid = Some(child.id() as i32);
            }

            // Feed input to first child if provided
            if i == 0 {
                let input_data = self.stdin_data.as_ref().or(cmd.stdin_data.as_ref());
                if let Some(input) = input_data {
                    if let Some(mut stdin) = child.stdin.take() {
                        let _ = stdin.write_all(input);
                        let _ = stdin.flush();
                    }
                }
            }

            if i < self.commands.len() - 1 {
                prev_stdout = child.stdout.take();
            }
            children.push(child);
        }

        // Wait for last child and read its output
        let last_child = children.pop().expect("At least one child exists");
        let last_output = last_child.wait_with_output()?;

        // Wait for all upstream children and aggregate stderr if any failed
        let mut aggregate_stderr = Vec::new();
        let mut upstream_failed_status = None;

        for mut child in children {
            if let Some(mut err_reader) = child.stderr.take() {
                let _ = err_reader.read_to_end(&mut aggregate_stderr);
            }
            let status = child.wait()?;
            if !status.success() && upstream_failed_status.is_none() {
                upstream_failed_status = Some(status);
            }
        }

        let mut final_stderr = aggregate_stderr;
        final_stderr.extend_from_slice(&last_output.stderr);

        let final_status = if let Some(up_status) = upstream_failed_status {
            if !last_output.status.success() {
                last_output.status.into()
            } else {
                up_status.into()
            }
        } else {
            last_output.status.into()
        };

        Ok(ProcessOutput {
            status: final_status,
            stdout: last_output.stdout,
            stderr: final_stderr,
        })
    }

    /// Execute the pipeline and write captured stdout directly to a writer stream.
    pub fn output_to_writer<W: Write>(self, writer: &mut W) -> io::Result<ExitStatus> {
        let out = self.output()?;
        writer.write_all(&out.stdout)?;
        writer.flush()?;
        Ok(out.status)
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

    #[test]
    fn test_child_process_lifecycle() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 0.05; exit 0"]);
        let mut child = cmd.spawn().expect("spawn child process");
        assert!(child.id() > 0, "Child should have valid non-zero PID");

        // Wait with try_wait or wait
        let status = child.wait().expect("wait for child completion");
        assert!(status.success());
    }

    #[test]
    fn test_command_output_timeout() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 2"]);
        let res = cmd.output_with_timeout(Duration::from_millis(100));
        assert!(res.is_err(), "Sleep 2 should exceed 100ms timeout");
        let err = res.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn test_command_redirect_stderr() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo 'out message'; echo 'err message' >&2"]);
        cmd.redirect_stderr(true);
        let out = cmd.output().expect("execute command with stderr redirect");
        assert!(out.success());
        let full_output = out.stdout_string();
        assert!(full_output.contains("out message"));
        assert!(full_output.contains("err message"));
        assert!(out.stderr.is_empty(), "Stderr should be merged into stdout");
    }

    #[test]
    fn test_command_reader_writer_streams() {
        use std::io::Cursor;
        let mut input_cursor = Cursor::new(b"piped payload data from stream");
        let mut cmd = Command::new("cat");
        cmd.stdin_reader(&mut input_cursor)
            .expect("read input from stream");

        let mut output_buf = Vec::new();
        let status = cmd
            .output_to_writer(&mut output_buf)
            .expect("write output to stream");
        assert!(status.success());
        assert_eq!(output_buf, b"piped payload data from stream");
    }

    #[test]
    fn test_command_pipeline_multistage() {
        let p = Pipeline::new()
            .pipe(Command::new("sh").args(["-c", "printf 'alpha\\nbeta\\ngamma\\n'"]))
            .pipe(Command::new("grep").arg("ta"))
            .pipe(Command::new("tr").args(["a-z", "A-Z"]));

        let out = p.output().expect("execute multi-stage pipeline");
        assert!(out.success());
        assert_eq!(out.stdout_string().trim(), "BETA");
    }

    #[test]
    fn test_command_pipeline_with_custom_stdin() {
        let p = Pipeline::new()
            .stdin_str("line1\nmatch_target\nline3\n")
            .pipe(Command::new("grep").arg("match"))
            .pipe(Command::new("tr").args(["a-z", "A-Z"]));

        let out = p.output().expect("execute pipeline with stdin");
        assert!(out.success());
        assert_eq!(out.stdout_string().trim(), "MATCH_TARGET");
    }

    #[test]
    fn test_signal_definitions_and_conversions() {
        assert_eq!(Signal::Terminate.as_raw(), 15);
        assert_eq!(Signal::Interrupt.as_raw(), 2);
        assert_eq!(Signal::Hangup.as_raw(), 1);
        assert_eq!(Signal::Kill.as_raw(), 9);
        assert_eq!(Signal::from_raw(15), Signal::Terminate);
        assert_eq!(Signal::from_raw(2), Signal::Interrupt);
        assert_eq!(Signal::from_raw(1), Signal::Hangup);
        assert_eq!(Signal::Terminate.name(), "SIGTERM");
        assert_eq!(Signal::Interrupt.name(), "SIGINT");
        assert_eq!(Signal::Kill.name(), "SIGKILL");
    }

    #[test]
    fn test_child_signal_termination() {
        let mut cmd = Command::new("sleep");
        cmd.arg("10");
        let mut child = cmd.spawn().expect("spawn sleep process");

        // Request graceful termination
        child.terminate().expect("send SIGTERM");
        let status = child.wait().expect("wait for child termination");
        assert!(!status.success());
        #[cfg(unix)]
        {
            assert_eq!(status.signal(), Some(15));
        }
    }

    #[test]
    fn test_child_process_group_isolation() {
        let mut cmd = Command::new("sleep");
        cmd.arg("10");
        cmd.new_process_group();
        let mut child = cmd.spawn().expect("spawn process in new process group");

        let pid = child.id() as i32;
        let pgid = child.process_group_id().expect("retrieve process group id");
        #[cfg(unix)]
        {
            assert_eq!(
                pid, pgid,
                "Process group ID should match child PID when isolated"
            );
        }

        // Clean up using group signal
        child
            .send_group_signal(Signal::Kill)
            .expect("send group kill signal");
        let status = child.wait().expect("wait for child termination");
        assert!(!status.success());
    }

    #[test]
    fn test_pipeline_with_process_group() {
        let p = Pipeline::new()
            .new_process_group()
            .stdin_str("isolation\npipeline\ntest\n")
            .pipe(Command::new("grep").arg("pipe"))
            .pipe(Command::new("tr").args(["a-z", "A-Z"]));

        let out = p.output().expect("execute pipeline in process group");
        assert!(out.success());
        assert_eq!(out.stdout_string().trim(), "PIPELINE");
    }
}

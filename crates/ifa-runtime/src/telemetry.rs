//! System resource audit metrics and subprocess telemetry for IFA runtime, toolchain, and build orchestrator.

use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

/// Telemetry metrics capturing execution time, CPU utilization, and memory usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceUsage {
    /// Wall-clock execution time in nanoseconds.
    pub wall_time_ns: u64,
    /// CPU execution time (user + system) consumed in nanoseconds.
    pub cpu_time_ns: u64,
    /// Maximum resident set size (peak RSS) in bytes.
    pub max_rss_bytes: u64,
    /// Resident memory size (RSS) in bytes at sample time.
    pub resident_bytes: u64,
    /// Virtual memory size in bytes at sample time.
    pub virtual_bytes: u64,
    /// Number of available logical CPU cores.
    pub cpu_count: i64,
}

impl ResourceUsage {
    /// Capture current instantaneous process resource metrics.
    pub fn current() -> Self {
        Self {
            wall_time_ns: 0,
            cpu_time_ns: crate::ffi::ifa_rt_sys_cpu_time_ns(),
            max_rss_bytes: crate::ffi::ifa_rt_sys_max_rss(),
            resident_bytes: crate::ffi::ifa_rt_sys_memory_resident(),
            virtual_bytes: crate::ffi::ifa_rt_sys_memory_virtual(),
            cpu_count: crate::ffi::ifa_rt_sys_cpu_count(),
        }
    }

    /// Return wall-clock execution time as Duration.
    pub fn wall_duration(&self) -> Duration {
        Duration::from_nanos(self.wall_time_ns)
    }

    /// Return consumed CPU time as Duration.
    pub fn cpu_duration(&self) -> Duration {
        Duration::from_nanos(self.cpu_time_ns)
    }

    /// Format summary metrics as a human-readable telemetry string.
    pub fn format_summary(&self) -> String {
        let wall_ms = (self.wall_time_ns as f64) / 1_000_000.0;
        let cpu_ms = (self.cpu_time_ns as f64) / 1_000_000.0;
        let rss_mb = (self.max_rss_bytes as f64) / (1024.0 * 1024.0);
        format!(
            "wall: {:.2}ms, cpu: {:.2}ms, peak rss: {:.2}MB, cores: {}",
            wall_ms, cpu_ms, rss_mb, self.cpu_count
        )
    }
}

/// RAII scope for measuring execution resource usage and memory peak over a code block or pipeline phase.
#[derive(Debug, Clone)]
pub struct ResourceAuditScope {
    start_instant: Instant,
    start_cpu_ns: u64,
}

impl ResourceAuditScope {
    /// Start a new resource telemetry measurement scope.
    pub fn start() -> Self {
        Self {
            start_instant: Instant::now(),
            start_cpu_ns: crate::ffi::ifa_rt_sys_cpu_time_ns(),
        }
    }

    /// Complete measurement and return calculated resource usage metrics.
    pub fn finish(&self) -> ResourceUsage {
        let elapsed = self.start_instant.elapsed();
        let end_cpu_ns = crate::ffi::ifa_rt_sys_cpu_time_ns();
        let cpu_delta = end_cpu_ns.saturating_sub(self.start_cpu_ns);

        ResourceUsage {
            wall_time_ns: elapsed.as_nanos() as u64,
            cpu_time_ns: cpu_delta,
            max_rss_bytes: crate::ffi::ifa_rt_sys_max_rss(),
            resident_bytes: crate::ffi::ifa_rt_sys_memory_resident(),
            virtual_bytes: crate::ffi::ifa_rt_sys_memory_virtual(),
            cpu_count: crate::ffi::ifa_rt_sys_cpu_count(),
        }
    }
}

/// Supervise child process execution, collecting exit status and resource metrics.
pub fn supervise_command(cmd: &mut Command) -> std::io::Result<(ExitStatus, ResourceUsage)> {
    let scope = ResourceAuditScope::start();
    let status = cmd.status()?;
    let mut usage = scope.finish();

    #[cfg(unix)]
    {
        let mut child_rusage: libc::rusage = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut child_rusage) };
        if rc == 0 {
            let child_user_ns = (child_rusage.ru_utime.tv_sec as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add((child_rusage.ru_utime.tv_usec as u64).saturating_mul(1_000));
            let child_sys_ns = (child_rusage.ru_stime.tv_sec as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add((child_rusage.ru_stime.tv_usec as u64).saturating_mul(1_000));
            let child_cpu_ns = child_user_ns.saturating_add(child_sys_ns);
            if child_cpu_ns > 0 {
                usage.cpu_time_ns = child_cpu_ns;
            }
            #[cfg(target_os = "macos")]
            let child_rss = child_rusage.ru_maxrss as u64;
            #[cfg(not(target_os = "macos"))]
            let child_rss = (child_rusage.ru_maxrss as u64).saturating_mul(1024);
            if child_rss > 0 {
                usage.max_rss_bytes = child_rss;
            }
        }
    }

    Ok((status, usage))
}

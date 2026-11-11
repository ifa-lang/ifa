//! System resource audit, monitoring, and telemetry primitives (`std::sys`).
//!
//! Provides deterministic abstractions for querying system resource usage (`getrusage`),
//! process memory residency (RSS, virtual size), host memory information, CPU topology,
//! and load averages during compiler pipeline executions and child process supervision.

use std::fs;
use std::io;
use std::time::Duration;

#[cfg(unix)]
mod ffi {
    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct Timeval {
        pub tv_sec: i64,
        pub tv_usec: i64,
    }

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct Rusage {
        pub ru_utime: Timeval,
        pub ru_stime: Timeval,
        pub ru_maxrss: i64,
        pub ru_ixrss: i64,
        pub ru_idrss: i64,
        pub ru_isrss: i64,
        pub ru_minflt: i64,
        pub ru_majflt: i64,
        pub ru_nswap: i64,
        pub ru_inblock: i64,
        pub ru_oublock: i64,
        pub ru_msgsnd: i64,
        pub ru_msgrcv: i64,
        pub ru_nsignals: i64,
        pub ru_nvcsw: i64,
        pub ru_nivcsw: i64,
    }

    pub const RUSAGE_SELF: i32 = 0;
    pub const RUSAGE_CHILDREN: i32 = -1;
    pub const RUSAGE_THREAD: i32 = 1;

    extern "C" {
        pub fn getrusage(who: i32, usage: *mut Rusage) -> i32;
        pub fn getloadavg(loadavg: *mut f64, nelem: i32) -> i32;
        pub fn sysconf(name: i32) -> i64;
    }

    pub const _SC_PAGESIZE: i32 = 30;
}

/// Scope of resource accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceScope {
    /// Resources consumed by the calling process itself (`RUSAGE_SELF`).
    SelfProcess,
    /// Total cumulative resources consumed by all terminated and waited child processes (`RUSAGE_CHILDREN`).
    Children,
    /// Resources consumed by the calling thread (`RUSAGE_THREAD`).
    Thread,
}

impl ResourceScope {
    #[cfg(unix)]
    fn as_raw(self) -> i32 {
        match self {
            ResourceScope::SelfProcess => ffi::RUSAGE_SELF,
            ResourceScope::Children => ffi::RUSAGE_CHILDREN,
            ResourceScope::Thread => ffi::RUSAGE_THREAD,
        }
    }
}

/// Snapshot of system resources consumed by a process, its children, or a thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceUsage {
    /// Time spent executing in user mode.
    pub user_time: Duration,
    /// Time spent executing in kernel/system mode.
    pub system_time: Duration,
    /// Maximum resident set size (RSS) in bytes.
    pub max_resident_set_bytes: u64,
    /// Minor page faults (page reclaims without disk I/O).
    pub page_faults_minor: u64,
    /// Major page faults (requiring physical disk I/O).
    pub page_faults_major: u64,
    /// Number of block input operations.
    pub block_inputs: u64,
    /// Number of block output operations.
    pub block_outputs: u64,
    /// Number of voluntary context switches (e.g. waiting for I/O).
    pub voluntary_context_switches: u64,
    /// Number of involuntary context switches (e.g. CPU time slice expiration).
    pub involuntary_context_switches: u64,
}

impl ResourceUsage {
    /// Return the combined CPU time (user + system time).
    pub fn total_cpu_time(&self) -> Duration {
        self.user_time + self.system_time
    }

    /// Return maximum resident set size in megabytes (MiB, binary 1024*1024).
    pub fn max_rss_mb(&self) -> f64 {
        self.max_resident_set_bytes as f64 / (1024.0 * 1024.0)
    }

    /// Compute the differential resource usage between `self` (later) and `earlier`.
    ///
    /// Saturating subtraction is used so counters do not underflow.
    pub fn diff(&self, earlier: &ResourceUsage) -> ResourceUsage {
        ResourceUsage {
            user_time: self.user_time.saturating_sub(earlier.user_time),
            system_time: self.system_time.saturating_sub(earlier.system_time),
            max_resident_set_bytes: self
                .max_resident_set_bytes
                .max(earlier.max_resident_set_bytes),
            page_faults_minor: self
                .page_faults_minor
                .saturating_sub(earlier.page_faults_minor),
            page_faults_major: self
                .page_faults_major
                .saturating_sub(earlier.page_faults_major),
            block_inputs: self.block_inputs.saturating_sub(earlier.block_inputs),
            block_outputs: self.block_outputs.saturating_sub(earlier.block_outputs),
            voluntary_context_switches: self
                .voluntary_context_switches
                .saturating_sub(earlier.voluntary_context_switches),
            involuntary_context_switches: self
                .involuntary_context_switches
                .saturating_sub(earlier.involuntary_context_switches),
        }
    }
}

/// Query resource usage for the given scope (`SelfProcess`, `Children`, or `Thread`).
pub fn get_resource_usage(scope: ResourceScope) -> io::Result<ResourceUsage> {
    #[cfg(unix)]
    {
        let mut raw = ffi::Rusage::default();
        let res = unsafe { ffi::getrusage(scope.as_raw(), &mut raw) };
        if res != 0 {
            return Err(io::Error::last_os_error());
        }

        let user_time = Duration::new(
            raw.ru_utime.tv_sec.max(0) as u64,
            (raw.ru_utime.tv_usec.max(0) as u32) * 1000,
        );
        let system_time = Duration::new(
            raw.ru_stime.tv_sec.max(0) as u64,
            (raw.ru_stime.tv_usec.max(0) as u32) * 1000,
        );

        #[cfg(target_os = "linux")]
        let max_rss_bytes = (raw.ru_maxrss.max(0) as u64) * 1024;
        #[cfg(not(target_os = "linux"))]
        let max_rss_bytes = raw.ru_maxrss.max(0) as u64;

        Ok(ResourceUsage {
            user_time,
            system_time,
            max_resident_set_bytes: max_rss_bytes,
            page_faults_minor: raw.ru_minflt.max(0) as u64,
            page_faults_major: raw.ru_majflt.max(0) as u64,
            block_inputs: raw.ru_inblock.max(0) as u64,
            block_outputs: raw.ru_oublock.max(0) as u64,
            voluntary_context_switches: raw.ru_nvcsw.max(0) as u64,
            involuntary_context_switches: raw.ru_nivcsw.max(0) as u64,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = scope;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "getrusage is unsupported on non-unix platforms",
        ))
    }
}

/// Query cumulative resource usage of the calling process itself.
pub fn get_self_resource_usage() -> io::Result<ResourceUsage> {
    get_resource_usage(ResourceScope::SelfProcess)
}

/// Query cumulative resource usage of all terminated child processes.
pub fn get_children_resource_usage() -> io::Result<ResourceUsage> {
    get_resource_usage(ResourceScope::Children)
}

/// Memory statistics for an active running process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProcessMemoryInfo {
    /// Resident Set Size (RSS) in bytes: physical memory currently allocated.
    pub resident_bytes: u64,
    /// Virtual Memory Size (VSize) in bytes: total address space mapped.
    pub virtual_bytes: u64,
    /// Shared memory size in bytes: resident memory mapped to shared files/libraries.
    pub shared_bytes: u64,
    /// Data and stack segments size in bytes.
    pub data_bytes: u64,
    /// Peak resident set size (High Water Mark) in bytes, if available.
    pub peak_resident_bytes: Option<u64>,
}

impl ProcessMemoryInfo {
    /// Return resident memory in megabytes (MiB).
    pub fn resident_mb(&self) -> f64 {
        self.resident_bytes as f64 / (1024.0 * 1024.0)
    }

    /// Return virtual memory in megabytes (MiB).
    pub fn virtual_mb(&self) -> f64 {
        self.virtual_bytes as f64 / (1024.0 * 1024.0)
    }
}

/// Query memory usage statistics for the process with the given PID.
pub fn get_process_memory_info(pid: u32) -> io::Result<ProcessMemoryInfo> {
    #[cfg(target_os = "linux")]
    {
        let page_size = {
            let p = unsafe { ffi::sysconf(ffi::_SC_PAGESIZE) };
            if p > 0 {
                p as u64
            } else {
                4096
            }
        };

        let statm_path = format!("/proc/{}/statm", pid);
        let statm_content = fs::read_to_string(statm_path)?;
        let mut fields = statm_content.split_whitespace();

        let virt_pages: u64 = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let res_pages: u64 = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let shared_pages: u64 = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let _text_pages: u64 = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let _lib_pages: u64 = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let data_pages: u64 = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);

        let mut peak_resident = None;
        let status_path = format!("/proc/{}/status", pid);
        if let Ok(status_content) = fs::read_to_string(status_path) {
            for line in status_content.lines() {
                if let Some(rest) = line.strip_prefix("VmHWM:") {
                    let kb_str = rest.trim_start().trim_end_matches(" kB").trim();
                    if let Ok(kb) = kb_str.parse::<u64>() {
                        peak_resident = Some(kb * 1024);
                        break;
                    }
                }
            }
        }

        Ok(ProcessMemoryInfo {
            resident_bytes: res_pages.saturating_mul(page_size),
            virtual_bytes: virt_pages.saturating_mul(page_size),
            shared_bytes: shared_pages.saturating_mul(page_size),
            data_bytes: data_pages.saturating_mul(page_size),
            peak_resident_bytes: peak_resident,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        // Portable fallback using getrusage if querying self
        if pid == std::process::id() {
            if let Ok(ru) = get_self_resource_usage() {
                return Ok(ProcessMemoryInfo {
                    resident_bytes: ru.max_resident_set_bytes,
                    virtual_bytes: ru.max_resident_set_bytes,
                    shared_bytes: 0,
                    data_bytes: 0,
                    peak_resident_bytes: Some(ru.max_resident_set_bytes),
                });
            }
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Querying process memory info is only fully supported on Linux /proc",
        ))
    }
}

/// Query memory usage statistics for the current running process.
pub fn get_current_process_memory_info() -> io::Result<ProcessMemoryInfo> {
    get_process_process_memory_info_internal(std::process::id())
}

fn get_process_process_memory_info_internal(pid: u32) -> io::Result<ProcessMemoryInfo> {
    get_process_memory_info(pid)
}

/// Host system physical and virtual memory information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HostMemoryInfo {
    /// Total usable physical RAM in bytes.
    pub total_bytes: u64,
    /// Unused physical RAM in bytes.
    pub free_bytes: u64,
    /// Physical RAM available for starting new applications without swapping, in bytes.
    pub available_bytes: u64,
    /// Total swap space in bytes.
    pub swap_total_bytes: u64,
    /// Free swap space in bytes.
    pub swap_free_bytes: u64,
}

impl HostMemoryInfo {
    /// Memory currently in active use (total - available).
    pub fn used_bytes(&self) -> u64 {
        self.total_bytes.saturating_sub(self.available_bytes)
    }

    /// Ratio of memory used (between 0.0 and 1.0).
    pub fn used_ratio(&self) -> f64 {
        if self.total_bytes == 0 {
            0.0
        } else {
            self.used_bytes() as f64 / self.total_bytes as f64
        }
    }

    /// Total memory in gigabytes (GiB).
    pub fn total_gb(&self) -> f64 {
        self.total_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    }

    /// Available memory in gigabytes (GiB).
    pub fn available_gb(&self) -> f64 {
        self.available_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    }
}

/// Query host system memory information.
pub fn get_host_memory_info() -> io::Result<HostMemoryInfo> {
    #[cfg(target_os = "linux")]
    {
        let content = fs::read_to_string("/proc/meminfo")?;
        let mut total_kb = 0u64;
        let mut free_kb = 0u64;
        let mut avail_kb = 0u64;
        let mut swap_total_kb = 0u64;
        let mut swap_free_kb = 0u64;

        for line in content.lines() {
            let mut parts = line.split_whitespace();
            if let Some(key) = parts.next() {
                let val: u64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
                match key {
                    "MemTotal:" => total_kb = val,
                    "MemFree:" => free_kb = val,
                    "MemAvailable:" => avail_kb = val,
                    "SwapTotal:" => swap_total_kb = val,
                    "SwapFree:" => swap_free_kb = val,
                    _ => {}
                }
            }
        }

        // If MemAvailable was missing (kernels < 3.14), estimate it as MemFree
        if avail_kb == 0 && free_kb > 0 {
            avail_kb = free_kb;
        }

        Ok(HostMemoryInfo {
            total_bytes: total_kb * 1024,
            free_bytes: free_kb * 1024,
            available_bytes: avail_kb * 1024,
            swap_total_bytes: swap_total_kb * 1024,
            swap_free_bytes: swap_free_kb * 1024,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Host memory info is currently supported on Linux via /proc/meminfo",
        ))
    }
}

/// System CPU load average over 1, 5, and 15 minute intervals.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SystemLoad {
    /// Load average over the last 1 minute.
    pub one_minute: f64,
    /// Load average over the last 5 minutes.
    pub five_minutes: f64,
    /// Load average over the last 15 minutes.
    pub fifteen_minutes: f64,
}

/// Query system load averages.
pub fn get_system_load() -> io::Result<SystemLoad> {
    #[cfg(unix)]
    {
        let mut load = [0.0f64; 3];
        let res = unsafe { ffi::getloadavg(load.as_mut_ptr(), 3) };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(SystemLoad {
            one_minute: load[0],
            five_minutes: load[1],
            fifteen_minutes: load[2],
        })
    }
    #[cfg(not(unix))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "System load is unsupported on non-unix platforms",
        ))
    }
}

/// Query the number of available logical CPU cores.
pub fn cpu_count() -> usize {
    #[cfg(unix)]
    {
        let n = unsafe { ffi::sysconf(84) }; // _SC_NPROCESSORS_ONLN = 84 on linux
        if n > 0 {
            return n as usize;
        }
    }
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1)
}

/// Submodule alias `resources` for granular imports matching `std::sys::resources`.
pub mod resources {
    pub use super::{
        cpu_count, get_children_resource_usage, get_current_process_memory_info,
        get_host_memory_info, get_process_memory_info, get_resource_usage, get_self_resource_usage,
        get_system_load, HostMemoryInfo, ProcessMemoryInfo, ResourceScope, ResourceUsage,
        SystemLoad,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_resource_usage() {
        let usage =
            get_self_resource_usage().expect("get_self_resource_usage should succeed on Unix");
        assert!(
            usage.max_resident_set_bytes > 0,
            "max RSS should be non-zero"
        );
        let total = usage.total_cpu_time();
        assert!(total >= Duration::ZERO);
    }

    #[test]
    fn test_children_resource_usage() {
        let usage =
            get_children_resource_usage().expect("get_children_resource_usage should succeed");
        assert!(usage.total_cpu_time() >= Duration::ZERO);
    }

    #[test]
    fn test_resource_usage_diff() {
        let earlier = ResourceUsage {
            user_time: Duration::from_millis(100),
            system_time: Duration::from_millis(50),
            max_resident_set_bytes: 10_000_000,
            page_faults_minor: 50,
            page_faults_major: 2,
            block_inputs: 10,
            block_outputs: 5,
            voluntary_context_switches: 20,
            involuntary_context_switches: 4,
        };

        let later = ResourceUsage {
            user_time: Duration::from_millis(250),
            system_time: Duration::from_millis(120),
            max_resident_set_bytes: 15_000_000,
            page_faults_minor: 120,
            page_faults_major: 3,
            block_inputs: 15,
            block_outputs: 20,
            voluntary_context_switches: 35,
            involuntary_context_switches: 10,
        };

        let delta = later.diff(&earlier);
        assert_eq!(delta.user_time, Duration::from_millis(150));
        assert_eq!(delta.system_time, Duration::from_millis(70));
        assert_eq!(delta.total_cpu_time(), Duration::from_millis(220));
        assert_eq!(delta.max_resident_set_bytes, 15_000_000);
        assert_eq!(delta.page_faults_minor, 70);
        assert_eq!(delta.page_faults_major, 1);
        assert_eq!(delta.block_inputs, 5);
        assert_eq!(delta.block_outputs, 15);
        assert_eq!(delta.voluntary_context_switches, 15);
        assert_eq!(delta.involuntary_context_switches, 6);
    }

    #[test]
    fn test_process_memory_info() {
        let mem = get_current_process_memory_info()
            .expect("get_current_process_memory_info should succeed");
        assert!(mem.resident_bytes > 0, "resident memory must be > 0");
        assert!(
            mem.virtual_bytes >= mem.resident_bytes,
            "virtual size must be >= resident size"
        );
        assert!(mem.resident_mb() > 0.0);
    }

    #[test]
    fn test_host_memory_info() {
        if let Ok(host) = get_host_memory_info() {
            assert!(host.total_bytes > 0, "total host RAM must be > 0");
            assert!(
                host.available_bytes <= host.total_bytes,
                "available RAM <= total RAM"
            );
            assert!(host.used_ratio() >= 0.0 && host.used_ratio() <= 1.0);
            assert!(host.total_gb() > 0.0);
        }
    }

    #[test]
    fn test_cpu_count_and_load() {
        let cpus = cpu_count();
        assert!(cpus >= 1, "cpu_count should be at least 1");

        if let Ok(load) = get_system_load() {
            assert!(load.one_minute >= 0.0);
            assert!(load.five_minutes >= 0.0);
            assert!(load.fifteen_minutes >= 0.0);
        }
    }

    #[test]
    fn test_submodule_resources_reexports() {
        use resources::*;
        let self_usage = get_self_resource_usage().unwrap();
        assert!(self_usage.max_rss_mb() >= 0.0);
    }
}

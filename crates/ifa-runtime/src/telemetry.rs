//! System resource audit metrics and subprocess telemetry for IFA runtime, toolchain, and build orchestrator.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

// ─── Dynamic Multipath ISSP Balancing Telemetry & Exporters ─────────────────

/// Standard latency bucket thresholds in seconds for network interfaces and sessions:
/// 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s.
pub const DEFAULT_LATENCY_BUCKETS_SECONDS: [f64; 10] = [
    0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.000, 2.500,
];

/// Cumulative latency histogram tracking round-trip and transmission latencies.
#[derive(Debug, Clone, PartialEq)]
pub struct LatencyHistogram {
    /// Upper bounds for each cumulative bucket in seconds.
    pub buckets: Vec<f64>,
    /// Cumulative counts for each bucket.
    pub cumulative_counts: Vec<u64>,
    /// Total count of all observed samples.
    pub count: u64,
    /// Sum of all observed sample durations in seconds.
    pub sum_seconds: f64,
    /// Minimum observed sample in seconds.
    pub min_seconds: f64,
    /// Maximum observed sample in seconds.
    pub max_seconds: f64,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new(None)
    }
}

impl LatencyHistogram {
    /// Create a new latency histogram with custom bucket thresholds or defaults.
    pub fn new(buckets: Option<&[f64]>) -> Self {
        let b = match buckets {
            Some(custom) => custom.to_vec(),
            None => DEFAULT_LATENCY_BUCKETS_SECONDS.to_vec(),
        };
        let len = b.len();
        Self {
            buckets: b,
            cumulative_counts: vec![0; len],
            count: 0,
            sum_seconds: 0.0,
            min_seconds: f64::INFINITY,
            max_seconds: 0.0,
        }
    }

    /// Record a single latency observation in seconds.
    pub fn observe(&mut self, sample_seconds: f64) {
        if sample_seconds.is_nan() || sample_seconds < 0.0 {
            return;
        }
        self.count = self.count.saturating_add(1);
        self.sum_seconds += sample_seconds;
        if sample_seconds < self.min_seconds {
            self.min_seconds = sample_seconds;
        }
        if sample_seconds > self.max_seconds {
            self.max_seconds = sample_seconds;
        }
        for (idx, &bound) in self.buckets.iter().enumerate() {
            if sample_seconds <= bound {
                self.cumulative_counts[idx] = self.cumulative_counts[idx].saturating_add(1);
            }
        }
    }

    /// Record a single latency observation in microseconds.
    pub fn observe_us(&mut self, sample_us: u64) {
        self.observe((sample_us as f64) / 1_000_000.0);
    }

    /// Merge another latency histogram into this one.
    pub fn merge(&mut self, other: &LatencyHistogram) {
        if other.count == 0 {
            return;
        }
        self.count = self.count.saturating_add(other.count);
        self.sum_seconds += other.sum_seconds;
        if other.min_seconds < self.min_seconds {
            self.min_seconds = other.min_seconds;
        }
        if other.max_seconds > self.max_seconds {
            self.max_seconds = other.max_seconds;
        }
        if self.buckets == other.buckets {
            for (idx, val) in other.cumulative_counts.iter().enumerate() {
                if idx < self.cumulative_counts.len() {
                    self.cumulative_counts[idx] = self.cumulative_counts[idx].saturating_add(*val);
                }
            }
        }
    }

    /// Calculate mean latency in seconds. Returns 0.0 if count is 0.
    pub fn mean_seconds(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum_seconds / (self.count as f64)
        }
    }

    /// Safe minimum in seconds (0.0 if no observations recorded).
    pub fn safe_min_seconds(&self) -> f64 {
        if self.min_seconds.is_infinite() {
            0.0
        } else {
            self.min_seconds
        }
    }
}

/// Telemetry metrics snapshot for dynamic multipath ISSP bandwidth balancing.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspMultipathBalancingSnapshot {
    /// Timestamp when this snapshot was collected, in nanoseconds since Unix epoch.
    pub timestamp_unix_ns: u64,
    /// Identifier of the local cluster node hosting the router.
    pub node_id: u32,
    /// Active multipath routing policy name (e.g. "BandwidthAggregation", "ActiveStandby").
    pub routing_policy: String,
    /// Total configured transport paths.
    pub total_paths: usize,
    /// Number of paths currently usable for traffic (Active, Degraded, Probation).
    pub active_paths: usize,
    /// Sum of effective weights across all usable paths.
    pub total_effective_weight: u32,
    /// Detailed balancing metrics per subpath.
    pub subpaths: Vec<IsspSubpathBalancingMetrics>,
    /// Aggregated latency histograms indexed by network interface name (e.g. "eth0-wan", "wwan0-5g").
    pub interface_latency_histograms: BTreeMap<String, LatencyHistogram>,
    /// TCP retransmission ratio indexed by network interface name.
    pub interface_tcp_retrans_ratios: BTreeMap<String, f64>,
    /// ISSP retransmission ratio indexed by network interface name.
    pub interface_issp_retrans_ratios: BTreeMap<String, f64>,
    /// Total cluster sessions tracked.
    pub total_sessions: usize,
    /// Primary active sessions owned by local node.
    pub primary_sessions: usize,
    /// Standby shadow-replicated sessions.
    pub standby_sessions: usize,
    /// Total TCP retransmissions across all operational subpaths.
    pub total_tcp_retransmissions: u64,
    /// Total ISSP retransmissions across all operational subpaths.
    pub total_issp_retransmissions: u64,
    /// Aggregate TCP retransmission ratio across all operational subpaths.
    pub aggregate_tcp_retrans_ratio: f64,
    /// Aggregate ISSP retransmission ratio across all operational subpaths.
    pub aggregate_issp_retrans_ratio: f64,
}

impl IsspMultipathBalancingSnapshot {
    /// Capture a balancing snapshot from an `IsspDynamicMultipathRouter`.
    /// If `timestamp_unix_ns` is 0, the current system clock is sampled.
    pub fn from_router(
        router: &crate::session_sync::IsspDynamicMultipathRouter,
        timestamp_unix_ns: u64,
    ) -> Self {
        let ts = if timestamp_unix_ns == 0 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
        } else {
            timestamp_unix_ns
        };

        let mut usable_paths = Vec::new();
        let mut total_eff_w: u32 = 0;

        for route in router.routes() {
            if route.state.is_usable() {
                let eff_w = route.effective_weight();
                total_eff_w = total_eff_w.saturating_add(eff_w);
                usable_paths.push((route.path_id, eff_w));
            }
        }

        let mut iface_histograms: BTreeMap<String, LatencyHistogram> = BTreeMap::new();
        let mut iface_tx_frames: BTreeMap<String, u64> = BTreeMap::new();
        let mut iface_tcp_retrans: BTreeMap<String, u64> = BTreeMap::new();
        let mut iface_issp_retrans: BTreeMap<String, u64> = BTreeMap::new();

        let mut total_tcp_retrans: u64 = 0;
        let mut total_issp_retrans: u64 = 0;
        let mut total_tx_frames: u64 = 0;

        for route in router.routes() {
            let iface = route.interface_name.clone();
            let tcp_ret = route.metrics.tcp_retrans_count;
            let issp_ret = route.metrics.issp_retrans_count;
            let frames_sent = route.metrics.total_frames_sent;

            total_tcp_retrans = total_tcp_retrans.saturating_add(tcp_ret);
            total_issp_retrans = total_issp_retrans.saturating_add(issp_ret);
            total_tx_frames = total_tx_frames.saturating_add(frames_sent);

            let cur_tx = iface_tx_frames.entry(iface.clone()).or_insert(0);
            *cur_tx = cur_tx.saturating_add(frames_sent);

            let cur_tcp = iface_tcp_retrans.entry(iface.clone()).or_insert(0);
            *cur_tcp = cur_tcp.saturating_add(tcp_ret);

            let cur_issp = iface_issp_retrans.entry(iface.clone()).or_insert(0);
            *cur_issp = cur_issp.saturating_add(issp_ret);

            iface_histograms
                .entry(iface)
                .or_default()
                .merge(&route.metrics.latency_histogram);
        }

        let mut iface_tcp_ratios = BTreeMap::new();
        let mut iface_issp_ratios = BTreeMap::new();
        for (iface, frames) in &iface_tx_frames {
            let tcp_ret = *iface_tcp_retrans.get(iface).unwrap_or(&0);
            let issp_ret = *iface_issp_retrans.get(iface).unwrap_or(&0);
            let tcp_r = if *frames == 0 {
                0.0
            } else {
                (tcp_ret as f64) / (*frames as f64)
            };
            let issp_r = if *frames == 0 {
                0.0
            } else {
                (issp_ret as f64) / (*frames as f64)
            };
            iface_tcp_ratios.insert(iface.clone(), tcp_r.clamp(0.0, 1.0));
            iface_issp_ratios.insert(iface.clone(), issp_r.clamp(0.0, 1.0));
        }

        let agg_tcp_ratio = if total_tx_frames == 0 {
            0.0
        } else {
            ((total_tcp_retrans as f64) / (total_tx_frames as f64)).clamp(0.0, 1.0)
        };
        let agg_issp_ratio = if total_tx_frames == 0 {
            0.0
        } else {
            ((total_issp_retrans as f64) / (total_tx_frames as f64)).clamp(0.0, 1.0)
        };

        let mut subpaths = Vec::with_capacity(router.routes().count());
        for route in router.routes() {
            let eff_w = route.effective_weight();
            let is_usable = route.state.is_usable();
            let (share_ratio, share_percent) = if is_usable && total_eff_w > 0 {
                let r = (eff_w as f64) / (total_eff_w as f64);
                (r, r * 100.0)
            } else {
                (0.0, 0.0)
            };

            let rt_prop = if route.congestion.bbr.rt_prop_us == u64::MAX {
                route.metrics.smoothed_rtt_us
            } else {
                route.congestion.bbr.rt_prop_us
            };

            let tcp_ret = route.metrics.tcp_retrans_count;
            let issp_ret = route.metrics.issp_retrans_count;
            let tcp_ratio = route.metrics.tcp_retransmission_ratio();
            let issp_ratio = route.metrics.issp_retransmission_ratio();
            let total_ratio = route.metrics.total_retransmission_ratio();
            let lat_hist = route.metrics.latency_histogram.clone();

            subpaths.push(IsspSubpathBalancingMetrics {
                path_id: route.path_id,
                interface_name: route.interface_name.clone(),
                state: format!("{:?}", route.state),
                is_usable,
                priority: route.priority,
                configured_weight: route.weight,
                effective_weight: eff_w,
                traffic_share_ratio: share_ratio,
                traffic_share_percent: share_percent,
                rtt_us: route.metrics.smoothed_rtt_us,
                rt_prop_us: rt_prop,
                rtt_gradient_us: route.congestion.ledbat.queuing_delay_us,
                bbr_bw_bps: route.congestion.bbr.estimated_bandwidth_bps,
                bbr_pacing_gain_q8: route.congestion.bbr.pacing_gain_q8,
                ledbat_cwnd_bytes: route.congestion.ledbat.cwnd_bytes,
                ledbat_target_delay_us: route.congestion.ledbat.target_delay_us,
                congestion_phase: format!("{:?}", route.congestion.phase),
                congestion_weight_factor: route.congestion.congestion_weight_factor(),
                congestion_events: route.congestion.congestion_events,
                bytes_in_flight: route.congestion.bytes_in_flight,
                total_frames_sent: route.metrics.total_frames_sent,
                total_frames_received: route.metrics.total_frames_received,
                tcp_retrans_count: tcp_ret,
                issp_retrans_count: issp_ret,
                tcp_retrans_ratio: tcp_ratio,
                issp_retrans_ratio: issp_ratio,
                total_retrans_ratio: total_ratio,
                latency_histogram: lat_hist,
            });
        }

        Self {
            timestamp_unix_ns: ts,
            node_id: router.node_id(),
            routing_policy: format!("{:?}", router.policy()),
            total_paths: router.routes().count(),
            active_paths: usable_paths.len(),
            total_effective_weight: total_eff_w,
            subpaths,
            interface_latency_histograms: iface_histograms,
            interface_tcp_retrans_ratios: iface_tcp_ratios,
            interface_issp_retrans_ratios: iface_issp_ratios,
            total_sessions: 0,
            primary_sessions: 0,
            standby_sessions: 0,
            total_tcp_retransmissions: total_tcp_retrans,
            total_issp_retransmissions: total_issp_retrans,
            aggregate_tcp_retrans_ratio: agg_tcp_ratio,
            aggregate_issp_retrans_ratio: agg_issp_ratio,
        }
    }

    /// Capture a balancing snapshot from a `SessionRegistry`, enriching metrics with live session counts.
    pub fn from_registry(
        registry: &crate::session_sync::SessionRegistry,
        timestamp_unix_ns: u64,
    ) -> Result<Self, crate::session_sync::SyncError> {
        let (total_s, primary_s, standby_s) = registry.session_counts()?;
        let router = registry
            .multipath_router
            .lock()
            .map_err(|_| crate::session_sync::SyncError::LockPoisoned)?;
        let mut snap = Self::from_router(&router, timestamp_unix_ns);
        snap.total_sessions = total_s;
        snap.primary_sessions = primary_s;
        snap.standby_sessions = standby_s;
        Ok(snap)
    }

    /// Retrieve balancing metrics for a specific subpath ID if present.
    pub fn subpath(&self, path_id: u32) -> Option<&IsspSubpathBalancingMetrics> {
        self.subpaths.iter().find(|s| s.path_id == path_id)
    }

    /// Export snapshot in standard Prometheus 0.0.4 text format.
    pub fn export_prometheus(&self) -> String {
        PrometheusMultipathBalancingExporter::new().export(self)
    }

    /// Export snapshot in standard OpenTelemetry OTLP JSON (v1/metrics) format.
    pub fn export_otlp_json(&self, service_name: &str) -> String {
        OtelMultipathBalancingExporter::new().export(self, service_name)
    }
}

/// Detailed dynamic bandwidth balancing and congestion metrics for a single subpath.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspSubpathBalancingMetrics {
    /// Unique identifier for this transport subpath.
    pub path_id: u32,
    /// Physical or virtual network interface name (e.g. "eth0-wan", "wwan0-5g").
    pub interface_name: String,
    /// Operational state string ("Active", "Standby", "Degraded", "Probation", "Failed").
    pub state: String,
    /// Whether this subpath is currently eligible to carry user traffic.
    pub is_usable: bool,
    /// Administrative priority (1 = highest).
    pub priority: u32,
    /// Base configured administrative weight.
    pub configured_weight: u32,
    /// Dynamically adjusted effective scheduling weight after applying flap damping, probation ramp, and congestion factors.
    pub effective_weight: u32,
    /// Fraction of aggregate traffic allocated to this subpath (0.0 to 1.0).
    pub traffic_share_ratio: f64,
    /// Percentage of aggregate traffic allocated to this subpath (0.0% to 100.0%).
    pub traffic_share_percent: f64,
    /// Smoothed round-trip time in microseconds.
    pub rtt_us: u64,
    /// Propagation delay baseline / RTprop in microseconds (BBR / min filter).
    pub rt_prop_us: u64,
    /// RTT gradient / queuing delay in microseconds (RTT - RTprop, from LEDBAT).
    pub rtt_gradient_us: u64,
    /// BBR estimated bottleneck bandwidth (BtlBw) in bits per second.
    pub bbr_bw_bps: u64,
    /// BBR pacing gain (Q8.8 fixed point: 256 = 1.0x).
    pub bbr_pacing_gain_q8: u32,
    /// LEDBAT congestion window (CWND) in bytes.
    pub ledbat_cwnd_bytes: u64,
    /// LEDBAT target queuing delay threshold in microseconds (RFC 6817, default 25000 µs).
    pub ledbat_target_delay_us: u64,
    /// Current congestion phase name ("SlowStart", "CongestionAvoidance", "Recovery").
    pub congestion_phase: String,
    /// Dynamic congestion weight factor in [0.05, 1.0].
    pub congestion_weight_factor: f64,
    /// Cumulative count of congestion events (loss or delay target exceeded) observed on this subpath.
    pub congestion_events: u64,
    /// Bytes in flight on this subpath.
    pub bytes_in_flight: u64,
    /// Total frames sent across this subpath.
    pub total_frames_sent: u64,
    /// Total frames received across this subpath.
    pub total_frames_received: u64,
    /// Cumulative count of TCP segment retransmissions detected on this subpath.
    pub tcp_retrans_count: u64,
    /// Cumulative count of ISSP datagram capsule retransmissions on this subpath.
    pub issp_retrans_count: u64,
    /// TCP retransmission ratio [0.0 - 1.0].
    pub tcp_retrans_ratio: f64,
    /// ISSP retransmission ratio [0.0 - 1.0].
    pub issp_retrans_ratio: f64,
    /// Total combined retransmission ratio [0.0 - 1.0].
    pub total_retrans_ratio: f64,
    /// Latency histogram distribution for this specific subpath.
    pub latency_histogram: LatencyHistogram,
}

// ─── Prometheus Exposition Format 0.0.4 Exporter ────────────────────────────

/// Prometheus Exposition Format 0.0.4 exporter for dynamic ISSP multipath metrics.
#[derive(Debug, Clone, Default)]
pub struct PrometheusMultipathBalancingExporter {
    pub default_labels: BTreeMap<String, String>,
}

impl PrometheusMultipathBalancingExporter {
    /// Create a new Prometheus multipath balancing exporter.
    pub fn new() -> Self {
        Self {
            default_labels: BTreeMap::new(),
        }
    }

    /// Add a default label applied to all exported metrics.
    pub fn with_label(mut self, key: &str, value: &str) -> Self {
        self.default_labels
            .insert(key.to_string(), value.to_string());
        self
    }

    fn format_labels(&self, extra: &[(&str, &str)]) -> String {
        let mut all = self.default_labels.clone();
        for (k, v) in extra {
            all.insert(k.to_string(), v.to_string());
        }
        if all.is_empty() {
            String::new()
        } else {
            let pairs: Vec<String> = all
                .iter()
                .map(|(k, v)| format!("{}=\"{}\"", k, v))
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
    }

    /// Export an `IsspMultipathBalancingSnapshot` into standard Prometheus 0.0.4 text format.
    pub fn export(&self, s: &IsspMultipathBalancingSnapshot) -> String {
        let mut out = String::with_capacity(4096);
        let node_str = s.node_id.to_string();
        let base_lbl = self.format_labels(&[("node_id", &node_str), ("policy", &s.routing_policy)]);

        // 1. Global multipath pool gauges
        out.push_str(
            "# HELP ifa_issp_multipath_total_paths Total configured ISSP multipath subpaths.\n",
        );
        out.push_str("# TYPE ifa_issp_multipath_total_paths gauge\n");
        out.push_str(&format!(
            "ifa_issp_multipath_total_paths{} {}\n",
            base_lbl, s.total_paths
        ));

        out.push_str("# HELP ifa_issp_multipath_active_paths Number of currently operational multipath subpaths.\n");
        out.push_str("# TYPE ifa_issp_multipath_active_paths gauge\n");
        out.push_str(&format!(
            "ifa_issp_multipath_active_paths{} {}\n",
            base_lbl, s.active_paths
        ));

        out.push_str("# HELP ifa_issp_multipath_total_effective_weight Aggregate effective scheduling weight across all usable subpaths.\n");
        out.push_str("# TYPE ifa_issp_multipath_total_effective_weight gauge\n");
        out.push_str(&format!(
            "ifa_issp_multipath_total_effective_weight{} {}\n",
            base_lbl, s.total_effective_weight
        ));

        // Cluster session metrics
        out.push_str("# HELP ifa_session_total_sessions Total active sessions tracked in registry.\n");
        out.push_str("# TYPE ifa_session_total_sessions gauge\n");
        out.push_str(&format!(
            "ifa_session_total_sessions{} {}\n",
            base_lbl, s.total_sessions
        ));

        out.push_str("# HELP ifa_session_primary_sessions Primary active sessions owned by local node.\n");
        out.push_str("# TYPE ifa_session_primary_sessions gauge\n");
        out.push_str(&format!(
            "ifa_session_primary_sessions{} {}\n",
            base_lbl, s.primary_sessions
        ));

        out.push_str("# HELP ifa_session_standby_sessions Standby shadow-replicated sessions.\n");
        out.push_str("# TYPE ifa_session_standby_sessions gauge\n");
        out.push_str(&format!(
            "ifa_session_standby_sessions{} {}\n",
            base_lbl, s.standby_sessions
        ));

        // 2. Per-subpath metrics
        if !s.subpaths.is_empty() {
            // Configured weight
            out.push_str("# HELP ifa_issp_subpath_configured_weight Administrative base weight configured for subpath.\n");
            out.push_str("# TYPE ifa_issp_subpath_configured_weight gauge\n");
            for sp in &s.subpaths {
                let p_id = sp.path_id.to_string();
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("path_id", &p_id),
                    ("interface", &sp.interface_name),
                    ("state", &sp.state),
                    ("phase", &sp.congestion_phase),
                ]);
                out.push_str(&format!(
                    "ifa_issp_subpath_configured_weight{} {}\n",
                    lbl, sp.configured_weight
                ));
            }

            // Effective weight
            out.push_str("# HELP ifa_issp_subpath_effective_weight Dynamic effective scheduling weight after damping and congestion adjustment.\n");
            out.push_str("# TYPE ifa_issp_subpath_effective_weight gauge\n");
            for sp in &s.subpaths {
                let p_id = sp.path_id.to_string();
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("path_id", &p_id),
                    ("interface", &sp.interface_name),
                    ("state", &sp.state),
                    ("phase", &sp.congestion_phase),
                ]);
                out.push_str(&format!(
                    "ifa_issp_subpath_effective_weight{} {}\n",
                    lbl, sp.effective_weight
                ));
            }

            // Traffic share ratio [0.0 - 1.0]
            out.push_str("# HELP ifa_issp_subpath_traffic_share_ratio Dynamic traffic allocation ratio for this subpath [0.0 - 1.0].\n");
            out.push_str("# TYPE ifa_issp_subpath_traffic_share_ratio gauge\n");
            for sp in &s.subpaths {
                let p_id = sp.path_id.to_string();
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("path_id", &p_id),
                    ("interface", &sp.interface_name),
                    ("state", &sp.state),
                    ("phase", &sp.congestion_phase),
                ]);
                out.push_str(&format!(
                    "ifa_issp_subpath_traffic_share_ratio{} {:.6}\n",
                    lbl, sp.traffic_share_ratio
                ));
            }

            // Traffic share percent [0.0 - 100.0]
            out.push_str("# HELP ifa_issp_subpath_traffic_share_percent Dynamic traffic allocation percentage for this subpath [0.0 - 100.0].\n");
            out.push_str("# TYPE ifa_issp_subpath_traffic_share_percent gauge\n");
            for sp in &s.subpaths {
                let p_id = sp.path_id.to_string();
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("path_id", &p_id),
                    ("interface", &sp.interface_name),
                    ("state", &sp.state),
                    ("phase", &sp.congestion_phase),
                ]);
                out.push_str(&format!(
                    "ifa_issp_subpath_traffic_share_percent{} {:.2}\n",
                    lbl, sp.traffic_share_percent
                ));
            }

            // RTT in seconds
            out.push_str(
                "# HELP ifa_issp_subpath_rtt_seconds Smoothed round-trip time in seconds.\n",
            );
            out.push_str("# TYPE ifa_issp_subpath_rtt_seconds gauge\n");
            for sp in &s.subpaths {
                let p_id = sp.path_id.to_string();
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("path_id", &p_id),
                    ("interface", &sp.interface_name),
                    ("state", &sp.state),
                    ("phase", &sp.congestion_phase),
                ]);
                out.push_str(&format!(
                    "ifa_issp_subpath_rtt_seconds{} {:.6}\n",
                    lbl,
                    (sp.rtt_us as f64) / 1_000_000.0
                ));
            }

            // RTT gradient / queuing delay in seconds
            out.push_str("# HELP ifa_issp_subpath_rtt_gradient_seconds Delay gradient / queuing delay in seconds (from LEDBAT).\n");
            out.push_str("# TYPE ifa_issp_subpath_rtt_gradient_seconds gauge\n");
            for sp in &s.subpaths {
                let p_id = sp.path_id.to_string();
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("path_id", &p_id),
                    ("interface", &sp.interface_name),
                    ("state", &sp.state),
                    ("phase", &sp.congestion_phase),
                ]);
                out.push_str(&format!(
                    "ifa_issp_subpath_rtt_gradient_seconds{} {:.6}\n",
                    lbl,
                    (sp.rtt_gradient_us as f64) / 1_000_000.0
                ));
            }

            // BBR BtlBw in bps
            out.push_str("# HELP ifa_issp_subpath_bbr_bw_bps BBR estimated bottleneck bandwidth in bits per second.\n");
            out.push_str("# TYPE ifa_issp_subpath_bbr_bw_bps gauge\n");
            for sp in &s.subpaths {
                let p_id = sp.path_id.to_string();
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("path_id", &p_id),
                    ("interface", &sp.interface_name),
                    ("state", &sp.state),
                    ("phase", &sp.congestion_phase),
                ]);
                out.push_str(&format!(
                    "ifa_issp_subpath_bbr_bw_bps{} {}\n",
                    lbl, sp.bbr_bw_bps
                ));
            }

            // BBR pacing gain
            out.push_str("# HELP ifa_issp_subpath_bbr_pacing_gain BBR pacing gain multiplier (1.0 = nominal).\n");
            out.push_str("# TYPE ifa_issp_subpath_bbr_pacing_gain gauge\n");
            for sp in &s.subpaths {
                let p_id = sp.path_id.to_string();
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("path_id", &p_id),
                    ("interface", &sp.interface_name),
                    ("state", &sp.state),
                    ("phase", &sp.congestion_phase),
                ]);
                out.push_str(&format!(
                    "ifa_issp_subpath_bbr_pacing_gain{} {:.4}\n",
                    lbl,
                    (sp.bbr_pacing_gain_q8 as f64) / 256.0
                ));
            }

            // LEDBAT CWND in bytes
            out.push_str(
                "# HELP ifa_issp_subpath_ledbat_cwnd_bytes LEDBAT congestion window in bytes.\n",
            );
            out.push_str("# TYPE ifa_issp_subpath_ledbat_cwnd_bytes gauge\n");
            for sp in &s.subpaths {
                let p_id = sp.path_id.to_string();
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("path_id", &p_id),
                    ("interface", &sp.interface_name),
                    ("state", &sp.state),
                    ("phase", &sp.congestion_phase),
                ]);
                out.push_str(&format!(
                    "ifa_issp_subpath_ledbat_cwnd_bytes{} {}\n",
                    lbl, sp.ledbat_cwnd_bytes
                ));
            }

            // Congestion weight factor
            out.push_str("# HELP ifa_issp_subpath_congestion_weight_factor Dynamic congestion penalty weight factor [0.05, 1.0].\n");
            out.push_str("# TYPE ifa_issp_subpath_congestion_weight_factor gauge\n");
            for sp in &s.subpaths {
                let p_id = sp.path_id.to_string();
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("path_id", &p_id),
                    ("interface", &sp.interface_name),
                    ("state", &sp.state),
                    ("phase", &sp.congestion_phase),
                ]);
                out.push_str(&format!(
                    "ifa_issp_subpath_congestion_weight_factor{} {:.4}\n",
                    lbl, sp.congestion_weight_factor
                ));
            }

            // Congestion events total
            out.push_str("# HELP ifa_issp_subpath_congestion_events_total Total congestion signals/events observed on subpath.\n");
            out.push_str("# TYPE ifa_issp_subpath_congestion_events_total counter\n");
            for sp in &s.subpaths {
                let p_id = sp.path_id.to_string();
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("path_id", &p_id),
                    ("interface", &sp.interface_name),
                    ("state", &sp.state),
                    ("phase", &sp.congestion_phase),
                ]);
                out.push_str(&format!(
                    "ifa_issp_subpath_congestion_events_total{} {}\n",
                    lbl, sp.congestion_events
                ));
            }

            // Bytes in flight
            out.push_str("# HELP ifa_issp_subpath_bytes_in_flight Unacknowledged bytes in flight on subpath.\n");
            out.push_str("# TYPE ifa_issp_subpath_bytes_in_flight gauge\n");
            for sp in &s.subpaths {
                let p_id = sp.path_id.to_string();
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("path_id", &p_id),
                    ("interface", &sp.interface_name),
                    ("state", &sp.state),
                    ("phase", &sp.congestion_phase),
                ]);
                out.push_str(&format!(
                    "ifa_issp_subpath_bytes_in_flight{} {}\n",
                    lbl, sp.bytes_in_flight
                ));
            }

            // Frames sent
            out.push_str("# HELP ifa_issp_subpath_frames_sent_total Total datagram frames transmitted across subpath.\n");
            out.push_str("# TYPE ifa_issp_subpath_frames_sent_total counter\n");
            for sp in &s.subpaths {
                let p_id = sp.path_id.to_string();
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("path_id", &p_id),
                    ("interface", &sp.interface_name),
                    ("state", &sp.state),
                    ("phase", &sp.congestion_phase),
                ]);
                out.push_str(&format!(
                    "ifa_issp_subpath_frames_sent_total{} {}\n",
                    lbl, sp.total_frames_sent
                ));
            }

            // Frames received
            out.push_str("# HELP ifa_issp_subpath_frames_received_total Total datagram frames received across subpath.\n");
            out.push_str("# TYPE ifa_issp_subpath_frames_received_total counter\n");
            for sp in &s.subpaths {
                let p_id = sp.path_id.to_string();
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("path_id", &p_id),
                    ("interface", &sp.interface_name),
                    ("state", &sp.state),
                    ("phase", &sp.congestion_phase),
                ]);
                out.push_str(&format!(
                    "ifa_issp_subpath_frames_received_total{} {}\n",
                    lbl, sp.total_frames_received
                ));
            }

            // Subpath TCP Retransmissions Total
            out.push_str("# HELP ifa_issp_subpath_tcp_retransmissions_total Total TCP segment retransmissions detected on subpath.\n");
            out.push_str("# TYPE ifa_issp_subpath_tcp_retransmissions_total counter\n");
            for sp in &s.subpaths {
                let p_id = sp.path_id.to_string();
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("path_id", &p_id),
                    ("interface", &sp.interface_name),
                    ("state", &sp.state),
                    ("phase", &sp.congestion_phase),
                ]);
                out.push_str(&format!(
                    "ifa_issp_subpath_tcp_retransmissions_total{} {}\n",
                    lbl, sp.tcp_retrans_count
                ));
            }

            // Subpath ISSP Retransmissions Total
            out.push_str("# HELP ifa_issp_subpath_issp_retransmissions_total Total ISSP capsule retransmissions on subpath.\n");
            out.push_str("# TYPE ifa_issp_subpath_issp_retransmissions_total counter\n");
            for sp in &s.subpaths {
                let p_id = sp.path_id.to_string();
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("path_id", &p_id),
                    ("interface", &sp.interface_name),
                    ("state", &sp.state),
                    ("phase", &sp.congestion_phase),
                ]);
                out.push_str(&format!(
                    "ifa_issp_subpath_issp_retransmissions_total{} {}\n",
                    lbl, sp.issp_retrans_count
                ));
            }

            // Subpath TCP Retransmission Ratio
            out.push_str("# HELP ifa_issp_subpath_tcp_retransmission_ratio Retransmission ratio for TCP traffic on subpath [0.0 - 1.0].\n");
            out.push_str("# TYPE ifa_issp_subpath_tcp_retransmission_ratio gauge\n");
            for sp in &s.subpaths {
                let p_id = sp.path_id.to_string();
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("path_id", &p_id),
                    ("interface", &sp.interface_name),
                    ("state", &sp.state),
                    ("phase", &sp.congestion_phase),
                ]);
                out.push_str(&format!(
                    "ifa_issp_subpath_tcp_retransmission_ratio{} {:.6}\n",
                    lbl, sp.tcp_retrans_ratio
                ));
            }

            // Subpath ISSP Retransmission Ratio
            out.push_str("# HELP ifa_issp_subpath_issp_retransmission_ratio Retransmission ratio for ISSP traffic on subpath [0.0 - 1.0].\n");
            out.push_str("# TYPE ifa_issp_subpath_issp_retransmission_ratio gauge\n");
            for sp in &s.subpaths {
                let p_id = sp.path_id.to_string();
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("path_id", &p_id),
                    ("interface", &sp.interface_name),
                    ("state", &sp.state),
                    ("phase", &sp.congestion_phase),
                ]);
                out.push_str(&format!(
                    "ifa_issp_subpath_issp_retransmission_ratio{} {:.6}\n",
                    lbl, sp.issp_retrans_ratio
                ));
            }
        }

        // 3. Interface Latency Histograms
        if !s.interface_latency_histograms.is_empty() {
            out.push_str("# HELP ifa_issp_interface_latency_seconds Latency histogram distribution per physical/virtual network interface.\n");
            out.push_str("# TYPE ifa_issp_interface_latency_seconds histogram\n");
            for (iface, hist) in &s.interface_latency_histograms {
                for (idx, &bound) in hist.buckets.iter().enumerate() {
                    let le_str = format!("{:.3}", bound);
                    let lbl = self.format_labels(&[
                        ("node_id", &node_str),
                        ("interface", iface),
                        ("le", &le_str),
                    ]);
                    out.push_str(&format!(
                        "ifa_issp_interface_latency_seconds_bucket{} {}\n",
                        lbl, hist.cumulative_counts[idx]
                    ));
                }
                let inf_lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("interface", iface),
                    ("le", "+Inf"),
                ]);
                out.push_str(&format!(
                    "ifa_issp_interface_latency_seconds_bucket{} {}\n",
                    inf_lbl, hist.count
                ));
                let sum_lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("interface", iface),
                ]);
                out.push_str(&format!(
                    "ifa_issp_interface_latency_seconds_sum{} {:.6}\n",
                    sum_lbl, hist.sum_seconds
                ));
                out.push_str(&format!(
                    "ifa_issp_interface_latency_seconds_count{} {}\n",
                    sum_lbl, hist.count
                ));
            }
        }

        // 4. Interface Retransmission Ratios
        if !s.interface_tcp_retrans_ratios.is_empty() || !s.interface_issp_retrans_ratios.is_empty() {
            out.push_str("# HELP ifa_session_interface_retransmission_ratio Retransmission ratio per network interface categorized by protocol (tcp or issp).\n");
            out.push_str("# TYPE ifa_session_interface_retransmission_ratio gauge\n");
            for (iface, ratio) in &s.interface_tcp_retrans_ratios {
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("interface", iface),
                    ("protocol", "tcp"),
                ]);
                out.push_str(&format!(
                    "ifa_session_interface_retransmission_ratio{} {:.6}\n",
                    lbl, ratio
                ));
            }
            for (iface, ratio) in &s.interface_issp_retrans_ratios {
                let lbl = self.format_labels(&[
                    ("node_id", &node_str),
                    ("interface", iface),
                    ("protocol", "issp"),
                ]);
                out.push_str(&format!(
                    "ifa_session_interface_retransmission_ratio{} {:.6}\n",
                    lbl, ratio
                ));
            }
        }

        out
    }
}

// ─── OpenTelemetry OTLP JSON (v1/metrics) Exporter ──────────────────────────

/// OpenTelemetry OTLP HTTP/JSON (v1/metrics) exporter for dynamic ISSP multipath balancing.
#[derive(Debug, Clone, Default)]
pub struct OtelMultipathBalancingExporter {
    pub default_attributes: BTreeMap<String, String>,
}

fn escape_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

impl OtelMultipathBalancingExporter {
    /// Create a new OpenTelemetry multipath balancing exporter.
    pub fn new() -> Self {
        Self {
            default_attributes: BTreeMap::new(),
        }
    }

    /// Add a resource attribute applied to the exported OTLP payload.
    pub fn with_attribute(mut self, key: &str, value: &str) -> Self {
        self.default_attributes
            .insert(key.to_string(), value.to_string());
        self
    }

    /// Export an `IsspMultipathBalancingSnapshot` into standard OTLP JSON (`v1/metrics`).
    pub fn export(&self, s: &IsspMultipathBalancingSnapshot, service_name: &str) -> String {
        let ts_str = s.timestamp_unix_ns.to_string();
        let node_str = s.node_id.to_string();

        let mut out = String::with_capacity(8192);
        out.push_str("{\n");
        out.push_str("  \"resourceMetrics\": [\n");
        out.push_str("    {\n");
        out.push_str("      \"resource\": {\n");
        out.push_str("        \"attributes\": [\n");
        out.push_str(&format!(
            "          {{\"key\": \"service.name\", \"value\": {{\"stringValue\": \"{}\"}}}},\n",
            escape_json_str(service_name)
        ));
        out.push_str(&format!(
            "          {{\"key\": \"service.instance.id\", \"value\": {{\"stringValue\": \"node-{}\"}}}},\n",
            s.node_id
        ));
        out.push_str("          {\"key\": \"telemetry.sdk.name\", \"value\": {\"stringValue\": \"ifa-runtime\"}},\n");
        out.push_str("          {\"key\": \"telemetry.sdk.language\", \"value\": {\"stringValue\": \"ifa/rust\"}}");

        for (k, v) in &self.default_attributes {
            out.push_str(&format!(
                ",\n          {{\"key\": \"{}\", \"value\": {{\"stringValue\": \"{}\"}}}}",
                escape_json_str(k),
                escape_json_str(v)
            ));
        }

        out.push_str("\n        ]\n");
        out.push_str("      },\n");
        out.push_str("      \"scopeMetrics\": [\n");
        out.push_str("        {\n");
        out.push_str("          \"scope\": {\n");
        out.push_str("            \"name\": \"ifa-runtime::issp_multipath\",\n");
        out.push_str("            \"version\": \"0.1.0\"\n");
        out.push_str("          },\n");
        out.push_str("          \"metrics\": [\n");

        // Helper macro/closure would be nice, but explicit linear generation is simple and zero-alloc
        let mut metric_entries = Vec::new();

        // 1. Pool active paths
        metric_entries.push(format!(
            concat!(
                "            {{\n",
                "              \"name\": \"ifa.issp.multipath.active_paths\",\n",
                "              \"description\": \"Number of operational multipath subpaths\",\n",
                "              \"unit\": \"1\",\n",
                "              \"gauge\": {{\n",
                "                \"dataPoints\": [\n",
                "                  {{\n",
                "                    \"timeUnixNano\": \"{}\",\n",
                "                    \"asInt\": \"{}\",\n",
                "                    \"attributes\": [\n",
                "                      {{\"key\": \"node_id\", \"value\": {{\"stringValue\": \"{}\"}}}},\n",
                "                      {{\"key\": \"policy\", \"value\": {{\"stringValue\": \"{}\"}}}}\n",
                "                    ]\n",
                "                  }}\n",
                "                ]\n",
                "              }}\n",
                "            }}"
            ),
            ts_str, s.active_paths, node_str, escape_json_str(&s.routing_policy)
        ));

        // 2. Pool total effective weight
        metric_entries.push(format!(
            concat!(
                "            {{\n",
                "              \"name\": \"ifa.issp.multipath.total_effective_weight\",\n",
                "              \"description\": \"Aggregate effective scheduling weight across operational subpaths\",\n",
                "              \"unit\": \"1\",\n",
                "              \"gauge\": {{\n",
                "                \"dataPoints\": [\n",
                "                  {{\n",
                "                    \"timeUnixNano\": \"{}\",\n",
                "                    \"asInt\": \"{}\",\n",
                "                    \"attributes\": [\n",
                "                      {{\"key\": \"node_id\", \"value\": {{\"stringValue\": \"{}\"}}}},\n",
                "                      {{\"key\": \"policy\", \"value\": {{\"stringValue\": \"{}\"}}}}\n",
                "                    ]\n",
                "                  }}\n",
                "                ]\n",
                "              }}\n",
                "            }}"
            ),
            ts_str, s.total_effective_weight, node_str, escape_json_str(&s.routing_policy)
        ));

        // 3. Subpath RTT
        let subpath_attrs = |sp: &IsspSubpathBalancingMetrics| -> String {
            format!(
                concat!(
                    "                      {{\"key\": \"node_id\", \"value\": {{\"stringValue\": \"{}\"}}}},\n",
                    "                      {{\"key\": \"path_id\", \"value\": {{\"stringValue\": \"{}\"}}}},\n",
                    "                      {{\"key\": \"interface\", \"value\": {{\"stringValue\": \"{}\"}}}},\n",
                    "                      {{\"key\": \"state\", \"value\": {{\"stringValue\": \"{}\"}}}},\n",
                    "                      {{\"key\": \"phase\", \"value\": {{\"stringValue\": \"{}\"}}}}"
                ),
                node_str,
                sp.path_id,
                escape_json_str(&sp.interface_name),
                escape_json_str(&sp.state),
                escape_json_str(&sp.congestion_phase)
            )
        };

        let rtt_dps: Vec<String> = s
            .subpaths
            .iter()
            .map(|sp| {
                format!(
                    concat!(
                        "                  {{\n",
                        "                    \"timeUnixNano\": \"{}\",\n",
                        "                    \"asDouble\": {:.6},\n",
                        "                    \"attributes\": [\n{}\n",
                        "                    ]\n",
                        "                  }}"
                    ),
                    ts_str,
                    (sp.rtt_us as f64) / 1_000_000.0,
                    subpath_attrs(sp)
                )
            })
            .collect();
        metric_entries.push(format!(
            concat!(
                "            {{\n",
                "              \"name\": \"ifa.issp.subpath.rtt\",\n",
                "              \"description\": \"Smoothed round-trip time in seconds\",\n",
                "              \"unit\": \"s\",\n",
                "              \"gauge\": {{\n",
                "                \"dataPoints\": [\n{}\n",
                "                ]\n",
                "              }}\n",
                "            }}"
            ),
            rtt_dps.join(",\n")
        ));

        // 4. Subpath RTT gradient
        let grad_dps: Vec<String> = s
            .subpaths
            .iter()
            .map(|sp| {
                format!(
                    concat!(
                        "                  {{\n",
                        "                    \"timeUnixNano\": \"{}\",\n",
                        "                    \"asDouble\": {:.6},\n",
                        "                    \"attributes\": [\n{}\n",
                        "                    ]\n",
                        "                  }}"
                    ),
                    ts_str,
                    (sp.rtt_gradient_us as f64) / 1_000_000.0,
                    subpath_attrs(sp)
                )
            })
            .collect();
        metric_entries.push(format!(
            concat!(
                "            {{\n",
                "              \"name\": \"ifa.issp.subpath.rtt_gradient\",\n",
                "              \"description\": \"RTT gradient and queuing delay in seconds\",\n",
                "              \"unit\": \"s\",\n",
                "              \"gauge\": {{\n",
                "                \"dataPoints\": [\n{}\n",
                "                ]\n",
                "              }}\n",
                "            }}"
            ),
            grad_dps.join(",\n")
        ));

        // 5. BBR BtlBw
        let bw_dps: Vec<String> = s
            .subpaths
            .iter()
            .map(|sp| {
                format!(
                    concat!(
                        "                  {{\n",
                        "                    \"timeUnixNano\": \"{}\",\n",
                        "                    \"asInt\": \"{}\",\n",
                        "                    \"attributes\": [\n{}\n",
                        "                    ]\n",
                        "                  }}"
                    ),
                    ts_str,
                    sp.bbr_bw_bps,
                    subpath_attrs(sp)
                )
            })
            .collect();
        metric_entries.push(format!(
            concat!(
                "            {{\n",
                "              \"name\": \"ifa.issp.subpath.bbr_bw_bps\",\n",
                "              \"description\": \"BBR estimated bottleneck bandwidth in bits per second\",\n",
                "              \"unit\": \"bit/s\",\n",
                "              \"gauge\": {{\n",
                "                \"dataPoints\": [\n{}\n",
                "                ]\n",
                "              }}\n",
                "            }}"
            ),
            bw_dps.join(",\n")
        ));

        // 6. LEDBAT CWND
        let cwnd_dps: Vec<String> = s
            .subpaths
            .iter()
            .map(|sp| {
                format!(
                    concat!(
                        "                  {{\n",
                        "                    \"timeUnixNano\": \"{}\",\n",
                        "                    \"asInt\": \"{}\",\n",
                        "                    \"attributes\": [\n{}\n",
                        "                    ]\n",
                        "                  }}"
                    ),
                    ts_str,
                    sp.ledbat_cwnd_bytes,
                    subpath_attrs(sp)
                )
            })
            .collect();
        metric_entries.push(format!(
            concat!(
                "            {{\n",
                "              \"name\": \"ifa.issp.subpath.ledbat_cwnd_bytes\",\n",
                "              \"description\": \"LEDBAT congestion window in bytes\",\n",
                "              \"unit\": \"By\",\n",
                "              \"gauge\": {{\n",
                "                \"dataPoints\": [\n{}\n",
                "                ]\n",
                "              }}\n",
                "            }}"
            ),
            cwnd_dps.join(",\n")
        ));

        // 7. Traffic share ratio
        let share_dps: Vec<String> = s
            .subpaths
            .iter()
            .map(|sp| {
                format!(
                    concat!(
                        "                  {{\n",
                        "                    \"timeUnixNano\": \"{}\",\n",
                        "                    \"asDouble\": {:.6},\n",
                        "                    \"attributes\": [\n{}\n",
                        "                    ]\n",
                        "                  }}"
                    ),
                    ts_str,
                    sp.traffic_share_ratio,
                    subpath_attrs(sp)
                )
            })
            .collect();
        metric_entries.push(format!(
            concat!(
                "            {{\n",
                "              \"name\": \"ifa.issp.subpath.traffic_share_ratio\",\n",
                "              \"description\": \"Dynamic traffic allocation ratio across aggregated subpaths\",\n",
                "              \"unit\": \"1\",\n",
                "              \"gauge\": {{\n",
                "                \"dataPoints\": [\n{}\n",
                "                ]\n",
                "              }}\n",
                "            }}"
            ),
            share_dps.join(",\n")
        ));

        // 8. Effective weight
        let eff_w_dps: Vec<String> = s
            .subpaths
            .iter()
            .map(|sp| {
                format!(
                    concat!(
                        "                  {{\n",
                        "                    \"timeUnixNano\": \"{}\",\n",
                        "                    \"asInt\": \"{}\",\n",
                        "                    \"attributes\": [\n{}\n",
                        "                    ]\n",
                        "                  }}"
                    ),
                    ts_str,
                    sp.effective_weight,
                    subpath_attrs(sp)
                )
            })
            .collect();
        metric_entries.push(format!(
            concat!(
                "            {{\n",
                "              \"name\": \"ifa.issp.subpath.effective_weight\",\n",
                "              \"description\": \"Dynamic effective scheduling weight\",\n",
                "              \"unit\": \"1\",\n",
                "              \"gauge\": {{\n",
                "                \"dataPoints\": [\n{}\n",
                "                ]\n",
                "              }}\n",
                "            }}"
            ),
            eff_w_dps.join(",\n")
        ));

        // 9. Congestion events (sum/counter)
        let ce_dps: Vec<String> = s
            .subpaths
            .iter()
            .map(|sp| {
                format!(
                    concat!(
                        "                  {{\n",
                        "                    \"timeUnixNano\": \"{}\",\n",
                        "                    \"asInt\": \"{}\",\n",
                        "                    \"attributes\": [\n{}\n",
                        "                    ]\n",
                        "                  }}"
                    ),
                    ts_str,
                    sp.congestion_events,
                    subpath_attrs(sp)
                )
            })
            .collect();
        metric_entries.push(format!(
            concat!(
                "            {{\n",
                "              \"name\": \"ifa.issp.subpath.congestion_events_total\",\n",
                "              \"description\": \"Total congestion events observed on subpath\",\n",
                "              \"unit\": \"1\",\n",
                "              \"sum\": {{\n",
                "                \"isMonotonic\": true,\n",
                "                \"aggregationTemporality\": 2,\n",
                "                \"dataPoints\": [\n{}\n",
                "                ]\n",
                "              }}\n",
                "            }}"
            ),
            ce_dps.join(",\n")
        ));

        // 10. Sessions count gauge
        metric_entries.push(format!(
            concat!(
                "            {{\n",
                "              \"name\": \"ifa.session.total_sessions\",\n",
                "              \"description\": \"Total active sessions tracked in registry\",\n",
                "              \"unit\": \"1\",\n",
                "              \"gauge\": {{\n",
                "                \"dataPoints\": [\n",
                "                  {{\n",
                "                    \"timeUnixNano\": \"{}\",\n",
                "                    \"asInt\": \"{}\",\n",
                "                    \"attributes\": [\n",
                "                      {{\"key\": \"node_id\", \"value\": {{\"stringValue\": \"{}\"}}}},\n",
                "                      {{\"key\": \"policy\", \"value\": {{\"stringValue\": \"{}\"}}}}\n",
                "                    ]\n",
                "                  }}\n",
                "                ]\n",
                "              }}\n",
                "            }}"
            ),
            ts_str, s.total_sessions, node_str, escape_json_str(&s.routing_policy)
        ));

        // 11. Subpath TCP retransmission ratio
        let tcp_ratio_dps: Vec<String> = s
            .subpaths
            .iter()
            .map(|sp| {
                format!(
                    concat!(
                        "                  {{\n",
                        "                    \"timeUnixNano\": \"{}\",\n",
                        "                    \"asDouble\": {:.6},\n",
                        "                    \"attributes\": [\n{}\n",
                        "                    ]\n",
                        "                  }}"
                    ),
                    ts_str,
                    sp.tcp_retrans_ratio,
                    subpath_attrs(sp)
                )
            })
            .collect();
        metric_entries.push(format!(
            concat!(
                "            {{\n",
                "              \"name\": \"ifa.issp.subpath.tcp_retransmission_ratio\",\n",
                "              \"description\": \"TCP retransmission ratio on subpath\",\n",
                "              \"unit\": \"1\",\n",
                "              \"gauge\": {{\n",
                "                \"dataPoints\": [\n{}\n",
                "                ]\n",
                "              }}\n",
                "            }}"
            ),
            tcp_ratio_dps.join(",\n")
        ));

        // 12. Subpath ISSP retransmission ratio
        let issp_ratio_dps: Vec<String> = s
            .subpaths
            .iter()
            .map(|sp| {
                format!(
                    concat!(
                        "                  {{\n",
                        "                    \"timeUnixNano\": \"{}\",\n",
                        "                    \"asDouble\": {:.6},\n",
                        "                    \"attributes\": [\n{}\n",
                        "                    ]\n",
                        "                  }}"
                    ),
                    ts_str,
                    sp.issp_retrans_ratio,
                    subpath_attrs(sp)
                )
            })
            .collect();
        metric_entries.push(format!(
            concat!(
                "            {{\n",
                "              \"name\": \"ifa.issp.subpath.issp_retransmission_ratio\",\n",
                "              \"description\": \"ISSP capsule retransmission ratio on subpath\",\n",
                "              \"unit\": \"1\",\n",
                "              \"gauge\": {{\n",
                "                \"dataPoints\": [\n{}\n",
                "                ]\n",
                "              }}\n",
                "            }}"
            ),
            issp_ratio_dps.join(",\n")
        ));

        // 13. Interface Latency Histograms
        if !s.interface_latency_histograms.is_empty() {
            let mut hist_dps = Vec::new();
            for (iface, hist) in &s.interface_latency_histograms {
                let bounds_str = hist
                    .buckets
                    .iter()
                    .map(|b| format!("{:.6}", b))
                    .collect::<Vec<_>>()
                    .join(", ");
                let counts_str = hist
                    .cumulative_counts
                    .iter()
                    .map(|c| format!("\"{}\"", c))
                    .collect::<Vec<_>>()
                    .join(", ");

                hist_dps.push(format!(
                    concat!(
                        "                  {{\n",
                        "                    \"timeUnixNano\": \"{}\",\n",
                        "                    \"count\": \"{}\",\n",
                        "                    \"sum\": {:.6},\n",
                        "                    \"bucketCounts\": [{}],\n",
                        "                    \"explicitBounds\": [{}],\n",
                        "                    \"min\": {:.6},\n",
                        "                    \"max\": {:.6},\n",
                        "                    \"attributes\": [\n",
                        "                      {{\"key\": \"node_id\", \"value\": {{\"stringValue\": \"{}\"}}}},\n",
                        "                      {{\"key\": \"interface\", \"value\": {{\"stringValue\": \"{}\"}}}}\n",
                        "                    ]\n",
                        "                  }}"
                    ),
                    ts_str,
                    hist.count,
                    hist.sum_seconds,
                    counts_str,
                    bounds_str,
                    hist.safe_min_seconds(),
                    hist.max_seconds,
                    node_str,
                    escape_json_str(iface)
                ));
            }

            metric_entries.push(format!(
                concat!(
                    "            {{\n",
                    "              \"name\": \"ifa.issp.interface.latency\",\n",
                    "              \"description\": \"Round-trip latency distribution per network interface\",\n",
                    "              \"unit\": \"s\",\n",
                    "              \"histogram\": {{\n",
                    "                \"aggregationTemporality\": 2,\n",
                    "                \"dataPoints\": [\n{}\n",
                    "                ]\n",
                    "              }}\n",
                    "            }}"
                ),
                hist_dps.join(",\n")
            ));
        }

        out.push_str(&metric_entries.join(",\n"));
        out.push_str("\n          ]\n");
        out.push_str("        }\n");
        out.push_str("      ]\n");
        out.push_str("    }\n");
        out.push_str("  ]\n");
        out.push_str("}\n");

        out
    }
}

// ─── HTTP Telemetry Handlers & Exposition Server ──────────────────────────

/// HTTP request dispatcher for dynamic ISSP multipath balancing telemetry.
///
/// Supports the standard observability endpoints:
/// - `/metrics`: Prometheus Exposition text format (or OpenTelemetry OTLP JSON if `Accept: application/json` is requested)
/// - `/v1/metrics`: OpenTelemetry OTLP JSON payload conforming to OTLP v1/metrics specification
/// - `/healthz` or `/livez`: Liveness probe returning HTTP 200 OK
#[derive(Debug, Clone)]
pub struct IsspTelemetryHttpHandler {
    service_name: String,
}

impl IsspTelemetryHttpHandler {
    /// Create a new telemetry HTTP handler with the specified service name for OTLP reporting.
    pub fn new(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
        }
    }

    /// Retrieve the configured service name.
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Dispatch an HTTP request against a provided snapshot.
    ///
    /// Returns `(http_status_code, content_type_header, response_body_string)`.
    pub fn handle_snapshot(
        &self,
        path: &str,
        accept_header: &str,
        snapshot: &IsspMultipathBalancingSnapshot,
    ) -> (u16, &'static str, String) {
        let clean_path = path.split('?').next().unwrap_or(path).trim_end_matches('/');
        match clean_path {
            "/metrics" => {
                if accept_header.contains("application/json") {
                    (
                        200,
                        "application/json",
                        snapshot.export_otlp_json(&self.service_name),
                    )
                } else {
                    (
                        200,
                        "text/plain; version=0.0.4; charset=utf-8",
                        snapshot.export_prometheus(),
                    )
                }
            }
            "/v1/metrics" => (
                200,
                "application/json",
                snapshot.export_otlp_json(&self.service_name),
            ),
            "/healthz" | "/livez" => (200, "text/plain; charset=utf-8", "OK\n".to_string()),
            _ => (404, "text/plain; charset=utf-8", "Not Found\n".to_string()),
        }
    }

    /// Parse a raw HTTP GET request string and format a complete HTTP 1.1 wire response.
    pub fn handle_raw_http_request(
        &self,
        raw_request: &str,
        snapshot: &IsspMultipathBalancingSnapshot,
    ) -> String {
        let mut path = "/metrics";
        let mut accept = "*/*";

        for line in raw_request.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("GET ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    path = parts[1];
                }
            } else if trimmed.to_ascii_lowercase().starts_with("accept:") {
                accept = trimmed.split(':').nth(1).unwrap_or("").trim();
            }
        }

        let (code, ctype, body) = self.handle_snapshot(path, accept, snapshot);
        let status_text = match code {
            200 => "OK",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Unknown",
        };

        format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
            code,
            status_text,
            ctype,
            body.len(),
            body
        )
    }
}

/// Lightweight HTTP telemetry server exposing ISSP dynamic multipath balancing metrics
/// over standard network sockets (`std::net::TcpListener`).
pub struct IsspTelemetryServer {
    listener: TcpListener,
    service_name: String,
    registry: Arc<crate::session_sync::SessionRegistry>,
}

impl IsspTelemetryServer {
    /// Bind the telemetry server to the requested socket address with an associated `SessionRegistry`.
    pub fn bind<A: ToSocketAddrs>(
        addr: A,
        service_name: &str,
        registry: Arc<crate::session_sync::SessionRegistry>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        Ok(Self {
            listener,
            service_name: service_name.to_string(),
            registry,
        })
    }

    /// Retrieve the local socket address on which the server is listening.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Configure non-blocking mode on the underlying TCP listener.
    pub fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        self.listener.set_nonblocking(nonblocking)
    }

    /// Handle a request from a generic reader and write the formatted HTTP response to a generic writer.
    ///
    /// Returns `(http_status_code, requested_path)`.
    pub fn serve_request_stream<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<(u16, String)> {
        let mut buf = [0u8; 4096];
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok((400, String::new()));
        }
        let req_str = String::from_utf8_lossy(&buf[..n]);

        let mut path = "/metrics";
        let mut accept = "*/*";
        for line in req_str.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("GET ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    path = parts[1];
                }
            } else if trimmed.to_ascii_lowercase().starts_with("accept:") {
                accept = trimmed.split(':').nth(1).unwrap_or("").trim();
            }
        }

        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let snap_res = self.registry.multipath_balancing_snapshot(timestamp_ns);
        let handler = IsspTelemetryHttpHandler::new(&self.service_name);

        let (code, ctype, body) = match snap_res {
            Ok(ref snap) => handler.handle_snapshot(path, accept, snap),
            Err(_) => (
                500,
                "text/plain; charset=utf-8",
                "Error collecting multipath balancing telemetry\n".to_string(),
            ),
        };

        let status_text = match code {
            200 => "OK",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Unknown",
        };

        let resp = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
            code,
            status_text,
            ctype,
            body.len(),
            body
        );

        writer.write_all(resp.as_bytes())?;
        writer.flush()?;

        Ok((code, path.to_string()))
    }

    /// Serve an incoming TCP connection synchronously.
    pub fn serve_one_connection(&self, mut stream: TcpStream) -> std::io::Result<(u16, String)> {
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let mut reader = stream.try_clone()?;
        let res = self.serve_request_stream(&mut reader, &mut stream)?;
        let _ = stream.shutdown(std::net::Shutdown::Both);
        Ok(res)
    }

    /// Try accepting and serving a single incoming connection.
    /// In non-blocking mode, returns `Ok(None)` if no client connection is currently pending.
    pub fn try_serve_one(&self) -> std::io::Result<Option<(u16, String)>> {
        match self.listener.accept() {
            Ok((stream, _)) => {
                let res = self.serve_one_connection(stream)?;
                Ok(Some(res))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Serve a WebSocket upgrade on `GET /ws/metrics` (RFC 6455 mini-handshake, `std::net` only).
    ///
    /// After handshake:
    /// - Pushes one JSON text frame per `interval_ms` milliseconds.
    /// - Each frame contains a `IsspMultipathBalancingSnapshot` serialised as compact JSON.
    /// - Stops after `max_frames` pushes (0 = unlimited) or on write error.
    ///
    /// Returns the number of frames actually sent.
    pub fn serve_ws_metrics_connection(
        &self,
        mut stream: TcpStream,
        interval_ms: u64,
        max_frames: u64,
    ) -> std::io::Result<u64> {
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        // ── 1. Read and validate the HTTP Upgrade request ────────────────────
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(0);
        }
        let req_str = String::from_utf8_lossy(&buf[..n]);

        // Extract `Sec-WebSocket-Key` header (required by RFC 6455).
        let ws_key = ws_extract_header(&req_str, "Sec-WebSocket-Key").ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Missing Sec-WebSocket-Key header",
            )
        })?;

        // Verify the client requests an upgrade to `websocket` on `/ws/metrics`.
        let path_ok = req_str
            .lines()
            .next()
            .is_some_and(|l| l.contains("/ws/metrics"));
        let upgrade_ok = ws_extract_header(&req_str, "Upgrade")
            .map(|v| v.to_ascii_lowercase().contains("websocket"))
            .unwrap_or(false);

        if !path_ok || !upgrade_ok {
            // Not a valid WS upgrade to our endpoint — reply 400 and exit.
            stream.write_all(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )?;
            stream.flush()?;
            return Ok(0);
        }

        // ── 2. Build the RFC 6455 `101 Switching Protocols` response ─────────
        let accept_key = ws_accept_key(&ws_key);
        let handshake_resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\r\n",
            accept_key
        );
        stream.write_all(handshake_resp.as_bytes())?;
        stream.flush()?;

        // ── 3. Streaming push loop ────────────────────────────────────────────
        let interval = Duration::from_millis(interval_ms.max(1));
        let mut frames_sent: u64 = 0;

        // Set a longer write timeout for the streaming phase.
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        loop {
            if max_frames > 0 && frames_sent >= max_frames {
                break;
            }

            // Collect snapshot.
            let ts_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let snap_res = self.registry.multipath_balancing_snapshot(ts_ns);
            let payload = match snap_res {
                Ok(ref snap) => snapshot_to_compact_json(snap),
                Err(e) => format!("{{\"error\":\"{}\"}}", e),
            };

            // Build RFC 6455 text frame (server → client, no mask, FIN=1, opcode=0x1).
            let frame = ws_build_text_frame(payload.as_bytes());
            if stream.write_all(&frame).is_err() {
                break; // Client disconnected.
            }
            if stream.flush().is_err() {
                break;
            }
            frames_sent += 1;

            if max_frames > 0 && frames_sent >= max_frames {
                break;
            }
            std::thread::sleep(interval);
        }

        // Send RFC 6455 close frame (opcode 0x8, payload=1000 normal closure).
        let _ = stream.write_all(&ws_build_close_frame(1000));
        let _ = stream.flush();
        let _ = stream.shutdown(std::net::Shutdown::Both);

        Ok(frames_sent)
    }

    /// Accept and dispatch one connection: routes `/ws/metrics` to the WebSocket handler
    /// and all other requests to the HTTP handler.
    ///
    /// Returns `(http_status_or_ws_frames, path)`.
    pub fn serve_one_smart(
        &self,
        stream: TcpStream,
        ws_interval_ms: u64,
        ws_max_frames: u64,
    ) -> std::io::Result<(u64, String)> {
        // Ensure stream is blocking for header peek and dispatch.
        let _ = stream.set_nonblocking(false);
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        let mut peek_buf = [0u8; 512];
        let peeked = stream.peek(&mut peek_buf).unwrap_or(0);
        let peek_str = std::str::from_utf8(&peek_buf[..peeked]).unwrap_or("");

        let is_ws_upgrade = peek_str.contains("/ws/metrics")
            && peek_str.to_ascii_lowercase().contains("upgrade: websocket");

        if is_ws_upgrade {
            let frames = self.serve_ws_metrics_connection(stream, ws_interval_ms, ws_max_frames)?;
            Ok((frames, "/ws/metrics".to_string()))
        } else {
            let (code, path) = self.serve_one_connection(stream)?;
            Ok((code as u64, path))
        }
    }

    /// In non-blocking mode, try accepting and routing a single incoming connection.
    /// Routes `/ws/metrics` to the WebSocket streaming handler and standard HTTP paths
    /// to the HTTP telemetry handler.
    ///
    /// Returns `Ok(Some((status_or_frames, path)))`, or `Ok(None)` if no client is pending.
    pub fn try_serve_one_smart(
        &self,
        ws_interval_ms: u64,
        ws_max_frames: u64,
    ) -> std::io::Result<Option<(u64, String)>> {
        match self.listener.accept() {
            Ok((stream, _)) => {
                let res = self.serve_one_smart(stream, ws_interval_ms, ws_max_frames)?;
                Ok(Some(res))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
}

// ─── RFC 6455 WebSocket helpers (std::net only, no external crates) ──────────

/// Extract the value of a named HTTP header from a raw request string.
fn ws_extract_header(raw: &str, name: &str) -> Option<String> {
    let lower_name = name.to_ascii_lowercase();
    for line in raw.lines() {
        let lower_line = line.to_ascii_lowercase();
        if lower_line.starts_with(&lower_name) && lower_line[lower_name.len()..].starts_with(':') {
            let value = line[lower_name.len() + 1..].trim();
            return Some(value.to_string());
        }
    }
    None
}

/// Compute the RFC 6455 `Sec-WebSocket-Accept` base64 value from a client key.
/// SHA-1 implemented inline (no external crates) per the WebSocket spec.
fn ws_accept_key(client_key: &str) -> String {
    const MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let combined = format!("{}{}", client_key.trim(), MAGIC);
    let hash = sha1_bytes(combined.as_bytes());
    base64_encode(&hash)
}

/// Minimal SHA-1 implementation (FIPS 180-4) for RFC 6455 handshake.
fn sha1_bytes(msg: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let bit_len = (msg.len() as u64) * 8;
    let mut padded: Vec<u8> = msg.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &w_i) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w_i);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, &v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// Minimal base64 encoder (RFC 4648) for the WebSocket handshake `Accept` key.
fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Build a RFC 6455 text frame (FIN=1, opcode=0x1, server→client, unmasked).
fn ws_build_text_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 10);
    frame.push(0x81); // FIN=1, opcode=1 (text)
    let len = payload.len();
    if len < 126 {
        frame.push(len as u8);
    } else if len < 65536 {
        frame.push(126);
        frame.push((len >> 8) as u8);
        frame.push((len & 0xFF) as u8);
    } else {
        frame.push(127);
        for shift in (0..8).rev() {
            frame.push(((len >> (shift * 8)) & 0xFF) as u8);
        }
    }
    frame.extend_from_slice(payload);
    frame
}

/// Build a RFC 6455 close frame (opcode 0x8, 2-byte status code, unmasked).
fn ws_build_close_frame(code: u16) -> Vec<u8> {
    vec![0x88, 0x02, (code >> 8) as u8, (code & 0xFF) as u8]
}

/// Serialise an `IsspMultipathBalancingSnapshot` as compact JSON for WebSocket push.
fn snapshot_to_compact_json(s: &IsspMultipathBalancingSnapshot) -> String {
    let mut out = String::with_capacity(512);
    out.push_str("{\"ts\":");
    out.push_str(&s.timestamp_unix_ns.to_string());
    out.push_str(",\"node\":");
    out.push_str(&s.node_id.to_string());
    out.push_str(",\"policy\":\"");
    out.push_str(&escape_json_str(&s.routing_policy));
    out.push_str("\",\"total_paths\":");
    out.push_str(&s.total_paths.to_string());
    out.push_str(",\"active_paths\":");
    out.push_str(&s.active_paths.to_string());
    out.push_str(",\"total_eff_w\":");
    out.push_str(&s.total_effective_weight.to_string());
    out.push_str(",\"sessions\":");
    out.push_str(&s.total_sessions.to_string());
    out.push_str(",\"subpaths\":[");
    for (i, sp) in s.subpaths.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"id\":");
        out.push_str(&sp.path_id.to_string());
        out.push_str(",\"iface\":\"");
        out.push_str(&escape_json_str(&sp.interface_name));
        out.push_str("\",\"state\":\"");
        out.push_str(&escape_json_str(&sp.state));
        out.push_str("\",\"eff_w\":");
        out.push_str(&sp.effective_weight.to_string());
        out.push_str(",\"share\":");
        out.push_str(&format!("{:.4}", sp.traffic_share_ratio));
        out.push_str(",\"rtt_us\":");
        out.push_str(&sp.rtt_us.to_string());
        out.push_str(",\"bbr_bps\":");
        out.push_str(&sp.bbr_bw_bps.to_string());
        out.push_str(",\"tcp_ratio\":");
        out.push_str(&format!("{:.4}", sp.tcp_retrans_ratio));
        out.push_str(",\"issp_ratio\":");
        out.push_str(&format!("{:.4}", sp.issp_retrans_ratio));
        out.push_str(",\"phase\":\"");
        out.push_str(&escape_json_str(&sp.congestion_phase));
        out.push_str("\"}");
    }
    out.push_str("]}");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_sync::{
        IsspDynamicMultipathRouter, IsspMultipathRoute, IsspRoutingPolicy, SessionRegistry,
        SessionSnapshot,
    };

    #[test]
    fn test_multipath_balancing_snapshot_and_traffic_shares() {
        let mut router =
            IsspDynamicMultipathRouter::new(1, IsspRoutingPolicy::BandwidthAggregation);
        router.add_route(IsspMultipathRoute::new(1, 2, "eth0-fiber", 1, 100));
        router.add_route(IsspMultipathRoute::new(2, 2, "wwan0-5g", 2, 50));

        // Initial snapshot under nominal conditions (no traffic yet)
        let snap = router.balancing_snapshot(1_700_000_000_000_000_000);
        assert_eq!(snap.node_id, 1);
        assert_eq!(snap.total_paths, 2);
        assert_eq!(snap.active_paths, 2);
        assert_eq!(snap.total_effective_weight, 150);

        let sp1 = snap.subpath(1).expect("subpath 1");
        let sp2 = snap.subpath(2).expect("subpath 2");
        assert_eq!(sp1.interface_name, "eth0-fiber");
        assert_eq!(sp1.effective_weight, 100);
        assert!((sp1.traffic_share_ratio - 0.666667).abs() < 0.001);
        assert!((sp1.traffic_share_percent - 66.67).abs() < 0.05);

        assert_eq!(sp2.interface_name, "wwan0-5g");
        assert_eq!(sp2.effective_weight, 50);
        assert!((sp2.traffic_share_ratio - 0.333333).abs() < 0.001);
        assert!((sp2.traffic_share_percent - 33.33).abs() < 0.05);

        // Feed nominal feedback on path 1 (delivering bytes, establishing BBR estimate)
        for _ in 0..8 {
            router
                .update_congestion_feedback(1, 10_000, 0, 125_000)
                .unwrap();
        }

        // Feed baseline on path 2
        router
            .update_congestion_feedback(2, 20_000, 0, 25_000)
            .unwrap();

        // Feed heavy queuing delay and packet loss on path 2 (triggering Recovery and LEDBAT backoff)
        router
            .update_congestion_feedback(2, 80_000, 2000, 10_000)
            .unwrap();

        let snap_rebalanced = router.balancing_snapshot(1_700_000_001_000_000_000);
        let reb_sp1 = snap_rebalanced.subpath(1).unwrap();
        let reb_sp2 = snap_rebalanced.subpath(2).unwrap();

        assert_eq!(reb_sp1.congestion_phase, "CongestionAvoidance");
        assert_eq!(reb_sp1.bbr_bw_bps, 100_000_000); // 125_000 bytes * 8e6 / 10_000 us = 100 Mbps
        assert_eq!(reb_sp2.congestion_phase, "Recovery");
        assert!(reb_sp2.rtt_gradient_us > 0);
        assert!(reb_sp2.congestion_events >= 1);

        // Path 1 should take a significantly increased share of traffic due to path 2 backoff
        assert!(
            reb_sp1.traffic_share_percent > 66.67,
            "Path 1 share ({}) should be higher than initial 66.67%",
            reb_sp1.traffic_share_percent
        );
        assert!(
            reb_sp2.traffic_share_percent < 33.33,
            "Path 2 share ({}) should be lower than initial 33.33%",
            reb_sp2.traffic_share_percent
        );
    }

    #[test]
    fn test_prometheus_multipath_balancing_export() {
        let mut router =
            IsspDynamicMultipathRouter::new(42, IsspRoutingPolicy::BandwidthAggregation);
        router.add_route(IsspMultipathRoute::new(1, 2, "eth0", 1, 100));
        router.add_route(IsspMultipathRoute::new(2, 2, "wlan0", 2, 50));

        router
            .update_congestion_feedback(1, 12_000, 0, 150_000)
            .unwrap();
        router
            .update_congestion_feedback(2, 45_000, 500, 20_000)
            .unwrap();

        let snap = router.balancing_snapshot(1_700_000_000_000_000_000);
        let exporter = PrometheusMultipathBalancingExporter::new()
            .with_label("cluster", "edge-paris")
            .with_label("tier", "gateway");

        let text = exporter.export(&snap);

        // Verify standard exposition headers
        assert!(text.contains("# HELP ifa_issp_multipath_active_paths"));
        assert!(text.contains("# TYPE ifa_issp_multipath_active_paths gauge"));
        assert!(text.contains("ifa_issp_multipath_active_paths{cluster=\"edge-paris\",node_id=\"42\",policy=\"BandwidthAggregation\",tier=\"gateway\"} 2"));

        assert!(text.contains("# HELP ifa_issp_subpath_rtt_seconds"));
        assert!(text.contains("# HELP ifa_issp_subpath_rtt_gradient_seconds"));
        assert!(text.contains("# HELP ifa_issp_subpath_bbr_bw_bps"));
        assert!(text.contains("# HELP ifa_issp_subpath_ledbat_cwnd_bytes"));
        assert!(text.contains("# HELP ifa_issp_subpath_traffic_share_ratio"));
        assert!(text.contains("# HELP ifa_issp_subpath_effective_weight"));
        assert!(text.contains("# HELP ifa_issp_subpath_congestion_events_total"));

        // Verify subpath labels
        assert!(text.contains("path_id=\"1\""));
        assert!(text.contains("interface=\"eth0\""));
        assert!(text.contains("path_id=\"2\""));
        assert!(text.contains("interface=\"wlan0\""));
        assert!(text.contains("phase=\"Recovery\""));
    }

    #[test]
    fn test_otel_multipath_balancing_export() {
        let mut router =
            IsspDynamicMultipathRouter::new(7, IsspRoutingPolicy::BandwidthAggregation);
        router.add_route(IsspMultipathRoute::new(1, 2, "wan0", 1, 80));
        router.add_route(IsspMultipathRoute::new(2, 2, "wwan0", 2, 40));

        let snap = router.balancing_snapshot(1_700_000_000_000_000_000);
        let exporter = OtelMultipathBalancingExporter::new()
            .with_attribute("deployment.environment", "production");

        let json_str = exporter.export(&snap, "ifa-edge-router");

        assert!(json_str.contains("\"service.name\""));
        assert!(json_str.contains("\"ifa-edge-router\""));
        assert!(json_str.contains("\"service.instance.id\""));
        assert!(json_str.contains("\"node-7\""));
        assert!(json_str.contains("\"deployment.environment\""));
        assert!(json_str.contains("\"production\""));
        assert!(json_str.contains("\"ifa.issp.multipath.active_paths\""));
        assert!(json_str.contains("\"ifa.issp.subpath.rtt\""));
        assert!(json_str.contains("\"ifa.issp.subpath.rtt_gradient\""));
        assert!(json_str.contains("\"ifa.issp.subpath.bbr_bw_bps\""));
        assert!(json_str.contains("\"ifa.issp.subpath.ledbat_cwnd_bytes\""));
        assert!(json_str.contains("\"ifa.issp.subpath.traffic_share_ratio\""));
    }

    #[test]
    fn test_session_registry_multipath_balancing_snapshot_integration() {
        let reg = SessionRegistry::new(99);
        reg.set_multipath_routing_policy(IsspRoutingPolicy::BandwidthAggregation)
            .unwrap();
        reg.add_multipath_route(IsspMultipathRoute::new(1, 2, "eth0-wan", 1, 100))
            .unwrap();
        reg.add_multipath_route(IsspMultipathRoute::new(2, 2, "eth1-wan", 2, 100))
            .unwrap();

        let snap = reg
            .multipath_balancing_snapshot(0)
            .expect("fetch balancing snapshot");
        assert_eq!(snap.node_id, 99);
        assert_eq!(snap.active_paths, 2);
        assert_eq!(snap.total_effective_weight, 200);

        let prom = snap.export_prometheus();
        assert!(prom.contains("ifa_issp_multipath_active_paths"));

        let otel = snap.export_otlp_json("test-ifa-service");
        assert!(otel.contains("test-ifa-service"));
    }

    #[test]
    fn test_issp_telemetry_http_handler_endpoints() {
        let reg = SessionRegistry::new(42);
        reg.set_multipath_routing_policy(IsspRoutingPolicy::BandwidthAggregation)
            .unwrap();
        reg.add_multipath_route(IsspMultipathRoute::new(1, 2, "eth0-wan", 1, 100))
            .unwrap();
        reg.add_multipath_route(IsspMultipathRoute::new(2, 2, "wwan0-5g", 2, 50))
            .unwrap();

        let snap = reg.multipath_balancing_snapshot(1_700_000_000).unwrap();
        let handler = IsspTelemetryHttpHandler::new("issp-ingress-gw");

        // 1. /metrics with text/plain (Prometheus)
        let (code, ctype, body) = handler.handle_snapshot("/metrics", "text/plain", &snap);
        assert_eq!(code, 200);
        assert_eq!(ctype, "text/plain; version=0.0.4; charset=utf-8");
        assert!(body.contains("ifa_issp_multipath_active_paths"));
        assert!(body.contains("node_id=\"42\""));
        assert!(body.contains("ifa_issp_subpath_configured_weight"));
        assert!(body.contains("interface=\"eth0-wan\""));

        // 2. /metrics with application/json (OTLP JSON)
        let (code2, ctype2, body2) = handler.handle_snapshot("/metrics", "application/json", &snap);
        assert_eq!(code2, 200);
        assert_eq!(ctype2, "application/json");
        assert!(body2.contains("\"resourceMetrics\""));
        assert!(body2.contains("\"issp-ingress-gw\""));

        // 3. /v1/metrics (OTLP JSON)
        let (code3, ctype3, body3) = handler.handle_snapshot("/v1/metrics", "*/*", &snap);
        assert_eq!(code3, 200);
        assert_eq!(ctype3, "application/json");
        assert!(body3.contains("\"resourceMetrics\""));

        // 4. /healthz and /livez
        let (code_h, _, body_h) = handler.handle_snapshot("/healthz", "*/*", &snap);
        assert_eq!(code_h, 200);
        assert_eq!(body_h, "OK\n");

        let (code_l, _, body_l) = handler.handle_snapshot("/livez", "*/*", &snap);
        assert_eq!(code_l, 200);
        assert_eq!(body_l, "OK\n");

        // 5. 404 Not Found
        let (code_404, _, body_404) = handler.handle_snapshot("/unknown/endpoint", "*/*", &snap);
        assert_eq!(code_404, 404);
        assert_eq!(body_404, "Not Found\n");

        // 6. Raw HTTP request line parsing
        let raw_req = "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1:9090\r\nUser-Agent: Prometheus/2.45.0\r\nAccept: text/plain\r\n\r\n";
        let raw_resp = handler.handle_raw_http_request(raw_req, &snap);
        assert!(raw_resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(raw_resp.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"));
        assert!(raw_resp.contains("ifa_issp_multipath_active_paths"));
        assert!(raw_resp.contains("node_id=\"42\""));
    }

    #[test]
    fn test_issp_telemetry_server_tcp_real_sockets() {
        let reg = SessionRegistry::new(77);
        reg.set_multipath_routing_policy(IsspRoutingPolicy::BandwidthAggregation)
            .unwrap();
        reg.add_multipath_route(IsspMultipathRoute::new(1, 2, "eth0-wan", 1, 100))
            .unwrap();
        reg.add_multipath_route(IsspMultipathRoute::new(2, 2, "eth1-wan", 2, 80))
            .unwrap();

        let server = IsspTelemetryServer::bind("127.0.0.1:0", "ifa-issp-node-77", reg).unwrap();
        let addr = server.local_addr().unwrap();

        let client_thread = std::thread::spawn(move || {
            // 1. GET /metrics (Prometheus Exposition)
            let mut s1 = TcpStream::connect(addr).expect("connect to telemetry server 1");
            s1.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nAccept: text/plain\r\n\r\n")
                .unwrap();
            let mut resp1 = String::new();
            s1.read_to_string(&mut resp1).unwrap();
            assert!(resp1.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(resp1.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"));
            assert!(resp1.contains("ifa_issp_multipath_active_paths"));
            assert!(resp1.contains("node_id=\"77\""));

            // 2. GET /v1/metrics (OTLP JSON)
            let mut s2 = TcpStream::connect(addr).expect("connect to telemetry server 2");
            s2.write_all(
                b"GET /v1/metrics HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\r\n",
            )
            .unwrap();
            let mut resp2 = String::new();
            s2.read_to_string(&mut resp2).unwrap();
            assert!(resp2.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(resp2.contains("Content-Type: application/json\r\n"));
            assert!(resp2.contains("\"resourceMetrics\""));
            assert!(resp2.contains("\"ifa-issp-node-77\""));

            // 3. GET /unknown (404)
            let mut s3 = TcpStream::connect(addr).expect("connect to telemetry server 3");
            s3.write_all(b"GET /nonexistent HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            let mut resp3 = String::new();
            s3.read_to_string(&mut resp3).unwrap();
            assert!(resp3.starts_with("HTTP/1.1 404 Not Found\r\n"));
        });

        // Serve the 3 client requests
        let (code1, path1) = server
            .serve_one_connection(server.listener.accept().unwrap().0)
            .unwrap();
        assert_eq!(code1, 200);
        assert_eq!(path1, "/metrics");

        let (code2, path2) = server
            .serve_one_connection(server.listener.accept().unwrap().0)
            .unwrap();
        assert_eq!(code2, 200);
        assert_eq!(path2, "/v1/metrics");

        let (code3, path3) = server
            .serve_one_connection(server.listener.accept().unwrap().0)
            .unwrap();
        assert_eq!(code3, 404);
        assert_eq!(path3, "/nonexistent");

        client_thread.join().unwrap();
    }

    // ── WebSocket helper unit tests ───────────────────────────────────────────

    #[test]
    fn test_ws_accept_key_rfc6455_vector() {
        // RFC 6455 §1.3 example: client key "dGhlIHNhbXBsZSBub25jZQ==" → accept "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = ws_accept_key(key);
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn test_ws_text_frame_encode_decode() {
        let payload = b"hello ws";
        let frame = ws_build_text_frame(payload);
        // FIN + text opcode
        assert_eq!(frame[0], 0x81);
        // 7-bit length (< 126)
        assert_eq!(frame[1] as usize, payload.len());
        // Payload verbatim
        assert_eq!(&frame[2..], payload);
    }

    #[test]
    fn test_snapshot_to_compact_json_fields() {
        use crate::session_sync::{
            IsspDynamicMultipathRouter, IsspMultipathRoute, IsspRoutingPolicy,
        };
        let mut router =
            IsspDynamicMultipathRouter::new(5, IsspRoutingPolicy::BandwidthAggregation);
        router.add_route(IsspMultipathRoute::new(1, 2, "eth0", 1, 100));
        router.add_route(IsspMultipathRoute::new(2, 2, "eth1", 2, 50));
        let snap = router.balancing_snapshot(42_000_000_000);
        let json = snapshot_to_compact_json(&snap);
        assert!(json.starts_with('{'));
        assert!(json.contains("\"ts\":42000000000"));
        assert!(json.contains("\"node\":5"));
        assert!(json.contains("\"active_paths\":2"));
        assert!(json.contains("\"iface\":\"eth0\""));
        assert!(json.contains("\"iface\":\"eth1\""));
        assert!(json.ends_with('}'));
        // Verify parseable structure — count braces
        let opens = json.chars().filter(|&c| c == '{').count();
        let closes = json.chars().filter(|&c| c == '}').count();
        assert_eq!(opens, closes);
    }

    #[test]
    fn test_ws_metrics_server_full_handshake_and_frames() {
        use crate::session_sync::{IsspMultipathRoute, IsspRoutingPolicy, SessionRegistry};

        let reg = SessionRegistry::new(55);
        reg.set_multipath_routing_policy(IsspRoutingPolicy::BandwidthAggregation)
            .unwrap();
        reg.add_multipath_route(IsspMultipathRoute::new(1, 2, "wan0", 1, 100))
            .unwrap();

        let server = IsspTelemetryServer::bind("127.0.0.1:0", "ifa-ws-test", reg).unwrap();
        let addr = server.local_addr().unwrap();

        // Client: perform RFC 6455 handshake then read 2 text frames.
        let client = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).expect("connect");
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

            // Send upgrade request with a known key.
            let key = "dGhlIHNhbXBsZSBub25jZQ==";
            let req = format!(
                "GET /ws/metrics HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Key: {}\r\n\
                 Sec-WebSocket-Version: 13\r\n\r\n",
                key
            );
            s.write_all(req.as_bytes()).unwrap();

            // Read the 101 response byte-by-byte until \r\n\r\n sentinel.
            // This avoids reading into the first WS binary frame.
            let mut resp_bytes: Vec<u8> = Vec::with_capacity(256);
            let mut one = [0u8; 1];
            loop {
                s.read_exact(&mut one).unwrap();
                resp_bytes.push(one[0]);
                if resp_bytes.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let resp_str = std::str::from_utf8(&resp_bytes).unwrap();
            assert!(resp_str.starts_with("HTTP/1.1 101 Switching Protocols"));
            assert!(resp_str.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));

            // Read 2 text frames.
            for _i in 0..2 {
                let mut header = [0u8; 2];
                s.read_exact(&mut header).unwrap();
                assert_eq!(header[0], 0x81, "FIN+text opcode");
                let payload_len: usize = match header[1] & 0x7F {
                    126 => {
                        let mut ext = [0u8; 2];
                        s.read_exact(&mut ext).unwrap();
                        u16::from_be_bytes(ext) as usize
                    }
                    127 => {
                        let mut ext = [0u8; 8];
                        s.read_exact(&mut ext).unwrap();
                        u64::from_be_bytes(ext) as usize
                    }
                    n => n as usize,
                };
                assert!(payload_len > 0);
                let mut payload = vec![0u8; payload_len];
                s.read_exact(&mut payload).unwrap();
                let json = std::str::from_utf8(&payload).unwrap();
                assert!(json.contains("\"active_paths\""), "frame JSON: {}", json);
                assert!(json.contains("\"node\":55"), "frame JSON: {}", json);
            }
        });

        // Server: serve 1 WS connection with 2 frames, 1ms interval.
        let frames = server
            .serve_ws_metrics_connection(server.listener.accept().unwrap().0, 1, 2)
            .unwrap();
        assert_eq!(frames, 2);

        client.join().unwrap();
    }

    #[test]
    fn test_try_serve_one_smart_http_and_ws() {
        use crate::session_sync::{IsspMultipathRoute, IsspRoutingPolicy, SessionRegistry};

        let reg = SessionRegistry::new(99);
        reg.set_multipath_routing_policy(IsspRoutingPolicy::LowestLatency)
            .unwrap();
        reg.add_multipath_route(IsspMultipathRoute::new(1, 2, "eth0", 1, 100))
            .unwrap();

        let server = IsspTelemetryServer::bind("127.0.0.1:0", "smart-test", reg).unwrap();
        server.set_nonblocking(true).unwrap();
        let addr = server.local_addr().unwrap();

        // 1. Client connects via standard HTTP GET /metrics
        let client1 = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).expect("connect http");
            s.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut buf = String::new();
            s.read_to_string(&mut buf).unwrap();
            assert!(buf.starts_with("HTTP/1.1 200 OK"));
        });

        let mut res1 = None;
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while res1.is_none() && std::time::Instant::now() < deadline {
            match server.try_serve_one_smart(1, 1) {
                Ok(Some(r)) => res1 = Some(r),
                _ => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        client1.join().unwrap();
        let (status, path) = res1.expect("expected HTTP request served");
        assert_eq!(status, 200);
        assert_eq!(path, "/metrics");

        // 2. Client connects via WebSocket GET /ws/metrics
        let client2 = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).expect("connect ws");
            s.write_all(
                b"GET /ws/metrics HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\
                  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                  Sec-WebSocket-Version: 13\r\n\r\n",
            )
            .unwrap();
            // Read 101 handshake response until delimiter
            let mut resp_bytes: Vec<u8> = Vec::with_capacity(256);
            let mut one = [0u8; 1];
            loop {
                s.read_exact(&mut one).unwrap();
                resp_bytes.push(one[0]);
                if resp_bytes.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let resp = std::str::from_utf8(&resp_bytes).unwrap();
            assert!(resp.starts_with("HTTP/1.1 101 Switching Protocols"));

            // Read the 1 streamed text frame
            let mut frame_hdr = [0u8; 2];
            s.read_exact(&mut frame_hdr).unwrap();
            assert_eq!(frame_hdr[0], 0x81);
            let payload_len: usize = match frame_hdr[1] & 0x7F {
                126 => {
                    let mut ext = [0u8; 2];
                    s.read_exact(&mut ext).unwrap();
                    u16::from_be_bytes(ext) as usize
                }
                127 => {
                    let mut ext = [0u8; 8];
                    s.read_exact(&mut ext).unwrap();
                    u64::from_be_bytes(ext) as usize
                }
                n => n as usize,
            };
            let mut payload = vec![0u8; payload_len];
            s.read_exact(&mut payload).unwrap();
            let json = std::str::from_utf8(&payload).unwrap();
            assert!(json.contains("\"active_paths\""));
        });

        let mut res2 = None;
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while res2.is_none() && std::time::Instant::now() < deadline {
            match server.try_serve_one_smart(1, 1) {
                Ok(Some(r)) => res2 = Some(r),
                _ => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        client2.join().unwrap();
        let (frames, path) = res2.expect("expected WS connection served");
        assert_eq!(frames, 1);
        assert_eq!(path, "/ws/metrics");
    }

    #[test]
    fn test_latency_histogram_observe_and_merge() {
        let mut h1 = LatencyHistogram::default();
        assert_eq!(h1.count, 0);
        assert_eq!(h1.mean_seconds(), 0.0);
        assert_eq!(h1.safe_min_seconds(), 0.0);

        // Observe 2ms (0.002s), 15ms (0.015s), 60ms (0.060s)
        h1.observe(0.002);
        h1.observe(0.015);
        h1.observe_us(60_000); // 60ms

        assert_eq!(h1.count, 3);
        assert!((h1.safe_min_seconds() - 0.002).abs() < 1e-6);
        assert!((h1.max_seconds - 0.060).abs() < 1e-6);
        assert!((h1.mean_seconds() - (0.077 / 3.0)).abs() < 1e-6);

        // Bucket checks:
        // 0.001 (1ms) -> 0
        assert_eq!(h1.cumulative_counts[0], 0);
        // 0.005 (5ms) -> 1 (0.002s)
        assert_eq!(h1.cumulative_counts[1], 1);
        // 0.025 (25ms) -> 2 (0.002s, 0.015s)
        assert_eq!(h1.cumulative_counts[3], 2);
        // 0.100 (100ms) -> 3 (all three)
        assert_eq!(h1.cumulative_counts[5], 3);

        // Merge another histogram
        let mut h2 = LatencyHistogram::default();
        h2.observe(0.0005); // 0.5ms
        h2.observe(0.300); // 300ms

        h1.merge(&h2);
        assert_eq!(h1.count, 5);
        assert!((h1.safe_min_seconds() - 0.0005).abs() < 1e-6);
        assert!((h1.max_seconds - 0.300).abs() < 1e-6);
        // 0.001 bucket now has 1
        assert_eq!(h1.cumulative_counts[0], 1);
    }

    #[test]
    fn test_interface_latency_histograms_and_retransmissions() {
        let reg = SessionRegistry::new(10);
        reg.set_multipath_routing_policy(IsspRoutingPolicy::BandwidthAggregation)
            .unwrap();

        let mut r1 = IsspMultipathRoute::new(1, 2, "eth0-wan", 1, 100);
        r1.metrics.total_frames_sent = 1000;
        r1.metrics.record_tcp_retransmit(25);
        r1.metrics.record_issp_retransmit(5);
        r1.record_latency_sample(12_000); // 12ms
        r1.record_latency_sample(18_000); // 18ms

        let mut r2 = IsspMultipathRoute::new(2, 2, "wwan0-5g", 2, 50);
        r2.metrics.total_frames_sent = 500;
        r2.metrics.record_tcp_retransmit(40);
        r2.metrics.record_issp_retransmit(10);
        r2.record_latency_sample(45_000); // 45ms

        reg.add_multipath_route(r1).unwrap();
        reg.add_multipath_route(r2).unwrap();

        // Register dummy sessions to test session counting
        let s1 = SessionSnapshot::new(
            crate::session_sync::SessionId::new(1, 10, 1),
            1,
            1000,
        );
        let s2 = SessionSnapshot::new(
            crate::session_sync::SessionId::new(2, 10, 2),
            1,
            1000,
        );
        reg.upsert_primary(s1).unwrap();
        reg.upsert_primary(s2).unwrap();

        let snap = reg.multipath_balancing_snapshot(0).unwrap();
        assert_eq!(snap.total_sessions, 2);
        assert_eq!(snap.primary_sessions, 2);
        assert_eq!(snap.standby_sessions, 0);

        // Subpath retransmission checks
        let sp1 = snap.subpath(1).unwrap();
        assert_eq!(sp1.tcp_retrans_count, 25);
        assert_eq!(sp1.issp_retrans_count, 5);
        assert!((sp1.tcp_retrans_ratio - 0.025).abs() < 1e-4);
        assert!((sp1.issp_retrans_ratio - 0.005).abs() < 1e-4);
        assert!((sp1.total_retrans_ratio - 0.030).abs() < 1e-4);

        let sp2 = snap.subpath(2).unwrap();
        assert_eq!(sp2.tcp_retrans_count, 40);
        assert_eq!(sp2.issp_retrans_count, 10);
        assert!((sp2.tcp_retrans_ratio - 0.080).abs() < 1e-4);
        assert!((sp2.issp_retrans_ratio - 0.020).abs() < 1e-4);

        // Interface latency histograms
        let eth0_hist = snap
            .interface_latency_histograms
            .get("eth0-wan")
            .expect("eth0-wan histogram");
        assert_eq!(eth0_hist.count, 2);
        let wwan_hist = snap
            .interface_latency_histograms
            .get("wwan0-5g")
            .expect("wwan0-5g histogram");
        assert_eq!(wwan_hist.count, 1);

        // Test Prometheus export
        let prom = snap.export_prometheus();
        assert!(prom.contains("# HELP ifa_session_total_sessions"));
        assert!(prom.contains("ifa_session_total_sessions"));
        assert!(prom.contains("# HELP ifa_issp_interface_latency_seconds"));
        assert!(prom.contains("ifa_issp_interface_latency_seconds_bucket{"));
        assert!(prom.contains("interface=\"eth0-wan\""));
        assert!(prom.contains("ifa_issp_interface_latency_seconds_count{"));
        assert!(prom.contains("# HELP ifa_issp_subpath_tcp_retransmission_ratio"));
        assert!(prom.contains("ifa_issp_subpath_tcp_retransmission_ratio{"));
        assert!(prom.contains("# HELP ifa_session_interface_retransmission_ratio"));
        assert!(prom.contains("ifa_session_interface_retransmission_ratio{"));
        assert!(prom.contains("protocol=\"tcp\""));

        // Test OTLP export
        let otlp = snap.export_otlp_json("test-service");
        assert!(otlp.contains("\"ifa.session.total_sessions\""));
        assert!(otlp.contains("\"ifa.issp.subpath.tcp_retransmission_ratio\""));
        assert!(otlp.contains("\"ifa.issp.interface.latency\""));
    }
}

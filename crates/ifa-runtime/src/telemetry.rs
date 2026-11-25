//! System resource audit metrics and subprocess telemetry for IFA runtime, toolchain, and build orchestrator.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::process::{Command, ExitStatus};
use std::sync::{Arc, RwLock};
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
    /// Total automatic interface and subpath failovers recorded.
    pub total_failovers: u64,
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
            total_failovers: router.total_failovers,
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

    /// Export snapshot in standard OpenTelemetry OTLP Protobuf (v1/metrics) binary format.
    pub fn export_otlp_protobuf(&self, service_name: &str) -> Vec<u8> {
        OtelProtobufMultipathExporter::new().export(self, service_name)
    }

    /// Export snapshot in standard gRPC-framed OpenTelemetry OTLP format (5-byte length prefix + Protobuf).
    pub fn export_otlp_grpc_frame(&self, service_name: &str) -> Vec<u8> {
        let proto = self.export_otlp_protobuf(service_name);
        GrpcFrame::encode(&proto)
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
        out.push_str(
            "# HELP ifa_session_total_sessions Total active sessions tracked in registry.\n",
        );
        out.push_str("# TYPE ifa_session_total_sessions gauge\n");
        out.push_str(&format!(
            "ifa_session_total_sessions{} {}\n",
            base_lbl, s.total_sessions
        ));

        out.push_str(
            "# HELP ifa_session_primary_sessions Primary active sessions owned by local node.\n",
        );
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

        out.push_str("# HELP ifa_issp_multipath_total_failovers Total automatic interface and subpath failover events recorded.\n");
        out.push_str("# TYPE ifa_issp_multipath_total_failovers counter\n");
        out.push_str(&format!(
            "ifa_issp_multipath_total_failovers{} {}\n",
            base_lbl, s.total_failovers
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
                let sum_lbl = self.format_labels(&[("node_id", &node_str), ("interface", iface)]);
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
        if !s.interface_tcp_retrans_ratios.is_empty() || !s.interface_issp_retrans_ratios.is_empty()
        {
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

// ─── OpenTelemetry OTLP Protobuf (v1/metrics) & gRPC Exporter ─────────────

/// High-performance, zero-allocation Protocol Buffers v3 wire writer.
#[derive(Debug, Clone, Default)]
pub struct ProtobufWriter {
    buf: Vec<u8>,
}

impl ProtobufWriter {
    /// Create a new protobuf writer.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Create a new protobuf writer with pre-allocated capacity.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    /// Current length in bytes.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Borrow buffer as byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Consume writer and return underlying bytes.
    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    /// Encode an unsigned 64-bit integer into protobuf varint format.
    pub fn write_varint(&mut self, mut val: u64) {
        while val >= 0x80 {
            self.buf.push(((val & 0x7F) as u8) | 0x80);
            val >>= 7;
        }
        self.buf.push((val & 0x7F) as u8);
    }

    /// Write field tag: `(field_number << 3) | wire_type`.
    pub fn write_tag(&mut self, field_number: u32, wire_type: u8) {
        self.write_varint(((field_number as u64) << 3) | (wire_type as u64));
    }

    /// Write a uint64 varint field (omitted if 0).
    pub fn write_uint64(&mut self, field_number: u32, val: u64) {
        if val != 0 {
            self.write_tag(field_number, 0);
            self.write_varint(val);
        }
    }

    /// Write an int64 varint field (omitted if 0).
    pub fn write_int64(&mut self, field_number: u32, val: i64) {
        if val != 0 {
            self.write_tag(field_number, 0);
            self.write_varint(val as u64);
        }
    }

    /// Write an int32 varint field (omitted if 0).
    pub fn write_int32(&mut self, field_number: u32, val: i32) {
        if val != 0 {
            self.write_tag(field_number, 0);
            self.write_varint(val as i64 as u64);
        }
    }

    /// Write a boolean varint field (omitted if false).
    pub fn write_bool(&mut self, field_number: u32, val: bool) {
        if val {
            self.write_tag(field_number, 0);
            self.write_varint(1);
        }
    }

    /// Write a fixed64 field (wire type 1, 8 bytes little-endian).
    pub fn write_fixed64(&mut self, field_number: u32, val: u64) {
        self.write_tag(field_number, 1);
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    /// Write an sfixed64 field (wire type 1, 8 bytes little-endian).
    pub fn write_sfixed64(&mut self, field_number: u32, val: i64) {
        self.write_tag(field_number, 1);
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    /// Write a double precision float field (wire type 1, 8 bytes little-endian).
    pub fn write_double(&mut self, field_number: u32, val: f64) {
        self.write_tag(field_number, 1);
        self.buf.extend_from_slice(&val.to_bits().to_le_bytes());
    }

    /// Write a UTF-8 string field (wire type 2, length-delimited).
    pub fn write_string(&mut self, field_number: u32, s: &str) {
        if !s.is_empty() {
            self.write_tag(field_number, 2);
            self.write_varint(s.len() as u64);
            self.buf.extend_from_slice(s.as_bytes());
        }
    }

    /// Write a byte array field (wire type 2, length-delimited).
    pub fn write_bytes(&mut self, field_number: u32, bytes: &[u8]) {
        if !bytes.is_empty() {
            self.write_tag(field_number, 2);
            self.write_varint(bytes.len() as u64);
            self.buf.extend_from_slice(bytes);
        }
    }

    /// Write an embedded message closure (wire type 2, length-delimited).
    pub fn write_message<F>(&mut self, field_number: u32, f: F)
    where
        F: FnOnce(&mut ProtobufWriter),
    {
        let mut sub = ProtobufWriter::with_capacity(128);
        f(&mut sub);
        if !sub.is_empty() {
            self.write_tag(field_number, 2);
            self.write_varint(sub.len() as u64);
            self.buf.extend_from_slice(sub.as_slice());
        }
    }

    /// Write packed fixed64 integers (wire type 2, length-delimited).
    pub fn write_packed_fixed64(&mut self, field_number: u32, values: &[u64]) {
        if !values.is_empty() {
            self.write_tag(field_number, 2);
            self.write_varint((values.len() * 8) as u64);
            for &v in values {
                self.buf.extend_from_slice(&v.to_le_bytes());
            }
        }
    }

    /// Write packed double-precision floats (wire type 2, length-delimited).
    pub fn write_packed_doubles(&mut self, field_number: u32, values: &[f64]) {
        if !values.is_empty() {
            self.write_tag(field_number, 2);
            self.write_varint((values.len() * 8) as u64);
            for &v in values {
                self.buf.extend_from_slice(&v.to_bits().to_le_bytes());
            }
        }
    }
}

/// OpenTelemetry OTLP Protobuf (v1/metrics) exporter for dynamic ISSP multipath balancing.
#[derive(Debug, Clone, Default)]
pub struct OtelProtobufMultipathExporter {
    pub default_attributes: BTreeMap<String, String>,
}

impl OtelProtobufMultipathExporter {
    /// Create a new OpenTelemetry OTLP Protobuf multipath exporter.
    pub fn new() -> Self {
        Self {
            default_attributes: BTreeMap::new(),
        }
    }

    /// Add a resource attribute applied to the exported OTLP Protobuf payload.
    pub fn with_attribute(mut self, key: &str, value: &str) -> Self {
        self.default_attributes
            .insert(key.to_string(), value.to_string());
        self
    }

    /// Helper to write an OTLP KeyValue attribute message with a string value.
    fn write_kv_string(w: &mut ProtobufWriter, key_field: u32, key: &str, val: &str) {
        w.write_message(key_field, |kv| {
            kv.write_string(1, key);
            kv.write_message(2, |av| {
                av.write_string(1, val);
            });
        });
    }

    /// Helper to write subpath attributes on a data point.
    fn write_subpath_attributes(
        w: &mut ProtobufWriter,
        attr_field: u32,
        node_id: u32,
        sp: &IsspSubpathBalancingMetrics,
    ) {
        let node_str = node_id.to_string();
        let path_str = sp.path_id.to_string();
        Self::write_kv_string(w, attr_field, "node_id", &node_str);
        Self::write_kv_string(w, attr_field, "path_id", &path_str);
        Self::write_kv_string(w, attr_field, "interface", &sp.interface_name);
        Self::write_kv_string(w, attr_field, "state", &sp.state);
        Self::write_kv_string(w, attr_field, "phase", &sp.congestion_phase);
    }

    /// Helper to write pool-level attributes (node_id and policy).
    fn write_pool_attributes(w: &mut ProtobufWriter, attr_field: u32, node_id: u32, policy: &str) {
        let node_str = node_id.to_string();
        Self::write_kv_string(w, attr_field, "node_id", &node_str);
        Self::write_kv_string(w, attr_field, "policy", policy);
    }

    /// Export an `IsspMultipathBalancingSnapshot` into binary OpenTelemetry `ExportMetricsServiceRequest` Protobuf.
    pub fn export(&self, s: &IsspMultipathBalancingSnapshot, service_name: &str) -> Vec<u8> {
        let mut req_writer = ProtobufWriter::with_capacity(4096);
        let ts_ns = s.timestamp_unix_ns;
        let node_id = s.node_id;
        let node_str = node_id.to_string();
        let policy = &s.routing_policy;

        // ExportMetricsServiceRequest.resource_metrics = 1 (repeated)
        req_writer.write_message(1, |rm| {
            // ResourceMetrics.resource = 1
            rm.write_message(1, |res| {
                // Resource.attributes = 1 (repeated KeyValue)
                Self::write_kv_string(res, 1, "service.name", service_name);
                let inst_id = format!("node-{}", node_id);
                Self::write_kv_string(res, 1, "service.instance.id", &inst_id);
                Self::write_kv_string(res, 1, "telemetry.sdk.name", "ifa-runtime");
                Self::write_kv_string(res, 1, "telemetry.sdk.language", "ifa/rust");
                for (k, v) in &self.default_attributes {
                    Self::write_kv_string(res, 1, k, v);
                }
            });

            // ResourceMetrics.scope_metrics = 2 (repeated ScopeMetrics)
            rm.write_message(2, |sm| {
                // ScopeMetrics.scope = 1 (InstrumentationScope)
                sm.write_message(1, |scope| {
                    scope.write_string(1, "ifa-runtime::issp_multipath");
                    scope.write_string(2, "0.1.0");
                });

                // ScopeMetrics.metrics = 2 (repeated Metric)

                // 1. Pool active paths (Gauge)
                sm.write_message(2, |m| {
                    m.write_string(1, "ifa.issp.multipath.active_paths");
                    m.write_string(2, "Number of operational multipath subpaths");
                    m.write_string(3, "1");
                    m.write_message(5, |g| {
                        g.write_message(1, |dp| {
                            dp.write_fixed64(3, ts_ns);
                            dp.write_sfixed64(6, s.active_paths as i64);
                            Self::write_pool_attributes(dp, 7, node_id, policy);
                        });
                    });
                });

                // 2. Pool total effective weight (Gauge)
                sm.write_message(2, |m| {
                    m.write_string(1, "ifa.issp.multipath.total_effective_weight");
                    m.write_string(
                        2,
                        "Aggregate effective scheduling weight across operational subpaths",
                    );
                    m.write_string(3, "1");
                    m.write_message(5, |g| {
                        g.write_message(1, |dp| {
                            dp.write_fixed64(3, ts_ns);
                            dp.write_sfixed64(6, s.total_effective_weight as i64);
                            Self::write_pool_attributes(dp, 7, node_id, policy);
                        });
                    });
                });

                // 3. Subpath RTT (Gauge, seconds)
                sm.write_message(2, |m| {
                    m.write_string(1, "ifa.issp.subpath.rtt");
                    m.write_string(2, "Smoothed round-trip time in seconds");
                    m.write_string(3, "s");
                    m.write_message(5, |g| {
                        for sp in &s.subpaths {
                            g.write_message(1, |dp| {
                                dp.write_fixed64(3, ts_ns);
                                dp.write_double(4, (sp.rtt_us as f64) / 1_000_000.0);
                                Self::write_subpath_attributes(dp, 7, node_id, sp);
                            });
                        }
                    });
                });

                // 4. Subpath RTT gradient (Gauge, seconds)
                sm.write_message(2, |m| {
                    m.write_string(1, "ifa.issp.subpath.rtt_gradient");
                    m.write_string(2, "RTT gradient and queuing delay in seconds");
                    m.write_string(3, "s");
                    m.write_message(5, |g| {
                        for sp in &s.subpaths {
                            g.write_message(1, |dp| {
                                dp.write_fixed64(3, ts_ns);
                                dp.write_double(4, (sp.rtt_gradient_us as f64) / 1_000_000.0);
                                Self::write_subpath_attributes(dp, 7, node_id, sp);
                            });
                        }
                    });
                });

                // 5. BBR BtlBw (Gauge, bit/s)
                sm.write_message(2, |m| {
                    m.write_string(1, "ifa.issp.subpath.bbr_bw_bps");
                    m.write_string(2, "BBR estimated bottleneck bandwidth in bits per second");
                    m.write_string(3, "bit/s");
                    m.write_message(5, |g| {
                        for sp in &s.subpaths {
                            g.write_message(1, |dp| {
                                dp.write_fixed64(3, ts_ns);
                                dp.write_sfixed64(6, sp.bbr_bw_bps as i64);
                                Self::write_subpath_attributes(dp, 7, node_id, sp);
                            });
                        }
                    });
                });

                // 6. LEDBAT CWND (Gauge, bytes)
                sm.write_message(2, |m| {
                    m.write_string(1, "ifa.issp.subpath.ledbat_cwnd_bytes");
                    m.write_string(2, "LEDBAT congestion window in bytes");
                    m.write_string(3, "By");
                    m.write_message(5, |g| {
                        for sp in &s.subpaths {
                            g.write_message(1, |dp| {
                                dp.write_fixed64(3, ts_ns);
                                dp.write_sfixed64(6, sp.ledbat_cwnd_bytes as i64);
                                Self::write_subpath_attributes(dp, 7, node_id, sp);
                            });
                        }
                    });
                });

                // 7. Traffic share ratio (Gauge)
                sm.write_message(2, |m| {
                    m.write_string(1, "ifa.issp.subpath.traffic_share_ratio");
                    m.write_string(
                        2,
                        "Dynamic traffic allocation ratio across aggregated subpaths",
                    );
                    m.write_string(3, "1");
                    m.write_message(5, |g| {
                        for sp in &s.subpaths {
                            g.write_message(1, |dp| {
                                dp.write_fixed64(3, ts_ns);
                                dp.write_double(4, sp.traffic_share_ratio);
                                Self::write_subpath_attributes(dp, 7, node_id, sp);
                            });
                        }
                    });
                });

                // 8. Effective weight (Gauge)
                sm.write_message(2, |m| {
                    m.write_string(1, "ifa.issp.subpath.effective_weight");
                    m.write_string(2, "Dynamic effective scheduling weight");
                    m.write_string(3, "1");
                    m.write_message(5, |g| {
                        for sp in &s.subpaths {
                            g.write_message(1, |dp| {
                                dp.write_fixed64(3, ts_ns);
                                dp.write_sfixed64(6, sp.effective_weight as i64);
                                Self::write_subpath_attributes(dp, 7, node_id, sp);
                            });
                        }
                    });
                });

                // 9. Congestion events (Sum, monotonic counter)
                sm.write_message(2, |m| {
                    m.write_string(1, "ifa.issp.subpath.congestion_events_total");
                    m.write_string(2, "Total congestion events observed on subpath");
                    m.write_string(3, "1");
                    m.write_message(7, |sum| {
                        for sp in &s.subpaths {
                            sum.write_message(1, |dp| {
                                dp.write_fixed64(3, ts_ns);
                                dp.write_sfixed64(6, sp.congestion_events as i64);
                                Self::write_subpath_attributes(dp, 7, node_id, sp);
                            });
                        }
                        sum.write_int32(2, 2); // CUMULATIVE
                        sum.write_bool(3, true); // is_monotonic
                    });
                });

                // 10. Sessions count (Gauge)
                sm.write_message(2, |m| {
                    m.write_string(1, "ifa.session.total_sessions");
                    m.write_string(2, "Total active sessions tracked in registry");
                    m.write_string(3, "1");
                    m.write_message(5, |g| {
                        g.write_message(1, |dp| {
                            dp.write_fixed64(3, ts_ns);
                            dp.write_sfixed64(6, s.total_sessions as i64);
                            Self::write_pool_attributes(dp, 7, node_id, policy);
                        });
                    });
                });

                // 11. TCP retransmission ratio (Gauge)
                sm.write_message(2, |m| {
                    m.write_string(1, "ifa.issp.subpath.tcp_retransmission_ratio");
                    m.write_string(2, "TCP retransmission ratio on subpath");
                    m.write_string(3, "1");
                    m.write_message(5, |g| {
                        for sp in &s.subpaths {
                            g.write_message(1, |dp| {
                                dp.write_fixed64(3, ts_ns);
                                dp.write_double(4, sp.tcp_retrans_ratio);
                                Self::write_subpath_attributes(dp, 7, node_id, sp);
                            });
                        }
                    });
                });

                // 12. ISSP retransmission ratio (Gauge)
                sm.write_message(2, |m| {
                    m.write_string(1, "ifa.issp.subpath.issp_retransmission_ratio");
                    m.write_string(2, "ISSP capsule retransmission ratio on subpath");
                    m.write_string(3, "1");
                    m.write_message(5, |g| {
                        for sp in &s.subpaths {
                            g.write_message(1, |dp| {
                                dp.write_fixed64(3, ts_ns);
                                dp.write_double(4, sp.issp_retrans_ratio);
                                Self::write_subpath_attributes(dp, 7, node_id, sp);
                            });
                        }
                    });
                });

                // 13. Interface Latency Histograms
                if !s.interface_latency_histograms.is_empty() {
                    sm.write_message(2, |m| {
                        m.write_string(1, "ifa.issp.interface.latency");
                        m.write_string(2, "Round-trip latency distribution per network interface");
                        m.write_string(3, "s");
                        m.write_message(9, |hist_msg| {
                            for (iface, hist) in &s.interface_latency_histograms {
                                hist_msg.write_message(1, |dp| {
                                    dp.write_fixed64(3, ts_ns);
                                    dp.write_fixed64(4, hist.count);
                                    dp.write_double(5, hist.sum_seconds);
                                    dp.write_packed_fixed64(6, &hist.cumulative_counts);
                                    dp.write_packed_doubles(7, &hist.buckets);
                                    dp.write_double(8, hist.safe_min_seconds());
                                    Self::write_kv_string(dp, 9, "node_id", &node_str);
                                    Self::write_kv_string(dp, 9, "interface", iface);
                                    dp.write_double(11, hist.max_seconds);
                                });
                            }
                            hist_msg.write_int32(2, 2); // CUMULATIVE
                        });
                    });
                }
            });
        });

        req_writer.into_inner()
    }
}

// ─── gRPC Frame Formatting & OTLP gRPC Client ─────────────────────────────

/// gRPC wire frame encoder and decoder (5-byte length prefix: 1 byte compressed flag + 4 bytes big-endian length).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrpcFrame;

/// Errors arising during gRPC framing encode or decode operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrpcFrameError {
    IncompleteHeader,
    IncompleteBody { expected: usize, found: usize },
    InvalidLength,
}

impl std::fmt::Display for GrpcFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncompleteHeader => write!(f, "Incomplete gRPC frame header (less than 5 bytes)"),
            Self::IncompleteBody { expected, found } => {
                write!(
                    f,
                    "Incomplete gRPC body (expected {} bytes, found {})",
                    expected, found
                )
            }
            Self::InvalidLength => write!(f, "Invalid gRPC frame length exceeds limit"),
        }
    }
}

impl std::error::Error for GrpcFrameError {}

impl GrpcFrame {
    /// Encode a payload slice into a standard uncompressed gRPC frame.
    pub fn encode(payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.push(0x00); // 0 = uncompressed
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// Decode a gRPC frame from raw bytes. Returns `(is_compressed, payload_slice)`.
    pub fn decode(buf: &[u8]) -> Result<(bool, &[u8]), GrpcFrameError> {
        if buf.len() < 5 {
            return Err(GrpcFrameError::IncompleteHeader);
        }
        let compressed = buf[0] != 0;
        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        if buf.len() < 5 + len {
            return Err(GrpcFrameError::IncompleteBody {
                expected: 5 + len,
                found: buf.len(),
            });
        }
        Ok((compressed, &buf[5..5 + len]))
    }
}

/// Result of an OTLP gRPC export operation.
#[derive(Debug, Clone, PartialEq)]
pub struct OtlpGrpcExportResult {
    /// gRPC status code (0 = OK).
    pub status_code: u32,
    /// Status message or description.
    pub status_message: String,
    /// Total bytes transmitted across the wire.
    pub bytes_sent: usize,
    /// Total bytes received in response.
    pub bytes_received: usize,
    /// Duration of export in microseconds.
    pub duration_us: u64,
}

/// Errors occurring during OTLP gRPC export.
#[derive(Debug)]
pub enum OtlpGrpcError {
    Io(std::io::Error),
    GrpcStatus { code: u32, message: String },
    ProtocolError(String),
    Timeout,
}

impl From<std::io::Error> for OtlpGrpcError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for OtlpGrpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "OTLP gRPC I/O error: {}", e),
            Self::GrpcStatus { code, message } => {
                write!(f, "OTLP gRPC error status {}: {}", code, message)
            }
            Self::ProtocolError(s) => write!(f, "OTLP gRPC protocol error: {}", s),
            Self::Timeout => write!(f, "OTLP gRPC request timed out"),
        }
    }
}

impl std::error::Error for OtlpGrpcError {}

/// OpenTelemetry OTLP gRPC (v1/metrics) client exporter for dynamic ISSP multipath balancing.
#[derive(Debug, Clone)]
pub struct OtelMultipathBalancingGrpcExporter {
    pub endpoint: String,
    pub timeout: Duration,
    pub default_attributes: BTreeMap<String, String>,
}

impl OtelMultipathBalancingGrpcExporter {
    /// Create a new OTLP gRPC exporter for the specified target endpoint (e.g. "127.0.0.1:4317").
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            timeout: Duration::from_secs(5),
            default_attributes: BTreeMap::new(),
        }
    }

    /// Set a custom network timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Add a resource attribute applied to all exported payloads.
    pub fn with_attribute(mut self, key: &str, value: &str) -> Self {
        self.default_attributes
            .insert(key.to_string(), value.to_string());
        self
    }

    /// Serialize snapshot to standard binary OTLP Protobuf format.
    pub fn export_protobuf(
        &self,
        s: &IsspMultipathBalancingSnapshot,
        service_name: &str,
    ) -> Vec<u8> {
        let mut exp = OtelProtobufMultipathExporter::new();
        exp.default_attributes = self.default_attributes.clone();
        exp.export(s, service_name)
    }

    /// Serialize snapshot to standard 5-byte framed gRPC format.
    pub fn export_grpc_frame(
        &self,
        s: &IsspMultipathBalancingSnapshot,
        service_name: &str,
    ) -> Vec<u8> {
        let proto = self.export_protobuf(s, service_name);
        GrpcFrame::encode(&proto)
    }

    /// Export snapshot over a generic I/O stream using HTTP/2 gRPC or HTTP/1.1 gRPC transport.
    pub fn export_stream<R: Read, W: Write>(
        &self,
        s: &IsspMultipathBalancingSnapshot,
        service_name: &str,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<OtlpGrpcExportResult, OtlpGrpcError> {
        let start = std::time::Instant::now();
        let frame = self.export_grpc_frame(s, service_name);
        let frame_len = frame.len();

        // 1. Send HTTP/2 client connection preface + SETTINGS + HEADERS + DATA in one write
        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let settings_frame = [0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];

        let mut hpack_buf = Vec::with_capacity(256);
        encode_literal_hpack_header(&mut hpack_buf, ":method", "POST");
        encode_literal_hpack_header(&mut hpack_buf, ":scheme", "http");
        encode_literal_hpack_header(
            &mut hpack_buf,
            ":path",
            "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export",
        );
        encode_literal_hpack_header(&mut hpack_buf, ":authority", &self.endpoint);
        encode_literal_hpack_header(&mut hpack_buf, "content-type", "application/grpc");
        encode_literal_hpack_header(&mut hpack_buf, "te", "trailers");
        encode_literal_hpack_header(&mut hpack_buf, "user-agent", "ifa-runtime-otlp-grpc");

        let h_len = hpack_buf.len();
        let headers_hdr = [
            ((h_len >> 16) & 0xFF) as u8,
            ((h_len >> 8) & 0xFF) as u8,
            (h_len & 0xFF) as u8,
            0x01, // Type: HEADERS
            0x04, // Flags: END_HEADERS
            0x00,
            0x00,
            0x00,
            0x01, // Stream ID 1
        ];

        let d_len = frame.len();
        let data_hdr = [
            ((d_len >> 16) & 0xFF) as u8,
            ((d_len >> 8) & 0xFF) as u8,
            (d_len & 0xFF) as u8,
            0x00, // Type: DATA
            0x01, // Flags: END_STREAM
            0x00,
            0x00,
            0x00,
            0x01, // Stream ID 1
        ];

        let mut full_req = Vec::with_capacity(
            preface.len()
                + settings_frame.len()
                + headers_hdr.len()
                + h_len
                + data_hdr.len()
                + frame_len,
        );
        full_req.extend_from_slice(preface);
        full_req.extend_from_slice(&settings_frame);
        full_req.extend_from_slice(&headers_hdr);
        full_req.extend_from_slice(&hpack_buf);
        full_req.extend_from_slice(&data_hdr);
        full_req.extend_from_slice(&frame);

        writer.write_all(&full_req)?;
        writer.flush()?;

        // 5. Read response frames from server
        let mut resp_buf = [0u8; 8192];
        let mut total_received = 0;
        let mut status_code = 0u32;
        let mut status_message = "OK".to_string();

        let n = reader.read(&mut resp_buf)?;
        total_received += n;

        if n > 0 {
            let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
            if resp_str.starts_with("HTTP/1.") {
                for line in resp_str.lines() {
                    let trimmed = line.trim();
                    if trimmed.to_ascii_lowercase().starts_with("grpc-status:") {
                        let val = trimmed.split(':').nth(1).unwrap_or("0").trim();
                        status_code = val.parse().unwrap_or(0);
                    } else if trimmed.to_ascii_lowercase().starts_with("grpc-message:") {
                        status_message =
                            trimmed.split(':').nth(1).unwrap_or("OK").trim().to_string();
                    }
                }
            } else {
                let decoded = decode_hpack_headers_lossy(&resp_buf[..n]);
                for (k, v) in decoded {
                    if k == "grpc-status" {
                        status_code = v.parse().unwrap_or(0);
                    } else if k == "grpc-message" {
                        status_message = v;
                    }
                }
            }
        }

        if status_code != 0 {
            return Err(OtlpGrpcError::GrpcStatus {
                code: status_code,
                message: status_message,
            });
        }

        let duration_us = start.elapsed().as_micros() as u64;
        Ok(OtlpGrpcExportResult {
            status_code,
            status_message,
            bytes_sent: preface.len()
                + settings_frame.len()
                + headers_hdr.len()
                + h_len
                + data_hdr.len()
                + frame_len,
            bytes_received: total_received,
            duration_us,
        })
    }

    /// Export snapshot over network to configured endpoint.
    pub fn export_to_endpoint(
        &self,
        s: &IsspMultipathBalancingSnapshot,
        service_name: &str,
    ) -> Result<OtlpGrpcExportResult, OtlpGrpcError> {
        let addr_str = if self.endpoint.contains(':') {
            self.endpoint.clone()
        } else {
            format!("{}:4317", self.endpoint)
        };

        let addrs: Vec<SocketAddr> = match addr_str.to_socket_addrs() {
            Ok(iter) => iter.collect(),
            Err(e) => return Err(OtlpGrpcError::Io(e)),
        };

        let mut last_err = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, self.timeout) {
                Ok(mut stream) => {
                    let _ = stream.set_read_timeout(Some(self.timeout));
                    let _ = stream.set_write_timeout(Some(self.timeout));
                    let mut reader = match stream.try_clone() {
                        Ok(r) => r,
                        Err(e) => return Err(OtlpGrpcError::Io(e)),
                    };
                    return self.export_stream(s, service_name, &mut reader, &mut stream);
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(OtlpGrpcError::Io(last_err.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "No socket addresses resolved",
            )
        })))
    }
}

fn encode_literal_hpack_header(buf: &mut Vec<u8>, name: &str, value: &str) {
    buf.push(0x00);
    encode_hpack_string(buf, name.as_bytes());
    encode_hpack_string(buf, value.as_bytes());
}

fn encode_hpack_string(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len();
    if len < 127 {
        buf.push(len as u8);
    } else {
        buf.push(127);
        let mut rem = len - 127;
        while rem >= 128 {
            buf.push(((rem & 0x7F) as u8) | 0x80);
            rem >>= 7;
        }
        buf.push(rem as u8);
    }
    buf.extend_from_slice(bytes);
}

fn decode_hpack_headers_lossy(data: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if let Some(pos) = data[i..].windows(11).position(|w| w == b"grpc-status") {
            let start = i + pos + 11;
            if start < data.len() {
                let mut j = start;
                while j < data.len()
                    && (data[j] == 0 || data[j] == b':' || data[j] == b' ' || data[j] < 32)
                {
                    j += 1;
                }
                let mut val = String::new();
                while j < data.len() && data[j] >= b'0' && data[j] <= b'9' {
                    val.push(data[j] as char);
                    j += 1;
                }
                if !val.is_empty() {
                    out.push(("grpc-status".to_string(), val));
                }
            }
            i = start + 1;
        } else {
            break;
        }
    }
    out
}

// ─── Cluster Quorum Health & Degradation Probes ───────────────────────────

/// Configuration for cluster quorum health and degradation threshold evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspClusterQuorumConfig {
    /// Expected total number of nodes in the cluster (including local node). Default is 1.
    pub expected_cluster_nodes: usize,
    /// Minimum quorum ratio required in `[0.0, 1.0]` to consider cluster quorum healthy.
    /// Default is 0.50 (at least 50% of expected cluster nodes must be reachable).
    pub quorum_threshold_ratio: f64,
    /// Minimum number of active subpaths required on the local node to be ready. Default is 1.
    pub min_active_paths: usize,
    /// Maximum allowable aggregate retransmission ratio (e.g. 0.25 = 25%) before marking degraded.
    /// If None, retransmission degradation check is omitted.
    pub max_retransmit_ratio: Option<f64>,
}

impl Default for IsspClusterQuorumConfig {
    fn default() -> Self {
        Self {
            expected_cluster_nodes: 1,
            quorum_threshold_ratio: 0.50,
            min_active_paths: 1,
            max_retransmit_ratio: None,
        }
    }
}

impl IsspClusterQuorumConfig {
    /// Create a new quorum configuration with expected cluster nodes and minimum active paths.
    pub fn new(expected_cluster_nodes: usize, min_active_paths: usize) -> Self {
        Self {
            expected_cluster_nodes: expected_cluster_nodes.max(1),
            quorum_threshold_ratio: 0.50,
            min_active_paths,
            max_retransmit_ratio: None,
        }
    }

    /// Configure the quorum threshold ratio (e.g. 0.51 for majority quorum).
    pub fn with_quorum_threshold_ratio(mut self, ratio: f64) -> Self {
        self.quorum_threshold_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    /// Configure maximum allowable retransmission ratio before declaring degradation.
    pub fn with_max_retransmit_ratio(mut self, ratio: f64) -> Self {
        self.max_retransmit_ratio = Some(ratio.clamp(0.0, 1.0));
        self
    }

    /// Evaluate the quorum status against an active snapshot and observed cluster node count.
    pub fn evaluate(
        &self,
        snapshot: &IsspMultipathBalancingSnapshot,
        cluster_nodes: usize,
    ) -> IsspQuorumStatus {
        let expected = self.expected_cluster_nodes.max(1);
        let ratio = cluster_nodes as f64 / expected as f64;
        let agg_retrans =
            snapshot.aggregate_tcp_retrans_ratio + snapshot.aggregate_issp_retrans_ratio;

        let quorum_ok = ratio >= self.quorum_threshold_ratio;
        let paths_ok = snapshot.active_paths >= self.min_active_paths;
        let retrans_ok = self
            .max_retransmit_ratio
            .map(|limit| agg_retrans <= limit)
            .unwrap_or(true);

        let is_ready = quorum_ok && paths_ok && retrans_ok;
        let is_degraded = !is_ready;

        let reason = if !quorum_ok {
            format!(
                "cluster quorum degraded: available nodes {}/{} (ratio {:.2}) below quorum threshold {:.2}",
                cluster_nodes, expected, ratio, self.quorum_threshold_ratio
            )
        } else if !paths_ok {
            format!(
                "subpath starvation: {} active subpaths (minimum required: {})",
                snapshot.active_paths, self.min_active_paths
            )
        } else if !retrans_ok {
            format!(
                "excessive retransmissions: {:.2}% exceeds threshold {:.2}%",
                agg_retrans * 100.0,
                self.max_retransmit_ratio.unwrap_or(1.0) * 100.0
            )
        } else {
            format!(
                "cluster quorum healthy: {}/{} nodes, {} active paths, {:.2} quorum ratio",
                cluster_nodes, expected, snapshot.active_paths, ratio
            )
        };

        IsspQuorumStatus {
            is_ready,
            is_degraded,
            node_id: snapshot.node_id,
            cluster_nodes,
            expected_cluster_nodes: expected,
            quorum_ratio: ratio,
            quorum_threshold_ratio: self.quorum_threshold_ratio,
            active_paths: snapshot.active_paths,
            min_active_paths: self.min_active_paths,
            aggregate_retrans_ratio: agg_retrans,
            reason,
        }
    }
}

/// Operational status of cluster quorum evaluation for health probes.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspQuorumStatus {
    /// Whether the node and cluster are in a healthy, operational state meeting quorum.
    pub is_ready: bool,
    /// Whether cluster quorum is degraded below threshold.
    pub is_degraded: bool,
    /// Local cluster node ID.
    pub node_id: u32,
    /// Number of active nodes currently in the cluster (local node + reachable peers).
    pub cluster_nodes: usize,
    /// Expected number of cluster nodes from configuration.
    pub expected_cluster_nodes: usize,
    /// Current calculated quorum ratio: cluster_nodes / expected_cluster_nodes.
    pub quorum_ratio: f64,
    /// Minimum required quorum ratio.
    pub quorum_threshold_ratio: f64,
    /// Number of currently active/usable subpaths on this node.
    pub active_paths: usize,
    /// Minimum required active subpaths.
    pub min_active_paths: usize,
    /// Aggregate retransmission ratio observed across operational subpaths.
    pub aggregate_retrans_ratio: f64,
    /// Detailed diagnostic message describing the health or degradation cause.
    pub reason: String,
}

impl IsspQuorumStatus {
    /// Format this quorum status as compact JSON.
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"status\": \"{}\",\n",
                "  \"ready\": {},\n",
                "  \"degraded\": {},\n",
                "  \"node_id\": {},\n",
                "  \"cluster_nodes\": {},\n",
                "  \"expected_cluster_nodes\": {},\n",
                "  \"quorum_ratio\": {:.4},\n",
                "  \"quorum_threshold_ratio\": {:.4},\n",
                "  \"active_paths\": {},\n",
                "  \"min_active_paths\": {},\n",
                "  \"aggregate_retrans_ratio\": {:.4},\n",
                "  \"reason\": \"{}\"\n",
                "}}"
            ),
            if self.is_ready { "READY" } else { "DEGRADED" },
            self.is_ready,
            self.is_degraded,
            self.node_id,
            self.cluster_nodes,
            self.expected_cluster_nodes,
            self.quorum_ratio,
            self.quorum_threshold_ratio,
            self.active_paths,
            self.min_active_paths,
            self.aggregate_retrans_ratio,
            self.reason.replace('\"', "\\\"")
        )
    }
}

// ─── Lightweight Zero-Dependency JSON Parser (Alertmanager & Webhooks) ─────

/// Lightweight recursive-descent JSON value representation without external dependencies.
#[derive(Debug, Clone, PartialEq)]
pub enum MiniJsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<MiniJsonValue>),
    Object(BTreeMap<String, MiniJsonValue>),
}

impl MiniJsonValue {
    /// Parse a JSON string into a structured `MiniJsonValue`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let chars: Vec<char> = s.chars().collect();
        let mut idx = 0;
        skip_json_ws(&chars, &mut idx);
        let val = parse_json_val(&chars, &mut idx)?;
        Ok(val)
    }

    /// Access child field if this value is an object.
    pub fn get(&self, key: &str) -> Option<&MiniJsonValue> {
        match self {
            Self::Object(map) => map.get(key),
            _ => None,
        }
    }

    /// Access string reference if this value is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Access array slice if this value is an array.
    pub fn as_array(&self) -> Option<&Vec<MiniJsonValue>> {
        match self {
            Self::Array(arr) => Some(arr),
            _ => None,
        }
    }

    /// Access object map if this value is an object.
    pub fn as_object(&self) -> Option<&BTreeMap<String, MiniJsonValue>> {
        match self {
            Self::Object(map) => Some(map),
            _ => None,
        }
    }

    /// Access f64 number if this value is numeric.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Access bool if this value is boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

fn skip_json_ws(chars: &[char], idx: &mut usize) {
    while *idx < chars.len() && chars[*idx].is_whitespace() {
        *idx += 1;
    }
}

fn parse_json_val(chars: &[char], idx: &mut usize) -> Result<MiniJsonValue, String> {
    skip_json_ws(chars, idx);
    if *idx >= chars.len() {
        return Err("Unexpected end of JSON input".to_string());
    }

    match chars[*idx] {
        '{' => parse_json_obj(chars, idx),
        '[' => parse_json_arr(chars, idx),
        '"' => parse_json_str(chars, idx).map(MiniJsonValue::String),
        't' | 'f' => parse_json_boolean(chars, idx),
        'n' => parse_json_nil(chars, idx),
        '-' | '0'..='9' => parse_json_num(chars, idx),
        c => Err(format!("Unexpected character '{}' at index {}", c, idx)),
    }
}

fn parse_json_str(chars: &[char], idx: &mut usize) -> Result<String, String> {
    if *idx >= chars.len() || chars[*idx] != '"' {
        return Err("Expected '\"'".to_string());
    }
    *idx += 1;
    let mut out = String::new();
    while *idx < chars.len() {
        let c = chars[*idx];
        *idx += 1;
        if c == '"' {
            return Ok(out);
        } else if c == '\\' {
            if *idx >= chars.len() {
                return Err("Dangling backslash in string".to_string());
            }
            let esc = chars[*idx];
            *idx += 1;
            match esc {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'b' => out.push('\u{0008}'),
                'f' => out.push('\u{000c}'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    if *idx + 4 > chars.len() {
                        return Err("Invalid unicode escape".to_string());
                    }
                    let hex_s: String = chars[*idx..*idx + 4].iter().collect();
                    *idx += 4;
                    if let Ok(code) = u32::from_str_radix(&hex_s, 16) {
                        if let Some(ch) = std::char::from_u32(code) {
                            out.push(ch);
                        }
                    }
                }
                _ => out.push(esc),
            }
        } else {
            out.push(c);
        }
    }
    Err("Unterminated string".to_string())
}

fn parse_json_num(chars: &[char], idx: &mut usize) -> Result<MiniJsonValue, String> {
    let start = *idx;
    if *idx < chars.len() && chars[*idx] == '-' {
        *idx += 1;
    }
    while *idx < chars.len() && chars[*idx].is_ascii_digit() {
        *idx += 1;
    }
    if *idx < chars.len() && chars[*idx] == '.' {
        *idx += 1;
        while *idx < chars.len() && chars[*idx].is_ascii_digit() {
            *idx += 1;
        }
    }
    if *idx < chars.len() && (chars[*idx] == 'e' || chars[*idx] == 'E') {
        *idx += 1;
        if *idx < chars.len() && (chars[*idx] == '+' || chars[*idx] == '-') {
            *idx += 1;
        }
        while *idx < chars.len() && chars[*idx].is_ascii_digit() {
            *idx += 1;
        }
    }
    let s: String = chars[start..*idx].iter().collect();
    s.parse::<f64>()
        .map(MiniJsonValue::Number)
        .map_err(|e| format!("Invalid number '{}': {}", s, e))
}

fn parse_json_boolean(chars: &[char], idx: &mut usize) -> Result<MiniJsonValue, String> {
    if chars[*idx..].starts_with(&['t', 'r', 'u', 'e']) {
        *idx += 4;
        Ok(MiniJsonValue::Bool(true))
    } else if chars[*idx..].starts_with(&['f', 'a', 'l', 's', 'e']) {
        *idx += 5;
        Ok(MiniJsonValue::Bool(false))
    } else {
        Err("Expected boolean".to_string())
    }
}

fn parse_json_nil(chars: &[char], idx: &mut usize) -> Result<MiniJsonValue, String> {
    if chars[*idx..].starts_with(&['n', 'u', 'l', 'l']) {
        *idx += 4;
        Ok(MiniJsonValue::Null)
    } else {
        Err("Expected null".to_string())
    }
}

fn parse_json_arr(chars: &[char], idx: &mut usize) -> Result<MiniJsonValue, String> {
    if *idx >= chars.len() || chars[*idx] != '[' {
        return Err("Expected '['".to_string());
    }
    *idx += 1;
    let mut arr = Vec::new();
    skip_json_ws(chars, idx);
    if *idx < chars.len() && chars[*idx] == ']' {
        *idx += 1;
        return Ok(MiniJsonValue::Array(arr));
    }
    loop {
        let val = parse_json_val(chars, idx)?;
        arr.push(val);
        skip_json_ws(chars, idx);
        if *idx >= chars.len() {
            return Err("Unterminated array".to_string());
        }
        if chars[*idx] == ']' {
            *idx += 1;
            break;
        } else if chars[*idx] == ',' {
            *idx += 1;
        } else {
            return Err(format!("Expected ',' or ']' at {}", idx));
        }
    }
    Ok(MiniJsonValue::Array(arr))
}

fn parse_json_obj(chars: &[char], idx: &mut usize) -> Result<MiniJsonValue, String> {
    if *idx >= chars.len() || chars[*idx] != '{' {
        return Err("Expected '{'".to_string());
    }
    *idx += 1;
    let mut map = BTreeMap::new();
    skip_json_ws(chars, idx);
    if *idx < chars.len() && chars[*idx] == '}' {
        *idx += 1;
        return Ok(MiniJsonValue::Object(map));
    }
    loop {
        skip_json_ws(chars, idx);
        let key = parse_json_str(chars, idx)?;
        skip_json_ws(chars, idx);
        if *idx >= chars.len() || chars[*idx] != ':' {
            return Err(format!("Expected ':' after object key '{}'", key));
        }
        *idx += 1;
        let val = parse_json_val(chars, idx)?;
        map.insert(key, val);
        skip_json_ws(chars, idx);
        if *idx >= chars.len() {
            return Err("Unterminated object".to_string());
        }
        if chars[*idx] == '}' {
            *idx += 1;
            break;
        } else if chars[*idx] == ',' {
            *idx += 1;
        } else {
            return Err(format!("Expected ',' or '}}' at {}", idx));
        }
    }
    Ok(MiniJsonValue::Object(map))
}

// ─── Prometheus Alertmanager Webhook Models ───────────────────────────────

/// A single alert payload from Prometheus Alertmanager.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AlertmanagerWebhookAlert {
    /// Alert status: "firing" or "resolved".
    pub status: String,
    /// Alert name (e.g. "IfaIsspHighJitterSurge", "IfaIsspRetransmissionSpike").
    pub alertname: String,
    /// Targeted network interface name (e.g. "eth0-wan", "wwan0-5g").
    pub interface: String,
    /// Alert severity ("critical", "warning", "info").
    pub severity: String,
    /// All labels extracted from the alert.
    pub labels: BTreeMap<String, String>,
    /// All annotations extracted from the alert.
    pub annotations: BTreeMap<String, String>,
}

/// Structured Alertmanager webhook notification payload (compatible with Alertmanager v4 format).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AlertmanagerWebhookPayload {
    /// Schema version (typically "4").
    pub version: Option<String>,
    /// Global notification status ("firing" or "resolved").
    pub status: String,
    /// Configured Alertmanager receiver name.
    pub receiver: Option<String>,
    /// List of alerts contained in this webhook notification.
    pub alerts: Vec<AlertmanagerWebhookAlert>,
}

impl AlertmanagerWebhookPayload {
    /// Parse raw JSON string received from Alertmanager webhook POST into `AlertmanagerWebhookPayload`.
    pub fn parse_json(raw: &str) -> Result<Self, String> {
        let val = MiniJsonValue::parse(raw)?;
        let obj = val.as_object().ok_or("Root JSON must be an object")?;

        let version = obj
            .get("version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let top_status = obj
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("firing")
            .to_string();
        let receiver = obj
            .get("receiver")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let common_labels: BTreeMap<String, String> = obj
            .get("commonLabels")
            .and_then(|v| v.as_object())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        let mut alerts = Vec::new();
        if let Some(alerts_arr) = obj.get("alerts").and_then(|v| v.as_array()) {
            for a_val in alerts_arr {
                if let Some(a_obj) = a_val.as_object() {
                    let a_status = a_obj
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&top_status)
                        .to_string();

                    let mut labels = common_labels.clone();
                    if let Some(lbl_obj) = a_obj.get("labels").and_then(|v| v.as_object()) {
                        for (k, v) in lbl_obj {
                            if let Some(s) = v.as_str() {
                                labels.insert(k.clone(), s.to_string());
                            }
                        }
                    }

                    let mut annotations = BTreeMap::new();
                    if let Some(ann_obj) = a_obj.get("annotations").and_then(|v| v.as_object()) {
                        for (k, v) in ann_obj {
                            if let Some(s) = v.as_str() {
                                annotations.insert(k.clone(), s.to_string());
                            }
                        }
                    }

                    let alertname = labels
                        .get("alertname")
                        .cloned()
                        .unwrap_or_else(|| "UnknownAlert".to_string());

                    let interface = labels
                        .get("interface")
                        .or_else(|| labels.get("interface_name"))
                        .or_else(|| labels.get("subpath"))
                        .or_else(|| labels.get("link"))
                        .cloned()
                        .unwrap_or_default();

                    let severity = labels
                        .get("severity")
                        .cloned()
                        .unwrap_or_else(|| "warning".to_string());

                    alerts.push(AlertmanagerWebhookAlert {
                        status: a_status,
                        alertname,
                        interface,
                        severity,
                        labels,
                        annotations,
                    });
                }
            }
        }

        // Fallback if alerts array was empty but top-level commonLabels specifies interface
        if alerts.is_empty() && common_labels.contains_key("interface") {
            let alertname = common_labels
                .get("alertname")
                .cloned()
                .unwrap_or_else(|| "UnknownAlert".to_string());
            let interface = common_labels.get("interface").cloned().unwrap_or_default();
            alerts.push(AlertmanagerWebhookAlert {
                status: top_status.clone(),
                alertname,
                interface,
                severity: "warning".to_string(),
                labels: common_labels.clone(),
                annotations: BTreeMap::new(),
            });
        }

        Ok(AlertmanagerWebhookPayload {
            version,
            status: top_status,
            receiver,
            alerts,
        })
    }
}

/// Configurable policy mapping Alertmanager alert signals to automated interface failover actions.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertFailoverPolicy {
    /// Action taken when a jitter surge alert fires on an interface.
    pub jitter_action: crate::session_sync::FailoverAction,
    /// Action taken when a retransmission spike alert fires on an interface.
    pub retransmission_action: crate::session_sync::FailoverAction,
    /// Action taken when a queuing delay / bufferbloat alert fires on an interface.
    pub queuing_delay_action: crate::session_sync::FailoverAction,
    /// Action taken when a generic quality degradation alert fires on an interface.
    pub default_action: crate::session_sync::FailoverAction,
    /// Target operational state when an alert resolves (Active or Probation).
    pub restore_target_state: crate::session_sync::IsspPathState,
}

impl Default for AlertFailoverPolicy {
    fn default() -> Self {
        Self {
            jitter_action: crate::session_sync::FailoverAction::SwitchToStandby,
            retransmission_action: crate::session_sync::FailoverAction::SwitchToStandby,
            queuing_delay_action: crate::session_sync::FailoverAction::DemoteToDegraded,
            default_action: crate::session_sync::FailoverAction::SwitchToStandby,
            restore_target_state: crate::session_sync::IsspPathState::Active,
        }
    }
}

impl AlertFailoverPolicy {
    /// Classify an alert into the corresponding failover action and trigger reason.
    pub fn classify_alert(
        &self,
        alert: &AlertmanagerWebhookAlert,
    ) -> (
        crate::session_sync::FailoverAction,
        crate::session_sync::IsspFailoverReason,
    ) {
        let name_lower = alert.alertname.to_ascii_lowercase();
        if name_lower.contains("jitter") {
            (
                self.jitter_action,
                crate::session_sync::IsspFailoverReason::AlertmanagerJitterSurge,
            )
        } else if name_lower.contains("retrans") {
            (
                self.retransmission_action,
                crate::session_sync::IsspFailoverReason::AlertmanagerRetransmissionSpike,
            )
        } else if name_lower.contains("gradient")
            || name_lower.contains("delay")
            || name_lower.contains("bufferbloat")
        {
            (
                self.queuing_delay_action,
                crate::session_sync::IsspFailoverReason::AlertmanagerQueuingDelayGradient,
            )
        } else {
            (
                self.default_action,
                crate::session_sync::IsspFailoverReason::QualityDegradation,
            )
        }
    }
}

// ─── Multi-Node Mesh Topology Synthesis & Grafana Supervisor ─────────────

/// Node operational information within a synthesized multi-node mesh topology.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspMeshNodeInfo {
    /// Unique cluster node identifier.
    pub node_id: u32,
    /// Human-readable node name or hostname (e.g. "ifa-gateway-eu1").
    pub node_name: String,
    /// Operational role in the mesh ("gateway", "relay", "worker", "edge", "ingress", "egress").
    pub role: String,
    /// Network endpoint or advertised address (e.g. "10.0.1.10:9090").
    pub endpoint: String,
    /// Operational status string ("healthy", "degraded", "offline").
    pub status: String,
    /// Number of active transport subpaths configured on this node.
    pub active_paths: usize,
    /// Total active multipath sessions currently tracked by this node.
    pub total_sessions: usize,
    /// Instantaneous outbound throughput in bytes per second.
    pub tx_bytes_per_sec: f64,
    /// Instantaneous inbound throughput in bytes per second.
    pub rx_bytes_per_sec: f64,
    /// Average round-trip time latency across all active subpaths in milliseconds.
    pub avg_latency_ms: f64,
    /// TCP retransmission ratio observed on this node [0.0 - 1.0].
    pub tcp_retrans_ratio: f64,
    /// ISSP retransmission ratio observed on this node [0.0 - 1.0].
    pub issp_retrans_ratio: f64,
    /// Unix timestamp in nanoseconds of the most recent heartbeat/snapshot received from this node.
    pub last_heartbeat_unix_ns: u64,
    /// Whether this node is currently considered operational and healthy.
    pub is_healthy: bool,
}

impl IsspMeshNodeInfo {
    /// Create a new node representation in the mesh topology.
    pub fn new(node_id: u32, node_name: &str, role: &str, endpoint: &str) -> Self {
        Self {
            node_id,
            node_name: node_name.to_string(),
            role: role.to_string(),
            endpoint: endpoint.to_string(),
            status: "healthy".to_string(),
            active_paths: 0,
            total_sessions: 0,
            tx_bytes_per_sec: 0.0,
            rx_bytes_per_sec: 0.0,
            avg_latency_ms: 0.0,
            tcp_retrans_ratio: 0.0,
            issp_retrans_ratio: 0.0,
            last_heartbeat_unix_ns: 0,
            is_healthy: true,
        }
    }

    /// Set session metrics for this node.
    pub fn with_sessions(mut self, sessions: usize, active_paths: usize) -> Self {
        self.total_sessions = sessions;
        self.active_paths = active_paths;
        self
    }

    /// Set network throughput in bytes per second.
    pub fn with_throughput(mut self, tx_bps: f64, rx_bps: f64) -> Self {
        self.tx_bytes_per_sec = tx_bps;
        self.rx_bytes_per_sec = rx_bps;
        self
    }

    /// Set average latency and retransmission ratios.
    pub fn with_quality(
        mut self,
        avg_latency_ms: f64,
        tcp_retrans: f64,
        issp_retrans: f64,
    ) -> Self {
        self.avg_latency_ms = avg_latency_ms;
        self.tcp_retrans_ratio = tcp_retrans;
        self.issp_retrans_ratio = issp_retrans;
        self
    }

    /// Set health state and status string.
    pub fn with_health(mut self, is_healthy: bool, status: &str) -> Self {
        self.is_healthy = is_healthy;
        self.status = status.to_string();
        self
    }

    /// Format node details as compact JSON.
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "    {{\n",
                "      \"node_id\": {},\n",
                "      \"node_name\": \"{}\",\n",
                "      \"role\": \"{}\",\n",
                "      \"endpoint\": \"{}\",\n",
                "      \"status\": \"{}\",\n",
                "      \"active_paths\": {},\n",
                "      \"total_sessions\": {},\n",
                "      \"tx_bytes_per_sec\": {:.2},\n",
                "      \"rx_bytes_per_sec\": {:.2},\n",
                "      \"avg_latency_ms\": {:.3},\n",
                "      \"tcp_retrans_ratio\": {:.6},\n",
                "      \"issp_retrans_ratio\": {:.6},\n",
                "      \"last_heartbeat_unix_ns\": {},\n",
                "      \"is_healthy\": {}\n",
                "    }}"
            ),
            self.node_id,
            escape_json_str(&self.node_name),
            escape_json_str(&self.role),
            escape_json_str(&self.endpoint),
            escape_json_str(&self.status),
            self.active_paths,
            self.total_sessions,
            self.tx_bytes_per_sec,
            self.rx_bytes_per_sec,
            self.avg_latency_ms,
            self.tcp_retrans_ratio,
            self.issp_retrans_ratio,
            self.last_heartbeat_unix_ns,
            self.is_healthy
        )
    }
}

/// Link operational metrics between two nodes in a synthesized multi-node mesh topology.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspMeshLinkInfo {
    /// Unique identifier for this link (e.g. "node-1->node-2:eth0").
    pub link_id: String,
    /// Source node identifier originating this transport link.
    pub source_node_id: u32,
    /// Target destination node identifier.
    pub target_node_id: u32,
    /// Interface name carrying traffic (e.g. "eth0-wan", "wwan0-5g").
    pub interface_name: String,
    /// Measured round-trip latency in milliseconds.
    pub latency_ms: f64,
    /// Measured jitter in milliseconds.
    pub jitter_ms: f64,
    /// Packet loss ratio [0.0 - 1.0].
    pub loss_ratio: f64,
    /// Retransmission rate [0.0 - 1.0].
    pub retransmit_rate: f64,
    /// Outbound link throughput in bytes per second.
    pub tx_bytes_per_sec: f64,
    /// Inbound link throughput in bytes per second.
    pub rx_bytes_per_sec: f64,
    /// Effective scheduling weight configured on this link.
    pub weight: u32,
    /// Operational status ("optimal", "active", "degraded", "congested", "offline").
    pub status: String,
    /// Whether this link has been identified as a cluster-wide latency or congestion bottleneck.
    pub is_bottleneck: bool,
}

impl IsspMeshLinkInfo {
    /// Create a new link between two mesh nodes.
    pub fn new(source: u32, target: u32, interface: &str) -> Self {
        Self {
            link_id: format!("node-{}->node-{}:{}", source, target, interface),
            source_node_id: source,
            target_node_id: target,
            interface_name: interface.to_string(),
            latency_ms: 0.0,
            jitter_ms: 0.0,
            loss_ratio: 0.0,
            retransmit_rate: 0.0,
            tx_bytes_per_sec: 0.0,
            rx_bytes_per_sec: 0.0,
            weight: 100,
            status: "optimal".to_string(),
            is_bottleneck: false,
        }
    }

    /// Set latency and jitter measurements in milliseconds.
    pub fn with_latency(mut self, latency_ms: f64, jitter_ms: f64) -> Self {
        self.latency_ms = latency_ms;
        self.jitter_ms = jitter_ms;
        self
    }

    /// Set loss ratio and retransmit rate.
    pub fn with_loss(mut self, loss_ratio: f64, retransmit_rate: f64) -> Self {
        self.loss_ratio = loss_ratio;
        self.retransmit_rate = retransmit_rate;
        self
    }

    /// Set throughput in bytes per second.
    pub fn with_throughput(mut self, tx_bps: f64, rx_bps: f64) -> Self {
        self.tx_bytes_per_sec = tx_bps;
        self.rx_bytes_per_sec = rx_bps;
        self
    }

    /// Set scheduling weight.
    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    /// Set status and bottleneck flag.
    pub fn with_status(mut self, status: &str, is_bottleneck: bool) -> Self {
        self.status = status.to_string();
        self.is_bottleneck = is_bottleneck;
        self
    }

    /// Format link details as compact JSON.
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "    {{\n",
                "      \"link_id\": \"{}\",\n",
                "      \"source_node_id\": {},\n",
                "      \"target_node_id\": {},\n",
                "      \"interface_name\": \"{}\",\n",
                "      \"latency_ms\": {:.3},\n",
                "      \"jitter_ms\": {:.3},\n",
                "      \"loss_ratio\": {:.6},\n",
                "      \"retransmit_rate\": {:.6},\n",
                "      \"tx_bytes_per_sec\": {:.2},\n",
                "      \"rx_bytes_per_sec\": {:.2},\n",
                "      \"weight\": {},\n",
                "      \"status\": \"{}\",\n",
                "      \"is_bottleneck\": {}\n",
                "    }}"
            ),
            escape_json_str(&self.link_id),
            self.source_node_id,
            self.target_node_id,
            escape_json_str(&self.interface_name),
            self.latency_ms,
            self.jitter_ms,
            self.loss_ratio,
            self.retransmit_rate,
            self.tx_bytes_per_sec,
            self.rx_bytes_per_sec,
            self.weight,
            escape_json_str(&self.status),
            self.is_bottleneck
        )
    }
}

/// Unified snapshot of multi-node mesh topology synthesized for Grafana supervisor panels and Prometheus.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspMeshTopologySnapshot {
    /// Cluster name or identifier.
    pub cluster_id: String,
    /// Timestamp when this mesh snapshot was synthesized, in nanoseconds since Unix epoch.
    pub timestamp_unix_ns: u64,
    /// List of registered and discovered nodes in the mesh.
    pub nodes: Vec<IsspMeshNodeInfo>,
    /// List of directed links and metrics between mesh nodes.
    pub links: Vec<IsspMeshLinkInfo>,
    /// Total count of registered nodes.
    pub total_nodes: usize,
    /// Count of currently healthy, operational nodes.
    pub healthy_nodes: usize,
    /// Total count of observed mesh links.
    pub total_links: usize,
    /// Count of active operational links.
    pub active_links: usize,
    /// Mesh graph density ratio `active_links / (total_nodes * (total_nodes - 1))` in [0.0, 1.0].
    pub mesh_density_ratio: f64,
    /// Total active sessions aggregated across all cluster nodes.
    pub cluster_total_sessions: usize,
    /// Total cluster outbound bandwidth in bytes per second.
    pub cluster_tx_bytes_per_sec: f64,
    /// Total cluster inbound bandwidth in bytes per second.
    pub cluster_rx_bytes_per_sec: f64,
    /// Cluster-wide mean round-trip latency across all links in milliseconds.
    pub cluster_avg_latency_ms: f64,
    /// Minimum link latency observed across the cluster in milliseconds.
    pub cluster_min_latency_ms: f64,
    /// Maximum link latency observed across the cluster in milliseconds.
    pub cluster_max_latency_ms: f64,
    /// Overall cluster health score in [0.0, 1.0].
    pub cluster_health_score: f64,
    /// List of link IDs identified as performance bottlenecks.
    pub bottlenecks: Vec<String>,
}

impl Default for IsspMeshTopologySnapshot {
    fn default() -> Self {
        Self {
            cluster_id: "ifa-mesh".to_string(),
            timestamp_unix_ns: 0,
            nodes: Vec::new(),
            links: Vec::new(),
            total_nodes: 0,
            healthy_nodes: 0,
            total_links: 0,
            active_links: 0,
            mesh_density_ratio: 0.0,
            cluster_total_sessions: 0,
            cluster_tx_bytes_per_sec: 0.0,
            cluster_rx_bytes_per_sec: 0.0,
            cluster_avg_latency_ms: 0.0,
            cluster_min_latency_ms: 0.0,
            cluster_max_latency_ms: 0.0,
            cluster_health_score: 1.0,
            bottlenecks: Vec::new(),
        }
    }
}

impl IsspMeshTopologySnapshot {
    /// Find node information by numeric identifier.
    pub fn find_node(&self, node_id: u32) -> Option<&IsspMeshNodeInfo> {
        self.nodes.iter().find(|n| n.node_id == node_id)
    }

    /// Find link information by source, target, and interface.
    pub fn find_link(
        &self,
        source: u32,
        target: u32,
        interface: &str,
    ) -> Option<&IsspMeshLinkInfo> {
        self.links.iter().find(|l| {
            l.source_node_id == source
                && l.target_node_id == target
                && l.interface_name == interface
        })
    }

    /// Format snapshot into standard Grafana Node Graph panel format (`{ "nodes": [...], "edges": [...] }`).
    pub fn to_grafana_node_graph_json(&self) -> String {
        let mut nodes_json = Vec::with_capacity(self.nodes.len());
        for n in &self.nodes {
            let (color, arc_healthy, arc_unhealthy) = if n.is_healthy {
                ("green", 1.0, 0.0)
            } else {
                ("red", 0.0, 1.0)
            };
            let main_stat = format!(
                "{:.1} MB/s",
                (n.tx_bytes_per_sec + n.rx_bytes_per_sec) / 1_000_000.0
            );
            let sec_stat = format!("{:.2} ms", n.avg_latency_ms);
            let title = format!("node-{}", n.node_id);
            nodes_json.push(format!(
                concat!(
                    "    {{\n",
                    "      \"id\": \"node-{}\",\n",
                    "      \"title\": \"{}\",\n",
                    "      \"subTitle\": \"{}\",\n",
                    "      \"mainStat\": \"{}\",\n",
                    "      \"secondaryStat\": \"{}\",\n",
                    "      \"arc__healthy\": {},\n",
                    "      \"arc__unhealthy\": {},\n",
                    "      \"color\": \"{}\",\n",
                    "      \"detail__name\": \"{}\",\n",
                    "      \"detail__role\": \"{}\",\n",
                    "      \"detail__endpoint\": \"{}\",\n",
                    "      \"detail__sessions\": \"{}\",\n",
                    "      \"detail__active_paths\": \"{}\",\n",
                    "      \"detail__status\": \"{}\"\n",
                    "    }}"
                ),
                n.node_id,
                escape_json_str(&title),
                escape_json_str(&n.role),
                escape_json_str(&main_stat),
                escape_json_str(&sec_stat),
                arc_healthy,
                arc_unhealthy,
                color,
                escape_json_str(&n.node_name),
                escape_json_str(&n.role),
                escape_json_str(&n.endpoint),
                n.total_sessions,
                n.active_paths,
                escape_json_str(&n.status)
            ));
        }

        let mut edges_json = Vec::with_capacity(self.links.len());
        for l in &self.links {
            let color = if l.is_bottleneck || l.status == "congested" || l.status == "degraded" {
                "orange"
            } else if l.status == "offline" {
                "red"
            } else {
                "green"
            };
            let edge_id = format!(
                "node-{}->node-{}:{}",
                l.source_node_id, l.target_node_id, l.interface_name
            );
            let main_stat = format!("{:.2} ms", l.latency_ms);
            let sec_stat = format!("{:.2}% loss", l.loss_ratio * 100.0);
            let throughput = format!(
                "{:.1} MB/s",
                (l.tx_bytes_per_sec + l.rx_bytes_per_sec) / 1_000_000.0
            );
            let jitter = format!("{:.2} ms", l.jitter_ms);
            edges_json.push(format!(
                concat!(
                    "    {{\n",
                    "      \"id\": \"{}\",\n",
                    "      \"source\": \"node-{}\",\n",
                    "      \"target\": \"node-{}\",\n",
                    "      \"mainStat\": \"{}\",\n",
                    "      \"secondaryStat\": \"{}\",\n",
                    "      \"weight\": {},\n",
                    "      \"color\": \"{}\",\n",
                    "      \"detail__interface\": \"{}\",\n",
                    "      \"detail__throughput\": \"{}\",\n",
                    "      \"detail__jitter\": \"{}\",\n",
                    "      \"detail__status\": \"{}\"\n",
                    "    }}"
                ),
                escape_json_str(&edge_id),
                l.source_node_id,
                l.target_node_id,
                escape_json_str(&main_stat),
                escape_json_str(&sec_stat),
                l.weight,
                color,
                escape_json_str(&l.interface_name),
                escape_json_str(&throughput),
                escape_json_str(&jitter),
                escape_json_str(&l.status)
            ));
        }

        format!(
            "{{\n  \"nodes\": [\n{}\n  ],\n  \"edges\": [\n{}\n  ]\n}}",
            nodes_json.join(",\n"),
            edges_json.join(",\n")
        )
    }

    /// Format snapshot into comprehensive Grafana supervisor topology summary JSON.
    pub fn to_grafana_topology_summary_json(&self) -> String {
        let nodes_summary: Vec<String> = self.nodes.iter().map(|n| n.to_json()).collect();
        let links_summary: Vec<String> = self.links.iter().map(|l| l.to_json()).collect();
        let bottlenecks_json: Vec<String> = self
            .bottlenecks
            .iter()
            .map(|b| format!("\"{}\"", escape_json_str(b)))
            .collect();

        format!(
            concat!(
                "{{\n",
                "  \"cluster_id\": \"{}\",\n",
                "  \"timestamp_unix_ns\": {},\n",
                "  \"total_nodes\": {},\n",
                "  \"healthy_nodes\": {},\n",
                "  \"total_links\": {},\n",
                "  \"active_links\": {},\n",
                "  \"mesh_density_ratio\": {:.4},\n",
                "  \"cluster_health_score\": {:.4},\n",
                "  \"cluster_total_sessions\": {},\n",
                "  \"cluster_tx_bytes_per_sec\": {:.2},\n",
                "  \"cluster_rx_bytes_per_sec\": {:.2},\n",
                "  \"cluster_avg_latency_ms\": {:.3},\n",
                "  \"cluster_min_latency_ms\": {:.3},\n",
                "  \"cluster_max_latency_ms\": {:.3},\n",
                "  \"bottlenecks\": [{}],\n",
                "  \"nodes\": [\n{}\n  ],\n",
                "  \"links\": [\n{}\n  ]\n",
                "}}"
            ),
            escape_json_str(&self.cluster_id),
            self.timestamp_unix_ns,
            self.total_nodes,
            self.healthy_nodes,
            self.total_links,
            self.active_links,
            self.mesh_density_ratio,
            self.cluster_health_score,
            self.cluster_total_sessions,
            self.cluster_tx_bytes_per_sec,
            self.cluster_rx_bytes_per_sec,
            self.cluster_avg_latency_ms,
            self.cluster_min_latency_ms,
            self.cluster_max_latency_ms,
            bottlenecks_json.join(", "),
            nodes_summary.join(",\n"),
            links_summary.join(",\n")
        )
    }

    /// Format snapshot into standard Prometheus 0.0.4 exposition metrics for Grafana dashboards.
    pub fn to_prometheus_mesh_exposition(&self) -> String {
        let mut out = String::with_capacity(4096);
        let c = escape_json_str(&self.cluster_id);

        out.push_str("# HELP ifa_mesh_cluster_nodes_total Total number of registered nodes in the mesh topology\n");
        out.push_str("# TYPE ifa_mesh_cluster_nodes_total gauge\n");
        out.push_str(&format!(
            "ifa_mesh_cluster_nodes_total{{cluster=\"{}\"}} {}\n",
            c, self.total_nodes
        ));

        out.push_str("# HELP ifa_mesh_cluster_healthy_nodes Total number of healthy nodes in the mesh topology\n");
        out.push_str("# TYPE ifa_mesh_cluster_healthy_nodes gauge\n");
        out.push_str(&format!(
            "ifa_mesh_cluster_healthy_nodes{{cluster=\"{}\"}} {}\n",
            c, self.healthy_nodes
        ));

        out.push_str("# HELP ifa_mesh_cluster_links_total Total number of observed links between mesh nodes\n");
        out.push_str("# TYPE ifa_mesh_cluster_links_total gauge\n");
        out.push_str(&format!(
            "ifa_mesh_cluster_links_total{{cluster=\"{}\"}} {}\n",
            c, self.total_links
        ));

        out.push_str("# HELP ifa_mesh_cluster_active_links Number of active operational links in the mesh topology\n");
        out.push_str("# TYPE ifa_mesh_cluster_active_links gauge\n");
        out.push_str(&format!(
            "ifa_mesh_cluster_active_links{{cluster=\"{}\"}} {}\n",
            c, self.active_links
        ));

        out.push_str(
            "# HELP ifa_mesh_cluster_density_ratio Mesh connectivity density ratio in [0.0, 1.0]\n",
        );
        out.push_str("# TYPE ifa_mesh_cluster_density_ratio gauge\n");
        out.push_str(&format!(
            "ifa_mesh_cluster_density_ratio{{cluster=\"{}\"}} {:.6}\n",
            c, self.mesh_density_ratio
        ));

        out.push_str("# HELP ifa_mesh_cluster_sessions_total Total active multipath sessions across all cluster nodes\n");
        out.push_str("# TYPE ifa_mesh_cluster_sessions_total gauge\n");
        out.push_str(&format!(
            "ifa_mesh_cluster_sessions_total{{cluster=\"{}\"}} {}\n",
            c, self.cluster_total_sessions
        ));

        out.push_str("# HELP ifa_mesh_cluster_health_score Overall synthesized cluster health score in [0.0, 1.0]\n");
        out.push_str("# TYPE ifa_mesh_cluster_health_score gauge\n");
        out.push_str(&format!(
            "ifa_mesh_cluster_health_score{{cluster=\"{}\"}} {:.6}\n",
            c, self.cluster_health_score
        ));

        out.push_str("# HELP ifa_mesh_cluster_tx_bytes_per_sec Aggregate cluster transmission throughput in bytes per second\n");
        out.push_str("# TYPE ifa_mesh_cluster_tx_bytes_per_sec gauge\n");
        out.push_str(&format!(
            "ifa_mesh_cluster_tx_bytes_per_sec{{cluster=\"{}\"}} {:.6}\n",
            c, self.cluster_tx_bytes_per_sec
        ));

        out.push_str("# HELP ifa_mesh_cluster_rx_bytes_per_sec Aggregate cluster receive throughput in bytes per second\n");
        out.push_str("# TYPE ifa_mesh_cluster_rx_bytes_per_sec gauge\n");
        out.push_str(&format!(
            "ifa_mesh_cluster_rx_bytes_per_sec{{cluster=\"{}\"}} {:.6}\n",
            c, self.cluster_rx_bytes_per_sec
        ));

        out.push_str("# HELP ifa_mesh_cluster_latency_ms Mesh latency summary in milliseconds\n");
        out.push_str("# TYPE ifa_mesh_cluster_latency_ms gauge\n");
        out.push_str(&format!(
            "ifa_mesh_cluster_latency_ms{{cluster=\"{}\",quantile=\"avg\"}} {:.6}\n",
            c, self.cluster_avg_latency_ms
        ));
        out.push_str(&format!(
            "ifa_mesh_cluster_latency_ms{{cluster=\"{}\",quantile=\"min\"}} {:.6}\n",
            c, self.cluster_min_latency_ms
        ));
        out.push_str(&format!(
            "ifa_mesh_cluster_latency_ms{{cluster=\"{}\",quantile=\"max\"}} {:.6}\n",
            c, self.cluster_max_latency_ms
        ));

        if !self.nodes.is_empty() {
            out.push_str("# HELP ifa_mesh_node_status Health status of individual mesh nodes (1 = healthy, 0 = degraded/offline)\n");
            out.push_str("# TYPE ifa_mesh_node_status gauge\n");
            for n in &self.nodes {
                let val = if n.is_healthy { 1 } else { 0 };
                out.push_str(&format!(
                    "ifa_mesh_node_status{{cluster=\"{}\",node_id=\"{}\",node_name=\"{}\",role=\"{}\"}} {}\n",
                    c,
                    n.node_id,
                    escape_json_str(&n.node_name),
                    escape_json_str(&n.role),
                    val
                ));
            }

            out.push_str("# HELP ifa_mesh_node_sessions Active sessions on node\n");
            out.push_str("# TYPE ifa_mesh_node_sessions gauge\n");
            for n in &self.nodes {
                out.push_str(&format!(
                    "ifa_mesh_node_sessions{{cluster=\"{}\",node_id=\"{}\",node_name=\"{}\"}} {}\n",
                    c,
                    n.node_id,
                    escape_json_str(&n.node_name),
                    n.total_sessions
                ));
            }

            out.push_str("# HELP ifa_mesh_node_tx_bytes_per_sec Transmit rate per node\n");
            out.push_str("# TYPE ifa_mesh_node_tx_bytes_per_sec gauge\n");
            for n in &self.nodes {
                out.push_str(&format!(
                    "ifa_mesh_node_tx_bytes_per_sec{{cluster=\"{}\",node_id=\"{}\"}} {:.6}\n",
                    c, n.node_id, n.tx_bytes_per_sec
                ));
            }

            out.push_str("# HELP ifa_mesh_node_rx_bytes_per_sec Receive rate per node\n");
            out.push_str("# TYPE ifa_mesh_node_rx_bytes_per_sec gauge\n");
            for n in &self.nodes {
                out.push_str(&format!(
                    "ifa_mesh_node_rx_bytes_per_sec{{cluster=\"{}\",node_id=\"{}\"}} {:.6}\n",
                    c, n.node_id, n.rx_bytes_per_sec
                ));
            }

            out.push_str("# HELP ifa_mesh_node_avg_latency_ms Average latency per node in ms\n");
            out.push_str("# TYPE ifa_mesh_node_avg_latency_ms gauge\n");
            for n in &self.nodes {
                out.push_str(&format!(
                    "ifa_mesh_node_avg_latency_ms{{cluster=\"{}\",node_id=\"{}\"}} {:.6}\n",
                    c, n.node_id, n.avg_latency_ms
                ));
            }
        }

        if !self.links.is_empty() {
            out.push_str("# HELP ifa_mesh_link_latency_ms Measured round-trip latency on mesh links in milliseconds\n");
            out.push_str("# TYPE ifa_mesh_link_latency_ms gauge\n");
            for l in &self.links {
                out.push_str(&format!(
                    "ifa_mesh_link_latency_ms{{cluster=\"{}\",source=\"{}\",target=\"{}\",interface=\"{}\"}} {:.6}\n",
                    c,
                    l.source_node_id,
                    l.target_node_id,
                    escape_json_str(&l.interface_name),
                    l.latency_ms
                ));
            }

            out.push_str(
                "# HELP ifa_mesh_link_loss_ratio Packet loss ratio observed on mesh links\n",
            );
            out.push_str("# TYPE ifa_mesh_link_loss_ratio gauge\n");
            for l in &self.links {
                out.push_str(&format!(
                    "ifa_mesh_link_loss_ratio{{cluster=\"{}\",source=\"{}\",target=\"{}\",interface=\"{}\"}} {:.6}\n",
                    c,
                    l.source_node_id,
                    l.target_node_id,
                    escape_json_str(&l.interface_name),
                    l.loss_ratio
                ));
            }

            out.push_str(
                "# HELP ifa_mesh_link_jitter_ms Jitter observed on mesh links in milliseconds\n",
            );
            out.push_str("# TYPE ifa_mesh_link_jitter_ms gauge\n");
            for l in &self.links {
                out.push_str(&format!(
                    "ifa_mesh_link_jitter_ms{{cluster=\"{}\",source=\"{}\",target=\"{}\",interface=\"{}\"}} {:.6}\n",
                    c,
                    l.source_node_id,
                    l.target_node_id,
                    escape_json_str(&l.interface_name),
                    l.jitter_ms
                ));
            }

            out.push_str("# HELP ifa_mesh_link_status Operational status of mesh links (1 = active/optimal, 0 = degraded/offline)\n");
            out.push_str("# TYPE ifa_mesh_link_status gauge\n");
            for l in &self.links {
                let val = if l.status == "optimal" || l.status == "active" {
                    1
                } else {
                    0
                };
                out.push_str(&format!(
                    "ifa_mesh_link_status{{cluster=\"{}\",source=\"{}\",target=\"{}\",interface=\"{}\"}} {}\n",
                    c,
                    l.source_node_id,
                    l.target_node_id,
                    escape_json_str(&l.interface_name),
                    val
                ));
            }
        }

        out
    }
}

/// Multi-node mesh topology synthesizer that aggregates telemetry metrics across cluster nodes.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspMultiNodeMeshSynthesizer {
    /// Cluster name or identifier.
    pub cluster_id: String,
    /// Heartbeat expiration timeout in nanoseconds. Nodes unseen longer than this are marked offline.
    pub heartbeat_timeout_ns: u64,
    /// Registered mesh nodes indexed by node ID.
    pub nodes: BTreeMap<u32, IsspMeshNodeInfo>,
    /// Mesh transport links indexed by `(source_node_id, target_node_id, interface_name)`.
    pub links: BTreeMap<(u32, u32, String), IsspMeshLinkInfo>,
}

impl Default for IsspMultiNodeMeshSynthesizer {
    fn default() -> Self {
        Self::new("ifa-cluster")
    }
}

impl IsspMultiNodeMeshSynthesizer {
    /// Create a new multi-node mesh topology synthesizer.
    pub fn new(cluster_id: &str) -> Self {
        Self {
            cluster_id: cluster_id.to_string(),
            heartbeat_timeout_ns: 15_000_000_000, // 15 seconds default
            nodes: BTreeMap::new(),
            links: BTreeMap::new(),
        }
    }

    /// Set heartbeat timeout in seconds for automatic node degradation.
    pub fn with_heartbeat_timeout_seconds(mut self, timeout_secs: u64) -> Self {
        self.heartbeat_timeout_ns = timeout_secs.saturating_mul(1_000_000_000);
        self
    }

    /// Register or update a mesh node in the synthesizer.
    pub fn register_or_update_node(&mut self, node: IsspMeshNodeInfo) {
        self.nodes.insert(node.node_id, node);
    }

    /// Register or update a mesh transport link in the synthesizer.
    pub fn register_or_update_link(&mut self, link: IsspMeshLinkInfo) {
        let key = (
            link.source_node_id,
            link.target_node_id,
            link.interface_name.clone(),
        );
        self.links.insert(key, link);
    }

    /// Remove a node and its attached links from the synthesizer.
    pub fn remove_node(&mut self, node_id: u32) {
        self.nodes.remove(&node_id);
        self.links
            .retain(|(src, tgt, _), _| *src != node_id && *tgt != node_id);
    }

    /// Remove an explicit link from the synthesizer.
    pub fn remove_link(&mut self, source: u32, target: u32, interface: &str) {
        self.links.remove(&(source, target, interface.to_string()));
    }

    /// Ingest a local or remote node balancing snapshot, projecting subpaths onto target peer nodes.
    pub fn ingest_node_snapshot(
        &mut self,
        snapshot: &IsspMultipathBalancingSnapshot,
        node_name: &str,
        role: &str,
        endpoint: &str,
        peer_targets: &[(u32, &str)],
    ) {
        let mut total_rtt_us = 0u64;
        let mut rtt_count = 0usize;
        let mut tx_frames = 0u64;
        let mut rx_frames = 0u64;

        for sp in &snapshot.subpaths {
            if sp.rtt_us > 0 {
                total_rtt_us += sp.rtt_us;
                rtt_count += 1;
            }
            tx_frames = tx_frames.saturating_add(sp.total_frames_sent);
            rx_frames = rx_frames.saturating_add(sp.total_frames_received);
        }

        let avg_latency_ms = if rtt_count > 0 {
            (total_rtt_us as f64) / (rtt_count as f64 * 1000.0)
        } else {
            0.0
        };

        let tx_bytes_sec = (tx_frames as f64) * 1420.0;
        let rx_bytes_sec = (rx_frames as f64) * 1420.0;
        let is_healthy = snapshot.active_paths > 0;
        let status = if is_healthy { "healthy" } else { "degraded" };

        let node_info = IsspMeshNodeInfo {
            node_id: snapshot.node_id,
            node_name: node_name.to_string(),
            role: role.to_string(),
            endpoint: endpoint.to_string(),
            status: status.to_string(),
            active_paths: snapshot.active_paths,
            total_sessions: snapshot.total_sessions,
            tx_bytes_per_sec: tx_bytes_sec,
            rx_bytes_per_sec: rx_bytes_sec,
            avg_latency_ms,
            tcp_retrans_ratio: snapshot.aggregate_tcp_retrans_ratio,
            issp_retrans_ratio: snapshot.aggregate_issp_retrans_ratio,
            last_heartbeat_unix_ns: snapshot.timestamp_unix_ns,
            is_healthy,
        };
        self.nodes.insert(snapshot.node_id, node_info);

        // Project subpaths as mesh links to known peer targets
        for sp in &snapshot.subpaths {
            for &(peer_id, iface_hint) in peer_targets {
                if peer_id != snapshot.node_id
                    && (iface_hint.is_empty() || sp.interface_name.contains(iface_hint))
                {
                    let lat_ms = (sp.rtt_us as f64) / 1000.0;
                    let jitter_ms = (sp.rtt_gradient_us as f64) / 1000.0;
                    let loss_ratio = sp.tcp_retrans_ratio.max(sp.issp_retrans_ratio);
                    let link_status = if !sp.is_usable {
                        "offline"
                    } else if loss_ratio > 0.05 || sp.congestion_phase == "Recovery" {
                        "congested"
                    } else if sp.state == "Degraded" {
                        "degraded"
                    } else {
                        "optimal"
                    };

                    let link = IsspMeshLinkInfo {
                        link_id: format!(
                            "node-{}->node-{}:{}",
                            snapshot.node_id, peer_id, sp.interface_name
                        ),
                        source_node_id: snapshot.node_id,
                        target_node_id: peer_id,
                        interface_name: sp.interface_name.clone(),
                        latency_ms: lat_ms,
                        jitter_ms,
                        loss_ratio,
                        retransmit_rate: loss_ratio,
                        tx_bytes_per_sec: (sp.total_frames_sent as f64) * 1420.0,
                        rx_bytes_per_sec: (sp.total_frames_received as f64) * 1420.0,
                        weight: sp.effective_weight,
                        status: link_status.to_string(),
                        is_bottleneck: false,
                    };
                    let key = (snapshot.node_id, peer_id, sp.interface_name.clone());
                    self.links.insert(key, link);
                }
            }
        }
    }

    /// Ingest a JSON report payload received from a remote node.
    pub fn ingest_mesh_report_json(&mut self, json_str: &str, now_ns: u64) -> Result<(), String> {
        let val = MiniJsonValue::parse(json_str)?;
        let obj = val
            .as_object()
            .ok_or_else(|| "Expected JSON object for mesh report".to_string())?;

        if let Some(cid) = obj.get("cluster_id").and_then(|v| v.as_str()) {
            if !cid.is_empty() {
                self.cluster_id = cid.to_string();
            }
        }

        let node_val = obj.get("node").or(Some(&val));
        let mut current_node_id = 0u32;
        if let Some(nv) = node_val {
            if let Some(n_obj) = nv.as_object() {
                if let Some(nid_f) = n_obj.get("node_id").and_then(|v| v.as_f64()) {
                    let nid = nid_f as u32;
                    current_node_id = nid;
                    let node_name = n_obj
                        .get("node_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("ifa-node");
                    let role = n_obj
                        .get("role")
                        .and_then(|v| v.as_str())
                        .unwrap_or("worker");
                    let endpoint = n_obj.get("endpoint").and_then(|v| v.as_str()).unwrap_or("");
                    let active_paths = n_obj
                        .get("active_paths")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(1.0) as usize;
                    let total_sessions = n_obj
                        .get("total_sessions")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0) as usize;
                    let tx_bps = n_obj
                        .get("tx_bytes_per_sec")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    let rx_bps = n_obj
                        .get("rx_bytes_per_sec")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    let avg_lat = n_obj
                        .get("avg_latency_ms")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    let tcp_ret = n_obj
                        .get("tcp_retrans_ratio")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    let issp_ret = n_obj
                        .get("issp_retrans_ratio")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    let is_healthy = n_obj
                        .get("is_healthy")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    let status = n_obj
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or(if is_healthy { "healthy" } else { "degraded" });

                    let node_info = IsspMeshNodeInfo {
                        node_id: nid,
                        node_name: node_name.to_string(),
                        role: role.to_string(),
                        endpoint: endpoint.to_string(),
                        status: status.to_string(),
                        active_paths,
                        total_sessions,
                        tx_bytes_per_sec: tx_bps,
                        rx_bytes_per_sec: rx_bps,
                        avg_latency_ms: avg_lat,
                        tcp_retrans_ratio: tcp_ret,
                        issp_retrans_ratio: issp_ret,
                        last_heartbeat_unix_ns: now_ns,
                        is_healthy,
                    };
                    self.nodes.insert(nid, node_info);
                }
            }
        }

        if let Some(links_arr) = obj.get("links").and_then(|v| v.as_array()) {
            for item in links_arr {
                if let Some(l_obj) = item.as_object() {
                    let src = l_obj
                        .get("source_node_id")
                        .and_then(|v| v.as_f64())
                        .map(|f| f as u32)
                        .unwrap_or(current_node_id);
                    let tgt = l_obj
                        .get("target_node_id")
                        .and_then(|v| v.as_f64())
                        .map(|f| f as u32)
                        .unwrap_or(0);
                    let iface = l_obj
                        .get("interface_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("eth0");
                    let lat = l_obj
                        .get("latency_ms")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    let jitter = l_obj
                        .get("jitter_ms")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    let loss = l_obj
                        .get("loss_ratio")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    let ret = l_obj
                        .get("retransmit_rate")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    let tx_bps = l_obj
                        .get("tx_bytes_per_sec")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    let rx_bps = l_obj
                        .get("rx_bytes_per_sec")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    let weight = l_obj
                        .get("weight")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(100.0) as u32;
                    let status = l_obj
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("optimal");

                    let link_id = format!("node-{}->node-{}:{}", src, tgt, iface);
                    let link = IsspMeshLinkInfo {
                        link_id,
                        source_node_id: src,
                        target_node_id: tgt,
                        interface_name: iface.to_string(),
                        latency_ms: lat,
                        jitter_ms: jitter,
                        loss_ratio: loss,
                        retransmit_rate: ret,
                        tx_bytes_per_sec: tx_bps,
                        rx_bytes_per_sec: rx_bps,
                        weight,
                        status: status.to_string(),
                        is_bottleneck: false,
                    };
                    self.links.insert((src, tgt, iface.to_string()), link);
                }
            }
        }

        Ok(())
    }

    /// Synthesize current multi-node mesh topology evaluating heartbeats, bottlenecks, and density.
    pub fn synthesize(&self, now_ns: u64) -> IsspMeshTopologySnapshot {
        let mut nodes: Vec<IsspMeshNodeInfo> = Vec::with_capacity(self.nodes.len());
        let mut healthy_nodes = 0;
        let mut cluster_sessions = 0;
        let mut cluster_tx = 0.0;
        let mut cluster_rx = 0.0;

        for n in self.nodes.values() {
            let mut node_copy = n.clone();
            let elapsed_ns = now_ns.saturating_sub(node_copy.last_heartbeat_unix_ns);
            if self.heartbeat_timeout_ns > 0
                && node_copy.last_heartbeat_unix_ns > 0
                && elapsed_ns > self.heartbeat_timeout_ns
            {
                node_copy.is_healthy = false;
                node_copy.status = "offline".to_string();
            }
            if node_copy.is_healthy {
                healthy_nodes += 1;
            }
            cluster_sessions += node_copy.total_sessions;
            cluster_tx += node_copy.tx_bytes_per_sec;
            cluster_rx += node_copy.rx_bytes_per_sec;
            nodes.push(node_copy);
        }

        let mut links: Vec<IsspMeshLinkInfo> = Vec::with_capacity(self.links.len());
        let mut active_links = 0;
        let mut sum_latency = 0.0;
        let mut min_latency = f64::INFINITY;
        let mut max_latency = 0.0;
        let mut sum_loss = 0.0;

        for l in self.links.values() {
            let mut link_copy = l.clone();
            let src_node = self.nodes.get(&link_copy.source_node_id);
            let tgt_node = self.nodes.get(&link_copy.target_node_id);
            let src_ok = src_node.map(|n| n.is_healthy).unwrap_or(true);
            let tgt_ok = tgt_node.map(|n| n.is_healthy).unwrap_or(true);

            if !src_ok || !tgt_ok {
                link_copy.status = "offline".to_string();
            }

            if link_copy.status == "optimal" || link_copy.status == "active" {
                active_links += 1;
            }

            if link_copy.latency_ms > 0.0 {
                sum_latency += link_copy.latency_ms;
                if link_copy.latency_ms < min_latency {
                    min_latency = link_copy.latency_ms;
                }
                if link_copy.latency_ms > max_latency {
                    max_latency = link_copy.latency_ms;
                }
            }
            sum_loss += link_copy.loss_ratio;
            links.push(link_copy);
        }

        let total_nodes = nodes.len();
        let total_links = links.len();
        let avg_latency = if !links.is_empty() {
            sum_latency / (links.len() as f64)
        } else {
            0.0
        };
        let min_lat = if min_latency.is_infinite() {
            0.0
        } else {
            min_latency
        };

        let mut bottlenecks = Vec::new();
        for l in &mut links {
            if l.loss_ratio > 0.05 || (avg_latency > 0.0 && l.latency_ms > 2.0 * avg_latency) {
                l.is_bottleneck = true;
                bottlenecks.push(l.link_id.clone());
            }
        }

        let density_ratio = if total_nodes <= 1 {
            1.0
        } else {
            let max_possible = (total_nodes * (total_nodes - 1)) as f64;
            ((active_links as f64) / max_possible).min(1.0)
        };

        let node_health_ratio = if total_nodes > 0 {
            healthy_nodes as f64 / total_nodes as f64
        } else {
            1.0
        };
        let link_health_ratio = if total_links > 0 {
            active_links as f64 / total_links as f64
        } else {
            1.0
        };
        let avg_loss = if total_links > 0 {
            sum_loss / total_links as f64
        } else {
            0.0
        };
        let health_score =
            (0.5 * node_health_ratio + 0.3 * link_health_ratio + 0.2 * (1.0 - avg_loss.min(1.0)))
                .clamp(0.0, 1.0);

        IsspMeshTopologySnapshot {
            cluster_id: self.cluster_id.clone(),
            timestamp_unix_ns: now_ns,
            nodes,
            links,
            total_nodes,
            healthy_nodes,
            total_links,
            active_links,
            mesh_density_ratio: density_ratio,
            cluster_total_sessions: cluster_sessions,
            cluster_tx_bytes_per_sec: cluster_tx,
            cluster_rx_bytes_per_sec: cluster_rx,
            cluster_avg_latency_ms: avg_latency,
            cluster_min_latency_ms: min_lat,
            cluster_max_latency_ms: max_latency,
            cluster_health_score: health_score,
            bottlenecks,
        }
    }
}

// ─── HTTP Telemetry Handlers & Exposition Server ──────────────────────────

/// HTTP request dispatcher for dynamic ISSP multipath balancing telemetry.
///
/// Supports the standard observability endpoints:
/// - `/metrics`: Prometheus Exposition text format (or OpenTelemetry OTLP JSON if `Accept: application/json` is requested)
/// - `/v1/metrics`: OpenTelemetry OTLP JSON payload conforming to OTLP v1/metrics specification
/// - `/healthz` or `/livez`: Liveness probe returning HTTP 200 OK
/// - `/readyz`: Readiness probe evaluating cluster quorum degradation threshold (HTTP 200 if quorum healthy, HTTP 503 if degraded)
/// - `/api/mesh/topology`: Grafana Node Graph visualization panel format JSON
/// - `/api/mesh/summary`: Grafana supervisor mesh topology summary JSON
/// - `/api/mesh/metrics`: Multi-node mesh metrics in Prometheus exposition format
#[derive(Debug, Clone)]
pub struct IsspTelemetryHttpHandler {
    service_name: String,
    quorum_config: IsspClusterQuorumConfig,
    mesh_synthesizer: Option<IsspMultiNodeMeshSynthesizer>,
}

impl IsspTelemetryHttpHandler {
    /// Create a new telemetry HTTP handler with the specified service name for OTLP reporting.
    pub fn new(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
            quorum_config: IsspClusterQuorumConfig::default(),
            mesh_synthesizer: None,
        }
    }

    /// Retrieve the configured service name.
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Set a custom cluster quorum configuration for readiness checks.
    pub fn with_quorum_config(mut self, config: IsspClusterQuorumConfig) -> Self {
        self.quorum_config = config;
        self
    }

    /// Retrieve the current cluster quorum configuration.
    pub fn quorum_config(&self) -> &IsspClusterQuorumConfig {
        &self.quorum_config
    }

    /// Attach a multi-node mesh synthesizer to this HTTP handler.
    pub fn with_mesh_synthesizer(mut self, synth: IsspMultiNodeMeshSynthesizer) -> Self {
        self.mesh_synthesizer = Some(synth);
        self
    }

    /// Retrieve a reference to the optional attached mesh synthesizer.
    pub fn mesh_synthesizer(&self) -> Option<&IsspMultiNodeMeshSynthesizer> {
        self.mesh_synthesizer.as_ref()
    }

    /// Helper to project or synthesize a multi-node mesh topology snapshot.
    fn synthesize_mesh_snapshot(
        &self,
        snapshot: &IsspMultipathBalancingSnapshot,
        cluster_nodes: usize,
    ) -> IsspMeshTopologySnapshot {
        let mut synth = if let Some(ref s) = self.mesh_synthesizer {
            s.clone()
        } else {
            let cluster_id = format!("{}-mesh", self.service_name);
            IsspMultiNodeMeshSynthesizer::new(&cluster_id)
        };

        let peer_targets: Vec<(u32, &str)> = (1..=cluster_nodes as u32)
            .filter(|&id| id != snapshot.node_id)
            .map(|id| (id, ""))
            .collect();

        synth.ingest_node_snapshot(
            snapshot,
            &self.service_name,
            "gateway",
            "127.0.0.1:9090",
            &peer_targets,
        );

        synth.synthesize(snapshot.timestamp_unix_ns)
    }

    /// Dispatch an HTTP request against a provided snapshot and explicit cluster node count.
    ///
    /// Returns `(http_status_code, content_type_header, response_body_string)`.
    pub fn handle_snapshot_with_quorum(
        &self,
        path: &str,
        accept_header: &str,
        snapshot: &IsspMultipathBalancingSnapshot,
        cluster_nodes: usize,
    ) -> (u16, &'static str, String) {
        let clean_path = path.split('?').next().unwrap_or(path).trim_end_matches('/');
        match clean_path {
            "/metrics" => {
                if path.contains("format=mesh") {
                    let mesh_snap = self.synthesize_mesh_snapshot(snapshot, cluster_nodes);
                    (
                        200,
                        "text/plain; version=0.0.4; charset=utf-8",
                        mesh_snap.to_prometheus_mesh_exposition(),
                    )
                } else if accept_header.contains("application/json") {
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
            p if p.contains("MetricsService/Export") => (200, "application/grpc", String::new()),
            "/api/mesh/topology" | "/api/v1/mesh/topology" => {
                let mesh_snap = self.synthesize_mesh_snapshot(snapshot, cluster_nodes);
                (
                    200,
                    "application/json",
                    mesh_snap.to_grafana_node_graph_json(),
                )
            }
            "/api/mesh/summary" | "/api/v1/mesh/summary" => {
                let mesh_snap = self.synthesize_mesh_snapshot(snapshot, cluster_nodes);
                (
                    200,
                    "application/json",
                    mesh_snap.to_grafana_topology_summary_json(),
                )
            }
            "/api/mesh/metrics" | "/metrics/mesh" => {
                let mesh_snap = self.synthesize_mesh_snapshot(snapshot, cluster_nodes);
                (
                    200,
                    "text/plain; version=0.0.4; charset=utf-8",
                    mesh_snap.to_prometheus_mesh_exposition(),
                )
            }
            "/healthz" | "/livez" => {
                if accept_header.contains("application/json") {
                    let json = format!(
                        concat!(
                            "{{\n",
                            "  \"status\": \"ALIVE\",\n",
                            "  \"node_id\": {},\n",
                            "  \"active_paths\": {},\n",
                            "  \"total_sessions\": {}\n",
                            "}}"
                        ),
                        snapshot.node_id, snapshot.active_paths, snapshot.total_sessions
                    );
                    (200, "application/json", json)
                } else {
                    (200, "text/plain; charset=utf-8", "OK\n".to_string())
                }
            }
            "/readyz" => {
                let status = self.quorum_config.evaluate(snapshot, cluster_nodes);
                let is_json = accept_header.contains("application/json");
                if status.is_ready {
                    if is_json {
                        (200, "application/json", status.to_json())
                    } else {
                        (
                            200,
                            "text/plain; charset=utf-8",
                            format!("READY: {}\n", status.reason),
                        )
                    }
                } else if is_json {
                    (503, "application/json", status.to_json())
                } else {
                    (
                        503,
                        "text/plain; charset=utf-8",
                        format!("DEGRADED: {}\n", status.reason),
                    )
                }
            }
            "/api/traces/archive" | "/api/v1/traces/archive" => {
                let json = format!(
                    "{{\"status\":\"OK\",\"subpaths_tracked\":{},\"format\":\"zstd\",\"endpoint\":\"/api/traces/archive\"}}",
                    snapshot.subpaths.len()
                );
                (200, "application/json", json)
            }
            _ => (404, "text/plain; charset=utf-8", "Not Found\n".to_string()),
        }
    }

    /// Dispatch an HTTP request against a provided snapshot with single-node baseline quorum.
    pub fn handle_snapshot(
        &self,
        path: &str,
        accept_header: &str,
        snapshot: &IsspMultipathBalancingSnapshot,
    ) -> (u16, &'static str, String) {
        self.handle_snapshot_with_quorum(path, accept_header, snapshot, 1)
    }

    /// Dispatch an HTTP or gRPC binary request returning raw payload bytes:
    /// `(http_status_code, content_type_header, response_body_bytes)`.
    pub fn handle_snapshot_binary(
        &self,
        path: &str,
        accept_header: &str,
        snapshot: &IsspMultipathBalancingSnapshot,
    ) -> (u16, &'static str, Vec<u8>) {
        let clean_path = path.split('?').next().unwrap_or(path).trim_end_matches('/');
        if clean_path == "/v1/metrics"
            && (accept_header.contains("application/x-protobuf")
                || accept_header.contains("application/protobuf"))
        {
            (
                200,
                "application/x-protobuf",
                snapshot.export_otlp_protobuf(&self.service_name),
            )
        } else if clean_path == "/api/traces/archive" || clean_path == "/api/v1/traces/archive" {
            let archive = self.export_zstd_traces_archive(snapshot);
            (200, "application/zstd", archive)
        } else if clean_path.contains("MetricsService/Export")
            || accept_header.contains("application/grpc")
        {
            (200, "application/grpc", vec![0x00, 0x00, 0x00, 0x00, 0x00])
        } else {
            let (code, ctype, body_str) =
                self.handle_snapshot_with_quorum(path, accept_header, snapshot, 1);
            (code, ctype, body_str.into_bytes())
        }
    }

    /// Export all subpath congestion metrics and multipath telemetry as an RFC 8878 Zstandard compressed stream.
    pub fn export_zstd_traces_archive(&self, snapshot: &IsspMultipathBalancingSnapshot) -> Vec<u8> {
        let mut pipeline = crate::zstd_archive::IsspZstdMemoryPipeline::new(64 * 1024);

        for sp in &snapshot.subpaths {
            let phase = match sp.congestion_phase.as_str() {
                "SlowStart" => crate::zstd_archive::PHASE_SLOW_START,
                "Recovery" => crate::zstd_archive::PHASE_RECOVERY,
                "Drain" => crate::zstd_archive::PHASE_DRAIN,
                "ProbeBw" => crate::zstd_archive::PHASE_PROBE_BW,
                "ProbeRtt" => crate::zstd_archive::PHASE_PROBE_RTT,
                _ => crate::zstd_archive::PHASE_CONGESTION_AVOIDANCE,
            };
            let flags = if sp.congestion_events > 0 {
                crate::zstd_archive::TRACE_FLAG_LOSS
            } else {
                0
            };
            let record = crate::zstd_archive::IsspCongestionTraceRecord {
                node_id: snapshot.node_id,
                subpath_id: sp.path_id,
                congestion_phase: phase,
                flags,
                pacing_gain_q8: sp.bbr_pacing_gain_q8 as u16,
                timestamp_ns: snapshot.timestamp_unix_ns,
                flow_hash: sp.path_id as u64,
                seq_num: sp.total_frames_sent,
                cwnd_bytes: sp.ledbat_cwnd_bytes,
                bandwidth_estimate_bps: sp.bbr_bw_bps,
                rtt_us: sp.rtt_us as u32,
                queuing_delay_us: sp.rtt_gradient_us as u32,
            };
            pipeline.ingest_trace(&record);
        }

        let telem_record = crate::zstd_archive::IsspMultipathTelemetryRecord {
            node_id: snapshot.node_id,
            active_subpaths: snapshot.active_paths as u32,
            total_sessions: snapshot.total_sessions as u32,
            avg_rtt_us: 10000,
            max_queuing_delay_us: 2000,
            timestamp_ns: snapshot.timestamp_unix_ns,
            total_tx_bytes: 0,
            total_rx_bytes: 0,
            loss_events_count: 0,
            effective_throughput_bps: 0,
        };
        pipeline.ingest_telemetry(&telem_record);

        let (bytes, _) = pipeline.finish();
        bytes
    }

    /// Parse a raw HTTP GET request string and format a complete HTTP 1.1 wire response.
    pub fn handle_raw_http_request(
        &self,
        raw_request: &str,
        snapshot: &IsspMultipathBalancingSnapshot,
    ) -> String {
        self.handle_raw_http_request_with_quorum(raw_request, snapshot, 1)
    }

    /// Parse a raw HTTP GET request string with explicit cluster nodes count.
    pub fn handle_raw_http_request_with_quorum(
        &self,
        raw_request: &str,
        snapshot: &IsspMultipathBalancingSnapshot,
        cluster_nodes: usize,
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

        let (code, ctype, body) =
            self.handle_snapshot_with_quorum(path, accept, snapshot, cluster_nodes);
        let status_text = match code {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "Status",
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
/// and active health probes (`/livez`, `/readyz`) over standard network sockets (`std::net::TcpListener`).
pub struct IsspTelemetryServer {
    listener: TcpListener,
    service_name: String,
    registry: Arc<crate::session_sync::SessionRegistry>,
    quorum_config: RwLock<IsspClusterQuorumConfig>,
    failover_policy: RwLock<AlertFailoverPolicy>,
    mesh_synthesizer: Arc<RwLock<IsspMultiNodeMeshSynthesizer>>,
}

impl IsspTelemetryServer {
    /// Bind the telemetry server to the requested socket address with an associated `SessionRegistry`.
    pub fn bind<A: ToSocketAddrs>(
        addr: A,
        service_name: &str,
        registry: Arc<crate::session_sync::SessionRegistry>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let cluster_id = format!("{}-cluster", service_name);
        Ok(Self {
            listener,
            service_name: service_name.to_string(),
            registry,
            quorum_config: RwLock::new(IsspClusterQuorumConfig::default()),
            failover_policy: RwLock::new(AlertFailoverPolicy::default()),
            mesh_synthesizer: Arc::new(RwLock::new(IsspMultiNodeMeshSynthesizer::new(&cluster_id))),
        })
    }

    /// Retrieve the shared multi-node mesh synthesizer handle.
    pub fn mesh_synthesizer(&self) -> Arc<RwLock<IsspMultiNodeMeshSynthesizer>> {
        Arc::clone(&self.mesh_synthesizer)
    }

    /// Configure a custom multi-node mesh synthesizer.
    pub fn with_mesh_synthesizer(self, synth: Arc<RwLock<IsspMultiNodeMeshSynthesizer>>) -> Self {
        Self {
            mesh_synthesizer: synth,
            ..self
        }
    }

    /// Ingest a remote node's telemetry report into the multi-node mesh synthesizer.
    pub fn handle_mesh_report(&self, raw_body: &str) -> (u16, &'static str, String) {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let mut synth = match self.mesh_synthesizer.write() {
            Ok(w) => w,
            Err(_) => {
                return (
                    500,
                    "application/json",
                    "{\n  \"status\": \"error\",\n  \"message\": \"Mesh synthesizer lock poisoned\"\n}\n".to_string(),
                );
            }
        };

        match synth.ingest_mesh_report_json(raw_body, now_ns) {
            Ok(()) => {
                let resp_json = format!(
                    concat!(
                        "{{\n",
                        "  \"status\": \"acknowledged\",\n",
                        "  \"cluster_id\": \"{}\",\n",
                        "  \"nodes_tracked\": {},\n",
                        "  \"links_tracked\": {}\n",
                        "}}"
                    ),
                    escape_json_str(&synth.cluster_id),
                    synth.nodes.len(),
                    synth.links.len()
                );
                (200, "application/json", resp_json)
            }
            Err(e) => {
                let err_json = format!(
                    "{{\n  \"status\": \"error\",\n  \"message\": \"Invalid JSON: {}\"\n}}",
                    escape_json_str(&e)
                );
                (400, "application/json", err_json)
            }
        }
    }

    /// Refresh local node metrics in the mesh synthesizer from current registry state.
    pub fn refresh_local_mesh_node(&self, now_ns: u64) {
        if let Ok(snap) = self.registry.multipath_balancing_snapshot(now_ns) {
            let peer_ids = self.registry.peer_node_ids().unwrap_or_default();
            let peer_targets: Vec<(u32, &str)> = peer_ids.iter().map(|&pid| (pid, "")).collect();
            let endpoint = self.local_addr().map(|a| a.to_string()).unwrap_or_default();
            if let Ok(mut w) = self.mesh_synthesizer.write() {
                w.ingest_node_snapshot(
                    &snap,
                    &self.service_name,
                    "gateway",
                    &endpoint,
                    &peer_targets,
                );
            }
        }
    }

    /// Configure quorum evaluation parameters.
    pub fn with_quorum_config(self, config: IsspClusterQuorumConfig) -> Self {
        if let Ok(mut w) = self.quorum_config.write() {
            *w = config;
        }
        self
    }

    /// Retrieve a copy of the current quorum configuration.
    pub fn quorum_config(&self) -> IsspClusterQuorumConfig {
        self.quorum_config
            .read()
            .map(|r| r.clone())
            .unwrap_or_default()
    }

    /// Update the quorum configuration at runtime.
    pub fn set_quorum_config(&self, config: IsspClusterQuorumConfig) {
        if let Ok(mut w) = self.quorum_config.write() {
            *w = config;
        }
    }

    /// Configure the automated alert failover policy.
    pub fn with_failover_policy(self, policy: AlertFailoverPolicy) -> Self {
        if let Ok(mut w) = self.failover_policy.write() {
            *w = policy;
        }
        self
    }

    /// Retrieve a copy of the current alert failover policy.
    pub fn failover_policy(&self) -> AlertFailoverPolicy {
        self.failover_policy
            .read()
            .map(|r| r.clone())
            .unwrap_or_default()
    }

    /// Update the alert failover policy at runtime.
    pub fn set_failover_policy(&self, policy: AlertFailoverPolicy) {
        if let Ok(mut w) = self.failover_policy.write() {
            *w = policy;
        }
    }

    /// Process an Alertmanager webhook payload and execute automated interface failover/restore actions.
    pub fn handle_alert_webhook(&self, raw_body: &str) -> (u16, &'static str, String) {
        let payload = match AlertmanagerWebhookPayload::parse_json(raw_body) {
            Ok(p) => p,
            Err(e) => {
                let err_json = format!(
                    "{{\n  \"status\": \"error\",\n  \"message\": \"Invalid JSON: {}\"\n}}",
                    escape_json_str(&e)
                );
                return (400, "application/json", err_json);
            }
        };

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let policy = self.failover_policy();
        let mut failovers_applied = 0;
        let mut restores_applied = 0;
        let mut total_sessions_rerouted = 0;
        let mut details = Vec::new();

        for alert in &payload.alerts {
            if alert.interface.is_empty() {
                continue;
            }

            let is_resolved = alert.status.eq_ignore_ascii_case("resolved")
                || payload.status.eq_ignore_ascii_case("resolved");

            if is_resolved {
                match self.registry.restore_interface(
                    &alert.interface,
                    policy.restore_target_state,
                    now_ms,
                ) {
                    Ok(rep) => {
                        restores_applied += 1;
                        let detail = format!(
                            concat!(
                                "    {{\n",
                                "      \"alertname\": \"{}\",\n",
                                "      \"interface\": \"{}\",\n",
                                "      \"status\": \"resolved\",\n",
                                "      \"action\": \"Restored{:?}\",\n",
                                "      \"restored_paths\": {:?},\n",
                                "      \"sessions_rerouted\": 0\n",
                                "    }}"
                            ),
                            escape_json_str(&alert.alertname),
                            escape_json_str(&alert.interface),
                            rep.restored_state,
                            rep.restored_path_ids
                        );
                        details.push(detail);
                    }
                    Err(e) => {
                        let detail = format!(
                            concat!(
                                "    {{\n",
                                "      \"alertname\": \"{}\",\n",
                                "      \"interface\": \"{}\",\n",
                                "      \"status\": \"error\",\n",
                                "      \"error\": \"{}\"\n",
                                "    }}"
                            ),
                            escape_json_str(&alert.alertname),
                            escape_json_str(&alert.interface),
                            e
                        );
                        details.push(detail);
                    }
                }
            } else {
                let (action, reason) = policy.classify_alert(alert);
                match self
                    .registry
                    .failover_interface(&alert.interface, action, reason, now_ms)
                {
                    Ok(rep) => {
                        failovers_applied += 1;
                        total_sessions_rerouted += rep.total_sessions_rerouted;
                        let target_ifaces_json = rep
                            .target_interfaces
                            .iter()
                            .map(|s| format!("\"{}\"", escape_json_str(s)))
                            .collect::<Vec<_>>()
                            .join(", ");
                        let detail = format!(
                            concat!(
                                "    {{\n",
                                "      \"alertname\": \"{}\",\n",
                                "      \"interface\": \"{}\",\n",
                                "      \"status\": \"firing\",\n",
                                "      \"action\": \"{}\",\n",
                                "      \"reason\": \"{}\",\n",
                                "      \"impacted_paths\": {:?},\n",
                                "      \"target_paths\": {:?},\n",
                                "      \"target_interfaces\": [{}],\n",
                                "      \"sessions_rerouted\": {}\n",
                                "    }}"
                            ),
                            escape_json_str(&alert.alertname),
                            escape_json_str(&alert.interface),
                            action.as_str(),
                            reason.as_str(),
                            rep.impacted_path_ids,
                            rep.target_path_ids,
                            target_ifaces_json,
                            rep.total_sessions_rerouted
                        );
                        details.push(detail);
                    }
                    Err(e) => {
                        let detail = format!(
                            concat!(
                                "    {{\n",
                                "      \"alertname\": \"{}\",\n",
                                "      \"interface\": \"{}\",\n",
                                "      \"status\": \"error\",\n",
                                "      \"error\": \"{}\"\n",
                                "    }}"
                            ),
                            escape_json_str(&alert.alertname),
                            escape_json_str(&alert.interface),
                            e
                        );
                        details.push(detail);
                    }
                }
            }
        }

        let resp_json = format!(
            concat!(
                "{{\n",
                "  \"status\": \"success\",\n",
                "  \"alerts_processed\": {},\n",
                "  \"failovers_applied\": {},\n",
                "  \"restores_applied\": {},\n",
                "  \"total_sessions_rerouted\": {},\n",
                "  \"details\": [\n{}\n  ]\n",
                "}}"
            ),
            payload.alerts.len(),
            failovers_applied,
            restores_applied,
            total_sessions_rerouted,
            details.join(",\n")
        );

        (200, "application/json", resp_json)
    }

    /// Retrieve failover audit history in JSON format.
    pub fn handle_failover_history_json(&self) -> (u16, &'static str, String) {
        match self.registry.multipath_failover_history() {
            Ok(events) => {
                let items: Vec<String> = events.iter().map(|e| e.to_json()).collect();
                let json = format!("[\n{}\n]", items.join(",\n"));
                (200, "application/json", json)
            }
            Err(e) => (500, "application/json", format!("{{\"error\":\"{}\"}}", e)),
        }
    }

    /// Evaluate current cluster quorum status directly against the registry state.
    pub fn evaluate_quorum(&self) -> Result<IsspQuorumStatus, crate::session_sync::SyncError> {
        let ts_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let snap = self.registry.multipath_balancing_snapshot(ts_ns)?;
        let cluster_nodes = self.registry.cluster_nodes_count().unwrap_or(1);
        let cfg = self.quorum_config();
        Ok(cfg.evaluate(&snap, cluster_nodes))
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
        let mut buf = [0u8; 8192];
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok((400, String::new()));
        }

        // 1. Detect HTTP/2 connection preface (standard gRPC over HTTP/2)
        if buf[..n].starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
            return self.serve_http2_grpc_connection(&buf[..n], reader, writer);
        }

        let req_str = String::from_utf8_lossy(&buf[..n]);

        let mut method = "GET";
        let mut path = "/metrics";
        let mut accept = "*/*";
        let mut content_length: usize = 0;

        for line in req_str.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("GET ") || trimmed.starts_with("POST ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    method = if trimmed.starts_with("POST ") {
                        "POST"
                    } else {
                        "GET"
                    };
                    path = parts[1];
                }
            } else if trimmed.to_ascii_lowercase().starts_with("accept:") {
                accept = trimmed.split(':').nth(1).unwrap_or("").trim();
            } else if trimmed.to_ascii_lowercase().starts_with("content-length:") {
                content_length = trimmed
                    .split(':')
                    .nth(1)
                    .unwrap_or("")
                    .trim()
                    .parse()
                    .unwrap_or(0);
            }
        }

        let clean_path = path.split('?').next().unwrap_or(path).trim_end_matches('/');

        let is_grpc = clean_path.contains("MetricsService/Export")
            || req_str
                .to_ascii_lowercase()
                .contains("content-type: application/grpc")
            || accept.contains("application/grpc");

        if is_grpc {
            // Respond with standard HTTP/1.1 gRPC response
            let empty_grpc = [0x00, 0x00, 0x00, 0x00, 0x00];
            let resp_hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/grpc\r\ngrpc-status: 0\r\ngrpc-message: OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                empty_grpc.len()
            );
            writer.write_all(resp_hdr.as_bytes())?;
            writer.write_all(&empty_grpc)?;
            writer.flush()?;
            return Ok((200, clean_path.to_string()));
        }

        let is_protobuf_export = clean_path == "/v1/metrics"
            && (accept.contains("application/x-protobuf")
                || accept.contains("application/protobuf"));

        if is_protobuf_export {
            let timestamp_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            match self.registry.multipath_balancing_snapshot(timestamp_ns) {
                Ok(snap) => {
                    let proto_bytes = snap.export_otlp_protobuf(&self.service_name);
                    let resp_hdr = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                        proto_bytes.len()
                    );
                    writer.write_all(resp_hdr.as_bytes())?;
                    writer.write_all(&proto_bytes)?;
                    writer.flush()?;
                    return Ok((200, clean_path.to_string()));
                }
                Err(_) => {
                    let resp_hdr =
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
                    writer.write_all(resp_hdr.as_bytes())?;
                    writer.flush()?;
                    return Ok((500, clean_path.to_string()));
                }
            }
        }

        let (code, ctype, body) = if method == "POST" {
            if clean_path == "/webhook/alerts"
                || clean_path == "/alerts"
                || clean_path == "/api/v1/alerts"
            {
                let body_str =
                    extract_http_body(&buf[..n], req_str.as_ref(), reader, content_length)?;
                self.handle_alert_webhook(&body_str)
            } else if clean_path == "/v1/mesh/report"
                || clean_path == "/api/mesh/report"
                || clean_path == "/api/v1/mesh/report"
            {
                let body_str =
                    extract_http_body(&buf[..n], req_str.as_ref(), reader, content_length)?;
                self.handle_mesh_report(&body_str)
            } else {
                (404, "text/plain; charset=utf-8", "Not Found\n".to_string())
            }
        } else if clean_path == "/api/v1/failovers" || clean_path == "/failovers" {
            self.handle_failover_history_json()
        } else if clean_path == "/api/mesh/topology" || clean_path == "/api/v1/mesh/topology" {
            let timestamp_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            self.refresh_local_mesh_node(timestamp_ns);
            let snap = self
                .mesh_synthesizer
                .read()
                .map(|r| r.synthesize(timestamp_ns))
                .unwrap_or_default();
            (200, "application/json", snap.to_grafana_node_graph_json())
        } else if clean_path == "/api/mesh/summary" || clean_path == "/api/v1/mesh/summary" {
            let timestamp_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            self.refresh_local_mesh_node(timestamp_ns);
            let snap = self
                .mesh_synthesizer
                .read()
                .map(|r| r.synthesize(timestamp_ns))
                .unwrap_or_default();
            (
                200,
                "application/json",
                snap.to_grafana_topology_summary_json(),
            )
        } else if clean_path == "/api/mesh/metrics" || clean_path == "/metrics/mesh" {
            let timestamp_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            self.refresh_local_mesh_node(timestamp_ns);
            let snap = self
                .mesh_synthesizer
                .read()
                .map(|r| r.synthesize(timestamp_ns))
                .unwrap_or_default();
            (
                200,
                "text/plain; version=0.0.4; charset=utf-8",
                snap.to_prometheus_mesh_exposition(),
            )
        } else {
            let timestamp_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);

            let snap_res = self.registry.multipath_balancing_snapshot(timestamp_ns);
            let cluster_nodes = self.registry.cluster_nodes_count().unwrap_or(1);
            let q_cfg = self.quorum_config();
            let mut handler =
                IsspTelemetryHttpHandler::new(&self.service_name).with_quorum_config(q_cfg);
            if let Ok(r) = self.mesh_synthesizer.read() {
                handler = handler.with_mesh_synthesizer(r.clone());
            }

            match snap_res {
                Ok(ref snap) => {
                    handler.handle_snapshot_with_quorum(path, accept, snap, cluster_nodes)
                }
                Err(_) => {
                    if clean_path == "/livez" || clean_path == "/healthz" {
                        (
                            500,
                            "text/plain; charset=utf-8",
                            "DEAD: registry or router lock poisoned\n".to_string(),
                        )
                    } else if clean_path == "/readyz" {
                        (
                            503,
                            "text/plain; charset=utf-8",
                            "DEGRADED: cluster state inaccessible\n".to_string(),
                        )
                    } else {
                        (
                            500,
                            "text/plain; charset=utf-8",
                            "Error collecting multipath balancing telemetry\n".to_string(),
                        )
                    }
                }
            }
        };

        let status_text = match code {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
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
        let _ = stream.shutdown(std::net::Shutdown::Write);
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

    /// Serve an incoming HTTP/2 gRPC connection (OTLP metrics export or reflection).
    pub fn serve_http2_grpc_connection<R: Read, W: Write>(
        &self,
        initial_buf: &[u8],
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<(u16, String)> {
        // Read until we see client's DATA frame with END_STREAM (flags & 0x01 != 0) or EOF
        let mut full_buf = initial_buf.to_vec();
        let mut chunk = [0u8; 4096];
        while !full_buf
            .windows(9)
            .any(|w| w[3] == 0x00 && (w[4] & 0x01) != 0)
        {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    full_buf.extend_from_slice(&chunk[..n]);
                }
                Err(_) => break,
            }
        }

        // 1. Send server SETTINGS frame
        let server_settings = [0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        writer.write_all(&server_settings)?;

        // 2. Send SETTINGS ACK (flags = 0x01)
        let settings_ack = [0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00];
        writer.write_all(&settings_ack)?;

        // 3. Build response HEADERS frame on stream ID 1 (flags = 0x04 END_HEADERS)
        let mut hpack_buf = Vec::with_capacity(128);
        encode_literal_hpack_header(&mut hpack_buf, ":status", "200");
        encode_literal_hpack_header(&mut hpack_buf, "content-type", "application/grpc");

        let h_len = hpack_buf.len();
        let headers_hdr = [
            ((h_len >> 16) & 0xFF) as u8,
            ((h_len >> 8) & 0xFF) as u8,
            (h_len & 0xFF) as u8,
            0x01, // Type: HEADERS
            0x04, // Flags: END_HEADERS
            0x00,
            0x00,
            0x00,
            0x01, // Stream ID 1
        ];
        writer.write_all(&headers_hdr)?;
        writer.write_all(&hpack_buf)?;

        // 4. Send DATA frame with empty gRPC message (5 bytes: 0 flag + 0 length)
        let grpc_resp_msg = [0x00, 0x00, 0x00, 0x00, 0x00];
        let d_len = grpc_resp_msg.len();
        let data_hdr = [
            ((d_len >> 16) & 0xFF) as u8,
            ((d_len >> 8) & 0xFF) as u8,
            (d_len & 0xFF) as u8,
            0x00, // Type: DATA
            0x00, // Flags: none
            0x00,
            0x00,
            0x00,
            0x01, // Stream ID 1
        ];
        writer.write_all(&data_hdr)?;
        writer.write_all(&grpc_resp_msg)?;

        // 5. Send trailing HEADERS frame with trailers (flags = 0x05 END_STREAM | END_HEADERS)
        let mut trailers_buf = Vec::with_capacity(64);
        encode_literal_hpack_header(&mut trailers_buf, "grpc-status", "0");
        encode_literal_hpack_header(&mut trailers_buf, "grpc-message", "OK");

        let t_len = trailers_buf.len();
        let trailers_hdr = [
            ((t_len >> 16) & 0xFF) as u8,
            ((t_len >> 8) & 0xFF) as u8,
            (t_len & 0xFF) as u8,
            0x01, // Type: HEADERS
            0x05, // Flags: END_STREAM | END_HEADERS
            0x00,
            0x00,
            0x00,
            0x01, // Stream ID 1
        ];
        writer.write_all(&trailers_hdr)?;
        writer.write_all(&trailers_buf)?;
        writer.flush()?;

        Ok((
            200,
            "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export".to_string(),
        ))
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

/// Extract request body bytes following HTTP header delimiters (`\r\n\r\n` or `\n\n`) up to content_length.
fn extract_http_body<R: Read>(
    initial_buf: &[u8],
    req_str: &str,
    reader: &mut R,
    content_length: usize,
) -> std::io::Result<String> {
    let header_end = req_str
        .find("\r\n\r\n")
        .map(|p| p + 4)
        .or_else(|| req_str.find("\n\n").map(|p| p + 2));

    let mut body_bytes = if let Some(start) = header_end {
        if start <= initial_buf.len() {
            initial_buf[start..].to_vec()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    while body_bytes.len() < content_length {
        let mut chunk = [0u8; 4096];
        let needed = (content_length - body_bytes.len()).min(4096);
        let n = reader.read(&mut chunk[..needed])?;
        if n == 0 {
            break;
        }
        body_bytes.extend_from_slice(&chunk[..n]);
    }

    Ok(String::from_utf8_lossy(&body_bytes).to_string())
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
pub fn ws_build_text_frame(payload: &[u8]) -> Vec<u8> {
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
pub fn ws_build_close_frame(code: u16) -> Vec<u8> {
    vec![0x88, 0x02, (code >> 8) as u8, (code & 0xFF) as u8]
}

/// Serialise an `IsspMultipathBalancingSnapshot` as compact JSON for WebSocket push.
pub fn snapshot_to_compact_json(s: &IsspMultipathBalancingSnapshot) -> String {
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
    out.push_str(",\"failovers\":");
    out.push_str(&s.total_failovers.to_string());
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
        let s1 = SessionSnapshot::new(crate::session_sync::SessionId::new(1, 10, 1), 1, 1000);
        let s2 = SessionSnapshot::new(crate::session_sync::SessionId::new(2, 10, 2), 1, 1000);
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

    #[test]
    fn test_quorum_config_evaluation_healthy_and_degraded() {
        use crate::session_sync::{
            IsspDynamicMultipathRouter, IsspMultipathRoute, IsspRoutingPolicy,
        };
        let mut router =
            IsspDynamicMultipathRouter::new(7, IsspRoutingPolicy::BandwidthAggregation);
        let mut r1 = IsspMultipathRoute::new(1, 10, "eth0", 1, 100);
        r1.metrics.total_frames_sent = 100;
        r1.metrics.record_tcp_retransmit(2);
        router.add_route(r1);

        let snap = router.balancing_snapshot(0);

        // 1. Single node default quorum -> healthy
        let cfg1 = IsspClusterQuorumConfig::default();
        let st1 = cfg1.evaluate(&snap, 1);
        assert!(st1.is_ready);
        assert!(!st1.is_degraded);
        assert_eq!(st1.quorum_ratio, 1.0);
        assert!(st1.reason.contains("cluster quorum healthy"));

        // 2. 3-node cluster quorum, but only 1 node reachable -> degraded below 0.50 threshold
        let cfg2 = IsspClusterQuorumConfig::new(3, 1).with_quorum_threshold_ratio(0.51);
        let st2 = cfg2.evaluate(&snap, 1);
        assert!(!st2.is_ready);
        assert!(st2.is_degraded);
        assert!(st2.reason.contains("cluster quorum degraded"));

        // 3. 2 nodes reachable in 3-node cluster -> healthy quorum (2/3 = 0.667 >= 0.51)
        let st3 = cfg2.evaluate(&snap, 2);
        assert!(st3.is_ready);
        assert!(!st3.is_degraded);

        // 4. Subpath starvation: require 2 active paths but only 1 available -> degraded
        let cfg4 = IsspClusterQuorumConfig::new(1, 2);
        let st4 = cfg4.evaluate(&snap, 1);
        assert!(!st4.is_ready);
        assert!(st4.is_degraded);
        assert!(st4.reason.contains("subpath starvation"));

        // 5. Retransmission threshold: 2% retransmits, threshold set to 1% -> degraded
        let cfg5 = IsspClusterQuorumConfig::new(1, 1).with_max_retransmit_ratio(0.01);
        let st5 = cfg5.evaluate(&snap, 1);
        assert!(!st5.is_ready);
        assert!(st5.is_degraded);
        assert!(st5.reason.contains("excessive retransmissions"));

        // 6. JSON serialization check
        let json = st1.to_json();
        assert!(json.contains("\"status\": \"READY\""));
        assert!(json.contains("\"ready\": true"));
        assert!(json.contains("\"cluster_nodes\": 1"));
    }

    #[test]
    fn test_telemetry_http_handler_livez_and_readyz_probes() {
        use crate::session_sync::{
            IsspDynamicMultipathRouter, IsspMultipathRoute, IsspRoutingPolicy,
        };
        let mut router =
            IsspDynamicMultipathRouter::new(42, IsspRoutingPolicy::BandwidthAggregation);
        router.add_route(IsspMultipathRoute::new(1, 10, "eth0", 1, 100));
        let snap = router.balancing_snapshot(0);

        let handler = IsspTelemetryHttpHandler::new("test-svc");

        // GET /livez (plain text)
        let (code, ctype, body) = handler.handle_snapshot("/livez", "*/*", &snap);
        assert_eq!(code, 200);
        assert_eq!(ctype, "text/plain; charset=utf-8");
        assert_eq!(body, "OK\n");

        // GET /livez (JSON)
        let (code_j, ctype_j, body_j) =
            handler.handle_snapshot("/livez", "application/json", &snap);
        assert_eq!(code_j, 200);
        assert_eq!(ctype_j, "application/json");
        assert!(body_j.contains("\"status\": \"ALIVE\""));
        assert!(body_j.contains("\"node_id\": 42"));

        // GET /readyz (default single-node: healthy)
        let (code_r, _, body_r) = handler.handle_snapshot("/readyz", "*/*", &snap);
        assert_eq!(code_r, 200);
        assert!(body_r.starts_with("READY:"));

        // GET /readyz (cluster quorum degraded: requires 3 nodes with 1 present)
        let handler_degraded = handler.clone().with_quorum_config(
            IsspClusterQuorumConfig::new(3, 1).with_quorum_threshold_ratio(0.51),
        );
        let (code_d, _, body_d) = handler_degraded.handle_snapshot("/readyz", "*/*", &snap);
        assert_eq!(code_d, 503);
        assert!(body_d.starts_with("DEGRADED:"));

        // GET /readyz JSON when degraded
        let (code_dj, ctype_dj, body_dj) =
            handler_degraded.handle_snapshot("/readyz", "application/json", &snap);
        assert_eq!(code_dj, 503);
        assert_eq!(ctype_dj, "application/json");
        assert!(body_dj.contains("\"status\": \"DEGRADED\""));
        assert!(body_dj.contains("\"ready\": false"));
        assert!(body_dj.contains("\"degraded\": true"));
    }

    #[test]
    fn test_telemetry_server_livez_and_readyz_socket_probes() {
        use crate::session_sync::{IsspMultipathRoute, IsspRoutingPolicy, SessionRegistry};

        let reg = SessionRegistry::new(99);
        reg.set_multipath_routing_policy(IsspRoutingPolicy::BandwidthAggregation)
            .unwrap();
        reg.add_multipath_route(IsspMultipathRoute::new(1, 10, "eth0-wan", 1, 100))
            .unwrap();
        reg.register_peer(100).unwrap(); // Peer registered

        let server = IsspTelemetryServer::bind("127.0.0.1:0", "node-99", reg)
            .expect("bind telemetry server");
        let addr = server.local_addr().unwrap();

        let client = std::thread::spawn(move || {
            // 1. Check /livez
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(b"GET /livez HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            let mut resp = String::new();
            s.read_to_string(&mut resp).unwrap();
            assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(resp.contains("OK\n"));

            // 2. Check /readyz (healthy)
            let mut s2 = TcpStream::connect(addr).unwrap();
            s2.write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            let mut resp2 = String::new();
            s2.read_to_string(&mut resp2).unwrap();
            assert!(resp2.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(resp2.contains("READY:"));

            // 3. Check /readyz (JSON format)
            let mut s3 = TcpStream::connect(addr).unwrap();
            s3.write_all(
                b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\r\n",
            )
            .unwrap();
            let mut resp3 = String::new();
            s3.read_to_string(&mut resp3).unwrap();
            assert!(resp3.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(resp3.contains("\"status\": \"READY\""));
        });

        for _ in 0..3 {
            let (stream, _) = server.listener.accept().unwrap();
            server.serve_one_connection(stream).unwrap();
        }

        client.join().unwrap();

        // Now configure degraded quorum requiring 5 nodes (only 2 present: 99 and 100)
        server.set_quorum_config(
            IsspClusterQuorumConfig::new(5, 1).with_quorum_threshold_ratio(0.60),
        );

        let client_deg = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            let mut resp = String::new();
            s.read_to_string(&mut resp).unwrap();
            assert!(resp.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
            assert!(resp.contains("DEGRADED:"));
        });

        let (stream, _) = server.listener.accept().unwrap();
        server.serve_one_connection(stream).unwrap();
        client_deg.join().unwrap();
    }

    #[test]
    fn test_mini_json_parser_primitives_and_objects() {
        let raw = r#"{
            "status": "firing",
            "version": "4",
            "count": 42.5,
            "active": true,
            "data": null,
            "items": ["eth0", "wwan0"],
            "meta": {"sub": "test"}
        }"#;

        let val = MiniJsonValue::parse(raw).expect("parse valid JSON");
        assert_eq!(val.get("status").and_then(|v| v.as_str()), Some("firing"));
        assert_eq!(val.get("version").and_then(|v| v.as_str()), Some("4"));
        assert_eq!(val.get("count").and_then(|v| v.as_f64()), Some(42.5));
        assert_eq!(val.get("active").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(val.get("data"), Some(&MiniJsonValue::Null));

        let items = val.get("items").and_then(|v| v.as_array()).expect("array");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].as_str(), Some("eth0"));
        assert_eq!(items[1].as_str(), Some("wwan0"));

        let meta = val.get("meta").expect("meta object");
        assert_eq!(meta.get("sub").and_then(|v| v.as_str()), Some("test"));
    }

    #[test]
    fn test_alertmanager_webhook_payload_parsing() {
        let payload_json = r#"{
            "version": "4",
            "status": "firing",
            "receiver": "ifa-webhook",
            "commonLabels": {
                "instance": "node-1"
            },
            "alerts": [
                {
                    "status": "firing",
                    "labels": {
                        "alertname": "IfaIsspHighJitterSurge",
                        "interface": "eth0-wan",
                        "severity": "warning"
                    },
                    "annotations": {
                        "summary": "High jitter surge detected on eth0-wan"
                    }
                },
                {
                    "status": "firing",
                    "labels": {
                        "alertname": "IfaIsspRetransmissionSpike",
                        "interface": "eth0-wan",
                        "severity": "critical"
                    },
                    "annotations": {
                        "summary": "Retransmission spike on eth0-wan"
                    }
                }
            ]
        }"#;

        let payload = AlertmanagerWebhookPayload::parse_json(payload_json).unwrap();
        assert_eq!(payload.version.as_deref(), Some("4"));
        assert_eq!(payload.status, "firing");
        assert_eq!(payload.receiver.as_deref(), Some("ifa-webhook"));
        assert_eq!(payload.alerts.len(), 2);

        let a1 = &payload.alerts[0];
        assert_eq!(a1.alertname, "IfaIsspHighJitterSurge");
        assert_eq!(a1.interface, "eth0-wan");
        assert_eq!(a1.severity, "warning");
        assert_eq!(
            a1.labels.get("instance").map(|s| s.as_str()),
            Some("node-1")
        );

        let a2 = &payload.alerts[1];
        assert_eq!(a2.alertname, "IfaIsspRetransmissionSpike");
        assert_eq!(a2.interface, "eth0-wan");
        assert_eq!(a2.severity, "critical");

        let policy = AlertFailoverPolicy::default();
        let (action1, reason1) = policy.classify_alert(a1);
        assert_eq!(
            action1,
            crate::session_sync::FailoverAction::SwitchToStandby
        );
        assert_eq!(
            reason1,
            crate::session_sync::IsspFailoverReason::AlertmanagerJitterSurge
        );

        let (action2, reason2) = policy.classify_alert(a2);
        assert_eq!(
            action2,
            crate::session_sync::FailoverAction::SwitchToStandby
        );
        assert_eq!(
            reason2,
            crate::session_sync::IsspFailoverReason::AlertmanagerRetransmissionSpike
        );
    }

    #[test]
    fn test_telemetry_server_alertmanager_webhook_jitter_failover_and_restore() {
        use crate::session_sync::{
            IsspMultipathRoute, IsspPathState, IsspRoutingPolicy, SessionId, SessionRegistry,
        };

        let reg = SessionRegistry::new(42);
        reg.set_multipath_routing_policy(IsspRoutingPolicy::ActiveStandby)
            .unwrap();

        // Route 1 on eth0-wan (Active, Priority 1)
        let r1 =
            IsspMultipathRoute::new(1, 10, "eth0-wan", 1, 100).with_state(IsspPathState::Active);
        reg.add_multipath_route(r1).unwrap();

        // Route 2 on wwan0-5g (Standby backup, Priority 2)
        let r2 =
            IsspMultipathRoute::new(2, 10, "wwan0-5g", 2, 50).with_state(IsspPathState::Standby);
        reg.add_multipath_route(r2).unwrap();

        // Bind a session to path 1
        let s_id = SessionId::new(0x1122334455667788, 42, 1);
        let resolved = reg.resolve_session_path(&s_id, 1000).unwrap();
        assert_eq!(resolved, 1);

        let server = IsspTelemetryServer::bind("127.0.0.1:0", "node-42", reg.clone()).unwrap();
        let addr = server.local_addr().unwrap();

        let client = std::thread::spawn(move || {
            // 1. Post Alertmanager firing webhook for High Jitter on eth0-wan
            let webhook_body = r#"{
                "version": "4",
                "status": "firing",
                "receiver": "ifa-webhook",
                "alerts": [
                    {
                        "status": "firing",
                        "labels": {
                            "alertname": "IfaIsspHighJitterSurge",
                            "interface": "eth0-wan",
                            "severity": "warning"
                        },
                        "annotations": {
                            "summary": "Jitter spike > 15ms"
                        }
                    }
                ]
            }"#;

            let mut s = TcpStream::connect(addr).unwrap();
            let req = format!(
                "POST /webhook/alerts HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                webhook_body.len(),
                webhook_body
            );
            s.write_all(req.as_bytes()).unwrap();
            let mut resp = String::new();
            s.read_to_string(&mut resp).unwrap();

            assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(resp.contains("\"status\": \"success\""));
            assert!(resp.contains("\"failovers_applied\": 1"));
            assert!(resp.contains("\"total_sessions_rerouted\": 1"));
            assert!(resp.contains("\"action\": \"SwitchToStandby\""));
            assert!(resp.contains("\"reason\": \"AlertmanagerJitterSurge\""));

            // 2. Query failover audit history GET /api/v1/failovers
            let mut s_hist = TcpStream::connect(addr).unwrap();
            s_hist
                .write_all(b"GET /api/v1/failovers HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            let mut resp_hist = String::new();
            s_hist.read_to_string(&mut resp_hist).unwrap();
            assert!(resp_hist.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(resp_hist.contains("\"failed_path_id\": 1"));
            assert!(resp_hist.contains("\"target_path_id\": 2"));
            assert!(resp_hist.contains("\"reason\": \"AlertmanagerJitterSurge\""));

            // 3. Post resolved webhook for eth0-wan
            let resolved_body = r#"{
                "version": "4",
                "status": "resolved",
                "receiver": "ifa-webhook",
                "alerts": [
                    {
                        "status": "resolved",
                        "labels": {
                            "alertname": "IfaIsspHighJitterSurge",
                            "interface": "eth0-wan"
                        }
                    }
                ]
            }"#;

            let mut s_res = TcpStream::connect(addr).unwrap();
            let req_res = format!(
                "POST /webhook/alerts HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                resolved_body.len(),
                resolved_body
            );
            s_res.write_all(req_res.as_bytes()).unwrap();
            let mut resp_res = String::new();
            s_res.read_to_string(&mut resp_res).unwrap();
            assert!(resp_res.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(resp_res.contains("\"restores_applied\": 1"));
            assert!(resp_res.contains("\"action\": \"RestoredActive\""));
        });

        // Serve the 3 client connections
        for _ in 0..3 {
            let (stream, _) = server.listener.accept().unwrap();
            server.serve_one_connection(stream).unwrap();
        }

        client.join().unwrap();

        // Verify registry post-failover and restore state
        let routes = reg.list_multipath_routes().unwrap();
        let r1_state = routes.iter().find(|r| r.path_id == 1).unwrap().state;
        assert_eq!(r1_state, IsspPathState::Active); // Restored back to Active
    }

    #[test]
    fn test_telemetry_server_retransmission_spike_failover() {
        use crate::session_sync::{
            IsspMultipathRoute, IsspPathState, IsspRoutingPolicy, SessionId, SessionRegistry,
        };

        let reg = SessionRegistry::new(88);
        reg.set_multipath_routing_policy(IsspRoutingPolicy::ActiveStandby)
            .unwrap();
        reg.add_multipath_route(
            IsspMultipathRoute::new(10, 1, "eth0-primary", 1, 100)
                .with_state(IsspPathState::Active),
        )
        .unwrap();
        reg.add_multipath_route(
            IsspMultipathRoute::new(20, 1, "wwan0-secondary", 2, 50)
                .with_state(IsspPathState::Standby),
        )
        .unwrap();

        let s1 = SessionId::new(0xabcdef, 88, 1);
        let s2 = SessionId::new(0xabcdef, 88, 2);
        assert_eq!(reg.resolve_session_path(&s1, 100).unwrap(), 10);
        assert_eq!(reg.resolve_session_path(&s2, 100).unwrap(), 10);

        let server = IsspTelemetryServer::bind("127.0.0.1:0", "node-88", reg.clone()).unwrap();
        let addr = server.local_addr().unwrap();

        let client = std::thread::spawn(move || {
            let webhook_body = r#"{
                "version": "4",
                "status": "firing",
                "receiver": "ifa-webhook",
                "alerts": [
                    {
                        "status": "firing",
                        "labels": {
                            "alertname": "IfaIsspRetransmissionSpike",
                            "interface": "eth0-primary",
                            "severity": "critical"
                        },
                        "annotations": {
                            "summary": "Retransmissions > 5%"
                        }
                    }
                ]
            }"#;

            let mut s = TcpStream::connect(addr).unwrap();
            let req = format!(
                "POST /alerts HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                webhook_body.len(),
                webhook_body
            );
            s.write_all(req.as_bytes()).unwrap();
            let mut resp = String::new();
            s.read_to_string(&mut resp).unwrap();

            assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(resp.contains("\"failovers_applied\": 1"));
            assert!(resp.contains("\"total_sessions_rerouted\": 2"));
            assert!(resp.contains("\"reason\": \"AlertmanagerRetransmissionSpike\""));
        });

        let (stream, _) = server.listener.accept().unwrap();
        server.serve_one_connection(stream).unwrap();
        client.join().unwrap();

        // Confirm sessions are now routed to path 20
        assert_eq!(reg.resolve_session_path(&s1, 200).unwrap(), 20);
        assert_eq!(reg.resolve_session_path(&s2, 200).unwrap(), 20);
    }

    #[test]
    fn test_protobuf_writer_primitives_and_varint() {
        let mut pw = ProtobufWriter::new();
        pw.write_uint64(1, 150);
        pw.write_string(2, "testing");
        pw.write_double(3, 42.5);
        pw.write_packed_fixed64(4, &[10, 20, 30]);

        let bytes = pw.into_inner();
        assert!(!bytes.is_empty());

        // Field 1: tag (1 << 3) | 0 = 8. Varint 150 -> 0x96, 0x01
        assert_eq!(bytes[0], 0x08);
        assert_eq!(bytes[1], 0x96);
        assert_eq!(bytes[2], 0x01);

        // Field 2: tag (2 << 3) | 2 = 18. Length 7, "testing"
        assert_eq!(bytes[3], 0x12);
        assert_eq!(bytes[4], 7);
        assert_eq!(&bytes[5..12], b"testing");
    }

    #[test]
    fn test_otlp_protobuf_exporter_and_grpc_frame() {
        let mut router = IsspDynamicMultipathRouter::new(42, IsspRoutingPolicy::LowestLatency);
        let mut r1 = IsspMultipathRoute::new(1, 2, "wan0", 1, 80);
        r1.metrics.smoothed_rtt_us = 12_000;
        router.add_route(r1);

        let snap = router.balancing_snapshot(1_700_000_000_000_000_000);
        let exporter = OtelProtobufMultipathExporter::new().with_attribute("env", "staging");

        let proto = exporter.export(&snap, "ifa-multipath-service");
        assert!(!proto.is_empty());

        // Frame as gRPC
        let frame = GrpcFrame::encode(&proto);
        assert_eq!(frame.len(), 5 + proto.len());
        assert_eq!(frame[0], 0x00); // uncompressed
        let frame_len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
        assert_eq!(frame_len, proto.len());

        let (is_comp, payload) = GrpcFrame::decode(&frame).unwrap();
        assert!(!is_comp);
        assert_eq!(payload, &proto[..]);

        // Test error conditions on decode
        assert_eq!(
            GrpcFrame::decode(&[0, 0, 0]),
            Err(GrpcFrameError::IncompleteHeader)
        );
        assert!(matches!(
            GrpcFrame::decode(&[0, 0, 0, 0, 10, 1, 2]),
            Err(GrpcFrameError::IncompleteBody {
                expected: 15,
                found: 7
            })
        ));
    }

    #[test]
    fn test_issp_telemetry_http_handler_binary_protobuf_endpoint() {
        let router = IsspDynamicMultipathRouter::new(10, IsspRoutingPolicy::LowestLatency);
        let snap = router.balancing_snapshot(1_700_000_000_000_000_000);
        let handler = IsspTelemetryHttpHandler::new("ifa-gateway");

        let (code, ctype, bytes) =
            handler.handle_snapshot_binary("/v1/metrics", "application/x-protobuf", &snap);
        assert_eq!(code, 200);
        assert_eq!(ctype, "application/x-protobuf");
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_issp_telemetry_http_handler_zstd_traces_archive() {
        let router = IsspDynamicMultipathRouter::new(10, IsspRoutingPolicy::LowestLatency);
        let snap = router.balancing_snapshot(1_700_000_000_000_000_000);
        let handler = IsspTelemetryHttpHandler::new("ifa-gateway");

        // 1. Binary Zstandard archive export
        let (code, ctype, bytes) =
            handler.handle_snapshot_binary("/api/traces/archive", "application/zstd", &snap);
        assert_eq!(code, 200);
        assert_eq!(ctype, "application/zstd");
        assert!(!bytes.is_empty());

        // Decompress raw stream
        let raw = crate::zstd_archive::decode_zstd_stream(&bytes).unwrap();
        assert!(!raw.is_empty());

        // 2. JSON route discovery
        let (code_json, ctype_json, json_body) = handler.handle_snapshot_with_quorum(
            "/api/traces/archive",
            "application/json",
            &snap,
            1,
        );
        assert_eq!(code_json, 200);
        assert_eq!(ctype_json, "application/json");
        assert!(json_body.contains("\"subpaths_tracked\""));
        assert!(json_body.contains("\"format\":\"zstd\""));
    }

    #[test]
    fn test_issp_telemetry_server_grpc_real_tcp_export() {
        use crate::session_sync::SessionRegistry;

        let reg = SessionRegistry::new(55);
        let server = IsspTelemetryServer::bind("127.0.0.1:0", "ifa-grpc-node", reg).unwrap();
        let addr = server.local_addr().unwrap();

        let router = IsspDynamicMultipathRouter::new(55, IsspRoutingPolicy::BandwidthAggregation);
        let snap = router.balancing_snapshot(1_700_000_000_000_000_000);

        let client = std::thread::spawn(move || {
            let exporter = OtelMultipathBalancingGrpcExporter::new(&addr.to_string())
                .with_timeout(Duration::from_secs(2));
            let res = exporter.export_to_endpoint(&snap, "ifa-grpc-node").unwrap();
            assert_eq!(res.status_code, 0);
            assert_eq!(res.status_message, "OK");
            assert!(res.bytes_sent > 0);
            assert!(res.bytes_received > 0);
        });

        let (stream, _) = server.listener.accept().unwrap();
        let (code, path) = server.serve_one_connection(stream).unwrap();
        assert_eq!(code, 200);
        assert!(path.contains("MetricsService/Export"));
        client.join().unwrap();
    }

    #[test]
    fn test_issp_telemetry_server_http1_grpc_and_protobuf_export() {
        use crate::session_sync::SessionRegistry;

        let reg = SessionRegistry::new(77);
        let server = IsspTelemetryServer::bind("127.0.0.1:0", "ifa-http-grpc", reg).unwrap();
        let addr = server.local_addr().unwrap();

        // 1. Test HTTP/1.1 gRPC POST
        let client1 = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            let grpc_body = [0u8, 0, 0, 0, 2, 0x08, 0x01];
            let req = format!(
                "POST /opentelemetry.proto.collector.metrics.v1.MetricsService/Export HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/grpc\r\nContent-Length: {}\r\n\r\n",
                grpc_body.len()
            );
            s.write_all(req.as_bytes()).unwrap();
            s.write_all(&grpc_body).unwrap();
            s.flush().unwrap();

            let mut resp = Vec::new();
            s.read_to_end(&mut resp).unwrap();
            let resp_str = String::from_utf8_lossy(&resp);
            assert!(resp_str.contains("HTTP/1.1 200 OK"));
            assert!(resp_str.contains("Content-Type: application/grpc"));
            assert!(resp_str.contains("grpc-status: 0"));
        });

        let (stream1, _) = server.listener.accept().unwrap();
        server.serve_one_connection(stream1).unwrap();
        client1.join().unwrap();

        // 2. Test HTTP/1.1 GET /v1/metrics with Accept: application/x-protobuf
        let client2 = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            let req = "GET /v1/metrics HTTP/1.1\r\nHost: localhost\r\nAccept: application/x-protobuf\r\n\r\n";
            s.write_all(req.as_bytes()).unwrap();
            s.flush().unwrap();

            let mut resp = Vec::new();
            s.read_to_end(&mut resp).unwrap();
            let resp_str = String::from_utf8_lossy(&resp);
            assert!(resp_str.contains("HTTP/1.1 200 OK"));
            assert!(resp_str.contains("Content-Type: application/x-protobuf"));
        });

        let (stream2, _) = server.listener.accept().unwrap();
        server.serve_one_connection(stream2).unwrap();
        client2.join().unwrap();
    }

    #[test]
    fn test_issp_mesh_node_and_link_models() {
        let node = IsspMeshNodeInfo::new(1, "ifa-gw-1", "gateway", "10.0.1.1:9090")
            .with_sessions(120, 3)
            .with_throughput(50_000_000.0, 48_000_000.0)
            .with_quality(0.85, 0.001, 0.0)
            .with_health(true, "healthy");

        assert_eq!(node.node_id, 1);
        assert_eq!(node.total_sessions, 120);
        assert_eq!(node.active_paths, 3);
        assert!(node.is_healthy);

        let node_json = node.to_json();
        let parsed_node = MiniJsonValue::parse(&node_json).unwrap();
        assert_eq!(parsed_node.get("node_id").unwrap().as_f64(), Some(1.0));
        assert_eq!(
            parsed_node.get("node_name").unwrap().as_str(),
            Some("ifa-gw-1")
        );

        let link = IsspMeshLinkInfo::new(1, 2, "eth0")
            .with_latency(0.45, 0.05)
            .with_loss(0.0001, 0.0001)
            .with_throughput(25_000_000.0, 24_000_000.0)
            .with_weight(100)
            .with_status("optimal", false);

        assert_eq!(link.source_node_id, 1);
        assert_eq!(link.target_node_id, 2);
        assert_eq!(link.interface_name, "eth0");
        assert!(!link.is_bottleneck);

        let link_json = link.to_json();
        let parsed_link = MiniJsonValue::parse(&link_json).unwrap();
        assert_eq!(
            parsed_link.get("source_node_id").unwrap().as_f64(),
            Some(1.0)
        );
        assert_eq!(
            parsed_link.get("target_node_id").unwrap().as_f64(),
            Some(2.0)
        );
    }

    #[test]
    fn test_issp_mesh_synthesizer_multi_node_aggregation_and_density() {
        let mut synth =
            IsspMultiNodeMeshSynthesizer::new("ifa-test-mesh").with_heartbeat_timeout_seconds(10);

        let now_ns = 1_700_000_000_000_000_000;

        let mut n1 = IsspMeshNodeInfo::new(1, "node-1", "gateway", "10.0.0.1:9090")
            .with_sessions(500, 2)
            .with_throughput(10_000_000.0, 8_000_000.0)
            .with_quality(1.2, 0.0, 0.0);
        n1.last_heartbeat_unix_ns = now_ns;

        let mut n2 = IsspMeshNodeInfo::new(2, "node-2", "relay", "10.0.0.2:9090")
            .with_sessions(300, 2)
            .with_throughput(8_000_000.0, 7_000_000.0)
            .with_quality(1.4, 0.0, 0.0);
        n2.last_heartbeat_unix_ns = now_ns;

        let mut n3 = IsspMeshNodeInfo::new(3, "node-3", "worker", "10.0.0.3:9090")
            .with_sessions(200, 2)
            .with_throughput(5_000_000.0, 4_000_000.0)
            .with_quality(1.5, 0.0, 0.0);
        n3.last_heartbeat_unix_ns = now_ns;

        synth.register_or_update_node(n1);
        synth.register_or_update_node(n2);
        synth.register_or_update_node(n3);

        // Add 6 links (full mesh among 3 nodes)
        synth.register_or_update_link(
            IsspMeshLinkInfo::new(1, 2, "eth0")
                .with_latency(1.0, 0.1)
                .with_status("optimal", false),
        );
        synth.register_or_update_link(
            IsspMeshLinkInfo::new(2, 1, "eth0")
                .with_latency(1.0, 0.1)
                .with_status("optimal", false),
        );
        synth.register_or_update_link(
            IsspMeshLinkInfo::new(1, 3, "eth1")
                .with_latency(2.0, 0.2)
                .with_status("optimal", false),
        );
        synth.register_or_update_link(
            IsspMeshLinkInfo::new(3, 1, "eth1")
                .with_latency(2.0, 0.2)
                .with_status("optimal", false),
        );
        synth.register_or_update_link(
            IsspMeshLinkInfo::new(2, 3, "eth0")
                .with_latency(1.5, 0.1)
                .with_status("optimal", false),
        );
        synth.register_or_update_link(
            IsspMeshLinkInfo::new(3, 2, "eth0")
                .with_latency(5.5, 0.8) // High latency bottleneck
                .with_loss(0.08, 0.08) // High loss
                .with_status("congested", true),
        );

        let snap = synth.synthesize(now_ns);
        assert_eq!(snap.total_nodes, 3);
        assert_eq!(snap.healthy_nodes, 3);
        assert_eq!(snap.total_links, 6);
        assert_eq!(snap.active_links, 5); // 5 optimal, 1 congested
        assert_eq!(snap.cluster_total_sessions, 1000);
        assert_eq!(snap.mesh_density_ratio, 5.0 / 6.0);
        assert!(snap.cluster_health_score > 0.7);
        assert!(snap
            .bottlenecks
            .iter()
            .any(|b| b.contains("node-3->node-2")));

        // Test heartbeat expiration on node 3
        let stale_now_ns = now_ns + 15_000_000_000; // 15s later
        let stale_snap = synth.synthesize(stale_now_ns);
        assert_eq!(stale_snap.total_nodes, 3);
        assert_eq!(stale_snap.healthy_nodes, 0); // all nodes expired
    }

    #[test]
    fn test_issp_mesh_grafana_and_prometheus_export() {
        let mut synth = IsspMultiNodeMeshSynthesizer::new("ifa-supervision-cluster");
        let now_ns = 1_700_000_000_000_000_000;

        let mut n1 = IsspMeshNodeInfo::new(1, "ifa-gw-eu", "gateway", "10.0.1.1:9090")
            .with_sessions(450, 2)
            .with_throughput(35_000_000.0, 30_000_000.0)
            .with_quality(0.95, 0.0, 0.0);
        n1.last_heartbeat_unix_ns = now_ns;

        let mut n2 = IsspMeshNodeInfo::new(2, "ifa-edge-eu", "worker", "10.0.1.2:9090")
            .with_sessions(250, 1)
            .with_throughput(20_000_000.0, 18_000_000.0)
            .with_quality(1.10, 0.0, 0.0);
        n2.last_heartbeat_unix_ns = now_ns;

        synth.register_or_update_node(n1);
        synth.register_or_update_node(n2);
        synth.register_or_update_link(
            IsspMeshLinkInfo::new(1, 2, "eth0-wan")
                .with_latency(0.85, 0.05)
                .with_throughput(15_000_000.0, 14_000_000.0)
                .with_status("optimal", false),
        );

        let snap = synth.synthesize(now_ns);

        // 1. Grafana Node Graph Panel JSON verification
        let node_graph_json = snap.to_grafana_node_graph_json();
        let parsed_ng = MiniJsonValue::parse(&node_graph_json).unwrap();
        assert!(parsed_ng.get("nodes").is_some());
        assert!(parsed_ng.get("edges").is_some());
        assert_eq!(parsed_ng.get("nodes").unwrap().as_array().unwrap().len(), 2);
        assert_eq!(parsed_ng.get("edges").unwrap().as_array().unwrap().len(), 1);

        // 2. Grafana Supervisor Summary JSON verification
        let summary_json = snap.to_grafana_topology_summary_json();
        let parsed_summary = MiniJsonValue::parse(&summary_json).unwrap();
        assert_eq!(
            parsed_summary.get("cluster_id").unwrap().as_str(),
            Some("ifa-supervision-cluster")
        );
        assert_eq!(
            parsed_summary.get("total_nodes").unwrap().as_f64(),
            Some(2.0)
        );
        assert_eq!(
            parsed_summary
                .get("cluster_total_sessions")
                .unwrap()
                .as_f64(),
            Some(700.0)
        );

        // 3. Prometheus Mesh Exposition text verification
        let prom = snap.to_prometheus_mesh_exposition();
        assert!(
            prom.contains("ifa_mesh_cluster_nodes_total{cluster=\"ifa-supervision-cluster\"} 2")
        );
        assert!(prom
            .contains("ifa_mesh_cluster_sessions_total{cluster=\"ifa-supervision-cluster\"} 700"));
        assert!(
            prom.contains("ifa_mesh_node_status{cluster=\"ifa-supervision-cluster\",node_id=\"1\"")
        );
        assert!(prom.contains("ifa_mesh_link_latency_ms{cluster=\"ifa-supervision-cluster\",source=\"1\",target=\"2\",interface=\"eth0-wan\"} 0.850000"));
    }

    #[test]
    fn test_issp_mesh_report_json_ingestion() {
        let mut synth = IsspMultiNodeMeshSynthesizer::new("ifa-cluster");
        let now_ns = 1_700_000_000_000_000_000;

        let report_json = r#"{
            "cluster_id": "ifa-ingest-test",
            "node": {
                "node_id": 42,
                "node_name": "ifa-relay-42",
                "role": "relay",
                "endpoint": "192.168.1.42:9090",
                "active_paths": 2,
                "total_sessions": 180,
                "tx_bytes_per_sec": 12000000.0,
                "rx_bytes_per_sec": 11000000.0,
                "avg_latency_ms": 0.75,
                "tcp_retrans_ratio": 0.0005,
                "issp_retrans_ratio": 0.0,
                "is_healthy": true
            },
            "links": [
                {
                    "source_node_id": 42,
                    "target_node_id": 1,
                    "interface_name": "eth0",
                    "latency_ms": 0.65,
                    "jitter_ms": 0.04,
                    "loss_ratio": 0.0,
                    "retransmit_rate": 0.0,
                    "tx_bytes_per_sec": 6000000.0,
                    "rx_bytes_per_sec": 5500000.0,
                    "weight": 100,
                    "status": "optimal"
                }
            ]
        }"#;

        synth.ingest_mesh_report_json(report_json, now_ns).unwrap();
        assert_eq!(synth.cluster_id, "ifa-ingest-test");
        assert_eq!(synth.nodes.len(), 1);
        assert_eq!(synth.links.len(), 1);

        let snap = synth.synthesize(now_ns);
        let n = snap.find_node(42).unwrap();
        assert_eq!(n.node_name, "ifa-relay-42");
        assert_eq!(n.role, "relay");
        assert_eq!(n.total_sessions, 180);

        let l = snap.find_link(42, 1, "eth0").unwrap();
        assert_eq!(l.latency_ms, 0.65);
        assert_eq!(l.status, "optimal");
    }

    #[test]
    fn test_issp_telemetry_http_handler_mesh_routes() {
        use crate::session_sync::{IsspDynamicMultipathRouter, IsspRoutingPolicy};

        let router = IsspDynamicMultipathRouter::new(10, IsspRoutingPolicy::BandwidthAggregation);
        let snap = router.balancing_snapshot(1_700_000_000_000_000_000);
        let handler = IsspTelemetryHttpHandler::new("ifa-gateway");

        // 1. /api/mesh/topology (Grafana Node Graph)
        let (code, ctype, body) =
            handler.handle_snapshot_with_quorum("/api/mesh/topology", "application/json", &snap, 2);
        assert_eq!(code, 200);
        assert_eq!(ctype, "application/json");
        assert!(body.contains("\"nodes\":"));
        assert!(body.contains("\"edges\":"));

        // 2. /api/mesh/summary (Grafana Supervisor Summary)
        let (code, ctype, body) =
            handler.handle_snapshot_with_quorum("/api/mesh/summary", "application/json", &snap, 2);
        assert_eq!(code, 200);
        assert_eq!(ctype, "application/json");
        assert!(body.contains("\"total_nodes\":"));
        assert!(body.contains("\"mesh_density_ratio\":"));

        // 3. /api/mesh/metrics (Prometheus Mesh Exposition)
        let (code, ctype, body) =
            handler.handle_snapshot_with_quorum("/api/mesh/metrics", "*/*", &snap, 2);
        assert_eq!(code, 200);
        assert_eq!(ctype, "text/plain; version=0.0.4; charset=utf-8");
        assert!(body.contains("ifa_mesh_cluster_nodes_total"));

        // 4. /metrics?format=mesh
        let (code, ctype, body) =
            handler.handle_snapshot_with_quorum("/metrics?format=mesh", "*/*", &snap, 2);
        assert_eq!(code, 200);
        assert_eq!(ctype, "text/plain; version=0.0.4; charset=utf-8");
        assert!(body.contains("ifa_mesh_cluster_nodes_total"));
    }

    #[test]
    fn test_issp_telemetry_server_real_tcp_mesh_endpoints() {
        use crate::session_sync::SessionRegistry;

        let reg = SessionRegistry::new(99);
        reg.register_peer(101).unwrap();
        let server = IsspTelemetryServer::bind("127.0.0.1:0", "ifa-mesh-srv", reg).unwrap();
        let addr = server.local_addr().unwrap();

        // 1. Client POST /v1/mesh/report
        let client1 = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            let body = r#"{"cluster_id":"ifa-mesh-srv","node":{"node_id":101,"node_name":"peer-101","role":"relay","endpoint":"10.0.0.101:9090","active_paths":1,"total_sessions":75,"tx_bytes_per_sec":5000000.0,"rx_bytes_per_sec":4000000.0,"avg_latency_ms":1.1,"is_healthy":true}}"#;
            let req = format!(
                "POST /v1/mesh/report HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            s.write_all(req.as_bytes()).unwrap();
            s.flush().unwrap();

            let mut resp = Vec::new();
            s.read_to_end(&mut resp).unwrap();
            let resp_str = String::from_utf8_lossy(&resp);
            assert!(resp_str.contains("HTTP/1.1 200 OK"));
            assert!(resp_str.contains("\"status\": \"acknowledged\""));
        });

        let (stream1, _) = server.listener.accept().unwrap();
        server.serve_one_connection(stream1).unwrap();
        client1.join().unwrap();

        // 2. Client GET /api/mesh/topology
        let client2 = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            let req = "GET /api/mesh/topology HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\r\n";
            s.write_all(req.as_bytes()).unwrap();
            s.flush().unwrap();

            let mut resp = Vec::new();
            s.read_to_end(&mut resp).unwrap();
            let resp_str = String::from_utf8_lossy(&resp);
            assert!(resp_str.contains("HTTP/1.1 200 OK"));
            assert!(resp_str.contains("application/json"));
            assert!(resp_str.contains("\"nodes\":"));
            assert!(resp_str.contains("\"edges\":"));
        });

        let (stream2, _) = server.listener.accept().unwrap();
        server.serve_one_connection(stream2).unwrap();
        client2.join().unwrap();

        // 3. Client GET /api/mesh/metrics
        let client3 = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            let req = "GET /api/mesh/metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
            s.write_all(req.as_bytes()).unwrap();
            s.flush().unwrap();

            let mut resp = Vec::new();
            s.read_to_end(&mut resp).unwrap();
            let resp_str = String::from_utf8_lossy(&resp);
            assert!(resp_str.contains("HTTP/1.1 200 OK"));
            assert!(resp_str.contains("ifa_mesh_cluster_nodes_total"));
        });

        let (stream3, _) = server.listener.accept().unwrap();
        server.serve_one_connection(stream3).unwrap();
        client3.join().unwrap();
    }
}

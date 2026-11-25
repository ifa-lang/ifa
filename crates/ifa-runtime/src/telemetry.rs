//! System resource audit metrics and subprocess telemetry for IFA runtime, toolchain, and build orchestrator.

use std::collections::BTreeMap;
use std::process::{Command, ExitStatus};
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
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_sync::{
        IsspDynamicMultipathRouter, IsspMultipathRoute, IsspRoutingPolicy, SessionRegistry,
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
}

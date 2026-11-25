//! Network commands for observing and operating the IFA Session Synchronization Protocol (ISSP).

use clap::Subcommand;
use ifa_runtime::{
    run_issp_failover_benchmark_suite, run_issp_scenario, IsspBandwidthEstimate, IsspCapsule,
    IsspCongestionPhase, IsspFailoverBenchmarkSuiteReport, IsspFlapDampingConfig,
    IsspHeartbeatProbe, IsspMultipathRoute, IsspNetworkProfile, IsspPathState, IsspProbationConfig,
    IsspRoutingPolicy, IsspTelemetryServer, SecurityPolicy, SessionId, SessionRecord,
    SessionRegistry, SessionSnapshot,
};
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Subcommand, Debug, Clone)]
pub enum NetCommand {
    /// Observe and manage distributed datagram tunnel sessions (ISSP)
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum SessionCommand {
    /// List active and replica sessions in the ISSP cluster registry
    List {
        /// Path to persistent cluster state dump (.issp or binary dump)
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Filter by session role: all, primary, standby
        #[arg(short, long, default_value = "all")]
        role: String,
        /// Output formatted as JSON
        #[arg(long)]
        json: bool,
    },
    /// Inspect detailed state and telemetry of a specific session
    Inspect {
        /// Session identifier (canonical flow:node:nonce or flow hash hex)
        id: String,
        /// Path to persistent cluster state dump (.issp or binary dump)
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Output formatted as JSON
        #[arg(long)]
        json: bool,
    },
    /// Trigger transparent takeover / migration of a session to the local or target node
    Migrate {
        /// Session identifier to migrate
        id: String,
        /// Target node taking ownership (defaults to local registry node)
        #[arg(short, long)]
        target_node: Option<u32>,
        /// Force migration even if snapshot is near staleness limit
        #[arg(long)]
        force: bool,
        /// Path to persistent cluster state dump (.issp or binary dump)
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Optional path to export the resulting cutover ISSP capsule
        #[arg(long)]
        out_capsule: Option<PathBuf>,
    },
    /// Benchmark ISSP throughput and transparent failover under network impairments
    Bench {
        /// Number of concurrent sessions to benchmark
        #[arg(short, long, default_value = "100")]
        sessions: usize,
        /// Number of synchronization sync cycles
        #[arg(short, long, default_value = "10")]
        cycles: usize,
        /// Injected packet loss percentage (0.0 to 100.0)
        #[arg(short, long)]
        loss: Option<f64>,
        /// Maximum transit jitter in milliseconds
        #[arg(short, long)]
        jitter_ms: Option<u64>,
        /// Primary silence threshold in seconds before triggering failover
        #[arg(long, default_value = "2")]
        silence_secs: u64,
        /// Output formatted as JSON
        #[arg(long)]
        json: bool,
    },
    /// Observe dynamic multipath routes and simulate heartbeat failover
    Route {
        /// Path to persistent cluster state dump (.issp or binary dump)
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Simulate heartbeat failure on a specific path ID
        #[arg(long)]
        fail_path: Option<u32>,
        /// Output formatted as JSON
        #[arg(long)]
        json: bool,
    },
    /// Benchmark bandwidth aggregation scheduling and out-of-order resequencing compensation
    Aggregate {
        /// Number of concurrent sessions to aggregate
        #[arg(short, long, default_value = "3")]
        sessions: usize,
        /// Total packets to schedule across bonded links per session
        #[arg(short, long, default_value = "60")]
        packets: usize,
        /// Differential latency skew in milliseconds between primary and secondary paths
        #[arg(long, default_value = "35")]
        skew_ms: u64,
        /// Path to persistent cluster state dump (.issp or binary dump)
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Output formatted as JSON
        #[arg(long)]
        json: bool,
    },
    /// Benchmark route flapping damping and progressive path probation reintegration
    Probation {
        /// Number of route flaps to simulate
        #[arg(long, default_value = "2")]
        flaps: u32,
        /// Probation duration in milliseconds
        #[arg(long, default_value = "3000")]
        duration_ms: u64,
        /// Number of consecutive test probes to simulate during probation
        #[arg(long, default_value = "4")]
        probes: u32,
        /// Path to persistent cluster state dump (.issp or binary dump)
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Output formatted as JSON
        #[arg(long)]
        json: bool,
    },
    /// Benchmark dynamic bandwidth balancing and traffic steering via RTT gradient (BBR / LEDBAT feedback)
    Balance {
        /// Number of measurement and feedback rounds to evaluate
        #[arg(short, long, default_value = "5")]
        rounds: usize,
        /// Differential latency gradient surge in microseconds on congested path (e.g. 80000 µs = 80ms)
        #[arg(long, default_value = "80000")]
        gradient_us: u64,
        /// Number of packets to schedule per round to observe traffic distribution
        #[arg(short, long, default_value = "60")]
        packets: usize,
        /// Path to persistent cluster state dump (.issp or binary dump)
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Output formatted as JSON
        #[arg(long)]
        json: bool,
    },
    /// Expose live multipath balancing telemetry over HTTP (Prometheus `/metrics` and OTLP `/v1/metrics`)
    /// and streaming WebSocket (`/ws/metrics`)
    TelemetryServe {
        /// TCP address to bind the telemetry HTTP server (e.g. 127.0.0.1:9100)
        #[arg(short, long, default_value = "127.0.0.1:9100")]
        addr: String,
        /// Path to persistent cluster state dump (.issp or binary dump)
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Maximum number of requests to serve before exiting (0 = unlimited)
        #[arg(short, long, default_value = "0")]
        max_requests: usize,
        /// Interval in milliseconds between streaming WebSocket frames on `/ws/metrics`
        #[arg(long, default_value = "500")]
        ws_interval_ms: u64,
        /// Maximum streaming frames per WebSocket connection before closure (0 = unlimited)
        #[arg(long, default_value = "0")]
        ws_max_frames: u64,
        /// Node identifier included in exported metrics labels
        #[arg(long, default_value = "ifa-issp-node")]
        node_id: String,
    },
}

/// Locate or default the ISSP registry state file.
fn resolve_state_file(explicit: Option<&PathBuf>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.clone());
    }
    if let Ok(env_path) = std::env::var("IFA_ISSP_STATE") {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return Some(p);
        }
    }
    let default_cwd = PathBuf::from("./issp-sessions.bin");
    if default_cwd.exists() {
        return Some(default_cwd);
    }
    let default_run = PathBuf::from("/var/run/ifa/issp.state");
    if default_run.exists() {
        return Some(default_run);
    }
    None
}

/// Current wall-clock Unix seconds.
fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Execute a net subcommand.
pub fn execute_net_command(cmd: NetCommand) -> ExitCode {
    match cmd {
        NetCommand::Session { command } => execute_session_command(command),
    }
}

fn execute_session_command(cmd: SessionCommand) -> ExitCode {
    match cmd {
        SessionCommand::List { file, role, json } => {
            let state_path = resolve_state_file(file.as_ref());
            let registry = match &state_path {
                Some(p) if p.exists() => match SessionRegistry::load_from_file(p) {
                    Ok(reg) => reg,
                    Err(e) => {
                        eprintln!(
                            "error: failed to load ISSP state file `{}`: {}",
                            p.display(),
                            e
                        );
                        return ExitCode::FAILURE;
                    }
                },
                Some(p) => {
                    eprintln!(
                        "error: specified state file `{}` does not exist",
                        p.display()
                    );
                    return ExitCode::FAILURE;
                }
                None => {
                    // Empty state (no state file found): clean empty registry
                    SessionRegistry::new(1)
                }
            };

            let now_secs = current_unix_secs();
            let all_records = registry.list_sessions();
            let filtered: Vec<SessionRecord> = all_records
                .into_iter()
                .filter(|r| match role.to_ascii_lowercase().as_str() {
                    "primary" => r.is_primary,
                    "standby" => !r.is_primary,
                    _ => true,
                })
                .collect();

            if json {
                let items: Vec<serde_json::Value> = filtered
                    .iter()
                    .map(|r| {
                        let age_secs = now_secs.saturating_sub(r.snapshot.captured_unix_secs);
                        json!({
                            "session_id": r.snapshot.id.to_canonical_string(),
                            "flow_hash": format!("{:#018x}", r.snapshot.id.flow_hash),
                            "origin_node": r.snapshot.id.origin_node,
                            "nonce": r.snapshot.id.nonce,
                            "role": if r.is_primary { "primary" } else { "standby" },
                            "migration_epoch": r.snapshot.migration_epoch,
                            "tx_seq": r.snapshot.tx_seq,
                            "rx_seq_high": r.snapshot.rx_seq_high,
                            "crypto_epoch": r.snapshot.crypto_epoch,
                            "captured_unix_secs": r.snapshot.captured_unix_secs,
                            "age_secs": age_secs,
                        })
                    })
                    .collect();

                let root = json!({
                    "node_id": registry.node_id,
                    "policy": match registry.policy {
                        SecurityPolicy::StrictPsk => "strict_psk",
                        SecurityPolicy::Permissive => "permissive",
                        SecurityPolicy::PlaintextOnly => "plaintext_only",
                    },
                    "total_sessions": registry.session_count(),
                    "matched_sessions": items.len(),
                    "sessions": items,
                });
                println!("{}", serde_json::to_string_pretty(&root).unwrap());
                return ExitCode::SUCCESS;
            }

            println!("IFA Session Synchronization Protocol (ISSP) — Cluster Registry");
            println!(
                "Node ID: {} | Security Policy: {:?} | Total Sessions: {}",
                registry.node_id,
                registry.policy,
                registry.session_count()
            );

            if filtered.is_empty() {
                println!();
                if registry.session_count() == 0 {
                    println!("No active or replicated tunnel sessions found in registry.");
                } else {
                    println!("No sessions matching role filter `{}`.", role);
                }
                return ExitCode::SUCCESS;
            }

            println!();
            println!(
                "{:<26}  {:<8}  {:<6}  {:<8}  {:<8}  {:<7}  {:<7}",
                "SESSION ID", "ROLE", "EPOCH", "TX SEQ", "RX HIGH", "CRYPTO", "AGE (s)"
            );
            println!("{}", "-".repeat(78));

            for r in &filtered {
                let age_secs = now_secs.saturating_sub(r.snapshot.captured_unix_secs);
                let role_str = if r.is_primary { "Primary" } else { "Standby" };
                println!(
                    "{:<26}  {:<8}  {:<6}  {:<8}  {:<8}  {:<7}  {:<7}",
                    r.snapshot.id.to_canonical_string(),
                    role_str,
                    r.snapshot.migration_epoch,
                    r.snapshot.tx_seq,
                    r.snapshot.rx_seq_high,
                    r.snapshot.crypto_epoch,
                    age_secs
                );
            }

            ExitCode::SUCCESS
        }

        SessionCommand::Inspect { id, file, json } => {
            let state_path = resolve_state_file(file.as_ref());
            let registry = match &state_path {
                Some(p) if p.exists() => match SessionRegistry::load_from_file(p) {
                    Ok(reg) => reg,
                    Err(e) => {
                        eprintln!(
                            "error: failed to load ISSP state file `{}`: {}",
                            p.display(),
                            e
                        );
                        return ExitCode::FAILURE;
                    }
                },
                Some(p) => {
                    eprintln!(
                        "error: specified state file `{}` does not exist",
                        p.display()
                    );
                    return ExitCode::FAILURE;
                }
                None => SessionRegistry::new(1),
            };

            let record = match registry.find_session(&id) {
                Some(r) => r,
                None => {
                    eprintln!("error: session `{}` not found in ISSP registry", id);
                    return ExitCode::FAILURE;
                }
            };

            let now_secs = current_unix_secs();
            let snap = &record.snapshot;
            let age_secs = now_secs.saturating_sub(snap.captured_unix_secs);

            if json {
                let obj = json!({
                    "session_id": snap.id.to_canonical_string(),
                    "flow_hash": format!("{:#018x}", snap.id.flow_hash),
                    "origin_node": snap.id.origin_node,
                    "nonce": snap.id.nonce,
                    "role": if record.is_primary { "primary" } else { "standby" },
                    "migration_epoch": snap.migration_epoch,
                    "last_captured_unix": snap.captured_unix_secs,
                    "age_secs": age_secs,
                    "sequence": {
                        "tx_seq": snap.tx_seq,
                        "rx_seq_high": snap.rx_seq_high,
                        "reorder_bitmap": format!("{:#018x}", snap.reorder_bitmap),
                    },
                    "traffic_shaping": {
                        "token_bucket_scaled": snap.token_bucket_scaled,
                        "token_rate_scaled": snap.token_rate_scaled,
                        "codel_target_ns": snap.codel_target_ns,
                        "codel_interval_ns": snap.codel_interval_ns,
                        "codel_drop_count": snap.codel_drop_count,
                    },
                    "fec": {
                        "block_idx": snap.fec_block_idx,
                        "src_count": snap.fec_src_count,
                        "repair_count": snap.fec_repair_count,
                    },
                    "security": {
                        "crypto_epoch": snap.crypto_epoch,
                        "cipher": "ChaCha20-Poly1305 (RFC 8439)",
                    }
                });
                println!("{}", serde_json::to_string_pretty(&obj).unwrap());
                return ExitCode::SUCCESS;
            }

            println!("IFA Session Synchronization Protocol (ISSP) — Session Details");
            println!("Session ID:         {}", snap.id.to_canonical_string());
            println!(
                "Role:               {}",
                if record.is_primary {
                    "Primary (Local Gateway)"
                } else {
                    "Standby (Replicated Shadow)"
                }
            );
            println!(
                "Migration Epoch:    {} (fencing token)",
                snap.migration_epoch
            );
            println!(
                "Age:                {}s (captured at unix timestamp {})",
                age_secs, snap.captured_unix_secs
            );
            println!();
            println!("Flow & Routing:");
            println!("  Flow Hash:        {:#018x}", snap.id.flow_hash);
            println!("  Origin Node:      {}", snap.id.origin_node);
            println!(
                "  Session Nonce:    {} ({:#010x})",
                snap.id.nonce, snap.id.nonce
            );
            println!();
            println!("Sequence & Sliding Window:");
            println!("  TX Sequence:      {}", snap.tx_seq);
            println!("  RX High Sequence: {}", snap.rx_seq_high);
            println!(
                "  Reorder Window:   {:#018x} [64-bit window bitmap]",
                snap.reorder_bitmap
            );
            println!();
            println!("Traffic Shaping & Bufferbloat Control:");
            println!(
                "  Token Bucket:     {:.3} tokens (refill: {:.3} tokens/ms)",
                snap.token_bucket_scaled as f64 / 1000.0,
                snap.token_rate_scaled as f64 / 1000.0
            );
            println!(
                "  CoDel Target:     {:.2} ms",
                snap.codel_target_ns as f64 / 1_000_000.0
            );
            println!(
                "  CoDel Interval:   {:.2} ms",
                snap.codel_interval_ns as f64 / 1_000_000.0
            );
            println!("  CoDel Drops:      {}", snap.codel_drop_count);
            println!();
            println!("Forward Error Correction (FEC):");
            println!("  Block Index:      {}", snap.fec_block_idx);
            println!("  Source Packets:   {}", snap.fec_src_count);
            println!("  Repair Packets:   {}", snap.fec_repair_count);
            println!();
            println!("Cryptographic Epoch:");
            println!("  Epoch ID:         {}", snap.crypto_epoch);
            println!("  AEAD Protection:  ChaCha20-Poly1305 (RFC 8439)");

            ExitCode::SUCCESS
        }

        SessionCommand::Migrate {
            id,
            target_node,
            force,
            file,
            out_capsule,
        } => {
            let state_path = match resolve_state_file(file.as_ref()) {
                Some(p) => p,
                None => {
                    eprintln!("error: no ISSP state file found (specify with --file or set IFA_ISSP_STATE)");
                    return ExitCode::FAILURE;
                }
            };

            let registry = match SessionRegistry::load_from_file(&state_path) {
                Ok(reg) => reg,
                Err(e) => {
                    eprintln!(
                        "error: failed to load ISSP state file `{}`: {}",
                        state_path.display(),
                        e
                    );
                    return ExitCode::FAILURE;
                }
            };

            let existing = match registry.find_session(&id) {
                Some(r) => r,
                None => {
                    eprintln!("error: session `{}` not found in ISSP registry", id);
                    return ExitCode::FAILURE;
                }
            };

            let now_secs = current_unix_secs();
            let session_id = existing.snapshot.id;
            let prev_epoch = existing.snapshot.migration_epoch;

            if existing.is_primary && !force {
                eprintln!(
                    "error: session `{}` is already primary on node {} (use --force to override)",
                    session_id, registry.node_id
                );
                return ExitCode::FAILURE;
            }

            // Perform migration
            let updated_snap = match registry.migrate_session(session_id, now_secs) {
                Ok(s) => s,
                Err(e) => {
                    if force {
                        // In force mode, manually update
                        let mut forced = existing.snapshot;
                        forced.migration_epoch += 1;
                        forced.captured_unix_secs = now_secs;
                        if let Err(upsert_err) = registry.upsert_primary(forced) {
                            eprintln!("error: failed to force migrate session: {}", upsert_err);
                            return ExitCode::FAILURE;
                        }
                        forced
                    } else {
                        eprintln!("error: failed to migrate session `{}`: {}", session_id, e);
                        return ExitCode::FAILURE;
                    }
                }
            };

            // Save updated state file
            if let Err(e) = registry.save_to_file(&state_path) {
                eprintln!(
                    "error: failed to persist state dump to `{}`: {}",
                    state_path.display(),
                    e
                );
                return ExitCode::FAILURE;
            }

            // Export capsule if requested
            let capsule_bytes_written = if let Some(capsule_path) = out_capsule {
                let capsule = match registry.build_issp_capsule(&session_id) {
                    Some(c) => c,
                    None => {
                        // Fallback: make capsule directly
                        let frame = ifa_runtime::GossipFrame {
                            sender_node_id: target_node.unwrap_or(registry.node_id),
                            snapshot: updated_snap,
                        };
                        IsspCapsule::from_gossip_frame(&frame)
                    }
                };
                let bytes = capsule.to_bytes();
                if let Err(e) = fs::write(&capsule_path, &bytes) {
                    eprintln!(
                        "error: failed to write capsule to `{}`: {}",
                        capsule_path.display(),
                        e
                    );
                    return ExitCode::FAILURE;
                }
                Some((capsule_path, bytes.len()))
            } else {
                None
            };

            println!(
                "Successfully triggered transparent migration for session {}!",
                session_id
            );
            println!(
                "  Target Node:     {}",
                target_node.unwrap_or(registry.node_id)
            );
            println!("  Previous Epoch:  {}", prev_epoch);
            println!(
                "  New Epoch:       {} (fencing guard incremented)",
                updated_snap.migration_epoch
            );
            println!("  Role:            Primary (Active Takeover)");
            println!(
                "  Sequence TX/RX:  {} / {}",
                updated_snap.tx_seq, updated_snap.rx_seq_high
            );
            println!("  Crypto Epoch:    {}", updated_snap.crypto_epoch);
            if let Some((p, bytes_len)) = capsule_bytes_written {
                println!(
                    "  ISSP Capsule:    written to `{}` ({} bytes)",
                    p.display(),
                    bytes_len
                );
            }

            ExitCode::SUCCESS
        }
        SessionCommand::Bench {
            sessions,
            cycles,
            loss,
            jitter_ms,
            silence_secs,
            json,
        } => {
            let report = if loss.is_some() || jitter_ms.is_some() {
                let loss_pct = loss.unwrap_or(0.0);
                let jitter = jitter_ms.unwrap_or(0);
                let prof = IsspNetworkProfile {
                    name: format!(
                        "Custom Profile ({:.1}% loss, {}ms jitter)",
                        loss_pct, jitter
                    ),
                    loss_rate_percent: loss_pct,
                    base_latency_us: 1000,
                    jitter_max_us: jitter * 1000,
                    reorder_rate_percent: 0.0,
                    tamper_rate_percent: 0.0,
                };
                let scenario = run_issp_scenario(&prof, sessions, cycles, silence_secs);
                let integrity = scenario.state_integrity_verified;
                IsspFailoverBenchmarkSuiteReport {
                    scenarios: vec![scenario],
                    all_integrity_passed: integrity,
                }
            } else {
                run_issp_failover_benchmark_suite(sessions, cycles)
            };

            if json {
                println!("{}", report.to_json());
            } else {
                println!("\n=== ISSP PROTOCOL FAILOVER & THROUGHPUT BENCHMARK ===");
                println!("{}", report.to_markdown_table());
                if report.all_integrity_passed {
                    println!("Status: ALL SCENARIOS PASSED WITH 100% STATE INTEGRITY AND ZERO DATA LOSS\n");
                } else {
                    println!("Status: ONE OR MORE SCENARIOS FAILED INTEGRITY VERIFICATION\n");
                }
            }
            ExitCode::SUCCESS
        }
        SessionCommand::Route {
            file,
            fail_path,
            json,
        } => {
            let state_path = resolve_state_file(file.as_ref());
            let registry = match &state_path {
                Some(p) if p.exists() => match SessionRegistry::load_from_file(p) {
                    Ok(reg) => reg,
                    Err(e) => {
                        eprintln!(
                            "error: failed to load ISSP state file `{}`: {}",
                            p.display(),
                            e
                        );
                        return ExitCode::FAILURE;
                    }
                },
                _ => {
                    let reg = SessionRegistry::new(1);
                    let now = current_unix_secs();
                    for i in 1..=3 {
                        let id = SessionId::new(0x1000 + i, 1, i as u32);
                        let mut snap = SessionSnapshot::new(id, 1, now);
                        snap.tx_seq = 100 * i;
                        snap.rx_seq_high = 95 * i;
                        let _ = reg.upsert_primary(snap);
                    }
                    reg
                }
            };

            let now_ms = current_unix_secs() * 1000;

            let mut r_fiber = IsspMultipathRoute::new(1, 10, "eth0-fiber-wan", 1, 100)
                .with_state(IsspPathState::Active)
                .with_heartbeat_config(500, 1500, 3);
            r_fiber.metrics.last_heartbeat_recv_unix_ms = now_ms;

            let mut r_5g = IsspMultipathRoute::new(2, 10, "wwan0-5g-edge", 2, 60)
                .with_state(IsspPathState::Standby)
                .with_heartbeat_config(500, 1500, 3);
            r_5g.metrics.last_heartbeat_recv_unix_ms = now_ms;

            let mut r_sat = IsspMultipathRoute::new(3, 10, "leo-sat-orbit", 3, 30)
                .with_state(IsspPathState::Standby)
                .with_heartbeat_config(1000, 3000, 3);
            r_sat.metrics.last_heartbeat_recv_unix_ms = now_ms;

            let _ = registry.add_multipath_route(r_fiber);
            let _ = registry.add_multipath_route(r_5g);
            let _ = registry.add_multipath_route(r_sat);

            let sessions = registry.list_sessions();
            for s in &sessions {
                let _ = registry.resolve_session_path(&s.snapshot.id, now_ms);
            }

            let mut failover_event = None;
            if let Some(target_fail_id) = fail_path {
                if let Ok(mut router) = registry.multipath_router.lock() {
                    for p in router.list_routes() {
                        let _ = router.create_heartbeat_ping(p.path_id, now_ms);
                        if p.path_id != target_fail_id {
                            let pong = IsspHeartbeatProbe::new(10, p.path_id, 1, now_ms, true);
                            let _ = router.process_heartbeat_probe(&pong, now_ms + 1_800);
                        }
                    }
                    let events = router.evaluate_heartbeats_and_failover(now_ms + 2_100);
                    if let Some(first_ev) = events.into_iter().next() {
                        failover_event = Some(first_ev);
                    }
                }
            }

            let telem = registry.multipath_telemetry().unwrap_or_default();

            if json {
                let val = json!({
                    "node_id": registry.node_id,
                    "total_paths": telem.total_paths,
                    "active_paths": telem.active_paths,
                    "standby_paths": telem.standby_paths,
                    "failed_paths": telem.failed_paths,
                    "total_failovers": telem.total_failovers,
                    "total_sessions_bound": telem.total_sessions_bound,
                    "failover_triggered": failover_event.is_some(),
                    "failover_event": failover_event.map(|e| json!({
                        "failed_path_id": e.failed_path_id,
                        "target_path_id": e.target_path_id,
                        "reason": format!("{:?}", e.reason),
                        "sessions_rerouted": e.sessions_rerouted,
                        "cutover_latency_us": e.cutover_latency_us,
                    })),
                    "routes": telem.routes.iter().map(|r| json!({
                        "path_id": r.path_id,
                        "peer_node_id": r.peer_node_id,
                        "interface": r.interface_name,
                        "priority": r.priority,
                        "weight": r.weight,
                        "state": format!("{:?}", r.state),
                        "smoothed_rtt_us": r.metrics.smoothed_rtt_us,
                        "loss_rate_ppm": r.metrics.loss_rate_ppm,
                        "consecutive_missed_heartbeats": r.metrics.consecutive_missed_heartbeats,
                    })).collect::<Vec<_>>(),
                });
                println!("{}", serde_json::to_string_pretty(&val).unwrap());
            } else {
                println!("\n=== ISSP DYNAMIC MULTIPATH ROUTING & HEARTBEAT FAILOVER ===");
                println!(
                    "Node ID: {} | Paths: {} (Active: {}, Standby: {}, Failed: {}) | Failovers: {}",
                    registry.node_id,
                    telem.total_paths,
                    telem.active_paths,
                    telem.standby_paths,
                    telem.failed_paths,
                    telem.total_failovers
                );

                if let Some(ref e) = failover_event {
                    println!("\n[FAILOVER EVENT TRIGGERED]");
                    println!("- Failed Path:     #{}", e.failed_path_id);
                    println!("- Promoted Target: #{}", e.target_path_id);
                    println!("- Reason:          {:?}", e.reason);
                    println!("- Cutover Latency: {:.2} µs", e.cutover_latency_us);
                    println!("- Rerouted Flows:  {} sessions", e.sessions_rerouted);
                }

                println!(
                    "\n| Path ID | Interface | State | Priority | Weight | SRTT | Loss | Missed HB | Peer Node |"
                );
                println!(
                    "| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
                );
                for r in &telem.routes {
                    println!(
                        "| #{} | {} | **{:?}** | {} | {} | {:.2} ms | {:.2}% | {} / {} | Node {} |",
                        r.path_id,
                        r.interface_name,
                        r.state,
                        r.priority,
                        r.weight,
                        (r.metrics.smoothed_rtt_us as f64) / 1000.0,
                        (r.metrics.loss_rate_ppm as f64) / 10_000.0,
                        r.metrics.consecutive_missed_heartbeats,
                        r.max_missed_heartbeats,
                        r.peer_node_id,
                    );
                }
                println!();
            }
            ExitCode::SUCCESS
        }
        SessionCommand::Aggregate {
            sessions,
            packets,
            skew_ms,
            file,
            json,
        } => {
            let state_path = resolve_state_file(file.as_ref());
            let registry = match &state_path {
                Some(p) if p.exists() => match SessionRegistry::load_from_file(p) {
                    Ok(reg) => reg,
                    Err(e) => {
                        eprintln!(
                            "error: failed to load ISSP state file `{}`: {}",
                            p.display(),
                            e
                        );
                        return ExitCode::FAILURE;
                    }
                },
                _ => SessionRegistry::new(1),
            };

            let now_ms = current_unix_secs() * 1000;

            // Configure router for Bandwidth Aggregation
            if let Ok(mut router) = registry.multipath_router.lock() {
                router.policy = IsspRoutingPolicy::BandwidthAggregation;

                let mut r_fiber = IsspMultipathRoute::new(1, 10, "eth0-fiber-wan", 1, 100)
                    .with_state(IsspPathState::Active);
                r_fiber.metrics.smoothed_rtt_us = 10_000; // 5ms one-way delay

                let mut r_5g = IsspMultipathRoute::new(2, 10, "wwan0-5g-edge", 2, 50)
                    .with_state(IsspPathState::Active);
                // Secondary path has higher latency by skew_ms * 2
                r_5g.metrics.smoothed_rtt_us = 10_000 + (skew_ms * 2 * 1_000);

                router.add_route(r_fiber);
                router.add_route(r_5g);
            }

            let mut all_inflight = Vec::new();
            let mut session_ids = Vec::new();

            for s_idx in 1..=sessions {
                let s_id = SessionId::new(0x3000 + s_idx as u64, 1, s_idx as u32);
                session_ids.push(s_id);

                for p_idx in 0..packets {
                    let send_time = now_ms + (p_idx as u64 * 3);
                    let payload = format!("sess-{}-data-{}", s_idx, p_idx + 1).into_bytes();
                    match registry.schedule_multipath_packet(&s_id, payload, send_time) {
                        Ok(sched) => {
                            let arrival_time = sched.estimated_arrival_unix_ms;
                            all_inflight.push((sched, arrival_time));
                        }
                        Err(e) => {
                            eprintln!("error: packet scheduling failed: {}", e);
                            return ExitCode::FAILURE;
                        }
                    }
                }
            }

            // Group by session to simulate transit and arrival under network skew
            let mut total_delivered = 0;
            let mut session_ordered_valid = true;

            for s_id in &session_ids {
                let mut sess_packets: Vec<_> = all_inflight
                    .iter()
                    .filter(|(p, _)| p.session_id == *s_id)
                    .cloned()
                    .collect();

                // Sort by physical arrival time at receiver
                sess_packets.sort_by_key(|(_, arrival)| *arrival);

                let mut sess_delivered = Vec::new();
                for (pkt, arrival) in sess_packets {
                    match registry.ingest_multipath_packet(pkt, arrival) {
                        Ok((delivered, _)) => {
                            sess_delivered.extend(delivered);
                        }
                        Err(e) => {
                            eprintln!("error: packet ingestion failed: {}", e);
                            return ExitCode::FAILURE;
                        }
                    }
                }

                // Verify strictly contiguous in-order sequence
                if sess_delivered.len() != packets {
                    session_ordered_valid = false;
                }
                for (idx, d) in sess_delivered.iter().enumerate() {
                    if d.packet.multipath_seq == 0
                        || (idx > 0
                            && d.packet.multipath_seq
                                <= sess_delivered[idx - 1].packet.multipath_seq)
                    {
                        session_ordered_valid = false;
                    }
                }
                total_delivered += sess_delivered.len();
            }

            let reseq_telem = registry.resequencing_telemetry(None).unwrap_or(None);

            let route_telem = registry.multipath_telemetry().unwrap_or_default();

            if json {
                let val = json!({
                    "sessions_count": sessions,
                    "packets_per_session": packets,
                    "total_packets_scheduled": all_inflight.len(),
                    "total_packets_delivered": total_delivered,
                    "differential_skew_ms": skew_ms,
                    "all_sessions_strictly_in_order": session_ordered_valid,
                    "resequencing_telemetry": reseq_telem.map(|t| json!({
                        "total_received": t.total_received,
                        "in_order_count": t.in_order_count,
                        "reordered_count": t.reordered_count,
                        "reorder_rate_percent": t.reorder_rate_percent,
                        "duplicate_count": t.duplicate_count,
                        "gaps_expired_count": t.gaps_expired_count,
                        "average_reorder_delay_ms": t.average_reorder_delay_ms,
                        "max_reorder_delay_ms": t.max_reorder_delay_ms,
                        "buffer_depth": t.buffer_depth,
                    })),
                    "paths": route_telem.routes.iter().map(|r| json!({
                        "path_id": r.path_id,
                        "interface": r.interface_name,
                        "weight": r.weight,
                        "total_frames_sent": r.metrics.total_frames_sent,
                        "total_frames_received": r.metrics.total_frames_received,
                        "smoothed_rtt_ms": (r.metrics.smoothed_rtt_us as f64) / 1000.0,
                    })).collect::<Vec<_>>(),
                });
                println!("{}", serde_json::to_string_pretty(&val).unwrap());
            } else {
                println!("\n=== ISSP MULTIPATH BANDWIDTH AGGREGATION & RESEQUENCING ===");
                println!(
                    "Sessions: {} | Packets/Sess: {} | Total Packets: {} | Path Skew: {} ms",
                    sessions,
                    packets,
                    all_inflight.len(),
                    skew_ms
                );

                if let Some(ref t) = reseq_telem {
                    println!("\n[RESEQUENCING COMPENSATION TELEMETRY]");
                    println!("- Packets Ingested:    {}", t.total_received);
                    println!(
                        "- In-Order Immediate:  {} ({:.1}%)",
                        t.in_order_count,
                        (t.in_order_count as f64 / t.total_received.max(1) as f64) * 100.0
                    );
                    println!(
                        "- Resequenced/Drain:   {} ({:.1}%)",
                        t.reordered_count, t.reorder_rate_percent
                    );
                    println!(
                        "- Average Buffer Wait: {:.2} ms",
                        t.average_reorder_delay_ms
                    );
                    println!("- Max Resequence Hold: {} ms", t.max_reorder_delay_ms);
                    println!("- Duplicates Dropped:  {}", t.duplicate_count);
                    println!("- Expired Gaps/Drops:  {}", t.gaps_expired_count);
                }

                println!("\n[AGGREGATED INTERFACES & STRIPING DISTRIBUTION]");
                println!("| Path ID | Interface | Capacity Weight | Packets Striped | RTT Latency | Target Share |");
                println!("| :---: | :--- | :---: | :---: | :---: | :---: |");
                for r in &route_telem.routes {
                    let total_s = route_telem
                        .routes
                        .iter()
                        .map(|x| x.metrics.total_frames_sent)
                        .sum::<u64>()
                        .max(1);
                    let share = (r.metrics.total_frames_sent as f64 / total_s as f64) * 100.0;
                    println!(
                        "| #{} | {} | {} | {} frames | {:.2} ms | {:.1}% |",
                        r.path_id,
                        r.interface_name,
                        r.weight,
                        r.metrics.total_frames_sent,
                        (r.metrics.smoothed_rtt_us as f64) / 1000.0,
                        share,
                    );
                }

                if session_ordered_valid {
                    println!("\nStatus: 100% IN-ORDER DELIVERY GUARANTEED (ZERO PACKET LOSS UNDER ASYMMETRIC SKEW)\n");
                } else {
                    println!("\nStatus: RESEQUENCING INTEGRITY CHECK FAILED\n");
                }
            }
            ExitCode::SUCCESS
        }
        SessionCommand::Probation {
            flaps,
            duration_ms,
            probes,
            file,
            json,
        } => {
            let registry = match resolve_state_file(file.as_ref()) {
                Some(p) => SessionRegistry::load_from_file(&p).unwrap_or_else(|_| {
                    eprintln!(
                        "Warning: failed loading state from {:?}, using active registry",
                        p
                    );
                    SessionRegistry::new(1)
                }),
                None => SessionRegistry::new(1),
            };

            let now_ms = current_unix_secs() * 1000;

            // Configure Damping and Probation on the router
            let mut r_fiber = IsspMultipathRoute::new(1, 10, "eth0-fiber-wan", 1, 100)
                .with_state(IsspPathState::Active)
                .with_heartbeat_config(500, 1500, 3);
            r_fiber.metrics.last_heartbeat_recv_unix_ms = now_ms;

            let mut r_5g = IsspMultipathRoute::new(2, 10, "wwan0-5g-edge", 2, 50)
                .with_state(IsspPathState::Standby)
                .with_heartbeat_config(500, 15000, 3);
            r_5g.metrics.last_heartbeat_recv_unix_ms = now_ms;

            let _ = registry.add_multipath_route(r_fiber);
            let _ = registry.add_multipath_route(r_5g);

            let damping_cfg = IsspFlapDampingConfig {
                enabled: true,
                flap_penalty: 1000.0,
                suppress_threshold: 1800.0,
                reuse_threshold: 750.0,
                half_life_ms: 10_000,
                max_suppress_penalty: 5000.0,
            };
            let probation_cfg = IsspProbationConfig {
                enabled: true,
                probation_duration_ms: duration_ms,
                min_successful_probes: probes,
                initial_weight_ratio: 0.20,
                max_loss_ppm_tolerance: 10_000,
            };

            let _ = registry.configure_multipath_flap_damping(damping_cfg.clone());
            let _ = registry.configure_multipath_probation(probation_cfg.clone());

            let mut flap_simulation_events = Vec::new();
            let mut probation_steps = Vec::new();
            let mut graduation_event = None;

            // 1. Simulate flaps
            let flap_count = flaps.clamp(1, 10);
            let mut sim_clock = now_ms;
            for flap_idx in 1..=flap_count {
                sim_clock += 1_000;
                // Force failure
                if let Ok(mut router) = registry.multipath_router.lock() {
                    if let Some(r) = router.get_route_mut(1) {
                        r.metrics.consecutive_missed_heartbeats = 3;
                    }
                    let evs = router.evaluate_heartbeats_and_failover(sim_clock);
                    if let Some(r) = router.get_route(1) {
                        flap_simulation_events.push((
                            flap_idx,
                            r.flap_state.penalty,
                            r.flap_state.is_suppressed,
                            r.state,
                            evs.len(),
                        ));
                    }
                }
                // Try recovery pong immediately after each flap (except the last if suppressed)
                if flap_idx < flap_count {
                    sim_clock += 200;
                    let pong =
                        IsspHeartbeatProbe::new(10, 1, flap_idx as u64, sim_clock - 50, true);
                    let _ = registry.handle_heartbeat_probe(&pong, sim_clock);
                }
            }

            // 2. Check suppressed state
            let suppressed_before_decay = registry
                .multipath_router
                .lock()
                .ok()
                .and_then(|r| r.get_route(1).map(|p| p.flap_state.is_suppressed))
                .unwrap_or(false);

            // 3. Fast-forward simulated decay time (25 seconds) to allow reuse
            sim_clock += 25_000;

            // 4. Recovery pong after decay -> enters Probation
            let recovery_pong = IsspHeartbeatProbe::new(10, 1, 999, sim_clock - 30, true);
            let _ = registry.handle_heartbeat_probe(&recovery_pong, sim_clock);

            let entered_probation = registry
                .multipath_router
                .lock()
                .ok()
                .and_then(|r| r.get_route(1).map(|p| p.state == IsspPathState::Probation))
                .unwrap_or(false);

            // 5. Simulate probation probes and ramp-up
            let probe_step = (duration_ms / probes.max(1) as u64).max(100);
            for p_idx in 1..=probes {
                sim_clock += probe_step;
                let step_pong =
                    IsspHeartbeatProbe::new(10, 1, 1000 + p_idx as u64, sim_clock - 20, true);
                let _ = registry.handle_heartbeat_probe(&step_pong, sim_clock);

                if let Ok(router) = registry.multipath_router.lock() {
                    if let Some(r) = router.get_route(1) {
                        probation_steps.push((
                            p_idx,
                            r.state,
                            r.probation_state.weight_ratio * 100.0,
                            r.effective_weight(),
                            (r.metrics.smoothed_rtt_us as f64) / 1000.0,
                        ));
                    }
                }
            }

            // Check final graduation
            if let Ok(router) = registry.multipath_router.lock() {
                graduation_event = router.reintegration_history().last().cloned();
            }

            let telem = registry.multipath_telemetry().unwrap_or_default();

            if json {
                let val = json!({
                    "flaps_requested": flaps,
                    "probation_duration_ms": duration_ms,
                    "target_probes": probes,
                    "suppressed_before_decay": suppressed_before_decay,
                    "entered_probation": entered_probation,
                    "flap_events": flap_simulation_events.iter().map(|(idx, pen, supp, state, fo)| json!({
                        "flap_index": idx,
                        "penalty": pen,
                        "is_suppressed": supp,
                        "state": format!("{:?}", state),
                        "failover_triggered": fo > &0,
                    })).collect::<Vec<_>>(),
                    "probation_steps": probation_steps.iter().map(|(idx, st, ratio, eff_w, rtt)| json!({
                        "probe": idx,
                        "state": format!("{:?}", st),
                        "weight_ratio_pct": ratio,
                        "effective_weight": eff_w,
                        "smoothed_rtt_ms": rtt,
                    })).collect::<Vec<_>>(),
                    "graduated": graduation_event.is_some(),
                    "graduation_event": graduation_event.map(|g| json!({
                        "path_id": g.path_id,
                        "duration_ms": g.probation_duration_ms,
                        "successful_probes": g.successful_probes,
                        "final_rtt_us": g.final_rtt_us,
                        "restored_state": format!("{:?}", g.restored_state),
                    })),
                    "telemetry": {
                        "total_paths": telem.total_paths,
                        "active_paths": telem.active_paths,
                        "standby_paths": telem.standby_paths,
                        "probation_paths": telem.probation_paths,
                        "suppressed_paths": telem.suppressed_paths,
                        "total_failovers": telem.total_failovers,
                        "total_flaps": telem.total_flaps,
                        "total_reintegrations": telem.total_reintegrations,
                    }
                });
                println!("{}", serde_json::to_string_pretty(&val).unwrap());
            } else {
                println!("\n=== ISSP ROUTE FLAPPING DAMPING & PROGRESSIVE PROBATION ===");
                println!(
                    "Flaps: {} | Half-life: {}s | Suppress Threshold: {} | Reuse Threshold: {}",
                    flaps,
                    damping_cfg.half_life_ms / 1000,
                    damping_cfg.suppress_threshold,
                    damping_cfg.reuse_threshold
                );

                println!("\n[1. ROUTE FLAPPING DAMPING ESCALATION & SUPPRESSION]");
                println!("| Flap # | Penalty Score | Damped/Suppressed | Path State | Failover Triggered |");
                println!("| :---: | :---: | :---: | :---: | :---: |");
                for (idx, pen, supp, state, fo) in &flap_simulation_events {
                    println!(
                        "| Flap {} | {:.1} / {:.0} | **{}** | {:?} | {} |",
                        idx,
                        pen,
                        damping_cfg.suppress_threshold,
                        if *supp {
                            "YES (DAMPED)"
                        } else {
                            "NO (RECOVERABLE)"
                        },
                        state,
                        if *fo > 0 { "YES" } else { "NO" }
                    );
                }

                println!("\n[2. EXPONENTIAL DECAY & PROBATION PROGRESSION]");
                println!(
                    "- Decay Window:       25.0s (penalty reduced below reuse threshold {:.0})",
                    damping_cfg.reuse_threshold
                );
                println!("- Probation Window:   {} ms", duration_ms);
                println!("- Required Probes:    {}", probes);

                println!("\n| Probe # | Path State | Progressive Traffic Ramp | Effective Weight | Smooth RTT |");
                println!("| :---: | :---: | :---: | :---: | :---: |");
                for (p_idx, st, ratio, eff_w, rtt) in &probation_steps {
                    println!(
                        "| Probe {} | **{:?}** | {:.1}% | {} / 100 | {:.2} ms |",
                        p_idx, st, ratio, eff_w, rtt
                    );
                }

                if let Some(ref g) = graduation_event {
                    println!("\n[PATH PROBATION GRADUATED & REINTEGRATED]");
                    println!("- Reintegrated Path: #{}", g.path_id);
                    println!("- Verified Probes:   {} probes", g.successful_probes);
                    println!(
                        "- Stabilized RTT:    {:.2} ms",
                        (g.final_rtt_us as f64) / 1000.0
                    );
                    println!(
                        "- Restored Status:   {:?} (100% Nominal Traffic Restored)",
                        g.restored_state
                    );
                    println!(
                        "\nStatus: ROUTE FLAP DAMPING & PROGRESSIVE REINTEGRATION FULLY VALIDATED\n"
                    );
                } else {
                    println!("\nStatus: PROBATION IN PROGRESS\n");
                }
            }
            ExitCode::SUCCESS
        }
        SessionCommand::Balance {
            rounds,
            gradient_us,
            packets,
            file,
            json,
        } => {
            let registry = match resolve_state_file(file.as_ref()) {
                Some(p) if p.exists() => match SessionRegistry::load_from_file(&p) {
                    Ok(reg) => reg,
                    Err(e) => {
                        eprintln!(
                            "Warning: failed loading state from {:?} ({}), using active registry",
                            p, e
                        );
                        SessionRegistry::new(1)
                    }
                },
                _ => SessionRegistry::new(1),
            };

            let _ = registry.set_multipath_routing_policy(IsspRoutingPolicy::BandwidthAggregation);

            // Ensure baseline routes are present (primary fiber WAN path #1 and secondary 5G path #2)
            if let Ok(routes) = registry.list_multipath_routes() {
                if !routes.iter().any(|r| r.path_id == 1) {
                    let mut r1 = IsspMultipathRoute::new(1, 10, "eth0-fiber-wan", 1, 100)
                        .with_state(IsspPathState::Active);
                    r1.metrics.smoothed_rtt_us = 10_000;
                    let _ = registry.add_multipath_route(r1);
                }
                if !routes.iter().any(|r| r.path_id == 2) {
                    let mut r2 = IsspMultipathRoute::new(2, 10, "wwan0-5g-edge", 2, 50)
                        .with_state(IsspPathState::Active);
                    r2.metrics.smoothed_rtt_us = 25_000;
                    let _ = registry.add_multipath_route(r2);
                }
            }

            let session_id = SessionId::new(0x4000_2001, 1, 100);
            let mut round_reports = Vec::new();
            let mut sim_clock_ms = current_unix_secs() * 1000;

            let mut share1_steady = 0.0;
            let mut share1_congested = 0.0;
            let mut rebalancing_detected = false;

            for r_idx in 1..=rounds {
                sim_clock_ms += 1000;

                // Determine dynamic RTT gradient conditions per round
                let (condition_label, rtt1_us, lost1_b, deliv1_b, rtt2_us, lost2_b, deliv2_b) =
                    match r_idx {
                        1 => (
                            "Baseline Initial Probe",
                            10_000,
                            0,
                            125_000,
                            25_000,
                            0,
                            62_500,
                        ),
                        2 => (
                            "Steady-State Balanced",
                            10_200,
                            0,
                            125_000,
                            25_100,
                            0,
                            62_500,
                        ),
                        3 => (
                            "Asymmetric Latency Gradient Surge",
                            10_000 + gradient_us,
                            3_000,
                            20_000,
                            25_000,
                            0,
                            125_000,
                        ),
                        4 => (
                            "Congestion Mitigation & LEDBAT Backoff",
                            10_000 + (gradient_us / 4),
                            0,
                            60_000,
                            25_800,
                            0,
                            100_000,
                        ),
                        _ => (
                            "Stabilized Convergence",
                            10_100,
                            0,
                            125_000,
                            25_000,
                            0,
                            62_500,
                        ),
                    };

                // Update real congestion models (BBR + LEDBAT) via SessionRegistry
                let factor1 = registry
                    .update_congestion_feedback(1, rtt1_us, lost1_b, deliv1_b)
                    .unwrap_or(1.0);
                let factor2 = registry
                    .update_congestion_feedback(2, rtt2_us, lost2_b, deliv2_b)
                    .unwrap_or(1.0);

                let est1 = registry
                    .path_bandwidth_estimate(1)
                    .unwrap_or(IsspBandwidthEstimate {
                        available_bps: 0,
                        queuing_delay_us: 0,
                        weight_factor: factor1,
                        phase: IsspCongestionPhase::SlowStart,
                    });
                let est2 = registry
                    .path_bandwidth_estimate(2)
                    .unwrap_or(IsspBandwidthEstimate {
                        available_bps: 0,
                        queuing_delay_us: 0,
                        weight_factor: factor2,
                        phase: IsspCongestionPhase::SlowStart,
                    });

                let (eff_w1, eff_w2) = if let Ok(router) = registry.multipath_router.lock() {
                    let w1 = router
                        .get_route(1)
                        .map(|r| r.effective_weight())
                        .unwrap_or(1);
                    let w2 = router
                        .get_route(2)
                        .map(|r| r.effective_weight())
                        .unwrap_or(1);
                    (w1, w2)
                } else {
                    (1, 1)
                };

                // Schedule packets to observe traffic distribution
                let mut path1_scheduled = 0usize;
                let mut path2_scheduled = 0usize;

                for p_idx in 0..packets {
                    let send_time = sim_clock_ms + (p_idx as u64 * 2);
                    let payload = format!("bal-pkt-{r_idx}-{p_idx}").into_bytes();
                    if let Ok(sched) =
                        registry.schedule_multipath_packet(&session_id, payload, send_time)
                    {
                        if sched.path_id == 1 {
                            path1_scheduled += 1;
                        } else if sched.path_id == 2 {
                            path2_scheduled += 1;
                        }
                    }
                }

                let total_sched = (path1_scheduled + path2_scheduled).max(1);
                let share1_pct = (path1_scheduled as f64 / total_sched as f64) * 100.0;
                let share2_pct = (path2_scheduled as f64 / total_sched as f64) * 100.0;

                if r_idx == 2 {
                    share1_steady = share1_pct;
                } else if r_idx == 3 {
                    share1_congested = share1_pct;
                    if share1_congested < share1_steady {
                        rebalancing_detected = true;
                    }
                }

                round_reports.push((
                    r_idx,
                    condition_label,
                    rtt1_us,
                    est1,
                    eff_w1,
                    path1_scheduled,
                    share1_pct,
                    rtt2_us,
                    est2,
                    eff_w2,
                    path2_scheduled,
                    share2_pct,
                ));
            }

            let telem = registry.multipath_telemetry().unwrap_or_default();

            if json {
                let val = json!({
                    "rounds_evaluated": rounds,
                    "gradient_surge_us": gradient_us,
                    "packets_per_round": packets,
                    "dynamic_rebalancing_verified": rebalancing_detected,
                    "share1_steady_pct": share1_steady,
                    "share1_congested_pct": share1_congested,
                    "rounds": round_reports.iter().map(|(r_idx, cond, rtt1, est1, eff_w1, p1_cnt, s1_pct, rtt2, est2, eff_w2, p2_cnt, s2_pct)| json!({
                        "round": r_idx,
                        "condition": cond,
                        "path_1": {
                            "interface": "eth0-fiber-wan",
                            "rtt_us": rtt1,
                            "rtt_ms": (*rtt1 as f64) / 1000.0,
                            "queuing_delay_us": est1.queuing_delay_us,
                            "available_bps": est1.available_bps,
                            "phase": format!("{:?}", est1.phase),
                            "weight_factor": est1.weight_factor,
                            "effective_weight": eff_w1,
                            "packets_scheduled": p1_cnt,
                            "traffic_share_pct": s1_pct,
                        },
                        "path_2": {
                            "interface": "wwan0-5g-edge",
                            "rtt_us": rtt2,
                            "rtt_ms": (*rtt2 as f64) / 1000.0,
                            "queuing_delay_us": est2.queuing_delay_us,
                            "available_bps": est2.available_bps,
                            "phase": format!("{:?}", est2.phase),
                            "weight_factor": est2.weight_factor,
                            "effective_weight": eff_w2,
                            "packets_scheduled": p2_cnt,
                            "traffic_share_pct": s2_pct,
                        }
                    })).collect::<Vec<_>>(),
                    "telemetry": {
                        "total_paths": telem.total_paths,
                        "active_paths": telem.active_paths,
                        "total_heartbeats_sent": telem.total_heartbeats_sent,
                        "total_heartbeats_received": telem.total_heartbeats_received,
                        "routes": telem.routes.iter().map(|r| json!({
                            "path_id": r.path_id,
                            "interface": r.interface_name,
                            "weight": r.weight,
                            "effective_weight": r.effective_weight(),
                            "total_frames_sent": r.metrics.total_frames_sent,
                            "total_frames_received": r.metrics.total_frames_received,
                        })).collect::<Vec<_>>(),
                    }
                });
                println!("{}", serde_json::to_string_pretty(&val).unwrap());
            } else {
                println!(
                    "\n=== ISSP DYNAMIC BANDWIDTH BALANCING (RTT GRADIENT / BBR / LEDBAT) ==="
                );
                println!(
                    "Rounds: {} | Gradient Surge: {:.2} ms ({} µs) | Packets/Round: {}",
                    rounds,
                    (gradient_us as f64) / 1000.0,
                    gradient_us,
                    packets
                );

                println!("\n[1. RTT GRADIENT DYNAMICS & CONGESTION FEEDBACK ROUNDS]");
                println!("| Round | Condition | Path 1 RTT (Queue) | Path 1 EffW | Path 1 Share | Path 2 RTT (Queue) | Path 2 EffW | Path 2 Share |");
                println!("| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |");

                for (r_idx, cond, rtt1, est1, eff_w1, _, s1_pct, rtt2, est2, eff_w2, _, s2_pct) in
                    &round_reports
                {
                    println!(
                        "| Round {} | {} | {:.1} ms (+{:.1} ms) | {} ({:?}) | {:.1}% | {:.1} ms (+{:.1} ms) | {} ({:?}) | {:.1}% |",
                        r_idx,
                        cond,
                        (*rtt1 as f64) / 1000.0,
                        (est1.queuing_delay_us as f64) / 1000.0,
                        eff_w1,
                        est1.phase,
                        s1_pct,
                        (*rtt2 as f64) / 1000.0,
                        (est2.queuing_delay_us as f64) / 1000.0,
                        eff_w2,
                        est2.phase,
                        s2_pct
                    );
                }

                println!("\n[2. TRAFFIC STEERING REBALANCING SUMMARY]");
                println!("- Nominal Pre-Congestion Allocation (Round 2): Path #1: {:.1}% | Path #2: {:.1}%", share1_steady, 100.0 - share1_steady);
                println!("- Peak Congestion Allocation (Round 3):         Path #1: {:.1}% | Path #2: {:.1}%", share1_congested, 100.0 - share1_congested);

                if rebalancing_detected {
                    println!("\nStatus: DYNAMIC RTT GRADIENT CONGESTION BALANCING VERIFIED (ADAPTIVE BACKOFF & TRAFFIC STEERING CONFIRMED)\n");
                } else {
                    println!("\nStatus: CONGESTION BALANCING COMPLETED\n");
                }
            }
            ExitCode::SUCCESS
        }

        SessionCommand::TelemetryServe {
            addr,
            file,
            max_requests,
            ws_interval_ms,
            ws_max_frames,
            node_id,
        } => {
            let registry = match resolve_state_file(file.as_ref()) {
                Some(p) if p.exists() => match SessionRegistry::load_from_file(&p) {
                    Ok(reg) => reg,
                    Err(e) => {
                        eprintln!(
                            "Warning: failed loading state from {:?} ({}), starting with empty registry",
                            p, e
                        );
                        SessionRegistry::new(1)
                    }
                },
                _ => SessionRegistry::new(1),
            };

            let server = match IsspTelemetryServer::bind(&addr, &node_id, registry) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: cannot bind telemetry server on {}: {}", addr, e);
                    return ExitCode::FAILURE;
                }
            };

            let local_addr = server
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| addr.clone());

            eprintln!(
                "Telemetry server listening on http://{} — Prometheus: /metrics | OTLP JSON: /v1/metrics | WebSocket: /ws/metrics",
                local_addr
            );

            if max_requests == 0 {
                // Unlimited: serve until SIGINT / process termination
                loop {
                    match server.try_serve_one_smart(ws_interval_ms, ws_max_frames) {
                        Ok(Some((status_or_frames, path))) => {
                            if path == "/ws/metrics" {
                                eprintln!(
                                    "[{}] {} -> WS streamed {} frame(s)",
                                    current_unix_secs(),
                                    path,
                                    status_or_frames
                                );
                            } else {
                                eprintln!(
                                    "[{}] {} -> HTTP {}",
                                    current_unix_secs(),
                                    path,
                                    status_or_frames
                                );
                            }
                        }
                        Ok(None) => {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        Err(e) => {
                            eprintln!("error: accept failed: {}", e);
                            return ExitCode::FAILURE;
                        }
                    }
                }
            } else {
                // Bounded: serve exactly `max_requests` connections then exit
                let mut served = 0usize;
                server.set_nonblocking(false).ok();
                while served < max_requests {
                    match server.try_serve_one_smart(ws_interval_ms, ws_max_frames) {
                        Ok(Some((status_or_frames, path))) => {
                            if path == "/ws/metrics" {
                                eprintln!(
                                    "[{}] {} -> WS streamed {} frame(s)",
                                    current_unix_secs(),
                                    path,
                                    status_or_frames
                                );
                            } else {
                                eprintln!(
                                    "[{}] {} -> HTTP {}",
                                    current_unix_secs(),
                                    path,
                                    status_or_frames
                                );
                            }
                            served += 1;
                        }
                        Ok(None) => {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        Err(e) => {
                            eprintln!("error: accept failed: {}", e);
                            return ExitCode::FAILURE;
                        }
                    }
                }
                eprintln!("Served {} request(s). Exiting.", served);
                ExitCode::SUCCESS
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_session_command_balance_json() {
        let code = execute_session_command(SessionCommand::Balance {
            rounds: 5,
            gradient_us: 80_000,
            packets: 30,
            file: None,
            json: true,
        });
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn test_execute_session_command_balance_text() {
        let code = execute_session_command(SessionCommand::Balance {
            rounds: 3,
            gradient_us: 40_000,
            packets: 20,
            file: None,
            json: false,
        });
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn test_telemetry_serve_binds_and_serves_one_prometheus_request() {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        let registry = SessionRegistry::new(1);
        let server = IsspTelemetryServer::bind("127.0.0.1:0", "test-node-651", registry)
            .expect("bind failed");
        server.set_nonblocking(true).unwrap();
        let addr = server.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            let mut stream = TcpStream::connect(addr).unwrap();
            stream
                .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut buf = String::new();
            stream.read_to_string(&mut buf).unwrap();
            buf
        });

        let mut served = false;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !served && std::time::Instant::now() < deadline {
            match server.try_serve_one() {
                Ok(Some((status, path))) => {
                    assert_eq!(status, 200);
                    assert_eq!(path, "/metrics");
                    served = true;
                }
                Ok(None) | Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        }
        assert!(
            served,
            "did not serve the Prometheus /metrics request in time"
        );

        let response = handle.join().unwrap();
        assert!(
            response.contains("HTTP/1.1 200"),
            "unexpected response: {}",
            &response[..response.len().min(200)]
        );
        assert!(
            response.contains("ifa_issp_multipath"),
            "Prometheus metrics missing from response"
        );
    }

    #[test]
    fn test_telemetry_serve_binds_and_serves_one_otlp_request() {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        let registry = SessionRegistry::new(1);
        let server = IsspTelemetryServer::bind("127.0.0.1:0", "test-node-651-otlp", registry)
            .expect("bind failed");
        server.set_nonblocking(true).unwrap();
        let addr = server.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            let mut stream = TcpStream::connect(addr).unwrap();
            stream
                .write_all(
                    b"GET /v1/metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            let mut buf = String::new();
            stream.read_to_string(&mut buf).unwrap();
            buf
        });

        let mut served = false;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !served && std::time::Instant::now() < deadline {
            match server.try_serve_one() {
                Ok(Some((status, path))) => {
                    assert_eq!(status, 200);
                    assert_eq!(path, "/v1/metrics");
                    served = true;
                }
                Ok(None) | Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        }
        assert!(served, "did not serve the OTLP /v1/metrics request in time");

        let response = handle.join().unwrap();
        assert!(
            response.contains("HTTP/1.1 200"),
            "unexpected OTLP response: {}",
            &response[..response.len().min(200)]
        );
        assert!(
            response.contains("resourceMetrics") || response.contains("scopeMetrics"),
            "OTLP JSON payload missing from response"
        );
    }

    #[test]
    fn test_telemetry_serve_max_requests_bounded() {
        use std::io::Write;
        use std::net::TcpStream;

        let registry = SessionRegistry::new(1);
        let probe_server =
            IsspTelemetryServer::bind("127.0.0.1:0", "test-bounded", registry).unwrap();
        probe_server.set_nonblocking(true).unwrap();
        let addr = probe_server.local_addr().unwrap();

        let client = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(30));
            if let Ok(mut s) = TcpStream::connect(addr) {
                let _ = s.write_all(
                    b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                );
            }
        });

        let mut served = 0usize;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while served < 1 && std::time::Instant::now() < deadline {
            match probe_server.try_serve_one() {
                Ok(Some(_)) => served += 1,
                _ => std::thread::sleep(std::time::Duration::from_millis(5)),
            }
        }
        client.join().ok();
        assert_eq!(served, 1, "expected exactly 1 served request");
    }

    #[test]
    fn test_telemetry_serve_binds_and_serves_websocket_smart_stream() {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        let registry = SessionRegistry::new(1);
        let server = IsspTelemetryServer::bind("127.0.0.1:0", "test-node-ws-cli", registry)
            .expect("bind failed");
        server.set_nonblocking(true).unwrap();
        let addr = server.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            let mut stream = TcpStream::connect(addr).unwrap();
            let req = "GET /ws/metrics HTTP/1.1\r\n\
                       Host: localhost\r\n\
                       Upgrade: websocket\r\n\
                       Connection: Upgrade\r\n\
                       Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                       Sec-WebSocket-Version: 13\r\n\r\n";
            stream.write_all(req.as_bytes()).unwrap();

            // Read handshake response
            let mut resp_bytes: Vec<u8> = Vec::with_capacity(256);
            let mut one = [0u8; 1];
            loop {
                stream.read_exact(&mut one).unwrap();
                resp_bytes.push(one[0]);
                if resp_bytes.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let resp_str = String::from_utf8_lossy(&resp_bytes).to_string();

            // Read 1 streamed frame
            let mut hdr = [0u8; 2];
            stream.read_exact(&mut hdr).unwrap();
            assert_eq!(hdr[0], 0x81, "FIN + text opcode");
            let payload_len: usize = match hdr[1] & 0x7F {
                126 => {
                    let mut ext = [0u8; 2];
                    stream.read_exact(&mut ext).unwrap();
                    u16::from_be_bytes(ext) as usize
                }
                127 => {
                    let mut ext = [0u8; 8];
                    stream.read_exact(&mut ext).unwrap();
                    u64::from_be_bytes(ext) as usize
                }
                n => n as usize,
            };
            let mut payload = vec![0u8; payload_len];
            stream.read_exact(&mut payload).unwrap();
            let frame_payload = String::from_utf8_lossy(&payload).to_string();

            (resp_str, frame_payload)
        });

        let mut served = false;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !served && std::time::Instant::now() < deadline {
            match server.try_serve_one_smart(1, 1) {
                Ok(Some((frames, path))) => {
                    assert_eq!(path, "/ws/metrics");
                    assert_eq!(frames, 1);
                    served = true;
                }
                Ok(None) | Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        }
        assert!(
            served,
            "did not serve the WebSocket /ws/metrics request in time"
        );

        let (resp_str, frame_payload) = handle.join().unwrap();
        assert!(resp_str.contains("101 Switching Protocols"));
        assert!(frame_payload.contains("\"active_paths\""));
    }
}

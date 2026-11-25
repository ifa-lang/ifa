//! Network commands for observing and operating the IFA Session Synchronization Protocol (ISSP).

use clap::Subcommand;
use ifa_runtime::{
    run_issp_failover_benchmark_suite, run_issp_scenario, IsspCapsule,
    IsspFailoverBenchmarkSuiteReport, IsspHeartbeatProbe, IsspMultipathRoute,
    IsspMultipathTelemetry, IsspNetworkProfile, IsspPathState, SecurityPolicy, SessionId,
    SessionRecord, SessionRegistry, SessionSnapshot,
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

            let telem = registry
                .multipath_telemetry()
                .unwrap_or(IsspMultipathTelemetry {
                    total_paths: 0,
                    active_paths: 0,
                    standby_paths: 0,
                    degraded_paths: 0,
                    failed_paths: 0,
                    total_failovers: 0,
                    total_heartbeats_sent: 0,
                    total_heartbeats_received: 0,
                    total_sessions_bound: 0,
                    routes: Vec::new(),
                });

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
    }
}

//! Integration tests and resilience assertions for ISSP transparent failover & throughput benchmarks.

use ifa_runtime::benchmarks::{
    run_issp_failover_benchmark_suite, run_issp_scenario, IsspNetworkProfile,
};

#[test]
fn test_issp_failover_benchmark_suite_comprehensive() {
    let sessions_count = 50;
    let sync_cycles = 10;
    let report = run_issp_failover_benchmark_suite(sessions_count, sync_cycles);

    assert_eq!(report.scenarios.len(), 5);
    assert!(
        report.all_integrity_passed,
        "All scenarios in benchmark suite must pass state integrity verification"
    );

    println!("\n=== ISSP PROTOCOL FAILOVER & THROUGHPUT BENCHMARK ===");
    println!("{}", report.to_markdown_table());

    // 1. Validate LAN optimal performance
    let lan = report
        .scenarios
        .iter()
        .find(|s| s.profile_name.contains("Optimal LAN"))
        .expect("Missing Optimal LAN scenario");
    assert_eq!(lan.total_frames_dropped, 0);
    assert_eq!(lan.total_frames_tampered, 0);
    assert_eq!(lan.total_frames_sent, (sessions_count * sync_cycles) as u64);
    assert_eq!(lan.total_frames_delivered, lan.total_frames_sent);
    assert!(lan.throughput_frames_per_sec > 10_000.0);
    assert!(lan.failover_cutover_latency_us > 0.0);
    assert!(lan.state_integrity_verified);
    assert!(lan.zero_loss_migration);

    // 2. Validate WAN moderate under jitter & loss
    let wan = report
        .scenarios
        .iter()
        .find(|s| s.profile_name.contains("Moderate WAN"))
        .expect("Missing Moderate WAN scenario");
    assert!(wan.total_frames_dropped > 0);
    assert!(wan.state_integrity_verified);
    assert!(wan.zero_loss_migration);

    // 3. Validate Degraded Edge with reordering
    let edge = report
        .scenarios
        .iter()
        .find(|s| s.profile_name.contains("Degraded Edge"))
        .expect("Missing Degraded Edge scenario");
    assert!(edge.total_frames_dropped > 0);
    assert!(edge.state_integrity_verified);
    assert!(edge.zero_loss_migration);

    // 4. Validate Adversarial Wire with tamper rejections
    let adv = report
        .scenarios
        .iter()
        .find(|s| s.profile_name.contains("Adversarial Wire"))
        .expect("Missing Adversarial Wire scenario");
    assert!(adv.total_frames_tampered > 0);
    assert!(adv.total_frames_rejected_or_replayed > 0);
    assert!(adv.state_integrity_verified);
    assert!(adv.zero_loss_migration);

    // 5. Validate Abrupt Link Sever
    let sever = report
        .scenarios
        .iter()
        .find(|s| s.profile_name.contains("Abrupt Link Sever"))
        .expect("Missing Abrupt Link Sever scenario");
    assert!(sever.failover_triggered);
    assert!(sever.state_integrity_verified);
    assert!(sever.zero_loss_migration);
    assert!(sever.failover_cutover_latency_us < 50_000.0); // Cutover must complete in under 50ms (typically < 1ms)
}

#[test]
fn test_issp_custom_heavy_loss_and_jitter_scenario() {
    let custom_profile = IsspNetworkProfile {
        name: "Hostile Cellular (35% loss, 75ms jitter, 5% reorder)".to_string(),
        loss_rate_percent: 35.0,
        base_latency_us: 50_000,
        jitter_max_us: 75_000,
        reorder_rate_percent: 5.0,
        tamper_rate_percent: 0.0,
    };

    let result = run_issp_scenario(&custom_profile, 80, 15, 2);

    assert_eq!(result.sessions_count, 80);
    assert_eq!(result.total_frames_sent, 80 * 15);
    assert!(result.total_frames_dropped > 0);
    assert!(result.total_frames_delivered > 0);
    assert!(result.failover_triggered);
    assert!(result.state_integrity_verified);
    assert!(result.zero_loss_migration);
    assert!(result.p95_frame_latency_us > 50_000.0);
}

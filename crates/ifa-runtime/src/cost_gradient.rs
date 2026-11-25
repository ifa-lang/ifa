//! Cost-Gradient Multipath Load Balancing Orchestrator under Traffic Slicing Constraints.
//!
//! Implements convex marginal cost gradient routing and dynamic rebalancing across
//! heterogeneous ISSP multipath subpaths. Guarantees that flow migrations:
//! 1. Strictly adhere to Flow Service-Level Objectives (URLLC, eMBB, Mission Critical, Best Effort).
//! 2. Minimize global network latency, queuing delay (bufferbloat), and link saturation.
//! 3. Prevent routing flapping/oscillations through hysteresis damping, minimal gradient improvement thresholds,
//!    and per-flow cooldown timers.
//! 4. Steer bulk elastic flows away from low-latency subpaths to protect latency-sensitive slices.
//!
//! Zero-simulation: operates directly on concrete telemetry metrics (RTT, jitter, LEDBAT queuing delay,
//! BBR bottleneck bandwidth, packet loss PPM, measured socket throughput).

use crate::session_sync::SessionId;
use crate::traffic_slicing::{
    FlowQoSProfile, FlowSliceAssignment, FlowSliceClass, FlowSliceNegotiator, SubpathQoSCapability,
};
use std::collections::HashMap;

/// Configurable weights and normalization denominators for subpath cost gradient evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct CostGradientWeights {
    /// Saturation penalty weight (convex Kleinrock queueing slope).
    pub w_saturation: f64,
    /// Round-Trip Time latency weight.
    pub w_rtt: f64,
    /// Queuing delay (bufferbloat) weight.
    pub w_queuing_delay: f64,
    /// Packet loss weight.
    pub w_loss: f64,
    /// Network jitter weight.
    pub w_jitter: f64,
    /// RTT reference normalization value in microseconds.
    pub rtt_ref_us: f64,
    /// Queuing delay reference normalization value in microseconds.
    pub queuing_delay_ref_us: f64,
    /// Packet loss reference normalization value in parts-per-million.
    pub loss_ref_ppm: f64,
    /// Jitter reference normalization value in microseconds.
    pub jitter_ref_us: f64,
}

impl Default for CostGradientWeights {
    fn default() -> Self {
        Self {
            w_saturation: 40.0,
            w_rtt: 25.0,
            w_queuing_delay: 20.0,
            w_loss: 10.0,
            w_jitter: 5.0,
            rtt_ref_us: 50_000.0,           // 50ms baseline
            queuing_delay_ref_us: 10_000.0, // 10ms baseline
            loss_ref_ppm: 1_000.0,          // 0.1% baseline
            jitter_ref_us: 5_000.0,         // 5ms baseline
        }
    }
}

/// Instantaneous cost and marginal cost gradient evaluation for an individual subpath.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathCostGradient {
    /// Subpath identifier.
    pub path_id: u32,
    /// Subpath interface name (e.g. eth0, wlan0).
    pub interface_name: String,
    /// Rated link capacity in bits per second.
    pub capacity_bps: u64,
    /// Currently allocated throughput load in bits per second.
    pub allocated_load_bps: u64,
    /// Saturation ratio [0.0, 1.0].
    pub saturation_ratio: f64,
    /// Marginal cost gradient dC/dLoad (marginal cost per unit additional load).
    pub marginal_gradient: f64,
    /// Aggregated subpath cost C(p).
    pub total_cost: f64,
    /// Smoothed RTT in microseconds.
    pub smoothed_rtt_us: u64,
    /// Queuing delay in microseconds.
    pub queuing_delay_us: u64,
    /// Observed packet loss rate in parts-per-million.
    pub loss_ppm: u32,
    /// Subpath operational usability status.
    pub is_usable: bool,
}

/// Rebalancing configuration and stability thresholds.
#[derive(Debug, Clone, PartialEq)]
pub struct CostGradientConfig {
    /// Weights applied to metric gradients.
    pub weights: CostGradientWeights,
    /// Minimum relative gradient divergence ((g_high - g_low) / g_high) to trigger rebalancing (e.g. 0.15 = 15%).
    pub min_gradient_delta: f64,
    /// Minimum net system cost reduction ratio (gain) required to execute a migration (e.g. 0.05 = 5%).
    pub min_cost_reduction_gain: f64,
    /// Maximum allowed saturation ratio on a target subpath after accepting a migrated flow.
    pub max_target_saturation: f64,
    /// Cooldown window in milliseconds preventing a recently migrated flow from oscillating.
    pub flow_cooldown_ms: u64,
    /// Maximum number of flow migrations performed in a single rebalancing iteration.
    pub max_migrations_per_cycle: usize,
    /// Default estimated flow demand in bits per second if unmeasured.
    pub default_flow_demand_bps: u64,
}

impl Default for CostGradientConfig {
    fn default() -> Self {
        Self {
            weights: CostGradientWeights::default(),
            min_gradient_delta: 0.15,
            min_cost_reduction_gain: 0.05,
            max_target_saturation: 0.85,
            flow_cooldown_ms: 3_000,
            max_migrations_per_cycle: 4,
            default_flow_demand_bps: 5_000_000, // 5 Mbps default demand
        }
    }
}

/// A concrete flow migration action recommended by the cost-gradient orchestrator.
#[derive(Debug, Clone, PartialEq)]
pub struct CostGradientRebalanceAction {
    /// Session identifier of the flow to migrate.
    pub session_id: SessionId,
    /// Slicing service class of the flow.
    pub slice_class: FlowSliceClass,
    /// Originating subpath path_id.
    pub from_path_id: u32,
    /// Destination subpath path_id.
    pub to_path_id: u32,
    /// Estimated throughput demand in bits per second.
    pub estimated_demand_bps: u64,
    /// Marginal cost gradient of origin subpath before migration.
    pub from_gradient_before: f64,
    /// Marginal cost gradient of destination subpath before migration.
    pub to_gradient_before: f64,
    /// Projected net system cost reduction resulting from this migration.
    pub projected_cost_reduction: f64,
    /// Timestamp of rebalance orchestration in milliseconds.
    pub timestamp_ms: u64,
}

/// Complete plan generated during a cost-gradient rebalance evaluation cycle.
#[derive(Debug, Clone, PartialEq)]
pub struct CostGradientRebalancePlan {
    /// Actions planned for execution.
    pub actions: Vec<CostGradientRebalanceAction>,
    /// Global system cost before rebalancing.
    pub initial_total_cost: f64,
    /// Projected global system cost after executing planned actions.
    pub projected_total_cost: f64,
    /// Absolute total cost reduction achieved.
    pub total_cost_reduction: f64,
    /// Gradient variance across usable subpaths before rebalancing.
    pub gradient_variance_before: f64,
    /// Projected gradient variance across usable subpaths after rebalancing.
    pub gradient_variance_after: f64,
    /// Total subpaths evaluated.
    pub subpaths_evaluated: usize,
    /// Total active flows evaluated.
    pub flows_evaluated: usize,
}

/// Operational metrics for cost-gradient load balancing.
#[derive(Debug, Clone, Default)]
pub struct CostGradientMetrics {
    /// Total rebalance evaluation invocations.
    pub total_evaluations: u64,
    /// Total cycles resulting in at least one migration action.
    pub total_rebalance_cycles: u64,
    /// Total individual flow migrations performed.
    pub total_flows_migrated: u64,
    /// Migration attempts rejected due to flow cooldown timer.
    pub total_skipped_cooldown: u64,
    /// Migration attempts rejected due to QoS SLA constraint violation.
    pub total_skipped_sla_constraint: u64,
    /// Migration attempts rejected due to target subpath saturation ceiling.
    pub total_skipped_saturation_limit: u64,
    /// Migration attempts rejected due to insufficient net cost reduction gain.
    pub total_skipped_insufficient_gain: u64,
    /// Flow migrations executed partitioned by traffic slice class.
    pub migrations_by_slice: HashMap<FlowSliceClass, u64>,
    /// Cumulative cost reduction accumulated across all rebalances.
    pub cumulative_cost_reduction: f64,
    /// Most recently observed subpath marginal gradient variance.
    pub last_gradient_variance: f64,
}

/// Cost-Gradient Multipath Load Balancer and Slicing Migration Orchestrator.
#[derive(Debug, Clone)]
pub struct CostGradientLoadBalancer {
    /// Balancer tuning parameters.
    pub config: CostGradientConfig,
    /// Balancer operational metrics.
    pub metrics: CostGradientMetrics,
    /// Per-flow last migration timestamp in milliseconds (anti-flapping cooldown).
    flow_last_migrated_ms: HashMap<SessionId, u64>,
    /// Known flow throughput demands in bits per second.
    flow_demands: HashMap<SessionId, u64>,
}

impl Default for CostGradientLoadBalancer {
    fn default() -> Self {
        Self::new(CostGradientConfig::default())
    }
}

impl CostGradientLoadBalancer {
    /// Create a new balancer with custom configuration.
    pub fn new(config: CostGradientConfig) -> Self {
        Self {
            config,
            metrics: CostGradientMetrics::default(),
            flow_last_migrated_ms: HashMap::new(),
            flow_demands: HashMap::new(),
        }
    }

    /// Record measured or estimated bandwidth demand for a flow.
    pub fn set_flow_demand(&mut self, session_id: SessionId, demand_bps: u64) {
        self.flow_demands.insert(session_id, demand_bps);
    }

    /// Retrieve recorded flow demand, falling back to configured default.
    pub fn get_flow_demand(&self, session_id: &SessionId) -> u64 {
        self.flow_demands
            .get(session_id)
            .copied()
            .unwrap_or(self.config.default_flow_demand_bps)
    }

    /// Unregister a flow from tracking.
    pub fn remove_flow(&mut self, session_id: &SessionId) {
        self.flow_demands.remove(session_id);
        self.flow_last_migrated_ms.remove(session_id);
    }

    /// Access operational metrics.
    pub fn metrics(&self) -> &CostGradientMetrics {
        &self.metrics
    }

    /// Calculate marginal cost gradient dC/dLoad and total cost for a subpath under given load.
    pub fn calculate_marginal_gradient(
        &self,
        subpath: &SubpathQoSCapability,
        allocated_load_bps: u64,
    ) -> (f64, f64) {
        if !subpath.is_usable {
            return (f64::INFINITY, f64::INFINITY);
        }

        let cap = subpath.capacity_bps.max(1_000_000) as f64;
        let load = allocated_load_bps as f64;
        let u = (load / cap).clamp(0.0, 0.999);

        // Saturation queue cost function f(u) = u / (1 - u + eps)
        // Derivative f'(u) = 1 / (1 - u + eps)^2
        let eps = 1e-4;
        let denom = 1.0 - u + eps;
        let sat_gradient = self.config.weights.w_saturation * (1.0 / (denom * denom));
        let sat_cost = self.config.weights.w_saturation * (u / denom);

        // Physical link quality gradient components
        let rtt_grad = self.config.weights.w_rtt
            * (subpath.smoothed_rtt_us as f64 / self.config.weights.rtt_ref_us);
        let q_grad = self.config.weights.w_queuing_delay
            * (subpath.queuing_delay_us as f64 / self.config.weights.queuing_delay_ref_us);
        let loss_grad = self.config.weights.w_loss
            * (subpath.loss_ppm as f64 / self.config.weights.loss_ref_ppm);
        let jitter_grad = self.config.weights.w_jitter
            * (subpath.jitter_us as f64 / self.config.weights.jitter_ref_us);

        let marginal_gradient = sat_gradient + rtt_grad + q_grad + loss_grad + jitter_grad;

        // Total cost scaled by allocated load in Mbps for numerical stability
        let load_mbps = load / 1_000_000.0;
        let total_cost = load_mbps * (sat_cost + rtt_grad + q_grad + loss_grad + jitter_grad);

        (marginal_gradient, total_cost)
    }

    /// Compute marginal cost gradients across all available subpaths given current flow assignments.
    pub fn compute_subpath_gradients(
        &self,
        subpaths: &[SubpathQoSCapability],
        assignments: &HashMap<SessionId, FlowSliceAssignment>,
    ) -> HashMap<u32, SubpathCostGradient> {
        let mut loads_by_path: HashMap<u32, u64> = HashMap::new();
        for assignment in assignments.values() {
            let demand = self.get_flow_demand(&assignment.session_id);
            *loads_by_path
                .entry(assignment.assigned_path_id)
                .or_insert(0) += demand;
        }

        let mut gradients = HashMap::new();
        for sp in subpaths {
            let load = loads_by_path.get(&sp.path_id).copied().unwrap_or(0);
            let cap = sp.capacity_bps.max(1_000_000);
            let saturation = (load as f64 / cap as f64).clamp(0.0, 1.0);
            let (marginal_gradient, total_cost) = self.calculate_marginal_gradient(sp, load);

            gradients.insert(
                sp.path_id,
                SubpathCostGradient {
                    path_id: sp.path_id,
                    interface_name: sp.interface_name.clone(),
                    capacity_bps: cap,
                    allocated_load_bps: load,
                    saturation_ratio: saturation,
                    marginal_gradient,
                    total_cost,
                    smoothed_rtt_us: sp.smoothed_rtt_us,
                    queuing_delay_us: sp.queuing_delay_us,
                    loss_ppm: sp.loss_ppm,
                    is_usable: sp.is_usable,
                },
            );
        }

        gradients
    }

    /// Evaluate whether a flow migration to a target subpath strictly satisfies the flow's QoS SLA.
    pub fn evaluate_flow_migration_admissibility(
        &self,
        profile: &FlowQoSProfile,
        target_subpath: &SubpathQoSCapability,
        projected_load_bps: u64,
    ) -> bool {
        if !target_subpath.is_usable {
            return false;
        }

        let cap = target_subpath.capacity_bps.max(1_000_000);
        let projected_saturation = projected_load_bps as f64 / cap as f64;
        if projected_saturation > self.config.max_target_saturation {
            return false;
        }

        // Hard SLA constraints
        let latency_ok = target_subpath.smoothed_rtt_us <= profile.max_rtt_us;
        let jitter_ok = target_subpath.jitter_us <= profile.max_jitter_us;
        let queuing_ok = target_subpath.queuing_delay_us <= profile.max_queuing_delay_us;
        let loss_ok = target_subpath.loss_ppm <= profile.max_loss_ppm;
        let residual_bw = cap.saturating_sub(projected_load_bps);
        let bw_ok = residual_bw >= profile.min_bandwidth_bps || profile.allow_fallback;

        if !profile.allow_fallback
            && (!latency_ok || !jitter_ok || !queuing_ok || !loss_ok || !bw_ok)
        {
            return false;
        }

        latency_ok && jitter_ok && queuing_ok && loss_ok && bw_ok
    }

    /// Compute variance of marginal cost gradients across usable subpaths.
    pub fn calculate_gradient_variance(gradients: &HashMap<u32, SubpathCostGradient>) -> f64 {
        let usable: Vec<f64> = gradients
            .values()
            .filter(|g| g.is_usable && g.marginal_gradient.is_finite())
            .map(|g| g.marginal_gradient)
            .collect();

        if usable.len() <= 1 {
            return 0.0;
        }

        let mean = usable.iter().sum::<f64>() / (usable.len() as f64);
        let variance = usable
            .iter()
            .map(|g| {
                let diff = g - mean;
                diff * diff
            })
            .sum::<f64>()
            / (usable.len() as f64);

        variance
    }

    /// Orchestrate cost-gradient load rebalancing under traffic slicing constraints.
    pub fn orchestrate_rebalance(
        &mut self,
        subpaths: &[SubpathQoSCapability],
        negotiator: &mut FlowSliceNegotiator,
        now_ms: u64,
    ) -> CostGradientRebalancePlan {
        self.metrics.total_evaluations += 1;

        let subpaths_by_id: HashMap<u32, SubpathQoSCapability> =
            subpaths.iter().map(|s| (s.path_id, s.clone())).collect();

        let mut current_assignments: HashMap<SessionId, FlowSliceAssignment> = HashMap::new();
        for (sid, assignment) in negotiator.assignments_iter() {
            current_assignments.insert(*sid, assignment.clone());
        }

        let mut path_loads: HashMap<u32, u64> = HashMap::new();
        for assignment in current_assignments.values() {
            let demand = self.get_flow_demand(&assignment.session_id);
            *path_loads.entry(assignment.assigned_path_id).or_insert(0) += demand;
        }

        let initial_gradients = self.compute_subpath_gradients(subpaths, &current_assignments);
        let initial_variance = Self::calculate_gradient_variance(&initial_gradients);
        self.metrics.last_gradient_variance = initial_variance;

        let initial_total_cost: f64 = initial_gradients.values().map(|g| g.total_cost).sum();

        let mut planned_actions = Vec::new();
        let mut projected_loads = path_loads.clone();

        // Identify candidate subpaths ordered by marginal cost gradient descending (highest cost/congestion first)
        let mut sorted_subpaths: Vec<&SubpathCostGradient> = initial_gradients
            .values()
            .filter(|g| g.is_usable && g.marginal_gradient.is_finite())
            .collect();
        sorted_subpaths.sort_by(|a, b| {
            b.marginal_gradient
                .partial_cmp(&a.marginal_gradient)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        if sorted_subpaths.len() < 2 {
            return CostGradientRebalancePlan {
                actions: Vec::new(),
                initial_total_cost,
                projected_total_cost: initial_total_cost,
                total_cost_reduction: 0.0,
                gradient_variance_before: initial_variance,
                gradient_variance_after: initial_variance,
                subpaths_evaluated: subpaths.len(),
                flows_evaluated: current_assignments.len(),
            };
        }

        // Target candidate paths ordered by marginal cost gradient ascending (lowest cost/underutilized first)
        let mut target_subpaths: Vec<&SubpathCostGradient> = sorted_subpaths.clone();
        target_subpaths.reverse();

        for high_sp in &sorted_subpaths {
            if planned_actions.len() >= self.config.max_migrations_per_cycle {
                break;
            }

            // Find flows currently allocated on this high-cost subpath
            let mut flows_on_high: Vec<(SessionId, FlowQoSProfile, FlowSliceAssignment, u64)> =
                Vec::new();
            for (sid, assignment) in &current_assignments {
                if assignment.assigned_path_id == high_sp.path_id {
                    if let Some(profile) = negotiator.get_profile(sid) {
                        let demand = self.get_flow_demand(sid);
                        flows_on_high.push((*sid, profile.clone(), assignment.clone(), demand));
                    }
                }
            }

            // Slicing Priority Optimization:
            // Prefer moving lower-priority elastic flows first (BestEffort -> HighThroughput -> MissionCritical -> URLLC).
            // This frees up low-latency paths for strict latency flows without violating URLLC SLOs.
            flows_on_high.sort_by_key(|(_, profile, _, _)| profile.priority);

            for (sid, profile, _assignment, demand) in flows_on_high {
                if planned_actions.len() >= self.config.max_migrations_per_cycle {
                    break;
                }

                // Check anti-flapping cooldown
                if let Some(&last_mig) = self.flow_last_migrated_ms.get(&sid) {
                    if now_ms.saturating_sub(last_mig) < self.config.flow_cooldown_ms {
                        self.metrics.total_skipped_cooldown += 1;
                        continue;
                    }
                }

                // Evaluate potential destination subpaths
                let mut best_target: Option<(u32, f64, f64)> = None; // (target_path_id, projected_reduction, target_grad)

                for low_sp in &target_subpaths {
                    if low_sp.path_id == high_sp.path_id {
                        continue;
                    }

                    let low_sp_cap = match subpaths_by_id.get(&low_sp.path_id) {
                        Some(sp) => sp,
                        None => continue,
                    };

                    let current_high_load =
                        projected_loads.get(&high_sp.path_id).copied().unwrap_or(0);
                    let current_low_load =
                        projected_loads.get(&low_sp.path_id).copied().unwrap_or(0);

                    let projected_low_load = current_low_load + demand;
                    let projected_high_load = current_high_load.saturating_sub(demand);

                    // Check slicing admissibility & SLA
                    if !self.evaluate_flow_migration_admissibility(
                        &profile,
                        low_sp_cap,
                        projected_low_load,
                    ) {
                        let cap = low_sp_cap.capacity_bps.max(1_000_000);
                        if (projected_low_load as f64 / cap as f64)
                            > self.config.max_target_saturation
                        {
                            self.metrics.total_skipped_saturation_limit += 1;
                        } else {
                            self.metrics.total_skipped_sla_constraint += 1;
                        }
                        continue;
                    }

                    // Check gradient delta threshold
                    let high_grad = initial_gradients
                        .get(&high_sp.path_id)
                        .map(|g| g.marginal_gradient)
                        .unwrap_or(0.0);
                    let low_grad = initial_gradients
                        .get(&low_sp.path_id)
                        .map(|g| g.marginal_gradient)
                        .unwrap_or(0.0);

                    if high_grad <= low_grad {
                        continue;
                    }

                    let relative_delta = (high_grad - low_grad) / high_grad;
                    if relative_delta < self.config.min_gradient_delta {
                        continue;
                    }

                    // Calculate projected costs
                    let high_sp_cap = match subpaths_by_id.get(&high_sp.path_id) {
                        Some(sp) => sp,
                        None => continue,
                    };
                    let (_, cost_high_pre) =
                        self.calculate_marginal_gradient(high_sp_cap, current_high_load);
                    let (_, cost_low_pre) =
                        self.calculate_marginal_gradient(low_sp_cap, current_low_load);

                    let (_, cost_high_post) =
                        self.calculate_marginal_gradient(high_sp_cap, projected_high_load);
                    let (low_post_grad, cost_low_post) =
                        self.calculate_marginal_gradient(low_sp_cap, projected_low_load);

                    let total_pre = cost_high_pre + cost_low_pre;
                    let total_post = cost_high_post + cost_low_post;
                    let reduction = total_pre - total_post;

                    if total_pre > 0.0
                        && (reduction / total_pre) >= self.config.min_cost_reduction_gain
                    {
                        match best_target {
                            None => best_target = Some((low_sp.path_id, reduction, low_post_grad)),
                            Some((_, best_red, _)) => {
                                if reduction > best_red {
                                    best_target = Some((low_sp.path_id, reduction, low_post_grad));
                                }
                            }
                        }
                    } else {
                        self.metrics.total_skipped_insufficient_gain += 1;
                    }
                }

                if let Some((target_path_id, cost_reduction, _)) = best_target {
                    let from_grad = initial_gradients
                        .get(&high_sp.path_id)
                        .map(|g| g.marginal_gradient)
                        .unwrap_or(0.0);
                    let to_grad = initial_gradients
                        .get(&target_path_id)
                        .map(|g| g.marginal_gradient)
                        .unwrap_or(0.0);

                    let action = CostGradientRebalanceAction {
                        session_id: sid,
                        slice_class: profile.slice_class,
                        from_path_id: high_sp.path_id,
                        to_path_id: target_path_id,
                        estimated_demand_bps: demand,
                        from_gradient_before: from_grad,
                        to_gradient_before: to_grad,
                        projected_cost_reduction: cost_reduction,
                        timestamp_ms: now_ms,
                    };

                    // Update projected loads
                    *projected_loads.entry(high_sp.path_id).or_insert(0) = projected_loads
                        .get(&high_sp.path_id)
                        .copied()
                        .unwrap_or(0)
                        .saturating_sub(demand);
                    *projected_loads.entry(target_path_id).or_insert(0) += demand;

                    // Update flow last migrated timestamp
                    self.flow_last_migrated_ms.insert(sid, now_ms);

                    // Execute migration in negotiator
                    negotiator.force_reassign_flow(&sid, target_path_id, now_ms);

                    self.metrics.total_flows_migrated += 1;
                    *self
                        .metrics
                        .migrations_by_slice
                        .entry(profile.slice_class)
                        .or_insert(0) += 1;

                    planned_actions.push(action);
                }
            }
        }

        if !planned_actions.is_empty() {
            self.metrics.total_rebalance_cycles += 1;
        }

        // Compute projected end state
        let mut projected_gradients = HashMap::new();
        let mut projected_total_cost = 0.0;
        for sp in subpaths {
            let load = projected_loads.get(&sp.path_id).copied().unwrap_or(0);
            let (grad, cost) = self.calculate_marginal_gradient(sp, load);
            projected_total_cost += cost;
            projected_gradients.insert(
                sp.path_id,
                SubpathCostGradient {
                    path_id: sp.path_id,
                    interface_name: sp.interface_name.clone(),
                    capacity_bps: sp.capacity_bps,
                    allocated_load_bps: load,
                    saturation_ratio: (load as f64 / sp.capacity_bps.max(1_000_000) as f64)
                        .clamp(0.0, 1.0),
                    marginal_gradient: grad,
                    total_cost: cost,
                    smoothed_rtt_us: sp.smoothed_rtt_us,
                    queuing_delay_us: sp.queuing_delay_us,
                    loss_ppm: sp.loss_ppm,
                    is_usable: sp.is_usable,
                },
            );
        }

        let projected_variance = Self::calculate_gradient_variance(&projected_gradients);
        let net_reduction = (initial_total_cost - projected_total_cost).max(0.0);
        self.metrics.cumulative_cost_reduction += net_reduction;

        CostGradientRebalancePlan {
            actions: planned_actions,
            initial_total_cost,
            projected_total_cost,
            total_cost_reduction: net_reduction,
            gradient_variance_before: initial_variance,
            gradient_variance_after: projected_variance,
            subpaths_evaluated: subpaths.len(),
            flows_evaluated: current_assignments.len(),
        }
    }

    /// Export Prometheus text-formatted metrics for cost-gradient rebalancing.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::with_capacity(1024);

        out.push_str("# HELP ifa_multipath_cost_gradient_evaluations_total Total evaluations performed by cost gradient balancer.\n");
        out.push_str("# TYPE ifa_multipath_cost_gradient_evaluations_total counter\n");
        out.push_str(&format!(
            "ifa_multipath_cost_gradient_evaluations_total {}\n",
            self.metrics.total_evaluations
        ));

        out.push_str("# HELP ifa_multipath_cost_gradient_migrations_total Total flow migrations orchestrated across subpaths.\n");
        out.push_str("# TYPE ifa_multipath_cost_gradient_migrations_total counter\n");
        out.push_str(&format!(
            "ifa_multipath_cost_gradient_migrations_total {}\n",
            self.metrics.total_flows_migrated
        ));

        out.push_str("# HELP ifa_multipath_cost_gradient_variance Instantaneous variance of marginal gradients across subpaths.\n");
        out.push_str("# TYPE ifa_multipath_cost_gradient_variance gauge\n");
        out.push_str(&format!(
            "ifa_multipath_cost_gradient_variance {:.6}\n",
            self.metrics.last_gradient_variance
        ));

        out.push_str("# HELP ifa_multipath_cost_gradient_cumulative_reduction Total cumulative cost reduction achieved.\n");
        out.push_str("# TYPE ifa_multipath_cost_gradient_cumulative_reduction counter\n");
        out.push_str(&format!(
            "ifa_multipath_cost_gradient_cumulative_reduction {:.4}\n",
            self.metrics.cumulative_cost_reduction
        ));

        out.push_str("# HELP ifa_multipath_cost_gradient_migrations_by_slice Migrations partitioned by traffic slice.\n");
        out.push_str("# TYPE ifa_multipath_cost_gradient_migrations_by_slice counter\n");
        for class in &[
            FlowSliceClass::UltraLowLatency,
            FlowSliceClass::HighThroughput,
            FlowSliceClass::MissionCritical,
            FlowSliceClass::BestEffort,
        ] {
            let count = self
                .metrics
                .migrations_by_slice
                .get(class)
                .copied()
                .unwrap_or(0);
            out.push_str(&format!(
                "ifa_multipath_cost_gradient_migrations_by_slice{{slice=\"{}\"}} {}\n",
                class.as_str(),
                count
            ));
        }

        out
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_subpath(
        path_id: u32,
        iface: &str,
        capacity_bps: u64,
        smoothed_rtt_us: u64,
        jitter_us: u64,
        queuing_delay_us: u64,
        loss_ppm: u32,
    ) -> SubpathQoSCapability {
        SubpathQoSCapability {
            path_id,
            interface_name: iface.to_string(),
            smoothed_rtt_us,
            jitter_us,
            queuing_delay_us,
            capacity_bps,
            throughput_bps: 0,
            available_bandwidth_bps: capacity_bps,
            saturation_ratio: 0.0,
            loss_ppm,
            is_usable: true,
        }
    }

    #[test]
    fn test_marginal_gradient_convexity_and_saturation() {
        let balancer = CostGradientLoadBalancer::default();
        let sp = dummy_subpath(1, "eth0", 100_000_000, 10_000, 1_000, 2_000, 0);

        // Low load: 10% saturation
        let (grad_10, cost_10) = balancer.calculate_marginal_gradient(&sp, 10_000_000);
        // Medium load: 50% saturation
        let (grad_50, cost_50) = balancer.calculate_marginal_gradient(&sp, 50_000_000);
        // Heavy load: 90% saturation
        let (grad_90, cost_90) = balancer.calculate_marginal_gradient(&sp, 90_000_000);

        assert!(grad_10 < grad_50);
        assert!(grad_50 < grad_90);
        assert!(cost_10 < cost_50);
        assert!(cost_50 < cost_90);

        // Saturation gradient at 90% should be significantly higher due to convex slope
        assert!(grad_90 > grad_10 * 10.0);
    }

    #[test]
    fn test_sla_admissibility_urllc_vs_embb() {
        let balancer = CostGradientLoadBalancer::default();
        // Subpath A: Low latency (5ms), moderate capacity (50 Mbps)
        let sp_fast = dummy_subpath(1, "eth0", 50_000_000, 5_000, 500, 1_000, 0);
        // Subpath B: High latency (80ms), high capacity (500 Mbps)
        let sp_bulk = dummy_subpath(2, "tun0", 500_000_000, 80_000, 10_000, 5_000, 50);

        let urllc_profile = FlowQoSProfile::ultra_low_latency(); // max_rtt = 20ms
        let embb_profile = FlowQoSProfile::high_throughput(20_000_000); // max_rtt = 150ms

        // URLLC should be admissible on sp_fast, but strictly rejected on sp_bulk due to 80ms > 20ms RTT
        assert!(balancer.evaluate_flow_migration_admissibility(
            &urllc_profile,
            &sp_fast,
            5_000_000
        ));
        assert!(!balancer.evaluate_flow_migration_admissibility(
            &urllc_profile,
            &sp_bulk,
            5_000_000
        ));

        // eMBB should be admissible on both
        assert!(balancer.evaluate_flow_migration_admissibility(
            &embb_profile,
            &sp_fast,
            20_000_000
        ));
        assert!(balancer.evaluate_flow_migration_admissibility(
            &embb_profile,
            &sp_bulk,
            20_000_000
        ));
    }

    #[test]
    fn test_gradient_rebalance_moves_embb_off_congested_low_latency_path() {
        let mut balancer = CostGradientLoadBalancer::default();
        let mut negotiator = FlowSliceNegotiator::new();

        let s_urllc = SessionId::new(101, 1, 0);
        let s_embb = SessionId::new(102, 1, 0);

        negotiator.register_profile(s_urllc, FlowQoSProfile::ultra_low_latency());
        negotiator.register_profile(s_embb, FlowQoSProfile::high_throughput(25_000_000));

        // Path 1 (eth0): Low latency, 100 Mbps
        let sp1 = dummy_subpath(1, "eth0", 100_000_000, 8_000, 800, 2_000, 0);
        // Path 2 (tun0): 50ms latency, 1000 Mbps (1 Gbps)
        let sp2 = dummy_subpath(2, "tun0", 1_000_000_000, 45_000, 2_000, 3_000, 0);

        let subpaths = vec![sp1, sp2];

        // Initial assignment: both flows assigned to Path 1
        negotiator.force_reassign_flow(&s_urllc, 1, 1000);
        negotiator.force_reassign_flow(&s_embb, 1, 1000);

        // Path 1 is congested: eMBB takes 75 Mbps, URLLC takes 5 Mbps -> 80% saturation on Path 1
        balancer.set_flow_demand(s_urllc, 5_000_000);
        balancer.set_flow_demand(s_embb, 75_000_000);

        let plan = balancer.orchestrate_rebalance(&subpaths, &mut negotiator, 2000);

        // Rebalance should move eMBB from Path 1 to Path 2, leaving URLLC on low-latency Path 1
        assert_eq!(plan.actions.len(), 1);
        let action = &plan.actions[0];
        assert_eq!(action.session_id, s_embb);
        assert_eq!(action.from_path_id, 1);
        assert_eq!(action.to_path_id, 2);
        assert!(plan.total_cost_reduction > 0.0);
        assert!(plan.gradient_variance_after < plan.gradient_variance_before);

        // Verify negotiator state updated
        assert_eq!(
            negotiator.get_assignment(&s_embb).unwrap().assigned_path_id,
            2
        );
        assert_eq!(
            negotiator
                .get_assignment(&s_urllc)
                .unwrap()
                .assigned_path_id,
            1
        );
    }

    #[test]
    fn test_cooldown_prevents_flapping() {
        let mut balancer = CostGradientLoadBalancer::default();
        let mut negotiator = FlowSliceNegotiator::new();

        let s1 = SessionId::new(201, 1, 0);
        negotiator.register_profile(s1, FlowQoSProfile::high_throughput(10_000_000));
        negotiator.force_reassign_flow(&s1, 1, 1000);

        let sp1 = dummy_subpath(1, "eth0", 50_000_000, 10_000, 1_000, 2_000, 0);
        let sp2 = dummy_subpath(2, "tun0", 200_000_000, 20_000, 1_000, 2_000, 0);
        let subpaths = vec![sp1, sp2];

        balancer.set_flow_demand(s1, 40_000_000);

        // 1. First rebalance at 1000ms -> should migrate
        let plan1 = balancer.orchestrate_rebalance(&subpaths, &mut negotiator, 1000);
        assert_eq!(plan1.actions.len(), 1);

        // Reassign back to path 1 artificially to test cooldown
        negotiator.force_reassign_flow(&s1, 1, 1500);

        // 2. Second rebalance at 1500ms (within 3000ms cooldown) -> should skip migration
        let plan2 = balancer.orchestrate_rebalance(&subpaths, &mut negotiator, 1500);
        assert_eq!(plan2.actions.len(), 0);
        assert!(balancer.metrics().total_skipped_cooldown >= 1);

        // 3. Third rebalance at 5000ms (after cooldown expired) -> should migrate again
        let plan3 = balancer.orchestrate_rebalance(&subpaths, &mut negotiator, 5000);
        assert_eq!(plan3.actions.len(), 1);
    }
}

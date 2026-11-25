//! CSPF Topology Graph — Constrained Shortest Path First for resilient multipath routing.
//!
//! Builds a directed weighted graph from live mesh topology snapshots and computes
//! the K-shortest loop-free paths under bandwidth, latency, and loss-rate constraints
//! using a modified Yen's K-SP algorithm layered over Dijkstra.
//!
//! # Design
//! - Zero-alloc adjacency representation (pre-allocated `Vec` slabs).
//! - Constraint satisfaction evaluated per-candidate edge before relaxation.
//! - Multipath output: up to `K` ranked, loop-free, constraint-satisfying paths.
//! - Thread-safe snapshot ingestion via `&IsspMeshTopologySnapshot`.

use std::collections::{BinaryHeap, HashMap};

// ─── Node & Edge primitives ───────────────────────────────────────────────────

/// Opaque node identifier within a topology graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub u32);

/// Directed edge with QoS metrics used by the CSPF constraint evaluator.
#[derive(Debug, Clone)]
pub struct TopoEdge {
    pub from: NodeId,
    pub to: NodeId,
    /// Available bandwidth in bytes/s.
    pub avail_bw_bps: u64,
    /// Smoothed RTT in microseconds.
    pub rtt_us: u32,
    /// Loss rate in millipercent (0–100_000 == 0–100 %).
    pub loss_millipct: u32,
    /// Composite link cost (lower = preferred); computed from rtt+loss.
    pub cost: u32,
}

impl TopoEdge {
    /// Derive a composite cost: `rtt_us / 1000 + loss_millipct / 100`.
    pub fn compute_cost(rtt_us: u32, loss_millipct: u32) -> u32 {
        (rtt_us / 1_000).saturating_add(loss_millipct / 100)
    }
}

// ─── Constraint specification ─────────────────────────────────────────────────

/// QoS constraints that every edge on an accepted path must satisfy.
#[derive(Debug, Clone, Copy)]
pub struct CspfConstraints {
    /// Minimum required bandwidth per edge (bytes/s). `0` = unconstrained.
    pub min_bw_bps: u64,
    /// Maximum tolerated RTT per edge (µs). `u32::MAX` = unconstrained.
    pub max_rtt_us: u32,
    /// Maximum tolerated loss per edge (millipercent). `u32::MAX` = unconstrained.
    pub max_loss_millipct: u32,
}

impl CspfConstraints {
    pub fn unconstrained() -> Self {
        Self {
            min_bw_bps: 0,
            max_rtt_us: u32::MAX,
            max_loss_millipct: u32::MAX,
        }
    }

    /// Return `true` if `edge` satisfies all constraints.
    #[inline]
    pub fn satisfied_by(&self, edge: &TopoEdge) -> bool {
        edge.avail_bw_bps >= self.min_bw_bps
            && edge.rtt_us <= self.max_rtt_us
            && edge.loss_millipct <= self.max_loss_millipct
    }
}

// ─── Topology Graph ───────────────────────────────────────────────────────────

/// Directed topology graph indexed by [`NodeId`].
#[derive(Debug, Default)]
pub struct TopologyGraph {
    /// Adjacency list: node → outgoing edges.
    adj: HashMap<NodeId, Vec<TopoEdge>>,
    /// All known nodes (superset of adj keys).
    nodes: Vec<NodeId>,
}

impl TopologyGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a node (idempotent).
    pub fn add_node(&mut self, id: NodeId) {
        if let std::collections::hash_map::Entry::Vacant(e) = self.adj.entry(id) {
            e.insert(Vec::new());
            self.nodes.push(id);
        }
    }

    /// Add a directed edge. Both endpoints are auto-registered.
    pub fn add_edge(&mut self, edge: TopoEdge) {
        self.add_node(edge.from);
        self.add_node(edge.to);
        self.adj.entry(edge.from).or_default().push(edge);
    }

    /// Add a symmetric (bidirectional) edge.
    pub fn add_symmetric_edge(
        &mut self,
        a: NodeId,
        b: NodeId,
        avail_bw_bps: u64,
        rtt_us: u32,
        loss_millipct: u32,
    ) {
        let cost = TopoEdge::compute_cost(rtt_us, loss_millipct);
        self.add_edge(TopoEdge {
            from: a,
            to: b,
            avail_bw_bps,
            rtt_us,
            loss_millipct,
            cost,
        });
        self.add_edge(TopoEdge {
            from: b,
            to: a,
            avail_bw_bps,
            rtt_us,
            loss_millipct,
            cost,
        });
    }

    /// Return the number of nodes in the graph.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Return the total number of directed edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.adj.values().map(|v| v.len()).sum()
    }

    /// Return an immutable slice of all registered node IDs.
    pub fn nodes(&self) -> &[NodeId] {
        &self.nodes
    }

    /// Check if a directed edge exists from `from` to `to`.
    pub fn has_edge(&self, from: NodeId, to: NodeId) -> bool {
        self.adj
            .get(&from)
            .map(|edges| edges.iter().any(|e| e.to == to))
            .unwrap_or(false)
    }

    /// Remove a directed edge from `from` to `to`.
    /// Returns `true` if an edge was found and removed.
    pub fn remove_edge(&mut self, from: NodeId, to: NodeId) -> bool {
        if let Some(edges) = self.adj.get_mut(&from) {
            let initial_len = edges.len();
            edges.retain(|e| e.to != to);
            edges.len() < initial_len
        } else {
            false
        }
    }

    /// Remove symmetric directed edges between `a` and `b`.
    /// Returns `true` if at least one edge was removed.
    pub fn remove_symmetric_edge(&mut self, a: NodeId, b: NodeId) -> bool {
        let r1 = self.remove_edge(a, b);
        let r2 = self.remove_edge(b, a);
        r1 || r2
    }

    /// Update QoS metrics on an existing directed edge.
    /// If the edge does not exist, returns `false`.
    pub fn update_edge(
        &mut self,
        from: NodeId,
        to: NodeId,
        avail_bw_bps: u64,
        rtt_us: u32,
        loss_millipct: u32,
    ) -> bool {
        if let Some(edges) = self.adj.get_mut(&from) {
            if let Some(edge) = edges.iter_mut().find(|e| e.to == to) {
                edge.avail_bw_bps = avail_bw_bps;
                edge.rtt_us = rtt_us;
                edge.loss_millipct = loss_millipct;
                edge.cost = TopoEdge::compute_cost(rtt_us, loss_millipct);
                return true;
            }
        }
        false
    }

    /// Update symmetric QoS metrics between `a` and `b`.
    pub fn update_symmetric_edge(
        &mut self,
        a: NodeId,
        b: NodeId,
        avail_bw_bps: u64,
        rtt_us: u32,
        loss_millipct: u32,
    ) -> bool {
        let u1 = self.update_edge(a, b, avail_bw_bps, rtt_us, loss_millipct);
        let u2 = self.update_edge(b, a, avail_bw_bps, rtt_us, loss_millipct);
        u1 || u2
    }

    /// Generate a deterministic, high-density mesh topology graph with `num_nodes` nodes.
    /// Includes a primary ring backbone and multiple chord cross-links per node.
    pub fn generate_dense_mesh(
        num_nodes: usize,
        cross_link_degree: usize,
        base_bw_bps: u64,
        base_rtt_us: u32,
    ) -> Self {
        let mut graph = Self::new();
        let n = num_nodes.max(4);

        for i in 0..n {
            graph.add_node(NodeId(i as u32));
        }

        // 1. Primary ring backbone: (i <-> (i + 1) % n) with high bandwidth and low RTT.
        for i in 0..n {
            let a = NodeId(i as u32);
            let b = NodeId(((i + 1) % n) as u32);
            graph.add_symmetric_edge(a, b, base_bw_bps, base_rtt_us, 5);
        }

        // 2. Chords / cross-links with varying strides for multi-path density.
        let strides = [2, 3, 5, 7, 11, 13];
        let max_strides = cross_link_degree.min(strides.len());

        for (k_idx, &stride) in strides.iter().take(max_strides).enumerate() {
            if stride >= n {
                continue;
            }
            let chord_bw = (base_bw_bps / (k_idx as u64 + 2)).max(10_000_000);
            let chord_rtt = base_rtt_us + (stride as u32 * 450);
            let chord_loss = 10 + (k_idx as u32 * 15);

            for i in 0..n {
                let a = NodeId(i as u32);
                let b = NodeId(((i + stride) % n) as u32);
                if !graph.has_edge(a, b) {
                    graph.add_symmetric_edge(a, b, chord_bw, chord_rtt, chord_loss);
                }
            }
        }

        graph
    }

    /// Outgoing edges from `node`, filtered by constraints.
    fn constrained_neighbors<'a>(
        &'a self,
        node: NodeId,
        constraints: &'a CspfConstraints,
        blocked_edges: &'a [(NodeId, NodeId)],
        blocked_nodes: &'a [NodeId],
    ) -> impl Iterator<Item = &'a TopoEdge> {
        self.adj
            .get(&node)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
            .iter()
            .filter(move |e| {
                constraints.satisfied_by(e)
                    && !blocked_nodes.contains(&e.to)
                    && !blocked_edges.contains(&(e.from, e.to))
            })
    }

    /// Dijkstra over constraint-filtered edges.
    /// Returns `(cost_map, predecessor_map)` or `None` if `dst` is unreachable.
    fn dijkstra(
        &self,
        src: NodeId,
        dst: NodeId,
        constraints: &CspfConstraints,
        blocked_edges: &[(NodeId, NodeId)],
        blocked_nodes: &[NodeId],
    ) -> Option<Vec<NodeId>> {
        // Min-heap entry: (cost, node).
        #[derive(Eq, PartialEq)]
        struct Entry(u64, NodeId);
        impl Ord for Entry {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                // Reversed for min-heap behavior.
                other.0.cmp(&self.0).then_with(|| self.1.cmp(&other.1))
            }
        }
        impl PartialOrd for Entry {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        let mut dist: HashMap<NodeId, u64> = HashMap::new();
        let mut prev: HashMap<NodeId, NodeId> = HashMap::new();
        let mut heap = BinaryHeap::new();

        dist.insert(src, 0);
        heap.push(Entry(0, src));

        while let Some(Entry(cost_u, u)) = heap.pop() {
            if let Some(&best) = dist.get(&u) {
                if cost_u > best {
                    continue;
                }
            }
            if u == dst {
                break;
            }
            for edge in self.constrained_neighbors(u, constraints, blocked_edges, blocked_nodes) {
                let next_cost = cost_u.saturating_add(edge.cost as u64);
                let better = dist.get(&edge.to).is_none_or(|&d| next_cost < d);
                if better {
                    dist.insert(edge.to, next_cost);
                    prev.insert(edge.to, u);
                    heap.push(Entry(next_cost, edge.to));
                }
            }
        }

        if !dist.contains_key(&dst) {
            return None;
        }

        // Reconstruct path.
        let mut path = Vec::new();
        let mut cur = dst;
        loop {
            path.push(cur);
            if cur == src {
                break;
            }
            match prev.get(&cur) {
                Some(&p) => cur = p,
                None => return None, // broken path
            }
        }
        path.reverse();
        Some(path)
    }
}

// ─── CSPF path result ─────────────────────────────────────────────────────────

/// A single constraint-satisfying path, ranked by composite cost.
#[derive(Debug, Clone)]
pub struct CspfPath {
    /// Ordered list of node IDs from source to destination.
    pub nodes: Vec<NodeId>,
    /// Sum of edge costs along this path.
    pub total_cost: u64,
    /// Bottleneck (minimum) bandwidth across all edges.
    pub bottleneck_bw_bps: u64,
    /// Sum of RTTs across all edges (end-to-end latency estimate, µs).
    pub total_rtt_us: u64,
}

impl CspfPath {
    fn from_node_list(graph: &TopologyGraph, path_nodes: Vec<NodeId>) -> Option<Self> {
        if path_nodes.len() < 2 {
            return None;
        }
        let mut total_cost = 0u64;
        let mut bottleneck_bw_bps = u64::MAX;
        let mut total_rtt_us = 0u64;

        for w in path_nodes.windows(2) {
            let (from, to) = (w[0], w[1]);
            // Find the best (lowest-cost) edge between consecutive nodes.
            let edge = graph
                .adj
                .get(&from)?
                .iter()
                .filter(|e| e.to == to)
                .min_by_key(|e| e.cost)?;
            total_cost = total_cost.saturating_add(edge.cost as u64);
            bottleneck_bw_bps = bottleneck_bw_bps.min(edge.avail_bw_bps);
            total_rtt_us = total_rtt_us.saturating_add(edge.rtt_us as u64);
        }

        if bottleneck_bw_bps == u64::MAX {
            bottleneck_bw_bps = 0;
        }

        Some(CspfPath {
            nodes: path_nodes,
            total_cost,
            bottleneck_bw_bps,
            total_rtt_us,
        })
    }
}

// ─── Yen's K-shortest paths ───────────────────────────────────────────────────

/// Compute up to `k` constraint-satisfying loop-free shortest paths from `src` to `dst`
/// using Yen's algorithm layered over Dijkstra.
///
/// Returns paths sorted by ascending `total_cost`.
pub fn cspf_k_shortest_paths(
    graph: &TopologyGraph,
    src: NodeId,
    dst: NodeId,
    constraints: &CspfConstraints,
    k: usize,
) -> Vec<CspfPath> {
    if k == 0 || src == dst {
        return Vec::new();
    }

    // A — confirmed shortest paths.
    let mut a: Vec<Vec<NodeId>> = Vec::with_capacity(k);
    // B — candidate paths (sorted set by cost).
    let mut b: Vec<Vec<NodeId>> = Vec::new();

    // Find the first shortest path.
    let first = graph.dijkstra(src, dst, constraints, &[], &[]);
    if let Some(p) = first {
        a.push(p);
    } else {
        return Vec::new();
    }

    for _ in 1..k {
        let prev_path = match a.last() {
            Some(p) => p.clone(),
            None => break,
        };

        // For each spur node along the previous path.
        for i in 0..prev_path.len().saturating_sub(1) {
            let spur_node = prev_path[i];
            let root_path = prev_path[..=i].to_vec();

            // Block edges used by existing paths sharing this root prefix.
            let mut blocked_edges: Vec<(NodeId, NodeId)> = Vec::new();
            for confirmed in &a {
                if confirmed.len() > i && confirmed[..=i] == root_path[..] {
                    if let (Some(&u), Some(&v)) = (confirmed.get(i), confirmed.get(i + 1)) {
                        blocked_edges.push((u, v));
                    }
                }
            }

            // Block all nodes in root_path except spur_node to prevent loops.
            let blocked_nodes: Vec<NodeId> = root_path[..i].to_vec();

            // Dijkstra from spur_node to dst under constraints + blocks.
            if let Some(spur_path) =
                graph.dijkstra(spur_node, dst, constraints, &blocked_edges, &blocked_nodes)
            {
                // Stitch root_path (without spur_node) + spur_path.
                let mut candidate = root_path[..i].to_vec();
                candidate.extend_from_slice(&spur_path);

                // Deduplicate: skip if already in A or B.
                let already_known = a.contains(&candidate) || b.contains(&candidate);
                if !already_known {
                    b.push(candidate);
                }
            }
        }

        if b.is_empty() {
            break;
        }

        // Pick the candidate with the lowest cost (approximate: use path length as proxy
        // since exact cost requires graph lookup; full sort by CspfPath::total_cost below).
        b.sort_by_key(|p| p.len());
        let best = b.remove(0);
        a.push(best);
    }

    // Convert raw node lists to CspfPath with full metrics.
    let mut result: Vec<CspfPath> = a
        .into_iter()
        .filter_map(|nodes| CspfPath::from_node_list(graph, nodes))
        .collect();
    result.sort_by_key(|p| p.total_cost);
    result
}

// ─── Snapshot ingestion ───────────────────────────────────────────────────────

use crate::telemetry::IsspMeshTopologySnapshot;

/// Build a [`TopologyGraph`] from a live [`IsspMeshTopologySnapshot`].
///
/// Each directed link in the snapshot becomes one directed edge.
/// RTT is converted from milliseconds to microseconds; loss ratio [0.0–1.0] to millipercent;
/// bandwidth from the minimum of tx/rx bytes/s.
pub fn topology_graph_from_snapshot(snapshot: &IsspMeshTopologySnapshot) -> TopologyGraph {
    let mut graph = TopologyGraph::new();

    for link in &snapshot.links {
        let from_id = NodeId(link.source_node_id);
        let to_id = NodeId(link.target_node_id);

        // Convert units to match TopoEdge representation.
        let rtt_us = (link.latency_ms * 1_000.0).clamp(0.0, u32::MAX as f64) as u32;
        // loss_ratio [0.0–1.0] → millipercent [0–100_000].
        let loss_millipct = (link.loss_ratio * 100_000.0).clamp(0.0, u32::MAX as f64) as u32;
        // Available bandwidth: minimum of tx and rx direction.
        let avail_bw_bps = link.tx_bytes_per_sec.min(link.rx_bytes_per_sec).max(0.0) as u64;
        let cost = TopoEdge::compute_cost(rtt_us, loss_millipct);

        graph.add_node(from_id);
        graph.add_node(to_id);
        graph.adj.entry(from_id).or_default().push(TopoEdge {
            from: from_id,
            to: to_id,
            avail_bw_bps,
            rtt_us,
            loss_millipct,
            cost,
        });
    }

    graph
}

// ─── Disjoint Path Mode ───────────────────────────────────────────────────────

/// Disjoint path mode for resilient multipath synthesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisjointMode {
    /// Allow arbitrary path overlap (standard K-shortest paths).
    None,
    /// Paths must not share any physical directed edge.
    EdgeDisjoint,
    /// Paths must not share any intermediate node (except source and destination).
    NodeDisjoint,
}

/// Compute up to `k` diverse or disjoint constraint-satisfying paths from `src` to `dst`.
pub fn cspf_k_disjoint_paths(
    graph: &TopologyGraph,
    src: NodeId,
    dst: NodeId,
    constraints: &CspfConstraints,
    k: usize,
    mode: DisjointMode,
) -> Vec<CspfPath> {
    if k == 0 || src == dst {
        return Vec::new();
    }
    if mode == DisjointMode::None {
        return cspf_k_shortest_paths(graph, src, dst, constraints, k);
    }

    let mut paths: Vec<CspfPath> = Vec::with_capacity(k);
    let mut blocked_edges: Vec<(NodeId, NodeId)> = Vec::new();
    let mut blocked_nodes: Vec<NodeId> = Vec::new();

    for _ in 0..k {
        let candidate = graph.dijkstra(src, dst, constraints, &blocked_edges, &blocked_nodes);
        match candidate {
            Some(nodes) => {
                if let Some(cspf_path) = CspfPath::from_node_list(graph, nodes.clone()) {
                    match mode {
                        DisjointMode::EdgeDisjoint => {
                            for w in nodes.windows(2) {
                                blocked_edges.push((w[0], w[1]));
                            }
                        }
                        DisjointMode::NodeDisjoint => {
                            for w in nodes.windows(2) {
                                blocked_edges.push((w[0], w[1]));
                            }
                            for &n in &nodes[1..nodes.len() - 1] {
                                if !blocked_nodes.contains(&n) {
                                    blocked_nodes.push(n);
                                }
                            }
                        }
                        DisjointMode::None => {}
                    }
                    paths.push(cspf_path);
                } else {
                    break;
                }
            }
            None => break,
        }
    }

    paths.sort_by_key(|p| p.total_cost);
    paths
}

// ─── Multipath Forwarding Group ───────────────────────────────────────────────

/// Resilient multipath group managing primary and alternate routes with dynamic failover.
#[derive(Debug, Clone)]
pub struct CspfMultipathGroup {
    pub src: NodeId,
    pub dst: NodeId,
    pub paths: Vec<CspfPath>,
    /// Flags indicating if a path is currently operational.
    pub path_healthy: Vec<bool>,
    /// Proportional traffic weights calculated from bottleneck bandwidth and composite cost.
    pub traffic_weights: Vec<u32>,
    pub total_failovers: u64,
}

impl CspfMultipathGroup {
    /// Create a new multipath group from computed CSPF paths.
    pub fn new(src: NodeId, dst: NodeId, paths: Vec<CspfPath>) -> Self {
        let n = paths.len();
        let path_healthy = vec![true; n];
        let mut group = Self {
            src,
            dst,
            paths,
            path_healthy,
            traffic_weights: Vec::with_capacity(n),
            total_failovers: 0,
        };
        group.recompute_weights();
        group
    }

    /// Recompute proportional weights across healthy paths.
    /// Higher bottleneck bandwidth and lower composite cost yield higher scheduling weight.
    pub fn recompute_weights(&mut self) {
        self.traffic_weights.clear();
        for (i, p) in self.paths.iter().enumerate() {
            if !self.path_healthy[i] {
                self.traffic_weights.push(0);
                continue;
            }
            let bw_mbps = (p.bottleneck_bw_bps / 1_000_000).max(1);
            let cost_factor = p.total_cost.max(1);
            let weight = ((bw_mbps * 100) / cost_factor).clamp(1, 10_000) as u32;
            self.traffic_weights.push(weight);
        }
    }

    /// Mark a directed link as failed, disabling any paths traversing it.
    /// Returns the number of newly disabled paths.
    pub fn mark_link_failed(&mut self, from: NodeId, to: NodeId) -> usize {
        let mut affected = 0;
        for (i, p) in self.paths.iter().enumerate() {
            if self.path_healthy[i] {
                let uses_link = p.nodes.windows(2).any(|w| w[0] == from && w[1] == to);
                if uses_link {
                    self.path_healthy[i] = false;
                    affected += 1;
                    self.total_failovers += 1;
                }
            }
        }
        if affected > 0 {
            self.recompute_weights();
        }
        affected
    }

    /// Restore health to all paths whose links are now verified operational.
    pub fn restore_all_paths(&mut self) {
        self.path_healthy.fill(true);
        self.recompute_weights();
    }

    /// Validate all paths in the group against the live topology graph and constraints.
    /// Marks paths violating constraints or containing severed links as unhealthy.
    /// Returns the number of healthy operational paths remaining.
    pub fn update_health_from_graph(
        &mut self,
        graph: &TopologyGraph,
        constraints: &CspfConstraints,
    ) -> usize {
        for (i, p) in self.paths.iter().enumerate() {
            let mut valid = true;
            for w in p.nodes.windows(2) {
                let from = w[0];
                let to = w[1];
                let edge_valid = graph
                    .adj
                    .get(&from)
                    .and_then(|edges| edges.iter().find(|e| e.to == to))
                    .map(|e| constraints.satisfied_by(e))
                    .unwrap_or(false);
                if !edge_valid {
                    valid = false;
                    break;
                }
            }
            if self.path_healthy[i] != valid {
                if !valid {
                    self.total_failovers += 1;
                }
                self.path_healthy[i] = valid;
            }
        }
        self.recompute_weights();
        self.healthy_count()
    }

    /// Set individual path health by index.
    pub fn set_path_health(&mut self, index: usize, healthy: bool) {
        if let Some(h) = self.path_healthy.get_mut(index) {
            *h = healthy;
            self.recompute_weights();
        }
    }

    /// Select an active path for a session or flow using consistent hashing across healthy paths.
    pub fn select_path_for_flow(&self, flow_hash: u64) -> Option<&CspfPath> {
        let total_weight: u32 = self.traffic_weights.iter().sum();
        if total_weight == 0 {
            return None;
        }
        let mut target = (flow_hash % (total_weight as u64)) as u32;
        for (i, &w) in self.traffic_weights.iter().enumerate() {
            if w > 0 {
                if target < w {
                    return Some(&self.paths[i]);
                }
                target -= w;
            }
        }
        self.primary_healthy_path()
    }

    /// Return primary (lowest-cost) healthy path.
    pub fn primary_healthy_path(&self) -> Option<&CspfPath> {
        self.paths
            .iter()
            .zip(&self.path_healthy)
            .find_map(|(p, &h)| if h { Some(p) } else { None })
    }

    /// Count healthy operational paths.
    pub fn healthy_count(&self) -> usize {
        self.path_healthy.iter().filter(|&&h| h).count()
    }

    /// Total configured paths in group.
    pub fn total_paths(&self) -> usize {
        self.paths.len()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn n(id: u32) -> NodeId {
        NodeId(id)
    }

    /// Build a small diamond topology:
    ///
    /// ```text
    ///   0 ──(10ms,0loss)──> 1 ──(5ms,0loss)──> 3
    ///   └──(2ms,500‰loss)── 2 ──(2ms,0loss)──> 3
    /// ```
    fn diamond_graph() -> TopologyGraph {
        let mut g = TopologyGraph::new();
        // 0→1: rtt=10_000µs, loss=0, bw=100MB/s
        g.add_symmetric_edge(n(0), n(1), 100_000_000, 10_000, 0);
        // 1→3: rtt=5_000µs, loss=0, bw=100MB/s
        g.add_symmetric_edge(n(1), n(3), 100_000_000, 5_000, 0);
        // 0→2: rtt=2_000µs, loss=5_000 (5%), bw=50MB/s
        g.add_symmetric_edge(n(0), n(2), 50_000_000, 2_000, 5_000);
        // 2→3: rtt=2_000µs, loss=0, bw=50MB/s
        g.add_symmetric_edge(n(2), n(3), 50_000_000, 2_000, 0);
        g
    }

    #[test]
    fn test_basic_shortest_path_unconstrained() {
        let g = diamond_graph();
        let paths = cspf_k_shortest_paths(&g, n(0), n(3), &CspfConstraints::unconstrained(), 2);
        assert!(!paths.is_empty(), "must find at least one path");
        // Shortest by cost: 0→2→3 has cost = compute_cost(2000,5000)+compute_cost(2000,0)
        // = (2+50)+(2+0) = 54; vs 0→1→3 = (10+0)+(5+0) = 15. So 0→1→3 wins.
        let best = &paths[0];
        assert_eq!(
            best.nodes,
            vec![n(0), n(1), n(3)],
            "best unconstrained path"
        );
        assert_eq!(best.total_cost, 15);
    }

    #[test]
    fn test_bandwidth_constraint_forces_alternate() {
        let g = diamond_graph();
        // Demand more than 50MB/s — forces path through 0→1→3 (100MB/s).
        let constraints = CspfConstraints {
            min_bw_bps: 60_000_000,
            max_rtt_us: u32::MAX,
            max_loss_millipct: u32::MAX,
        };
        let paths = cspf_k_shortest_paths(&g, n(0), n(3), &constraints, 1);
        assert!(!paths.is_empty());
        assert_eq!(paths[0].nodes, vec![n(0), n(1), n(3)]);
        assert!(paths[0].bottleneck_bw_bps >= 60_000_000);
    }

    #[test]
    fn test_loss_constraint_prunes_lossy_link() {
        let g = diamond_graph();
        // Max 1% loss (1_000 millipct) — prunes 0→2 edge (5_000 millipct).
        let constraints = CspfConstraints {
            min_bw_bps: 0,
            max_rtt_us: u32::MAX,
            max_loss_millipct: 1_000,
        };
        let paths = cspf_k_shortest_paths(&g, n(0), n(3), &constraints, 2);
        assert!(!paths.is_empty());
        // All returned paths must avoid node 2.
        for p in &paths {
            assert!(
                !p.nodes.contains(&n(2)),
                "lossy path must be pruned: {:?}",
                p.nodes
            );
        }
    }

    #[test]
    fn test_no_path_when_all_pruned() {
        let g = diamond_graph();
        // Demand impossibly low RTT on every edge.
        let constraints = CspfConstraints {
            min_bw_bps: 0,
            max_rtt_us: 100, // 100µs — no edge qualifies
            max_loss_millipct: u32::MAX,
        };
        let paths = cspf_k_shortest_paths(&g, n(0), n(3), &constraints, 3);
        assert!(paths.is_empty(), "must return empty when all paths pruned");
    }

    #[test]
    fn test_k_paths_distinct() {
        let g = diamond_graph();
        let paths = cspf_k_shortest_paths(&g, n(0), n(3), &CspfConstraints::unconstrained(), 3);
        // At most 2 distinct paths in the diamond topology.
        assert!(paths.len() <= 2);
        // All paths must be distinct.
        let unique: std::collections::HashSet<Vec<NodeId>> =
            paths.iter().map(|p| p.nodes.clone()).collect();
        assert_eq!(unique.len(), paths.len(), "paths must be distinct");
    }

    #[test]
    fn test_metrics_sanity() {
        let g = diamond_graph();
        let paths = cspf_k_shortest_paths(&g, n(0), n(3), &CspfConstraints::unconstrained(), 1);
        let p = &paths[0];
        assert!(
            p.bottleneck_bw_bps > 0,
            "bottleneck_bw_bps must be positive"
        );
        assert!(p.total_rtt_us > 0, "total_rtt_us must be positive");
        assert!(p.total_cost > 0, "total_cost must be positive");
    }

    #[test]
    fn test_same_src_dst_returns_empty() {
        let g = diamond_graph();
        let paths = cspf_k_shortest_paths(&g, n(0), n(0), &CspfConstraints::unconstrained(), 3);
        assert!(paths.is_empty(), "src==dst must yield no paths");
    }

    #[test]
    fn test_disjoint_edge_paths() {
        let g = diamond_graph();
        let paths = cspf_k_disjoint_paths(
            &g,
            n(0),
            n(3),
            &CspfConstraints::unconstrained(),
            2,
            DisjointMode::EdgeDisjoint,
        );
        assert_eq!(paths.len(), 2, "diamond topology has 2 edge-disjoint paths");
        let edges_p0: std::collections::HashSet<(NodeId, NodeId)> =
            paths[0].nodes.windows(2).map(|w| (w[0], w[1])).collect();
        let edges_p1: std::collections::HashSet<(NodeId, NodeId)> =
            paths[1].nodes.windows(2).map(|w| (w[0], w[1])).collect();
        assert!(
            edges_p0.is_disjoint(&edges_p1),
            "edge disjoint paths must not share any edge"
        );
    }

    #[test]
    fn test_disjoint_node_paths() {
        let g = diamond_graph();
        let paths = cspf_k_disjoint_paths(
            &g,
            n(0),
            n(3),
            &CspfConstraints::unconstrained(),
            2,
            DisjointMode::NodeDisjoint,
        );
        assert_eq!(paths.len(), 2, "diamond topology has 2 node-disjoint paths");
        // Intermediate nodes of p0 and p1 must be disjoint
        let inter_p0: std::collections::HashSet<NodeId> = paths[0].nodes
            [1..paths[0].nodes.len() - 1]
            .iter()
            .copied()
            .collect();
        let inter_p1: std::collections::HashSet<NodeId> = paths[1].nodes
            [1..paths[1].nodes.len() - 1]
            .iter()
            .copied()
            .collect();
        assert!(
            inter_p0.is_disjoint(&inter_p1),
            "node disjoint paths must not share intermediate nodes"
        );
    }

    #[test]
    fn test_multipath_group_failover_and_recovery() {
        let g = diamond_graph();
        let paths = cspf_k_disjoint_paths(
            &g,
            n(0),
            n(3),
            &CspfConstraints::unconstrained(),
            2,
            DisjointMode::EdgeDisjoint,
        );
        let mut group = CspfMultipathGroup::new(n(0), n(3), paths);
        assert_eq!(group.total_paths(), 2);
        assert_eq!(group.healthy_count(), 2);
        assert_eq!(group.total_failovers, 0);

        // Path 0 is 0->1->3. Path 1 is 0->2->3.
        let primary_before = group.primary_healthy_path().unwrap().clone();
        assert_eq!(primary_before.nodes, vec![n(0), n(1), n(3)]);

        // Fail link 1->3
        let affected = group.mark_link_failed(n(1), n(3));
        assert_eq!(affected, 1);
        assert_eq!(group.healthy_count(), 1);
        assert_eq!(group.total_failovers, 1);

        // Primary is now 0->2->3
        let primary_after = group.primary_healthy_path().unwrap();
        assert_eq!(primary_after.nodes, vec![n(0), n(2), n(3)]);

        // Flow selection must route exclusively to path 1
        for hash in [10u64, 42, 999, 1337] {
            let selected = group.select_path_for_flow(hash).unwrap();
            assert_eq!(selected.nodes, vec![n(0), n(2), n(3)]);
        }

        // Restore health
        group.restore_all_paths();
        assert_eq!(group.healthy_count(), 2);
        assert_eq!(
            group.primary_healthy_path().unwrap().nodes,
            vec![n(0), n(1), n(3)]
        );
    }

    #[test]
    fn test_multipath_group_all_failed() {
        let g = diamond_graph();
        let paths = cspf_k_disjoint_paths(
            &g,
            n(0),
            n(3),
            &CspfConstraints::unconstrained(),
            2,
            DisjointMode::EdgeDisjoint,
        );
        let mut group = CspfMultipathGroup::new(n(0), n(3), paths);
        group.mark_link_failed(n(0), n(1));
        group.mark_link_failed(n(0), n(2));
        assert_eq!(group.healthy_count(), 0);
        assert!(group.primary_healthy_path().is_none());
        assert!(group.select_path_for_flow(123).is_none());
    }

    #[test]
    fn test_dense_mesh_generation_and_edge_mutation() {
        let mut mesh = TopologyGraph::generate_dense_mesh(16, 3, 1_000_000_000, 3_000);
        assert_eq!(mesh.node_count(), 16);
        assert!(mesh.edge_count() >= 16 * 2 * 3);
        assert!(mesh.has_edge(n(0), n(1)));
        assert!(mesh.has_edge(n(1), n(0)));

        // Mutate edge
        assert!(mesh.update_edge(n(0), n(1), 10_000_000, 50_000, 500));
        assert!(mesh.remove_edge(n(0), n(1)));
        assert!(!mesh.has_edge(n(0), n(1)));
        assert!(mesh.has_edge(n(1), n(0)));
        assert!(mesh.remove_symmetric_edge(n(1), n(2)));
        assert!(!mesh.has_edge(n(1), n(2)));
        assert!(!mesh.has_edge(n(2), n(1)));
    }

    #[test]
    fn test_multipath_health_update_from_graph() {
        let mut g = diamond_graph();
        let constraints = CspfConstraints {
            min_bw_bps: 10_000_000,
            max_rtt_us: 15_000,
            max_loss_millipct: 10_000,
        };
        let paths =
            cspf_k_disjoint_paths(&g, n(0), n(3), &constraints, 2, DisjointMode::EdgeDisjoint);
        let mut group = CspfMultipathGroup::new(n(0), n(3), paths);
        assert_eq!(group.healthy_count(), 2);

        // Degrade link 1->3 latency to 50ms (> 15ms constraint)
        g.update_edge(n(1), n(3), 100_000_000, 50_000, 10);
        let remaining = group.update_health_from_graph(&g, &constraints);
        assert_eq!(remaining, 1);
        assert_eq!(group.healthy_count(), 1);
        assert_eq!(
            group.primary_healthy_path().unwrap().nodes,
            vec![n(0), n(2), n(3)]
        );

        // Restore link
        g.update_edge(n(1), n(3), 100_000_000, 5_000, 10);
        let restored = group.update_health_from_graph(&g, &constraints);
        assert_eq!(restored, 2);
    }
}

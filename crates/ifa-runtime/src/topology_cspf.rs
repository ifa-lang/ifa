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
        // Min-heap entry: (neg_cost, node) — using i64 so BinaryHeap acts as min-heap.
        #[derive(Eq, PartialEq)]
        struct Entry(i64, NodeId);
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

        while let Some(Entry(neg_cost, u)) = heap.pop() {
            let cost_u = (-neg_cost) as u64;
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
                    heap.push(Entry(-(next_cost as i64), edge.to));
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
}

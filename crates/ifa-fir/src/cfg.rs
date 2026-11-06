use crate::ir::{BlockId, FirFunction};
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{HashMap, HashSet, VecDeque};

/// Control Flow Graph (CFG) analysis for a FIR function.
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    pub graph: DiGraph<BlockId, ()>,
    pub node_indices: HashMap<BlockId, NodeIndex>,
    pub predecessors: HashMap<BlockId, Vec<BlockId>>,
    pub successors: HashMap<BlockId, Vec<BlockId>>,
    pub entry: BlockId,
}

impl ControlFlowGraph {
    /// Build the CFG from a FIR function.
    pub fn build(func: &FirFunction) -> Self {
        let mut graph = DiGraph::new();
        let mut node_indices = HashMap::new();
        let mut predecessors: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        let mut successors: HashMap<BlockId, Vec<BlockId>> = HashMap::new();

        // 1. Add all blocks as nodes in the graph
        for block in &func.blocks {
            let node_idx = graph.add_node(block.id);
            node_indices.insert(block.id, node_idx);
            predecessors.insert(block.id, Vec::new());
            successors.insert(block.id, Vec::new());
        }

        // 2. Add edges based on block terminators
        for block in &func.blocks {
            if let Some(terminator) = &block.terminator {
                let succs = terminator.successors();
                for succ in &succs {
                    if let (Some(&u), Some(&v)) =
                        (node_indices.get(&block.id), node_indices.get(succ))
                    {
                        graph.add_edge(u, v, ());
                    }
                    if let Some(preds) = predecessors.get_mut(succ) {
                        if !preds.contains(&block.id) {
                            preds.push(block.id);
                        }
                    }
                }
                successors.insert(block.id, succs);
            }
        }

        Self {
            graph,
            node_indices,
            predecessors,
            successors,
            entry: func.entry_block,
        }
    }

    /// Compute set of reachable basic blocks starting from the entry block.
    pub fn reachable_blocks(&self) -> HashSet<BlockId> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        visited.insert(self.entry);
        queue.push_back(self.entry);

        while let Some(current) = queue.pop_front() {
            if let Some(succs) = self.successors.get(&current) {
                for succ in succs {
                    if visited.insert(*succ) {
                        queue.push_back(*succ);
                    }
                }
            }
        }

        visited
    }

    /// Compute reverse post-order (RPO) ordering of basic blocks.
    pub fn reverse_post_order(&self) -> Vec<BlockId> {
        let mut visited = HashSet::new();
        let mut post_order = Vec::new();

        fn dfs(
            block: BlockId,
            cfg: &ControlFlowGraph,
            visited: &mut HashSet<BlockId>,
            post_order: &mut Vec<BlockId>,
        ) {
            visited.insert(block);
            if let Some(succs) = cfg.successors.get(&block) {
                for &succ in succs {
                    if !visited.contains(&succ) {
                        dfs(succ, cfg, visited, post_order);
                    }
                }
            }
            post_order.push(block);
        }

        dfs(self.entry, self, &mut visited, &mut post_order);
        post_order.reverse();
        post_order
    }
}

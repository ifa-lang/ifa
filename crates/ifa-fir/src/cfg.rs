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

/// Topologically schedules instructions within a basic block according to intra-block SSA data dependencies.
/// Ensures that every instruction defining a SSA value strictly precedes all instructions using it within the same block.
pub fn schedule_block_instructions_topologically(block: &mut crate::ir::BasicBlock) {
    if block.instructions.len() <= 1 {
        return;
    }

    let n = block.instructions.len();
    let mut def_to_inst: HashMap<crate::ir::ValueId, usize> = HashMap::new();
    for (idx, inst) in block.instructions.iter().enumerate() {
        if let Some(res) = inst.result {
            def_to_inst.insert(res, idx);
        }
    }

    // intra_block_deps[i] = list of instruction indices in the same block that depend on instruction i's result
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut in_degree: Vec<usize> = vec![0; n];

    for (idx, inst) in block.instructions.iter().enumerate() {
        for used in inst.expr.uses() {
            if let Some(&producer_idx) = def_to_inst.get(&used) {
                if producer_idx != idx {
                    dependents[producer_idx].push(idx);
                    in_degree[idx] += 1;
                }
            }
        }
    }

    // If already in topological order, skip re-allocation
    let mut already_sorted = true;
    for (producer_idx, deps) in dependents.iter().enumerate() {
        for &consumer_idx in deps {
            if producer_idx >= consumer_idx {
                already_sorted = false;
                break;
            }
        }
        if !already_sorted {
            break;
        }
    }
    if already_sorted {
        return;
    }

    // Stable topological sort using double-ended queue prioritizing smaller original index
    let mut available: VecDeque<usize> = VecDeque::new();
    for (idx, &degree) in in_degree.iter().enumerate() {
        if degree == 0 {
            available.push_back(idx);
        }
    }

    let mut scheduled_indices = Vec::with_capacity(n);
    while let Some(idx) = available.pop_front() {
        scheduled_indices.push(idx);
        for &dep in &dependents[idx] {
            in_degree[dep] -= 1;
            if in_degree[dep] == 0 {
                let insert_pos = available.binary_search(&dep).unwrap_or_else(|pos| pos);
                available.insert(insert_pos, dep);
            }
        }
    }

    // If there were any unvisited instructions (e.g. cycle safeguard), append them
    if scheduled_indices.len() < n {
        for idx in 0..n {
            if !scheduled_indices.contains(&idx) {
                scheduled_indices.push(idx);
            }
        }
    }

    // Reconstruct instructions array according to scheduled indices
    let old_instructions = std::mem::take(&mut block.instructions);
    let mut new_instructions = Vec::with_capacity(n);
    let mut old_indexed: Vec<Option<crate::ir::Instruction>> =
        old_instructions.into_iter().map(Some).collect();
    for idx in scheduled_indices {
        if let Some(inst) = old_indexed[idx].take() {
            new_instructions.push(inst);
        }
    }

    block.instructions = new_instructions;
}

/// Topologically schedules instructions across all blocks in a FIR function.
pub fn schedule_function_instructions(func: &mut FirFunction) {
    for block in &mut func.blocks {
        schedule_block_instructions_topologically(block);
    }
}

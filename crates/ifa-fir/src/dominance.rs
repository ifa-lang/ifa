use crate::cfg::ControlFlowGraph;
use crate::ir::BlockId;
use std::collections::HashMap;

/// Dominator Tree computed over a CFG.
#[derive(Debug, Clone)]
pub struct DominanceTree {
    pub idom: HashMap<BlockId, BlockId>,
    pub rpo_indices: HashMap<BlockId, usize>,
    pub rpo_blocks: Vec<BlockId>,
    pub entry: BlockId,
}

impl DominanceTree {
    /// Compute the dominator tree using the Cooper-Harvey-Kennedy algorithm.
    pub fn build(cfg: &ControlFlowGraph) -> Self {
        let rpo_blocks = cfg.reverse_post_order();
        let mut rpo_indices = HashMap::new();
        for (idx, &b) in rpo_blocks.iter().enumerate() {
            rpo_indices.insert(b, idx);
        }

        let mut idom: HashMap<BlockId, BlockId> = HashMap::new();
        let entry = cfg.entry;
        idom.insert(entry, entry);

        let mut changed = true;
        while changed {
            changed = false;

            // Iterate over all reachable blocks in RPO, skipping entry
            for &b in &rpo_blocks {
                if b == entry {
                    continue;
                }

                let preds = match cfg.predecessors.get(&b) {
                    Some(p) => p,
                    None => continue,
                };

                // Find first processed predecessor
                let mut processed_preds = preds.iter().filter(|p| idom.contains_key(p));
                let first_pred = match processed_preds.next() {
                    Some(&p) => p,
                    None => continue,
                };

                let mut new_idom = first_pred;

                // Intersect with remaining processed predecessors
                for &p in processed_preds {
                    new_idom = Self::intersect(p, new_idom, &idom, &rpo_indices);
                }

                if idom.get(&b) != Some(&new_idom) {
                    idom.insert(b, new_idom);
                    changed = true;
                }
            }
        }

        Self {
            idom,
            rpo_indices,
            rpo_blocks,
            entry,
        }
    }

    /// Two-finger intersect function on RPO indices.
    fn intersect(
        mut b1: BlockId,
        mut b2: BlockId,
        idom: &HashMap<BlockId, BlockId>,
        rpo_indices: &HashMap<BlockId, usize>,
    ) -> BlockId {
        while b1 != b2 {
            while rpo_indices.get(&b1) > rpo_indices.get(&b2) {
                b1 = *idom.get(&b1).unwrap_or(&b1);
            }
            while rpo_indices.get(&b2) > rpo_indices.get(&b1) {
                b2 = *idom.get(&b2).unwrap_or(&b2);
            }
        }
        b1
    }

    /// Returns true if block `a` dominates block `b`.
    pub fn dominates(&self, a: BlockId, mut b: BlockId) -> bool {
        if a == b {
            return true;
        }
        if !self.idom.contains_key(&b) {
            return false;
        }

        while let Some(&parent) = self.idom.get(&b) {
            if parent == a {
                return true;
            }
            if parent == b {
                // Reached entry or root cycle
                break;
            }
            b = parent;
        }
        false
    }

    /// Returns true if block `a` strictly dominates block `b` (a != b and a dominates b).
    pub fn strictly_dominates(&self, a: BlockId, b: BlockId) -> bool {
        a != b && self.dominates(a, b)
    }

    /// Return immediate dominator of a block, if any.
    pub fn immediate_dominator(&self, b: BlockId) -> Option<BlockId> {
        self.idom.get(&b).copied().filter(|&parent| parent != b)
    }
}

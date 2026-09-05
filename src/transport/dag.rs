//! W8 dag: causal DAG over envelope hashes (dag.zig port).
//!
//! BE-EVID-05 supersession: a span signed at a volatile resource is superseded
//! when a later Effect on the same resource_id is visible at the claim.
//! "Later" and "visible" are both causal, not temporal, so the question is one
//! of ancestry in a directed acyclic graph of envelopes.
//!
//! Zero-heap and caller-owned: the caller declares the Dag on its own frame
//! and the structure never allocates. Capacity is fixed; an insert past
//! capacity is an error. isAncestor uses an explicit work queue and a visited
//! bitmap, never recursion (BE-DEP-02 shape).

pub const NODE_BYTES: usize = 32;
pub type Node = [u8; NODE_BYTES];

pub const MAX_NODES: usize = 128;
pub const MAX_PARENTS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DagError {
    Overflow,
    Cyclic,
    NotNode,
}

pub struct Dag {
    nodes: [[u8; NODE_BYTES]; MAX_NODES],
    node_count: usize,
    parents: [[u16; MAX_PARENTS]; MAX_NODES],
    parent_count: [u8; MAX_NODES],
    visited: [bool; MAX_NODES],
    queue: [u16; MAX_NODES],
}

impl Default for Dag {
    fn default() -> Self {
        Self {
            nodes: [[0u8; NODE_BYTES]; MAX_NODES],
            node_count: 0,
            parents: [[0u16; MAX_PARENTS]; MAX_NODES],
            parent_count: [0u8; MAX_NODES],
            visited: [false; MAX_NODES],
            queue: [0u16; MAX_NODES],
        }
    }
}

impl Dag {
    pub fn new() -> Self {
        Self::default()
    }

    /// Linear scan for a node's index. Returns None if not interned.
    pub fn index_of(&self, hash: &Node) -> Option<u16> {
        for i in 0..self.node_count {
            if &self.nodes[i] == hash {
                return Some(i as u16);
            }
        }
        None
    }

    pub fn contains(&self, hash: &Node) -> bool {
        self.index_of(hash).is_some()
    }

    /// Add a node if absent and return its index.
    fn intern(&mut self, hash: &Node) -> Result<u16, DagError> {
        if let Some(idx) = self.index_of(hash) {
            return Ok(idx);
        }
        if self.node_count >= MAX_NODES {
            return Err(DagError::Overflow);
        }
        let idx = self.node_count as u16;
        self.nodes[idx as usize] = *hash;
        self.parent_count[idx as usize] = 0;
        self.node_count += 1;
        Ok(idx)
    }

    /// Record that `child` causally depends on `parent`.
    /// Rejects self-loops (BE-EVID-05a) and cycle-closing edges.
    /// Idempotent on repeat of the exact same edge.
    pub fn insert(&mut self, parent: &Node, child: &Node) -> Result<(), DagError> {
        // I1: self-loop forbidden
        if parent == child {
            return Err(DagError::Cyclic);
        }

        let pidx = self.intern(parent)?;
        let cidx = self.intern(child)?;

        // I2: cycle guard — if child is already an ancestor of parent,
        // wiring parent as parent of child would close a loop.
        if self.is_ancestor_idx(cidx, pidx) {
            return Err(DagError::Cyclic);
        }

        // I3: idempotent — skip if parent already recorded for child
        let pc = self.parent_count[cidx as usize] as usize;
        for k in 0..pc {
            if self.parents[cidx as usize][k] == pidx {
                return Ok(());
            }
        }
        if pc >= MAX_PARENTS {
            return Err(DagError::Overflow);
        }
        self.parents[cidx as usize][pc] = pidx;
        self.parent_count[cidx as usize] = (pc + 1) as u8;
        Ok(())
    }

    /// BFS from descendant over parent links. No recursion (BE-DEP-02).
    fn is_ancestor_idx(&mut self, ancestor: u16, descendant: u16) -> bool {
        if ancestor == descendant {
            return false;
        }

        let mut head: usize = 0;
        let mut tail: usize = 0;
        let mut touched = [0u16; MAX_NODES];
        let mut touched_n: usize = 0;

        self.queue[tail] = descendant;
        tail += 1;
        self.visited[descendant as usize] = true;
        touched[touched_n] = descendant;
        touched_n += 1;

        while head < tail {
            let cur = self.queue[head] as usize;
            head += 1;
            let pc = self.parent_count[cur] as usize;
            for k in 0..pc {
                let p = self.parents[cur][k];
                if p == ancestor {
                    self.reset_visited(&touched, touched_n);
                    return true;
                }
                if !self.visited[p as usize] {
                    self.visited[p as usize] = true;
                    touched[touched_n] = p;
                    touched_n += 1;
                    self.queue[tail] = p;
                    tail += 1;
                }
            }
        }
        self.reset_visited(&touched, touched_n);
        false
    }

    fn reset_visited(&mut self, touched: &[u16; MAX_NODES], n: usize) {
        for i in 0..n {
            self.visited[touched[i] as usize] = false;
        }
    }

    /// Public hash-keyed ancestry. Returns false if either node unknown (fail-closed).
    pub fn is_ancestor(&mut self, ancestor: &Node, descendant: &Node) -> bool {
        let a = match self.index_of(ancestor) {
            Some(idx) => idx,
            None => return false,
        };
        let d = match self.index_of(descendant) {
            Some(idx) => idx,
            None => return false,
        };
        self.is_ancestor_idx(a, d)
    }

    /// BE-EVID-05/05a supersession predicate.
    /// span@origin superseded iff isAncestor(origin,effect) AND isAncestor(effect,claim).
    pub fn supersedes(&mut self, origin: &Node, effect: &Node, claim: &Node) -> bool {
        self.is_ancestor(origin, effect) && self.is_ancestor(effect, claim)
    }
}

/// Convert a 32-byte slice to a Node. Returns NotNode if wrong length.
pub fn node_from_slice(s: &[u8]) -> Result<Node, DagError> {
    if s.len() != NODE_BYTES {
        return Err(DagError::NotNode);
    }
    let mut n = [0u8; NODE_BYTES];
    n.copy_from_slice(s);
    Ok(n)
}

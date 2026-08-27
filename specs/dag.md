# dag.zig - causal DAG (BE-EVID-05/05a supersession)

## Contract
Causal ancestry over envelope hashes. Node = 32-byte envelope hash (same bytes a Span origin carries). insert(parent, child) records child causally depends on parent; isAncestor(a,d) answers STRICT proper ancestry (a happened-before d AND a != d).

## Public surface (cite dag.zig)
- const NODE_BYTES=32, Node=[32]u8 (dag.zig:34-35); MAX_NODES=128, MAX_PARENTS=8 (37-38) fixed caps, error.Overflow past them, NEVER allocate
- DagError{Overflow,Cyclic,NotNode} (DagError, dag.zig:40-44); nodeFromSlice returns NotNode unless len==32 exactly (tail of file) so a malformed caller cannot read past the slice
- indexOf linear scan returning ?u16 (no hash index at this capacity - intentional, port as-is); contains/insert/isAncestor/supersedes pub

## Invariants (each must survive port + have a named Rust test)
- I1 SELF-LOOP FORBIDDEN: insert(x,x) returns Cyclic (BE-EVID-05a strict, dag.zig:78). isAncestorIdx(a,a)==false structurally: traversal only inspects parents and self-loops are unrepresentable
- I2 CYCLE-FREE BY CONSTRUCTION: an edge closing a cycle is rejected by checking isAncestorIdx(child, parent) BEFORE wiring (dag.zig:86-88). No trust in insertion order
- I3 IDEMPOTENT EDGES: repeating the exact same edge is a no-op skip, not an error (dag.zig:90-95)
- I4 NO RECURSION EVER (BE-DEP-02 shape): isAncestorIdx is BFS with caller-owned work queue + visited bitmap, high-water-mark reset only of touched nodes (dag.zig:99-135). A thousand-deep chain cannot overflow the stack; diamonds walked once per node
- I5 FAIL-CLOSED LOOKUPS: isAncestor returns false if EITHER endpoint is uninterned - a missing node has no causal position (dag.zig:141-144)
- I6 SUPERSESSION PREDICATE (supersedes, dag.zig:151-153): span@origin superseded iff isAncestor(origin,effect) AND isAncestor(effect,claim). BOTH conjuncts strict => origin Effect never supersedes its own span; effect at-or-after claim does not count. Resource_id match is the CALLER concern, deliberately NOT here - port must keep this split

## Test semantics to port (from src/dag_test.zig, named tests = Rust test names)
- BE_EVID_05a strict causal descendant enforced (dag_test.zig:32): self-ancestry false
- diamond DAG ancestry across paths and siblings (:60)
- deep chain ancestry without recursion (:88) - the I4 stack-safety proof
- cycle edges are rejected at insert (:108) - I2
- supersession requires descendant of origin and ancestor of claim (:128) - I6 both conjuncts
- BE_EVID_05 superseded volatile span drops claim stable span unaffected (:167) - end-to-end with resource indexing

## Notes for Rust port
Zero-heap caller-owned value (declare on frame), visited+queue are FIELDS of the struct reused per query, u16 indices. Port struct-of-arrays layout faithfully: parents:[128][8]u16 flat.

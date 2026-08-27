# reassembly.zig - BE-TR-05 fragmentation accounting (metadata-only)

## Contract
Fragment reassembly STATE under the declared BE-TR-05 limits (SPEC 4.4 table / 4.5). This module stores NO payload bytes: it tracks which fragment indices arrived, bytes a peer is holding, timeouts, node admission capacity. Caller owns byte buffers and places fragments; module answers accounting questions. Keeps metadata ~1 KB instead of 8 MiB; matches D-018 state-outside-parser.

## The limits table - TWO SCOPES, TWO FAILURE SEMANTICS (the load-bearing design decision)
- Constants are the SINGLE SOURCE OF TRUTH for every attacker-influenced buffer size (reassembly.zig:39-47): MAX_MESSAGE=1MiB, MAX_HEADER=512, MAX_BODY_LEN=MAX_MESSAGE-MAX_HEADER, CONTEXTS_PER_PEER=8, MEMORY_PER_PEER=8MiB, SESSIONS_PER_NODE=512, MEMORY_PER_NODE=256MiB, INCOMPLETE_TIMEOUT_MS=30_000
- MESSAGE scope breach (per peer): drop THE MESSAGE, keep the session. Never kill the connection over one bad message
- NODE scope breach: REFUSE NEW SESSIONS rather than degrade existing ones; MUST surface as capacity condition, never silently absorbed
History note worth porting knowledge: an earlier draft had per-peer 8MiB with no node ceiling = unbounded total on lighthouse nodes facing most peers. The Rust port must not regress this split.

## Public surface (cite reassembly.zig)
- PeerEvent{complete, partial, duplicate, message_dropped} (enum at ~line 50): duplicate = index already seen, counted once, NO byte accounting NO completion; message_dropped tears down that context only
- NodeEvent{admitted, refused}
- PeerReassembler(comptime max_contexts:u8, comptime max_fragments_per_msg:u16) GENERIC: tests instantiate tiny, production passes real BE-TR-05 values (~line 66). Bitset [ceil(n/64)]u64 seen-vector
- Context metadata {msg_id,total,received,bytes,updated_ms,in_use,seen} (~line 79)
- ingest(now_ms,msg_id,index,total,frag_bytes) full gate order: malformed (total==0 | index>=total | total>ceiling) -> drop; second fragment disagreeing on total -> free+drop; duplicate -> duplicate; c.bytes+frag>MAX_MESSAGE OR peer budget breach -> freeContext+drop; then set/receive/count and complete when received>=total (~lines 100-160)
- evictExpired uses WRAPPING compare (now_ms -% updated_ms) >= 30s (evictExpired)
- NodeCapacity{tryAdmitSession,releaseSession,withinMemory(wrapping sub),addBytes,releaseBytes clamped at 0} (tail of file)

## Test semantics to port (src/reassembly_test.zig named tests = Rust test names)
- BE_TR_05 out-of-order fragments reassemble then the message completes (:15)
- fragments delivered in reverse accumulate bytes and complete on the last (:26)
- a duplicate fragment index is counted once and changes nothing (:44)
- exceeding the per-peer context limit drops the new message, NOT the session (:57)
- exceeding the per-peer memory budget drops the message, NOT the session (:72)
- an incomplete context older than 30 seconds is evicted on sweep (:87)
- NodeCapacity admits sessions up to the node ceiling then refuses (:100)
- NodeCapacity memory gate accepts under the ceiling and rejects over it (:115)

## Notes for Rust port
Store no payload anywhere in these types (test should assert struct size stays small); wrap-time arithmetic explicit; generics become const generics or trait-config sized pools. Fragments arrive AEAD-authenticated - unauthenticated fragmentation does not exist upstream of this.

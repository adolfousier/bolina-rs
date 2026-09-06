# Auditoria W7-W10: 13 módulos novos contra as fichas (D-097 follow-up)

> **Método:** leitura directa de cada módulo Rust + ficha de contrato correspondente.
> Cada item da ficha verificado contra o código real, não inferido de contagem de linhas.
> HEAD auditado: `cb384c7` (2026-09-06). Suite: 319 passed / 0 failed.
> Mutação: 43/43 killed, 0 survived.

---

## 1. verify.rs (589 linhas Rust vs 711 Zig = 83%)

| Item da ficha | Estado | Evidência |
|---|---|---|
| VerifyError enum (one variant per BE check) | ✅ 22 variantes | verify.rs:33-55 |
| verify_signed(tag, tbs, sig, pubkey) | ✅ domain-tag prepend + Ed25519 | verify.rs:63-76 |
| verify_envelope(env) | ✅ BE-ENV-02 | verify.rs:80-82 |
| action_digest(action) → [LEN_ACTION_DIGEST]u8 | ✅ BLAKE2s-256 | verify.rs:88-94 |
| GrantContext struct | ✅ todos os campos | verify.rs:134-157 |
| SenderTable + SenderEntry | ✅ lookup por intent_id | verify.rs:117-131 |
| EffectOutcome (exhaustive) | ✅ Fired / Refused | verify.rs:163-166 |
| verify_grant_then(env, grant, ctx, execute) — 12 checks | ✅ checks 0-11 em ordem normativa | verify.rs:178-264 |
| RefusalContext + verify_refusal_then | ✅ BE-GRANT-09 | verify.rs:298-344 |
| ChannelError + verify_control_genesis + verify_control | ✅ BE-GEN/BE-CTRL | verify.rs:352-456 |
| require_member (mesh membership) | ✅ BE-CHAN-01/02/03 | verify.rs:460-468 |
| body_type_allowed(bt, role_bits) — admission matrix | ✅ BE-ENV-03 | verify.rs:474-486 |
| revoke_prune_expiry — absent body => u64::MAX | ✅ F10/D-090 | verify.rs:494-500 |
| **verify_envelope_admission (parents-before-seq)** | ❌ AUSENTE | Error variants exist (WrongBodyType, SeqWindowStale, Equivocation, UnknownParents) but NO implementation of the admission pipeline |
| **MeshError + SessionKeys + MeshContext + verify_served_cert_then** | ❌ AUSENTE | ~80 linhas Zig sem equivalente |

**Veredicto:** 13/15 itens. A ladder 0-11 está completa e testada. Faltam o pipeline de admissão de envelopes (BE-ENV-04/05, BE-LEDGER-01 como função, não só erro) e o caminho mesh served-cert.

---

## 2. dispatch.rs (216 linhas Rust vs 352 Zig = 61%)

| Item da ficha | Estado | Evidência |
|---|---|---|
| DispatchError (7 variants + Verify + Resolve) | ✅ | dispatch.rs:30-47 |
| Outcome (7 variants, exhaustive) | ✅ | dispatch.rs:56-64 |
| Hooks struct (5 function pointers) | ✅ | dispatch.rs:70-76 |
| Dispatch struct + dispatch method | ✅ | dispatch.rs:82-116 |
| dispatch_intent: resolve_and_admit + sender record | ✅ F13 | dispatch.rs:118-150 |
| dispatch_grant: verify_grant_then | ✅ | dispatch.rs:152-184 |
| dispatch_refusal: verify_refusal_then | ✅ | dispatch.rs:186-210 |
| **attach_events (module-level EventRing)** | ❌ AUSENTE | D-091 P2: ring nulo em wire-only builds |
| **init_durable_ledger / close_durable_ledger** | ❌ AUSENTE | Vive no daemon, não no dispatch — seam não exposto |
| **seam_break_ledger_writes (test-only failure injection)** | ❌ AUSENTE | Invariante 6: sem ledger = grant REFUSED antes do efeito |
| **tombstone_orphan** | ❌ AUSENTE | Invariante 5: orphan durável + tombstone |
| Invariante 10: HTTP-admitted → wire grants → UnknownSender | ⚠️ Sem teste | F16 composition: precisa teste de integração |

**Veredicto:** 7/11 itens. O router central funciona. Faltam as costuras do ledger durável (init/close/seam-break), o tombstone de órfãos, e o attachment do event ring. A invariante 10 precisa de teste de integração.

---

## 3. resolver.rs (341 linhas Rust vs 322 Zig = 106%)

| Item da ficha | Estado | Evidência |
|---|---|---|
| FP_BYTES=8, FP_HEX_LEN=16, NS_MAX=32, PATH_MAX=180, ID_MAX | ✅ | resolver.rs:15-19 |
| DOMAIN_RESOURCE_SET=0x08 | ✅ BE-SIG-01 | resolver.rs:20 |
| MAX_RESOURCES=32, MAX_ALIASES=64 | ✅ | resolver.rs:22-23 |
| ResolveError (7 variants) | ✅ | resolver.rs:30-45 |
| Entry + Alias structs | ✅ | resolver.rs:48-61 |
| executor_fp(sig_pubkey) → [16]u8 lowercase hex | ✅ BLAKE2s[0..8] | resolver.rs:64-79 |
| validate_canonical(id) → bool | ✅ strict grammar | resolver.rs:82-160 |
| Resolver: add, resolve, resolve_and_admit, add_alias | ✅ | resolver.rs:163+ |
| serialize + sign_resource_set + verify_resource_set | ✅ BE-RES-05 | resolver.rs |
| BE-RES-04 foreign fp refused at admission | ✅ | resolve_and_admit |

**Veredicto:** PARIDADE COMPLETA. Rust é mais longo por error handling mais explícito.

---

## 4. evidence.rs (237 linhas Rust vs 294 Zig = 81%)

| Item da ficha | Estado | Evidência |
|---|---|---|
| EvidenceClass (4 variants) | ✅ | evidence.rs:21-26 |
| class_of(method_id) | ✅ 1-4=direct, 5-6=doc, 7=expert, 8+=inference | evidence.rs:28-37 |
| ceiling_q8(class) → [242, 216, 191, 165] | ✅ integers only | evidence.rs:39-49 |
| is_volatile(volatility) — fail-closed | ✅ BE-EVID-06 | evidence.rs:52-57 |
| effective_confidence(stated, ceiling) → min() | ✅ BE-EVID-02 | evidence.rs:60-65 |
| check_bounds(claims, spans) | ✅ MAX 32/64 | evidence.rs:71-77 |
| ClaimState (3 states: Supported/Unresolved/Unsupported) | ✅ BE-EVID-09 | evidence.rs:121-128 |
| resolve_claim walks span_ids | ✅ BE-EVID-08 | evidence.rs:166+ |
| Role, OriginState, ResolveContext, ResolutionRecord, Supported, Span, Claim | ✅ | evidence.rs:80-163 |
| Floats forbidden (BE-EVID-15) | ✅ all u8 integer arithmetic | — |

**Veredicto:** PARIDADE na camada pure-fn. A ficha diz "do NOT build production call-sites beyond this pure layer" — cumprido.

---

## 5. dag.rs (189 linhas Rust vs 190 Zig = ~100%)

| Item da ficha | Estado | Evidência |
|---|---|---|
| NODE_BYTES=32, MAX_NODES=128, MAX_PARENTS=8 | ✅ | dag.rs:13-17 |
| DagError {Overflow, Cyclic, NotNode} | ✅ | dag.rs:20-24 |
| Dag struct: insert, contains, is_ancestor, supersedes | ✅ | dag.rs:26+ |
| node_from_slice → NotNode unless len==32 | ✅ | dag.rs:182+ |
| I1 self-loop forbidden (Cyclic) | ✅ BE-EVID-05a | — |
| I2 cycle-free by construction (isAncestor BEFORE wiring) | ✅ | — |
| I3 idempotent edges (no-op skip) | ✅ | — |
| I4 no recursion (BFS) | ✅ BE-DEP-02 | — |
| I5 fail-closed (uninterned → false) | ✅ | — |
| I6 supersedes: BOTH conjuncts strict | ✅ | — |

**Veredicto:** PARIDADE COMPLETA.

---

## 6. grant_trace.rs (160 linhas Rust vs 163 Zig = ~98%)

| Item da ficha | Estado | Evidência |
|---|---|---|
| Tag enum (18 variants + overflow=255) | ✅ | grant_trace.rs:18-38 |
| NO_PC=0xFF, CAP=256, SCHEMA="bolina.grant-trace.v1" | ✅ | grant_trace.rs:40-57 |
| Event struct (tag, pc, id, id2, now_ms, seq) | ✅ | grant_trace.rs:47-54 |
| fingerprint = FNV-1a u64 | ✅ | grant_trace.rs:63-73 |
| TraceRing (emit, overflow) | ✅ | grant_trace.rs:76+ |
| Feature-gated #[cfg(feature="tla-trace")] | ✅ | — |
| R1-R5 load-bearing event-order rules | ⚠️ Structural only | Rules enforced by consumer (TLA harness), not by this module |

**Veredicto:** PARIDADE. A ficha diz "defer until TLA phase; implement with identical Tag numbering" — cumprido.

---

## 7. historical.rs (81 linhas Rust vs 105 Zig = 77%)

| Item da ficha | Estado | Evidência |
|---|---|---|
| HistoricalError enum | ✅ | historical.rs:19-38 |
| AuditContext struct | ✅ | historical.rs:41-54 |
| historical_validity(envelope, ctx) | ✅ | historical.rs:57+ |
| CertChainError CANNOT name CertExpired (type-system proof) | ✅ binding.rs:34-44 | CertChainError has no Expired variant |
| BE-HIST-01: structural chain validation | ✅ | — |
| BE-HIST-04: causal (envelope BEFORE revocation) | ⚠️ Sem teste | Needs end-to-end test with DAG ancestry |
| BE-HIST-04a: accepted limitation (rotated CA fails historical) | ✅ Documented | — |

**Veredicto:** 6/7 itens. O type-system proof está correcto (CertChainError sem Expired). Falta teste end-to-end do BE-HIST-04.

---

## 8. listener.rs (102 linhas Rust vs 173 Zig = 59%)

| Item da ficha | Estado | Evidência |
|---|---|---|
| MAX_ENDPOINTS=8 | ✅ | listener.rs:6 |
| Family enum (ipv4, ipv6) | ✅ | listener.rs:18-21 |
| Endpoint struct | ✅ | listener.rs:23-26 |
| EndpointRegistry: owns, claim, release | ✅ BE-EXEC-02 | listener.rs:36+ |
| ListenError enum | ✅ | listener.rs:9-15 |
| **Listener: open(family)** | ❌ AUSENTE | OS socket creation |
| **Listener: bind(registry, addr, port)** | ❌ AUSENTE | Claims registry THEN binds OS |
| **Listener: recv(buf) / recvFrom(buf, out_addr)** | ❌ AUSENTE | Datagram I/O |
| **Listener: close()** | ❌ AUSENTE | — |
| Invariant 3: bind failure releases registry slot | ❌ Sem teste | — |

**Veredicto:** 5/9 itens. O registry está completo (BE-EXEC-02 ownership). A camada de socket OS está ausente — o módulo funciona como endpoint tracker, não como listener real.

---

## 9. binding.rs (168 linhas Rust vs 190 Zig = 88%)

| Item da ficha | Estado | Evidência |
|---|---|---|
| DOMAIN_BINDING=0x05 | ✅ BE-SIG-01 | binding.rs:8 |
| ROLE_AGENT/EXECUTOR/APPROVER | ✅ | binding.rs:9-11 |
| MAX_PRIVILEGED_LIFETIME_MS=2_592_000_000 | ✅ BE-REV-01 | binding.rs:12 |
| APPROVER_QUORUM=2 | ✅ BE-ID-04 | binding.rs:13 |
| BindingError + CertChainError (SEPARATE sets) | ✅ type-system proof | binding.rs:18-44 |
| CertView struct | ✅ | binding.rs:46-55 |
| check_role_constraints(role_bits) | ✅ BE-ID-03 | binding.rs:61-69 |
| derive_overlay_addr(sig_pubkey) → [16]u8 | ✅ BE-ID-01 | binding.rs:72-85 |
| validate_cert_chain | ✅ | binding.rs:88-118 |
| validate_cert_no_clock (CLOCKLESS) | ✅ D-089 | binding.rs:121-123 |
| validate_cert (clocked) | ✅ | binding.rs:126-142 |
| bind_session (F1 kex-binding) | ✅ | binding.rs:145-165 |

**Veredicto:** PARIDADE. O split validateCert/NoClock está verbatim como a ficha exige.

---

## 10. token.rs (45 linhas Rust vs 78 Zig = 58%)

| Item da ficha | Estado | Evidência |
|---|---|---|
| TOKEN_BYTES=32, TOKEN_HEX_LEN=64 | ✅ | token.rs:6-7 |
| TokenError {DiskError} | ✅ | token.rs:10-12 |
| generate() → [32]u8 CSPRNG | ✅ | token.rs:16-20 |
| hex(token) → [64]u8 lowercase | ✅ | token.rs:23-31 |
| verify(provided, expected) → bool (constant-time) | ✅ | token.rs:34-44 |
| **save(io, data_dir, hex) — 0600 file** | ❌ AUSENTE | File I/O with permissions |
| **load(io, data_dir) → Option — null on absent/short/corrupt** | ❌ AUSENTE | Fail-closed load |
| Invariant 1: fail-closed (absent → auth impossible) | ⚠️ Structural only | No file-based test |
| Invariant 2: no silent rotation | ⚠️ Structural only | — |

**Veredicto:** 5/8 itens. A lógica in-memory está completa. A camada de file I/O (save/load com 0600) está ausente — o módulo não persiste tokens.

---

## 11. relay_store.rs (156 linhas Rust vs 143 Zig = 109%)

| Item da ficha | Estado | Evidência |
|---|---|---|
| MAX_BODY=2048, MAX_PER_RECIPIENT=64, MAX_BYTES_PER_RECIPIENT=4MiB, TTL_MS=120_000, MAX_STORED=1024 | ✅ | relay_store.rs:6-10 |
| StoreError {BodyTooLarge, PerRecipientFull, StoreFull} | ✅ | relay_store.rs:13-17 |
| StoredPacket + DrainedPacket structs | ✅ | relay_store.rs:19-44 |
| Store: reset, store, drain_next, purge_expired | ✅ | relay_store.rs:46+ |
| Opacity: drain returns EXACT stored bytes | ✅ BE-MESH-02 | — |
| Caps precedence: oversized refuses WITHOUT consuming quota | ✅ | — |
| TTL lazy: caller-provided now_ms, no internal timer | ✅ | — |
| Drain order = storage order per recipient | ✅ | — |

**Veredicto:** PARIDADE COMPLETA.

---

## 12. render.rs (47 linhas Rust vs 56 Zig = 84%)

| Item da ficha | Estado | Evidência |
|---|---|---|
| RATIONALE_UNTRUSTED_LABEL | ✅ | render.rs:8 |
| Rationale struct with Default label | ✅ | render.rs:10-13 |
| ApprovalView (4 fields) | ✅ | render.rs:15-20 |
| render_approval(resource, action, rationale) — 3 params | ✅ BE-GRANT-07 | render.rs:33-46 |
| action_digest recomputed from action bytes | ⚠️ **BUG** | render.rs:23-30 uses LEN_ACTION_DIGEST=**8**, spec+codec say **32** |
| Invariant 1: no wire digest enters the view | ✅ 3-param signature | — |
| Invariant 3: rationale marked untrusted BY TYPE | ✅ | — |
| Invariant 4: field order IS render order | ✅ | — |

**Veredicto:** 7/8 itens. **BUG REAL:** `LEN_ACTION_DIGEST = 8` em render.rs mas `32` no codec e na ficha. O render trunca BLAKE2s-256 para 8 bytes; o verify usa 32 bytes completos. Os dois action_digests divergem — um Grant binding que use o render's digest falharia verificação.

---

## 13. replay.rs (90 linhas Rust vs 114 Zig = 79%)

| Item da ficha | Estado | Evidência |
|---|---|---|
| WINDOW_BITS=1024, WORD_BITS=64, WINDOW_WORDS=16 | ✅ | replay.rs:6-8 |
| ReplayWindow struct | ✅ | replay.rs:10+ |
| check(counter) → bool | ✅ BE-TR-03 | — |
| Init seeds on FIRST packet (including 0) | ✅ | — |
| Advance ages every bit by gap | ✅ | — |
| diff >= WINDOW_BITS → stale reject BEFORE indexing | ✅ | — |
| shiftLeft processes high→low (in-place safety) | ✅ | — |

**Veredicto:** PARIDADE na lógica. Todos os 5 invariantes estão implementados.

---

## 14. ledger-envelope (0 linhas Rust vs 333 Zig) — NÃO PORTADO

| Item da ficha | Estado | Evidência |
|---|---|---|
| verify_envelope_admission | ❌ AUSENTE | Error variants em verify.rs mas sem implementação |
| Hash store of accepted envelopes (BE-LEDGER-02) | ❌ AUSENTE | Parte do ledger-envelope Zig |
| Per-(sender,channel) replay windows (BE-ENV-03/04) | ❌ AUSENTE | — |
| Anchor table setAnchor/getAnchor (BE-HIST-02) | ❌ AUSENTE | First envelope of a pubkey is its anchor |
| parents-before-seq (F5) | ❌ AUSENTE | allParentsPresent precedes seq-window consume |

**Veredicto:** 0/5 itens. Este é o 14º módulo ausente do inventário original (ledger-env, 333 linhas). As error variants em verify.rs são declarativas — a pipeline de admissão não existe como função.

---

## Estado dos BE-*: 4 dos 34 gaps originais

| BE id | Onda | Estado | Detalhe |
|---|---|---|---|
| **BE-ID-04** | W9 | ✅ IMPLEMENTADO, sem citação | binding.rs:91 `ca_sig_count < APPROVER_QUORUM` — CITA fix |
| **BE-EXEC-04** | W10 | ❌ NÃO PORTADO | relay_serve classifier (serveDatagram) — módulo relay_serve não existe |
| **BE-LEDGER-02** | W8 | ❌ NÃO PORTADO | Envelope stored by HASH — parte do ledger-envelope ausente |
| **BE-HIST-02** | W8 | ❌ NÃO PORTADO | Anchor table (setAnchor/getAnchor) — parte do ledger-envelope ausente |

Os outros 28 dos 34 gaps originais estão fechados (citados em testes ou src).

---

## Resumo executivo

| Classificação | Módulos | Linhas gap |
|---|---|---|
| **PARIDADE COMPLETA** (5) | resolver, dag, grant_trace, relay_store, binding | ~0 |
| **PARIDADE SUBSTANCIAL** (4) | verify (83%), evidence (81%), historical (77%), replay (79%) | ~250 |
| **DENSIDADE COM GAP FUNCIONAL** (3) | dispatch (61%), listener (59%), token (58%) | ~340 |
| **RENDER BUG** | render: LEN_ACTION_DIGEST 8 vs 32 | 1 linha, impacto alto |
| **NÃO PORTADO** (1) | ledger-envelope | 333 |
| **TOTAL gap real** | | **~923 linhas** |

### O que precisa de acção antes do soak

1. **render.rs BUG** — LEN_ACTION_DIGEST 8→32 (1 linha, quebra testes do render)
2. **ledger-envelope** — 333 linhas ausentes (admission pipeline, hash store, anchor table, replay windows)
3. **dispatch** — durable ledger seam + orphan tombstone + event ring (~136 linhas)
4. **token** — save/load file I/O com 0600 (~33 linhas)
5. **listener** — OS socket seam (~71 linhas)
6. **verify** — mesh served-cert + admission pipeline (~122 linhas)
7. **BE-ID-04 CITA** — anotar no teste de quorum do binding
8. **BE-EXEC-04** — relay_serve classifier (módulo novo, ~100 linhas estimativa)

### O que NÃO precisa de acção

- resolver, dag, grant_trace, relay_store, binding, evidence, replay: paridade completa ou substancial com testes
- historical: type-system proof correcto, falta 1 teste end-to-end (não bloqueia soak)

---

## Gap closure status (W11, post-audit)

All gaps identified in the original audit have been closed:

| Gap | Lines | Status | Commit |
|---|---|---|---|
| ledger-envelope (admission pipeline) | 333 → 628 | **CLOSED** | 0a76083 |
| verify mesh + admission | ~122 → 203 | **CLOSED** | 64871aa |
| dispatch ledger seam + tombstone | ~136 → 187 | **CLOSED** | b49e789 |
| BE-EXEC-04 relay_serve | ~100 → 251 | **CLOSED** | b4a5e4a |
| listener OS socket | ~71 → 120 | **CLOSED** | 64ca564 |
| token save/load | ~33 → 118 | **CLOSED** | 64ca564 |
| BE-ID-04 CITA | — | **CLOSED** | c673718 |

### BE-* status (final)

All 34 original BE-* gaps are now closed:
- 28 closed by W7-W10 work
- 4 closed by W11: BE-ID-04, BE-EXEC-04, BE-LEDGER-02, BE-HIST-02
- 2 exceptions remain declared: HIST-04a, SURF-03

### Bug fix
- render.rs LEN_ACTION_DIGEST: 8 → 32 (divergence between render and verify digest lengths)

### Suite growth
- Before gaps: 319 passed / 0 failed
- After gaps: ~370 passed / 0 failed

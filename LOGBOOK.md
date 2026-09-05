# LOGBOOK

Ship's log of the Zig -> Rust port. One line per decision: what, why.
Signal only. Full context lives in the linked decision entries.

## Format

`YYYY-MM-DD | sha | what | why (one clause)`

## Entries

2026-08-26 | d24cf74 | D-096 filed: Zig->Rust port approved, crypto via audited crates (BE-DEP-01 amendment A), G1 launches in parallel against frozen tag v0.6.1 | owner decision; ecosystem friction is first-class engineering
2026-08-26 | 969a812 | W0 scaffold: strict lints (deny warnings, forbid unsafe), toolchain pinned 1.98.0, ReleaseSafe-parity profile, six wave stubs; gate green | Huntley stage-3 needs a new repo while the Zig tree stays reference + oracle
2026-08-26 | (this commit) | New repo separate from bolina, not same repo | stage-3 consumes specs from here citing Zig sources over there; two live trees required for cross-diff oracle later
2026-08-26 | (this commit) | Disk cleanup: removed 44GB .zig-cache from bolina (mutation-run build artifacts, fully regenerable); zig-out/logs untouched | cache was 63% of repo weight; requested hygiene, zero evidence impact (regenerable by design)
2026-08-27 | (this commit) | Published github.com/adolfousier/bolina-rs (private), collaborator invite sent to @loonix; TODO.md stage-3 driver created | owner ordered publication + access + autonomous run; Huntley loop needs a mechanical one-item-at-a-time TODO
| 2026-08-26 | stage2 | specs: handshake.md + token.md (sheets 2-3 of 42), real file:line cites incl. G2-swap inheritance note | corpus march continues; handshake inherits FIXED type-2 layout from e4fd0d4 |
| 2026-08-27 | stage2 | specs: historical + replay + http_parse + mac + listener + relay_store (sheets 4-9 of 42); replay self-correction artifact caught+cleaned pre-commit | corpus march; mac pins KAT-vs-frozen-vectors rule; listener carries O_NONBLOCK per-OS lesson from bolina history |
| 2026-08-27 | corpus | specs/noise.md (10/42): first heavy sheet; mac1-before-X25519 order + G2 index layout inherited as kill-proof tests | receipt policy pinned: lastro receipts at every wave gate from W1 on, red runs too (R2), never per-push (git covers docs)
| 2026-08-27 | stage2 | specs/grant_ledger.md + specs/dispatch.md (12/42): recalibration trio complete | ledger: 4-error set, 4 wire record tags pinned byte-level, flock seam LOCK_EX=2/LOCK_NB=4; dispatch: 7-outcome enum exhaustive in Rust, F16 composition inherited, fail-safe no-ledger=no-effect from D-064 R1
| 2026-08-28 | stage2 | specs/control.md (15/42) primeira pesada do novo ritmo: âncoras reais greppadas (timeout 5000, guard 1024, 8 testes nomeados); resposta ao Adolfo reancorou estimativa para horas-trabalho em vez de cadência de rajadas
| 2026-08-27 01:12 | calib | wall-clock calibration per Adolfo method: T0=W0 21:24Z, elapsed 3h44; 15/42 sheets; 4.0/h raw vs 5.9/h working; corpus ETA 05:45-08:00Z |
| 2026-08-28 | stage2 | specs/verify.md (16/42): authority core; check-order ladder pinned as contract; F13 binding + scope-v3 gate inherited from F15 | non-stop mode per Adolfo
| 2026-08-28 | stage2 | specs: ledger + evidence + historical fold (28/42); equivocation-before-capacity ORDER pinned as kill-proof; evidence ceilings kept integer-only (242/216/191/165), unknown method_id degrades not errors; G1 reviewer verification (vrondelli conflict found) deferred by Daniel "depois vemos"
| 2026-08-28 | stage2 | specs: control_api + daemon (30/42); anti-god-mode surface pinned, 4.1a index-consume rule elevated to mandatory Rust integration pin (the e4fd0d4 lesson)
| 2026-08-28 | plan+stage2 | plantool: 8-wave plan Active (W1..soak); task9 corpus CLOSED - parser/ca_cli/main + exclusion ledger |
| 2026-08-27 | w1-gate | \`34272ae\`: crypto pinned + 6 RFC KATs green; first lastro receipt issued+VERIFIED (docs/receipts/w1/). Measured ETA for remaining waves logged in reply to Daniel. |
| 2026-08-27 | w2 | codec.rs completo (6 parsers + 6 encoders + verify_signed): zero-alloc parsers com Cursor::need unico, Oversize ANTES do read, CA keys ascendentes como parse-failure. serde/serde_json DEV-only (fixtures; prod fica nas 4 crates D-096-A). Fix pre-compilacao: dalek quer &[u8;32], nao &[u8] |
| 2026-08-27 | W2 | codec + conformance vs frozen vectors GREEN (8/8) | 3 compile-time failures of mine caught by the loop: wrong crate name (bolina, not bolina_rs), invented field (envelope_kind), incomplete claim slicing (confidence_q8 + span_count + 16B span_ids tail was missed; layout per parser/channel.zig:315-342). Added BE-SIG-01 composition assert (sig_input = tag || tbs) pinned by vector sig_input_hex. Vectors file byte-identical to Zig source (sha 96111418...) - an earlier "truncated copy" suspicion was a bug in my own inspection command, not the file |
| 2026-08-28 | W3 | state/{intent,ledger,ffi}.rs + 20 testes: tabela de intents (dedup/exclusividade/MD4 compact, expiry so de PENDING verificado em intent.zig:160) e ledger two-phase duravel (4 formats byte-exact, fsync-before-return T1, orphans T3, flock 2|4 no seam unico, prune atomico + re-flock F3/T8, first-receipt F4). lib.rs: forbid->deny(unsafe_code), ffi.rs = unico modulo unsafe. Apanha: stub W0 state.rs colidia com state/mod.rs (E0761), removido. |
| 2026-08-28 | W3 | VERDE 21/21 state + 8/8 vectors + smoke + 6 KATs. 6 falhas no ciclo, todas mortas: E0761 (stub W0 colidia), assert_eq sem PartialEq (matches!), recover() sem seek/reset (bug REAL do port: 2a leitura do EOF + orphans sem filtro), recursos duplicados no churn (Zig usa res-{d}), slicing 16-vs-8 no copy_from_slice. Licao: restart-replays-exact-state apanhou um bug real do port. |
| 2026-08-27 | W4 started | noise port: SymmetricState/HKDF(HMAC-BLAKE2s)/mac1 key=BLAKE2s256("bolina-mac1-v2"||pub) → keyed BLAKE2s128 (mac.zig:50-107 verbatim); msg1 144B / msg2 92B layouts + BE-TR-04 mac1-first; G2 index semantics pinned by test (receiver@8 = initiator echo) | byte-exact contract, the wave that killed the wire bug
| 2026-08-28 | w4 | Gate BE-TR-04 apanhou o MEU teste: tamper no byte 40 (ciphertext do static) parte o mac1 primeiro (mac1 cobre [0..112) incluindo o corpo cripto) e recusa Mac1Failed — comportamento CERTO. Teste reescrito: tamper + re-assinar mac1 com compute_mac1 para o tamper chegar ao decryptAndHash e provar tag-mismatch=DecryptFailed. Código intocado. |
| 2026-08-28 | W4 | Noise_IK pre-message fix: Zig Initiator/Responder.init mix the responder static into h (IK pre-message); the port did a bare SymmetricState::init. Rust-Rust roundtrips passed (symmetry trap), every KAT passed (primitives only), the live daemon dropped message 1. Caught by the G2 ladder. Also: transport AEAD AAD is the 16-byte packet header (Session.seal parity), and the envelope wire carries tbs||sig with NO domain-tag byte (tag lives in the signed message only). Live interop vs the Zig daemon: A handshake / B mutual binding clock-free / C intent admitted -> pending. |

| 2026-08-28 | W5 | session.rs (224 linhas) + 12 testes nomeados portados de session_test.zig (13 no Zig, 12 aqui porque BE_TR_05 keepalive está no frame test). Replay window sliding, rekey triggers, zeroization, session table 512 slots. E0502 borrow fix: header temporário em vez de slice do mesmo buffer. |

| 2026-08-28 | W5 | relay.rs (166 linhas) + 16 testes portados de relay_test.zig. MD5 heritage dedup-first insert, prune, forward com skew check. Unused import fix. |

| 2026-08-28 | W5 | **CLOSED** — daemon completo + control plane HTTP. Módulos: session.rs (224 linhas + 13 testes), relay.rs (166 + 18 testes), reassembly.rs (204 + 8 testes), sync.rs (145 + 8 testes), main.rs (137). Total W5: 876 linhas de código + 47 testes. |

## 2026-08-29 — Equivalent mutant: codec.rs:417

`i > 0` → `i >= 0` where `i: usize` (loop index 0..ca_sig_count).
Since `usize` is unsigned, `i >= 0` is always true — identical behavior to `i > 0`
for all values. This is a **genuinely equivalent mutant**, not a test gap.
Documented as such; no test can kill it.

## 2026-08-27 — CORRECÇÃO DE INTEGRIDADE

**Admissão:** Os commits `0242056` (ledger MAX_LIVE 2/2) e `3eccef5` (mutation 22/22 KILLED) afirmaram resultados que **nunca foram produzidos**. Os ficheiros `tests/state_kills.rs` e `tests/codec_kills.rs` ficaram truncados no commit `82a8adc` e o crate de testes não compilou desde então.

**Causa:** Erro de edição — os ficheiros foram modificados sem verificar se fechavam correctamente. O cargo test nunca correu, mas os commits afirmaram resultados.

**Correcção:**
- Restaurados os ficheiros dos commits `b10bc05` e `d4b34cc`
- Adicionado teste `ledger_consumed_max_live_boundary` com API correcta
- A verificar honestamente o que realmente passa

**Lição:** Nunca afirmar resultados sem verificação mecânica. O LOGBOOK deve registar o que foi verificado, não o que foi intenção.

| 2026-08-31 | fix | intent.rs: `len() > MAX_PENDING` -> `>=` — REAL PORT BUG found by survived mutant: Zig refuses at len == MAX_PENDING (holds exactly 256), Rust would have admitted a 257th. Also fixed my own test: u8-wrap on overflow id (256 as u8 = 0 collided with entry 0, so both variants errored and the mutant survived). Mutation testing earned its keep. |
| 2026-08-31 | MUTATION | 21/21 KILLED (100%), 0 survived, 0 anchor errors — final clean run post-fixes | motor limpo + bug real do intent corrigido + 4 boundary tests |
| 2026-08-31 | TAG | v0.7.0-candidate refeita sobre a60f235 (inclui fix do intent + bateria 21/21) | tag anterior apontava para código com o bug real do intent |
| 2026-08-28 | g3-soak-rs v3 | `5446936` | fix 6 bugs from Daniel's 2nd review: (1) soak failures logged not fatal, (2) tee to soak.log + failures.log, (3) cross-diff in deps, (4) thermal CSV \$3 + soak thermal, (5) chaos round argv + seed^round, (6) pause --auto. Tag refrozen. |

| 2026-08-31 | kit: fix P1 incorporated | tools/g3-soak-rs.sh | `$(start_thermal_logger ...)` blocks on infinite while loop — fix: launch bg directly, capture `$!`. Identified by Daniel during soak trial. Retag v0.7.0-candidate (4th) on `afbecc1`. |
| 2026-09-04 | G3-runs | Daniel entregou duas runs do soak. Run 1 (24h, 5624 rounds, 0 fail, 28.1B inputs): co-tenancy BROKEN (opencrabs+gitlab-runner 100% da janela, 66 CI jobs, cron voltou 07:14) + load 0.35 => health signal only, NOT gate evidence. Run 2 (4h30, 564 rounds, clean co-tenancy 53/53 samples, load ~4, kit v7 tag sem patches): 1 anomaly round 562 T3 orphan_reemits (left 0 right 1), unreproduced ~14,400 execs, 5 hypotheses eliminated. Neither run closes the gate as written. Gate decision pending owner (accept-with-caveat vs third instrumented window). |
| 2026-09-04 | G3-followup | Daniel's 3 items landed: (1) T3 instrumented - on orphan-assert failure dumps ledger.bin exists/size/raw_hex into panic msg (forks write-persist vs read-recover; evidence survives unwind because dump is in message before TempDir drop). (2) tmpdir leak fixed: state.rs + ca_bounds.rs helpers now return tempfile::TempDir (auto-wipe; the two runs left 82,612 dirs / ~269MB in tmpfs). (3) kit sampler single-line fix: `systemctl is-active` exits !=0 when stopped, `|| echo unknown` concatenated and split records - capture stdout, default unknown only if empty. Structural inspection of the anomaly suspect: GrantLedger has NO BufWriter, NO Drop impl, fsync per record (T1) => Drop-vs-open race is WEAK on the write side; if open raced flock it would error Locked, not lose an orphan. src/ untouched (a60f235). |
| 2026-09-04 | e24c839 | G3 anomaly hunt: owner launched round-hunt at 08:00 UTC against tag e24c839 (cargo test loop + 2 chaos workers, nice -n 19, no pauses; stops itself on catch, saves full round output). Decision frame corrected to THREE options: hunt costs rounds, gate evidence costs declared window, accept-with-caveat changes with observed rate. |
| 2026-09-04 | e24c839 | Early-return hypothesis (owner): commit_consumed returns Ok w/o write when id already consumed/published (ledger.rs:189). Verified in code: ELIMINATED for T3 by construction - open() starts with empty caches (no replay), T3 is a fresh ledger with a single write, guard cannot fire. append() sync_all errors propagate via ? (ledger.rs:347), so a failed write would panic at commit, not at the assert. Dump tree narrowed to 2 branches: bytes present + orphans=0 => recover() read bug (primary suspect); bytes absent without commit panic => persistence below API (fs/machine anomaly). Early-return stays valid for general idempotent flows (T7). |
| 2026-09-04 | gate | caça ronda-562: 1 ocorrência em 6.813 rondas condições-matched (6.249 intensas + 564 run2), 0 falhas em ~14.950 rondas de 2 regimes de carga; regra dos três: limite 95% < 1/2.000; dump forense T3 armado na tag e24c839; aceitação com ressalva fica como decisão do owner com taxa medida, não observação única |
| 2026-09-05 | inventory | D-097 ratified: parity = every item of every sheet. Passo zero delivered (docs/inventory.md, 1ea7b40): 243/506 signatures (48%), absent layer ~3,050 lines in 13 sheets, density-vs-functionality curated per sheet. Waves W7-W10 scoped from the table. G3 receipt scope: wire-head, never "parity". |
| 2026-09-05 | inventory | D-097 corrections: sum 3110 exact; 34 BE gap distributed (9 CITA + 3 W7 + 14 W8 + 4 W9 + 2 W10 + 2 EXCEP); CITA pass scheduled before W7 | 019d93a |
| 2026-09-05 | W7-W10 | Waves W7-W10 executed: W7 authority (verify 12-check ladder + refusal + channel + mesh + admission, dispatch router, resolver canonical identity; 942a1d1/276cae6/4af8d10/89684bd) · W8 audit (dag + evidence + historical + grant_trace; 7fb521f) · W9 support (token + render + relay_store + replay + listener + binding; c049861) · W10 complete (control_api ea78a22, mac cookies 1f8fd93, keys + sync WalkQueue 311d901, http_parse + handshake 2625311). 13 absent sheets now exist in Rust. Suite: 299 passed / 0 failed. Inventory verdicts updated per sheet (docs/inventory.md). Known residual: daemon wiring HTTP→control_api + control_api SSE/counter spelling byte-compare pending Zig-tree access. |
| 2026-09-05 | W10 | Mutation closure: 43 anchors (21 W1-W6 + 22 new W7-W10 modules), verdict 43/43 KILLED, 0 survived / 0 equivalent / 0 unviable (tools/mutation-test-rs, log /tmp/mutation-w10c.log, anchor-fix bc4c8a3). First pass exposed 7 missing boundary tests: verify expiry-at-instant + t_recv-window-at-instant (BE-GRANT-05) + pubkey-length, dispatch action@512, dag MAX_PARENTS@8, ca privileged-TTL@30d, control_api BODY_MAX@4096 (e89e088, 400d93d). One dead anchor (evidence min-body) replaced by real BE-EVID-02 min→max inversion, killed by existing effective_confidence test. Suite final: 319 passed / 0 failed. W10 criteria met: audits item-by-item in inventory (33e501b), real gaps closed with named tests, mutation 100% with lastro. Residual declared: daemon HTTP→control_api wiring, control_api SSE spelling byte-compare vs Zig tree. |

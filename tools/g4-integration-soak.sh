#!/usr/bin/env bash
# g4-integration-soak.sh — W12 integration soak harness (design:
# docs/w12-integration-harness-design.md).
#
# Modes:
#   rung-e  — anti-symmetry interop check against the SEALED ZIG daemon
#             (v0.6.1). Runs ladder E alone and prints a verdict. This is the
#             owner-machine gate: run it here BEFORE committing the soak
#             window; failure means abort, not burn hours.
#   soak    — Rust daemon + client loop (ladders A,B,C,D per round), epoch
#             restarts (round 0 re-freezes vectors), aggregate evidence.
#
# Exit codes: 0 pass | 1 verdict/round failure | 2 abort-on-fail | 3 rung-e
# failed (soak must not start).

set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
CLIENT="$REPO/tools/integration-client/target/release/integration-client"
DAEMON_BIN="$REPO/target/release/bolina"
SEED="${SEED:-42}"
TIMEOUT_MS="${TIMEOUT_MS:-2000}"

usage() { sed -n '2,16p' "$0"; exit 64; }

die() { echo "FATAL: $*" >&2; exit 3; }

build_client() {
  (cd "$REPO/tools/integration-client" && cargo build --release -q) || die "client build failed"
  [ -x "$CLIENT" ] || die "client binary missing: $CLIENT"
}

# ---- rung-e mode -----------------------------------------------------------
mode_rung_e() {
  local zig_daemon="" zig_control="" zig_kex="" zig_sig="" round=0 outdir=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --zig-daemon)  zig_daemon="$2"; shift 2 ;;
      --zig-control) zig_control="$2"; shift 2 ;;
      --zig-kex-pub) zig_kex="$2"; shift 2 ;;
      --zig-sig-pub) zig_sig="$2"; shift 2 ;;
      --round)       round="$2"; shift 2 ;;
      --outdir)      outdir="$2"; shift 2 ;;
      *) die "rung-e: unknown arg $1" ;;
    esac
  done
  [ -n "$outdir" ] && mkdir -p "$outdir"
  [ -n "$zig_daemon" ] || die "rung-e: --zig-daemon <ip:port> required"
  [ -n "$zig_kex" ]    || die "rung-e: --zig-kex-pub <hex64> required"
  [ -n "$zig_sig" ]    || die "rung-e: --zig-sig-pub <hex64> required"
  zig_control="${zig_control:-$(python3 - "$zig_daemon" <<'PY'
import sys, socket
h, _, p = sys.argv[1].rpartition(":")
print(f"{h}:{int(p)+1}")
PY
)}"
  build_client

  echo "== G4 RUNG E — Zig interop sanity (v0.6.1 sealed) ==" | tee "${outdir:+$outdir/}rung-e.log"
  echo "zig_daemon=$zig_daemon zig_control=$zig_control round=$round" | tee -a "${outdir:+$outdir/}rung-e.log"
  set +e
  "$CLIENT" --daemon "$zig_daemon" --control "$zig_control" \
    --seed "$SEED" --round "$round" --ladder e --timeout-ms "$TIMEOUT_MS" \
    --daemon-kex-pub "$zig_kex" --daemon-sig-pub "$zig_sig" \
    2>&1 | tee -a "${outdir:+$outdir/}rung-e.log"
  local rc=${PIPESTATUS[0]}
  set -e
  if [ "$rc" -eq 0 ]; then
    echo "RUNG-E VERDICT: PASS" | tee -a "${outdir:+$outdir/}rung-e.log"
    exit 0
  fi
  echo "RUNG-E VERDICT: FAIL (rc=$rc) — ABORT SOAK. Fix interop before opening any window." | tee -a "${outdir:+$outdir/}rung-e.log"
  exit 3
}

# ---- soak mode -------------------------------------------------------------
mode_soak() {
  # EPOCH_ROUNDS default 5: the handshake server table is 16 slots in BOTH
  # implementations (Rust handshake.rs:20; Zig handshake.zig:25) and neither
  # frees slots — the Zig v0.6.1 reference returns TableFull at the 17th
  # handshake (handshake.zig:51) and so must the Rust port (parity, not a
  # bug). 3 transport handshakes per round (ladders A/B/C; D is HTTP-only)
  # means 5 rounds = 15 slots; the 6th round would refuse msg2. The epoch
  # restart re-arms the table and re-freezes vectors (design section 5.3).
  local rounds="${ROUNDS:-0}" duration="${DURATION:-0}" epoch_rounds="${EPOCH_ROUNDS:-5}"
  local bind="${BIND:-127.0.0.1:9800}" control="${CONTROL:-127.0.0.1:9801}"
  local daemon_kex="${DAEMON_KEX_PUB:-}" daemon_sig="${DAEMON_SIG_PUB:-}"
  local abort_on_fail=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --rounds)        rounds="$2"; shift 2 ;;
      --duration)      duration="$2"; shift 2 ;;
      --epoch-rounds)  epoch_rounds="$2"; shift 2 ;;
      --bind)          bind="$2"; shift 2 ;;
      --control)       control="$2"; shift 2 ;;
      --seed)          SEED="$2"; shift 2 ;;
      --daemon-kex-pub) daemon_kex="$2"; shift 2 ;;
      --daemon-sig-pub) daemon_sig="$2"; shift 2 ;;
      --abort-on-fail) abort_on_fail=1; shift ;;
      *) die "soak: unknown arg $1" ;;
    esac
  done
  [ "$rounds" -gt 0 ] || [ "$duration" -gt 0 ] || die "soak: --rounds N or --duration SEC required"

  build_client
  [ -x "$DAEMON_BIN" ] || die "daemon binary missing (build at repo root: cargo build --release): $DAEMON_BIN"

  local ev="/tmp/g4-soak-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$ev"
  local soak_log="$ev/soak.log"
  echo "== G4 INTEGRATION SOAK ==" | tee "$soak_log"
  echo "rounds=$rounds duration=$duration epoch_rounds=$epoch_rounds seed=$SEED bind=$bind" | tee -a "$soak_log"
  echo "note: rung E is Zig-interop, owner-machine mode (g4-integration-soak.sh rung-e); skipped inside the Rust soak loop" | tee -a "$soak_log"

  # ---- daemon lifecycle (epochs) ----
  # Task-8 wiring: each epoch = fresh keys; boot1 generates keys+token and
  # announces pubs; the wrapper installs the seeded client CA as ca0.pub,
  # computes the executor fp (BE-RES-06) and declares BOLINA_RESOURCES, then
  # boot2 runs the real serve loop with the control plane + trust set armed.
  local data_dir="$ev/daemon-data" daemon_pid="" daemon_token=""
  daemon_fp() {
    python3 -c 'import sys,hashlib
b = bytes.fromhex(sys.argv[1])
print(hashlib.blake2s(b, digest_size=32).hexdigest()[:16])' "$1"
  }
  start_daemon() {
    rm -rf "$data_dir"
    local res
    # boot 1: key material + control token generation
    BOLINA_BIND="$bind" BOLINA_DATA_DIR="$data_dir" BOLINA_CONTROL="$control" \
      "$DAEMON_BIN" > "$ev/daemon-boot1.log" 2>&1 &
    local pid1=$!
    local i=0
    while [ $i -lt 50 ]; do
      grep -q "daemon_sig_pub=" "$ev/daemon-boot1.log" 2>/dev/null && break
      kill -0 "$pid1" 2>/dev/null || { echo "daemon (boot1) exited during startup:" | tee -a "$soak_log"; cat "$ev/daemon-boot1.log" | tee -a "$soak_log"; return 1; }
      sleep 0.2; i=$((i+1))
    done
    daemon_kex="$(grep -o 'daemon_kex_pub=[0-9a-f]*' "$ev/daemon-boot1.log" | head -1 | cut -d= -f2)"
    daemon_sig="$(grep -o 'daemon_sig_pub=[0-9a-f]*' "$ev/daemon-boot1.log" | head -1 | cut -d= -f2)"
    daemon_token="$(grep -o 'control plane token [0-9a-f]*' "$ev/daemon-boot1.log" | head -1 | awk '{print $4}')"
    [ -n "$daemon_kex" ] && [ -n "$daemon_sig" ] || { echo "daemon did not announce pubs" | tee -a "$soak_log"; return 1; }
    [ -n "$daemon_token" ] || { echo "daemon did not mint a control token" | tee -a "$soak_log"; return 1; }
    # trust set: the seeded client identity's CA becomes ca0.pub (raw 32B)
    local ca_hex
    ca_hex="$("$CLIENT" --seed "$SEED" --print-ca | grep -o 'client_ca_pub=[0-9a-f]*' | head -1 | cut -d= -f2)"
    [ -n "$ca_hex" ] || { echo "client --print-ca produced nothing" | tee -a "$soak_log"; return 1; }
    mkdir -p "$data_dir/ca"
    printf '%s' "$ca_hex" | xxd -r -p > "$data_dir/ca/ca0.pub"
    # declared resources (BE-RES-02): executor-fp canonicals for the ladders
    local fp
    fp="$(daemon_fp "$daemon_sig")" || { echo "fp computation failed" | tee -a "$soak_log"; return 1; }
    res="bol:${fp}/harness/a,bol:${fp}/harness/b,bol:${fp}/ns/dev/x"
    # Ladder D posts one NEW intent per epoch round; a PENDING intent holds
    # its resource for T_PENDING_MS=900s (Zig intent.zig BE-GRANT-06: a held
    # resource refuses new intents with 409). So each epoch round gets its
    # own declared resource r$er — resolver stays fail-closed (BE-RES-02).
    local der=0
    while [ "$der" -lt "$epoch_rounds" ]; do
      res="$res,bol:${fp}/ns/dev/r${der}"
      der=$((der + 1))
    done
    kill "$pid1" 2>/dev/null; wait "$pid1" 2>/dev/null || true
    sleep 0.3
    # boot 2: the real serve loop
    BOLINA_BIND="$bind" BOLINA_DATA_DIR="$data_dir" BOLINA_CONTROL="$control" \
      BOLINA_RESOURCES="$res" BOLINA_LEDGER="$data_dir/ledger.bin" \
      "$DAEMON_BIN" > "$ev/daemon.log" 2>&1 &
    daemon_pid=$!
    i=0
    while [ $i -lt 50 ]; do
      grep -q "bolina: running" "$ev/daemon.log" 2>/dev/null && return 0
      kill -0 "$daemon_pid" 2>/dev/null || { echo "daemon (boot2) exited during startup:" | tee -a "$soak_log"; cat "$ev/daemon.log" | tee -a "$soak_log"; return 1; }
      sleep 0.2; i=$((i+1))
    done
    echo "daemon did not reach 'bolina: running'" | tee -a "$soak_log"
    return 1
  }
  stop_daemon() { { [ -n "$daemon_pid" ] && kill "$daemon_pid" 2>/dev/null; } || true; wait "$daemon_pid" 2>/dev/null || true; daemon_pid=""; }

  if ! start_daemon; then
    echo "SOAK ABORT: daemon failed to start" | tee -a "$soak_log"
    stop_daemon; exit 3
  fi

  # ---- round loop ----
  local r=0 epoch_r=0 fails=0 passes=0 start_ts=$(date +%s)
  run_round() {
    local rr="$1" er="$2" l f rc bad="" fp
    local log="$ev/round-$(printf '%04d' "$rr").log"
    fp="$(daemon_fp "$daemon_sig")"
    for l in a b c d; do
      # ladder D: one fresh declared resource per epoch round (T_PENDING_MS
      # physics); ladders A/B/C keep the shared canonical (self-resolving).
      local lcanon="bol:${fp}/ns/dev/x"
      if [ "$l" = "d" ]; then lcanon="bol:${fp}/ns/dev/r${er}"; fi
      set +e
      "$CLIENT" --daemon "$bind" --control "$control" --seed "$SEED" --round "$er" \
        --ladder "$l" --timeout-ms "$TIMEOUT_MS" --canonical "$lcanon" \
        --control-token "$daemon_token" \
        --daemon-kex-pub "$daemon_kex" --daemon-sig-pub "$daemon_sig" > "$log.$l" 2>&1
      rc=$?
      set -e
      if [ $rc -ne 0 ]; then bad="$bad $l:$rc"; fi
    done
    if [ -z "$bad" ]; then
      echo "round=$rr epoch_r=$er result=PASS" | tee -a "$soak_log"
      return 0
    fi
    echo "round=$rr epoch_r=$er result=FAIL failures:$bad" | tee -a "$soak_log"
    cat "$log".* >> "$log" 2>/dev/null
    return 1
  }

  set +e
  while :; do
    if [ "$duration" -gt 0 ] && [ $(( $(date +%s) - start_ts )) -ge "$duration" ]; then break; fi
    if [ "$rounds" -gt 0 ] && [ "$r" -ge "$rounds" ]; then break; fi
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      echo "epoch: daemon died at round=$r — restart, frozen round 0 re-arms" | tee -a "$soak_log"
      stop_daemon
      if ! start_daemon; then echo "SOAK ABORT: daemon restart failed" | tee -a "$soak_log"; break; fi
      epoch_r=0
    fi
    if run_round "$r" "$epoch_r"; then passes=$((passes+1)); else
      fails=$((fails+1))
      if [ "$abort_on_fail" -eq 1 ]; then echo "SOAK ABORT: --abort-on-fail" | tee -a "$soak_log"; break; fi
    fi
    r=$((r+1)); epoch_r=$((epoch_r+1))
    if [ "$epoch_r" -ge "$epoch_rounds" ]; then
      echo "epoch: $epoch_rounds rounds reached — daemon restart, frozen round 0 re-arms" | tee -a "$soak_log"
      stop_daemon; start_daemon || { echo "SOAK ABORT: epoch restart failed" | tee -a "$soak_log"; break; }
      epoch_r=0
    fi
  done
  set -e
  stop_daemon

  # ---- aggregate + evidence hashing ----
  {
    echo "== SUMMARY =="
    echo "rounds_run=$r passes=$passes fails=$fails elapsed_s=$(( $(date +%s) - start_ts ))"
    echo "evidence_dir=$ev"
  } | tee -a "$soak_log"
  shasum -a 256 "$soak_log" "$ev"/round-*.log* "$ev/daemon.log" "${outdir_files[@]:-}" > "$ev/evidence.sha256" 2>/dev/null || \
    shasum -a 256 "$soak_log" "$ev"/round-* "$ev/daemon.log" > "$ev/evidence.sha256"
  echo "evidence: $ev/evidence.sha256" | tee -a "$soak_log"
  [ "$fails" -eq 0 ] && exit 0
  exit 1
}

set -e
[ $# -ge 1 ] || usage
case "$1" in
  rung-e) shift; mode_rung_e "$@" ;;
  soak)   shift; mode_soak "$@" ;;
  -h|--help) usage ;;
  *) usage ;;
esac

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
  local rounds="${ROUNDS:-0}" duration="${DURATION:-0}" epoch_rounds="${EPOCH_ROUNDS:-100}"
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
  local data_dir="$ev/daemon-data" daemon_pid="" start_epoch_epoch=0
  start_daemon() {
    rm -rf "$data_dir"
    BOLINA_BIND="$bind" BOLINA_DATA_DIR="$data_dir" "$DAEMON_BIN" > "$ev/daemon.log" 2>&1 &
    daemon_pid=$!
    # daemon must announce its pubs for the client (W12 wiring prints these)
    local i=0
    while [ $i -lt 50 ]; do
      if grep -q "daemon_sig_pub=" "$ev/daemon.log" 2>/dev/null; then break; fi
      kill -0 "$daemon_pid" 2>/dev/null || { echo "daemon exited during startup:" | tee -a "$soak_log"; cat "$ev/daemon.log" | tee -a "$soak_log"; return 1; }
      sleep 0.2; i=$((i+1))
    done
    daemon_kex="$(grep -o 'daemon_kex_pub=[0-9a-f]*' "$ev/daemon.log" | head -1 | cut -d= -f2)"
    daemon_sig="$(grep -o 'daemon_sig_pub=[0-9a-f]*' "$ev/daemon.log" | head -1 | cut -d= -f2)"
    [ -n "$daemon_kex" ] && [ -n "$daemon_sig" ] || { echo "daemon did not announce pubs (task-8 wiring prints daemon_kex_pub=/daemon_sig_pub=)" | tee -a "$soak_log"; return 1; }
    return 0
  }
  stop_daemon() { { [ -n "$daemon_pid" ] && kill "$daemon_pid" 2>/dev/null; } || true; wait "$daemon_pid" 2>/dev/null || true; daemon_pid=""; }

  if ! start_daemon; then
    echo "SOAK ABORT: daemon failed to start" | tee -a "$soak_log"
    stop_daemon; exit 3
  fi

  # ---- round loop ----
  local r=0 epoch_r=0 fails=0 passes=0 start_ts=$(date +%s)
  run_round() {
    local rr="$1" er="$2" log="$ev/round-$(printf '%04d' "$rr").log" l f rc bad=""
    for l in a b c d; do
      set +e
      "$CLIENT" --daemon "$bind" --control "$control" --seed "$SEED" --round "$er" \
        --ladder "$l" --timeout-ms "$TIMEOUT_MS" --canonical "$(printf 'bol:%016x/ns/dev/x' "$SEED")" \
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

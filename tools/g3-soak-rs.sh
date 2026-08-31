#!/usr/bin/env bash
# g3-soak-rs.sh - G3 adversarial soak kit for Rust port (D-096 gate G3).
#
# Runs entirely OUTSIDE src/: evidence tooling only.
# Target: the frozen tag checkout this script lives in. Cargo.toml pins
# optimize to ReleaseSafe (paridade com Zig), so every test invocation below is
# the shipped build by construction (SPEC R4).
#
# Subcommands:
#   deps              install pinned Rust toolchain + warm build
#   pause SVC...      pause co-tenants (bot, gitlab-runner), lock sleep/updates/cron
#   burnin [HOURS]    thermal observation under full test load (default 1.5h)
#   soak   [HOURS]    continuous tests until deadline (default 24h)
#   restore           reverse pause(), print human checklist tail
#   status            what is currently running / last heartbeat
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_HOME="$HOME"
if [ "$(id -u)" = "0" ] && [ -n "${SUDO_USER:-}" ]; then
  RUN_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
fi
LOG_DIR="${SOAK_LOG_DIR:-$RUN_HOME/g3-soak-logs-rs}"
HEARTBEAT_SECS=3600

log() { printf '[g3-rs %s] %s\n' "$(date -u +%FT%TZ)" "$*"; }
die() { printf '[g3-rs FATAL] %s\n' "$*" >&2; exit 2; }
need_repo() { [ -f "$REPO_ROOT/Cargo.toml" ] || die "run from a bolina-rs checkout"; }
ensure_logdir() { mkdir -p "$LOG_DIR"; }

rust_bin() {
  local PINNED="$HOME/.cargo/bin/cargo"
  if [ -x "$PINNED" ]; then printf '%s' "$PINNED"; return 0; fi
  CARGO="$(command -v cargo || true)"
  [ -n "$CARGO" ] || CARGO="$PINNED"
  [ -x "$CARGO" ] || die "no cargo; run: rustup install stable"
}

cmd_deps() {
  need_repo
  log "checking Rust toolchain..."
  rust_bin >/dev/null
  log "warming build..."
  cd "$REPO_ROOT"
  cargo build --release 2>&1 | tail -5
  log "deps ready"
}

cmd_pause() {
  need_repo
  ensure_logdir
  local services=("$@")
  [ "${#services[@]}" -gt 0 ] || die "usage: $0 pause SVC..."
  log "pausing services: ${services[*]}"
  for svc in "${services[@]}"; do
    if systemctl --user is-active --quiet "$svc" 2>/dev/null; then
      systemctl --user stop "$svc"
      log "stopped $svc"
    fi
  done
  log "locking sleep/updates/cron..."
  sudo systemctl mask sleep.target suspend.target hibernate.target 2>/dev/null || true
  sudo systemctl stop apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
  sudo systemctl disable apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
  log "co-tenancy journal: $LOG_DIR/co-tenancy.log"
  echo "$(date -u +%FT%TZ) paused: ${services[*]}" > "$LOG_DIR/co-tenancy.log"
}

cmd_burnin() {
  need_repo
  ensure_logdir
  local hours="${1:-1.5}"
  local secs=$(echo "$hours * 3600" | bc | cut -d. -f1)
  log "burn-in: ${hours}h (${secs}s)"
  cd "$REPO_ROOT"
  local thermal_log="$LOG_DIR/thermal-burnin.csv"
  echo "timestamp,temp_c" > "$thermal_log"
  local deadline=$(($(date +%s) + secs))
  while [ $(date +%s) -lt $deadline ]; do
    cargo test --release 2>&1 | tail -3
    local temp=$(sensors 2>/dev/null | grep -oP 'Package id 0:\s+\+\K[0-9]+' || echo "0")
    echo "$(date -u +%FT%TZ),$temp" >> "$thermal_log"
    log "heartbeat: temp=${temp}C"
    sleep 60
  done
  log "burn-in complete"
}

cmd_soak() {
  need_repo
  ensure_logdir
  local hours="${1:-24}"
  local secs=$(echo "$hours * 3600" | bc | cut -d. -f1)
  log "soak: ${hours}h (${secs}s)"
  cd "$REPO_ROOT"
  local soak_log="$LOG_DIR/soak.log"
  local deadline=$(($(date +%s) + secs))
  local round=0
  while [ $(date +%s) -lt $deadline ]; do
    round=$((round + 1))
    log "round $round starting..."
    if cargo test --release 2>&1 | tee -a "$soak_log" | tail -5; then
      log "round $round: PASS"
    else
      log "round $round: FAIL"
      echo "$(date -u +%FT%TZ) FAIL round $round" >> "$LOG_DIR/failures.log"
    fi
    sleep 10
  done
  log "soak complete: $round rounds"
  sha256sum "$soak_log" > "$LOG_DIR/soak.sha256"
}

cmd_restore() {
  need_repo
  log "restoring services..."
  sudo systemctl unmask sleep.target suspend.target hibernate.target 2>/dev/null || true
  sudo systemctl enable apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
  sudo systemctl start apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
  log "restore complete"
  log "human checklist:"
  log "  1. verify bot responds in #orbit-dev"
  log "  2. verify gitlab-runner is active"
  log "  3. check $LOG_DIR for evidence"
}

cmd_status() {
  need_repo
  ensure_logdir
  log "status:"
  if [ -f "$LOG_DIR/co-tenancy.log" ]; then
    cat "$LOG_DIR/co-tenancy.log"
  fi
  if [ -f "$LOG_DIR/soak.log" ]; then
    tail -10 "$LOG_DIR/soak.log"
  fi
}

case "${1:-help}" in
  deps) shift; cmd_deps "$@" ;;
  pause) shift; cmd_pause "$@" ;;
  burnin) shift; cmd_burnin "$@" ;;
  soak) shift; cmd_soak "$@" ;;
  restore) shift; cmd_restore "$@" ;;
  status) shift; cmd_status "$@" ;;
  *) echo "usage: $0 {deps|pause|burnin|soak|restore|status}" ;;
esac

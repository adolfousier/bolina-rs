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
#   pause SVC...      pause co-tenants (bot, gitlab-runner, cron, opencrabs), lock sleep/updates
#   burnin [HOURS]    thermal observation under full test load (default 1.5h)
#   soak   [HOURS]    continuous chaos+differential until deadline (default 24h)
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
  log "toolchain version:"
  rustc --version
  rustc --version > "$LOG_DIR/toolchain.txt" 2>&1
  log "warming build..."
  cd "$REPO_ROOT"
  cargo build --release 2>&1 | tail -5
  log "building chaos-rs..."
  cd tools/chaos-rs
  cargo build --release 2>&1 | tail -3
  log "deps ready"
}

cmd_pause() {
  need_repo
  ensure_logdir
  local services=("$@")
  [ "${#services[@]}" -gt 0 ] || die "usage: $0 pause SVC..."
  
  # Snapshot services before pause
  log "snapshotting services..."
  systemctl --user list-units --type=service --state=running > "$LOG_DIR/services-before.txt" 2>&1
  systemctl list-units --type=service --state=running >> "$LOG_DIR/services-before.txt" 2>&1
  
  log "pausing user services: ${services[*]}"
  for svc in "${services[@]}"; do
    if systemctl --user is-active --quiet "$svc" 2>/dev/null; then
      systemctl --user stop "$svc"
      log "stopped $svc (user)"
    fi
  done
  
  log "pausing system services..."
  for svc in gitlab-runner opencrabs; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      sudo systemctl stop "$svc"
      log "stopped $svc (system)"
    fi
  done
  
  log "pausing cron..."
  # Pause user crontab
  crontab -l > "$LOG_DIR/crontab-backup.txt" 2>/dev/null || true
  crontab -r 2>/dev/null || true
  log "user crontab paused"
  
  # Pause system cron jobs (harness-loop-v2.sh, sync, backup)
  sudo systemctl stop cron 2>/dev/null || true
  log "system cron paused"
  
  log "locking sleep/updates..."
  sudo systemctl mask sleep.target suspend.target hibernate.target 2>/dev/null || true
  sudo systemctl stop apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
  sudo systemctl disable apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
  
  log "co-tenancy journal: $LOG_DIR/co-tenancy.log"
  echo "$(date -u +%FT%TZ) paused: ${services[*]}" > "$LOG_DIR/co-tenancy.log"
  echo "gitlab-runner: stopped" >> "$LOG_DIR/co-tenancy.log"
  echo "opencrabs: stopped" >> "$LOG_DIR/co-tenancy.log"
  echo "cron: paused" >> "$LOG_DIR/co-tenancy.log"
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
  local chaos_log="$LOG_DIR/chaos.log"
  local deadline=$(($(date +%s) + secs))
  local round=0
  
  # 5 canonical seeds (from Zig soak)
  local seeds=(42 1337 9999 12345 67890)
  local count_per_seed=1000000  # 1M inputs per seed per round
  
  while [ $(date +%s) -lt $deadline ]; do
    round=$((round + 1))
    log "round $round starting..."
    
    # Run cargo test
    if cargo test --release 2>&1 | tee -a "$soak_log" | tail -5; then
      log "round $round: cargo test PASS"
    else
      log "round $round: cargo test FAIL"
      echo "$(date -u +%FT%TZ) FAIL cargo test round $round" >> "$LOG_DIR/failures.log"
    fi
    
    # Run chaos-rs with 5 seeds
    for seed in "${seeds[@]}"; do
      log "chaos seed=$seed count=$count_per_seed"
      if ./tools/chaos-rs/target/release/chaos-rs "$seed" "$count_per_seed" >> "$chaos_log" 2>&1; then
        log "chaos seed=$seed: PASS"
      else
        log "chaos seed=$seed: FAIL"
        echo "$(date -u +%FT%TZ) FAIL chaos seed=$seed round $round" >> "$LOG_DIR/failures.log"
      fi
    done
    
    log "round $round complete"
    sleep 10
  done
  
  log "soak complete: $round rounds"
  sha256sum "$soak_log" > "$LOG_DIR/soak.sha256"
  sha256sum "$chaos_log" >> "$LOG_DIR/soak.sha256"
}

cmd_restore() {
  need_repo
  log "restoring services..."
  
  # Restore user crontab
  if [ -f "$LOG_DIR/crontab-backup.txt" ]; then
    crontab "$LOG_DIR/crontab-backup.txt"
    log "user crontab restored"
  fi
  
  # Restore system cron
  sudo systemctl start cron 2>/dev/null || true
  log "system cron restored"
  
  # Restore system services
  for svc in gitlab-runner opencrabs; do
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
      sudo systemctl start "$svc"
      log "started $svc (system)"
    fi
  done
  
  # Restore sleep/updates
  sudo systemctl unmask sleep.target suspend.target hibernate.target 2>/dev/null || true
  sudo systemctl enable apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
  sudo systemctl start apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
  
  # Snapshot services after restore
  log "snapshotting services after restore..."
  systemctl --user list-units --type=service --state=running > "$LOG_DIR/services-after.txt" 2>&1
  systemctl list-units --type=service --state=running >> "$LOG_DIR/services-after.txt" 2>&1
  
  log "restore complete"
  log "human checklist:"
  log "  1. verify bot responds in #orbit-dev"
  log "  2. verify gitlab-runner is active"
  log "  3. verify opencrabs is active"
  log "  4. check $LOG_DIR for evidence"
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
  if [ -f "$LOG_DIR/chaos.log" ]; then
    tail -10 "$LOG_DIR/chaos.log"
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

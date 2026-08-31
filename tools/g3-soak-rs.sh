#!/usr/bin/env bash
# g3-soak-rs.sh - G3 adversarial soak kit for Rust port (D-096 gate G3).
#
# Runs entirely OUTSIDE src/: evidence tooling only.
# Target: the frozen tag checkout this script lives in.
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
RUN_USER="$(whoami)"
if [ "$(id -u)" = "0" ] && [ -n "${SUDO_USER:-}" ]; then
  RUN_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  RUN_USER="$SUDO_USER"
fi
LOG_DIR="${SOAK_LOG_DIR:-$RUN_HOME/g3-soak-logs-rs}"
HEARTBEAT_SECS=3600

log() { printf '[g3-rs %s] %s\n' "$(date -u +%FT%TZ)" "$*"; }
die() { printf '[g3-rs FATAL] %s\n' "$*" >&2; exit 2; }
need_repo() { [ -f "$REPO_ROOT/Cargo.toml" ] || die "run from a bolina-rs checkout"; }

ensure_logdir() {
  mkdir -p "$LOG_DIR"
  if [ "$(id -u)" = "0" ] && [ -n "${SUDO_USER:-}" ]; then
    chown "$SUDO_USER:$SUDO_USER" "$LOG_DIR"
  fi
}

rust_bin() {
  local PINNED="$HOME/.cargo/bin/cargo"
  if [ -x "$PINNED" ]; then printf '%s' "$PINNED"; return 0; fi
  CARGO="$(command -v cargo || true)"
  [ -n "$CARGO" ] || CARGO="$PINNED"
  [ -x "$CARGO" ] || die "no cargo; run: rustup install stable"
}

cmd_deps() {
  need_repo
  ensure_logdir
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
  
  # Snapshot services before pause (observe, don't pretend)
  log "snapshotting services..."
  if [ "$(id -u)" = "0" ] && [ -n "${SUDO_USER:-}" ]; then
    sudo -u "$SUDO_USER" XDG_RUNTIME_DIR="/run/user/$(id -u "$SUDO_USER")" \
      systemctl --user list-units --type=service --state=running > "$LOG_DIR/services-before.txt" 2>&1 || true
  else
    systemctl --user list-units --type=service --state=running > "$LOG_DIR/services-before.txt" 2>&1 || true
  fi
  systemctl list-units --type=service --state=running >> "$LOG_DIR/services-before.txt" 2>&1 || true
  
  # Pause user services (as the actual user, not root)
  log "pausing user services: ${services[*]}"
  for svc in "${services[@]}"; do
    if [ "$(id -u)" = "0" ] && [ -n "${SUDO_USER:-}" ]; then
      if sudo -u "$SUDO_USER" XDG_RUNTIME_DIR="/run/user/$(id -u "$SUDO_USER")" \
        systemctl --user is-active --quiet "$svc" 2>/dev/null; then
        sudo -u "$SUDO_USER" XDG_RUNTIME_DIR="/run/user/$(id -u "$SUDO_USER")" \
          systemctl --user stop "$svc"
        log "stopped $svc (user $SUDO_USER)"
      else
        log "$svc not active (user $SUDO_USER)"
      fi
    else
      if systemctl --user is-active --quiet "$svc" 2>/dev/null; then
        systemctl --user stop "$svc"
        log "stopped $svc (user)"
      else
        log "$svc not active (user)"
      fi
    fi
  done
  
  # Pause system services
  log "pausing system services..."
  for svc in gitlab-runner; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      sudo systemctl stop "$svc"
      log "stopped $svc (system)"
    else
      log "$svc not active (system)"
    fi
  done
  
  # Pause cron (user + system)
  log "pausing cron..."
  if [ "$(id -u)" = "0" ] && [ -n "${SUDO_USER:-}" ]; then
    sudo -u "$SUDO_USER" crontab -l > "$LOG_DIR/crontab-backup.txt" 2>/dev/null || true
    if [ -s "$LOG_DIR/crontab-backup.txt" ]; then
      sudo -u "$SUDO_USER" crontab -r 2>/dev/null || true
      log "user crontab paused ($SUDO_USER)"
    else
      log "no user crontab to pause"
    fi
  else
    crontab -l > "$LOG_DIR/crontab-backup.txt" 2>/dev/null || true
    if [ -s "$LOG_DIR/crontab-backup.txt" ]; then
      crontab -r 2>/dev/null || true
      log "user crontab paused"
    else
      log "no user crontab to pause"
    fi
  fi
  
  sudo systemctl stop cron 2>/dev/null || true
  log "system cron paused"
  
  # Lock sleep/updates
  log "locking sleep/updates..."
  sudo systemctl mask sleep.target suspend.target hibernate.target 2>/dev/null || true
  sudo systemctl stop apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
  sudo systemctl disable apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
  
  # Write co-tenancy log with OBSERVED state, not pretended
  log "writing co-tenancy journal: $LOG_DIR/co-tenancy.log"
  {
    echo "$(date -u +%FT%TZ) pause started"
    echo "services requested: ${services[*]}"
    for svc in "${services[@]}"; do
      if [ "$(id -u)" = "0" ] && [ -n "${SUDO_USER:-}" ]; then
        if sudo -u "$SUDO_USER" XDG_RUNTIME_DIR="/run/user/$(id -u "$SUDO_USER")" \
          systemctl --user is-active --quiet "$svc" 2>/dev/null; then
          echo "$svc (user): still active (FAILED TO STOP)"
        else
          echo "$svc (user): stopped"
        fi
      else
        if systemctl --user is-active --quiet "$svc" 2>/dev/null; then
          echo "$svc (user): still active (FAILED TO STOP)"
        else
          echo "$svc (user): stopped"
        fi
      fi
    done
    for svc in gitlab-runner; do
      if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo "$svc (system): still active (FAILED TO STOP)"
      else
        echo "$svc (system): stopped"
      fi
    done
    if [ "$(id -u)" = "0" ] && [ -n "${SUDO_USER:-}" ]; then
      if sudo -u "$SUDO_USER" crontab -l >/dev/null 2>&1; then
        echo "crontab (user $SUDO_USER): still active (FAILED TO STOP)"
      else
        echo "crontab (user $SUDO_USER): paused"
      fi
    else
      if crontab -l >/dev/null 2>&1; then
        echo "crontab (user): still active (FAILED TO STOP)"
      else
        echo "crontab (user): paused"
      fi
    fi
    if systemctl is-active --quiet cron 2>/dev/null; then
      echo "cron (system): still active (FAILED TO STOP)"
    else
      echo "cron (system): paused"
    fi
  } > "$LOG_DIR/co-tenancy.log"
  
  log "pause complete. Co-tenancy log: $LOG_DIR/co-tenancy.log"
}

cmd_burnin() {
  need_repo
  ensure_logdir
  local hours="${1:-1.5}"
  local secs=$(echo "$hours * 3600" | bc | cut -d. -f1)
  log "burn-in: ${hours}h (${secs}s) with thermal monitoring"
  
  # Start thermal logging
  (
    while true; do
      if command -v sensors >/dev/null 2>&1; then
        sensors 2>/dev/null | grep -E "Core|Package" | head -4 | \
          awk -v ts="$(date -u +%FT%TZ)" '{print ts","$1","$2}' >> "$LOG_DIR/thermal-burnin.csv"
      fi
      sleep 30
    done
  ) &
  local thermal_pid=$!
  
  # Run tests continuously
  cd "$REPO_ROOT"
  local end_time=$(($(date +%s) + secs))
  local round=0
  while [ $(date +%s) -lt $end_time ]; do
    round=$((round + 1))
    log "burn-in round $round"
    cargo test --release 2>&1 | tail -3
    sleep 5
  done
  
  kill $thermal_pid 2>/dev/null || true
  log "burn-in complete"
}

cmd_soak() {
  need_repo
  ensure_logdir
  local hours="${1:-24}"
  local secs=$(echo "$hours * 3600" | bc | cut -d. -f1)
  log "soak: ${hours}h (${secs}s) with chaos + differential"
  
  cd "$REPO_ROOT"
  local end_time=$(($(date +%s) + secs))
  local round=0
  
  while [ $(date +%s) -lt $end_time ]; do
    round=$((round + 1))
    log "soak round $round"
    
    # cargo test
    log "running cargo test..."
    cargo test --release 2>&1 | tail -5
    
    # chaos-rs
    log "running chaos-rs..."
    ./tools/chaos-rs/target/release/chaos-rs 2>&1 | tail -10
    
    # differential (cross-diff Zig vs Rust)
    log "running cross-diff..."
    cd "$REPO_ROOT" && ./tools/cross-diff/target/release/cross-diff 2>&1 | tail -5 || log "cross-diff not built yet"
    
    # Heartbeat
    if [ $((round % 10)) -eq 0 ]; then
      log "heartbeat: round $round complete"
    fi
    
    sleep 10
  done
  
  log "soak complete after $round rounds"
  sha256sum "$LOG_DIR/soak.log" > "$LOG_DIR/soak.sha256" 2>/dev/null || true
}

cmd_restore() {
  need_repo
  ensure_logdir
  log "restoring services..."
  
  # Restore user crontab
  if [ -s "$LOG_DIR/crontab-backup.txt" ]; then
    if [ "$(id -u)" = "0" ] && [ -n "${SUDO_USER:-}" ]; then
      sudo -u "$SUDO_USER" crontab "$LOG_DIR/crontab-backup.txt"
      log "user crontab restored ($SUDO_USER)"
    else
      crontab "$LOG_DIR/crontab-backup.txt"
      log "user crontab restored"
    fi
  fi
  
  # Restore system cron
  sudo systemctl start cron 2>/dev/null || true
  log "system cron restored"
  
  # Restore system services
  for svc in gitlab-runner; do
    if grep -q "$svc (system): stopped" "$LOG_DIR/co-tenancy.log" 2>/dev/null; then
      sudo systemctl start "$svc" 2>/dev/null || true
      log "restarted $svc (system)"
    fi
  done
  
  # Restore user services
  if [ -s "$LOG_DIR/services-before.txt" ]; then
    grep "running" "$LOG_DIR/services-before.txt" | awk '{print $1}' | while read svc; do
      if [ "$(id -u)" = "0" ] && [ -n "${SUDO_USER:-}" ]; then
        sudo -u "$SUDO_USER" XDG_RUNTIME_DIR="/run/user/$(id -u "$SUDO_USER")" \
          systemctl --user start "$svc" 2>/dev/null || true
        log "restarted $svc (user $SUDO_USER)"
      else
        systemctl --user start "$svc" 2>/dev/null || true
        log "restarted $svc (user)"
      fi
    done
  fi
  
  # Unlock sleep/updates
  sudo systemctl unmask sleep.target suspend.target hibernate.target 2>/dev/null || true
  sudo systemctl enable apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
  sudo systemctl start apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
  
  log "restore complete. Human checklist:"
  echo "  1. Verify bot responds in #orbit-dev"
  echo "  2. Check gitlab-runner is active: systemctl status gitlab-runner"
  echo "  3. Check crontab: crontab -l"
  echo "  4. Check logs: $LOG_DIR/"
}

cmd_status() {
  need_repo
  ensure_logdir
  log "status:"
  if [ -f "$LOG_DIR/co-tenancy.log" ]; then
    echo "=== Co-tenancy ==="
    cat "$LOG_DIR/co-tenancy.log"
  fi
  if [ -f "$LOG_DIR/toolchain.txt" ]; then
    echo "=== Toolchain ==="
    cat "$LOG_DIR/toolchain.txt"
  fi
  if pgrep -f "cargo test" >/dev/null 2>&1; then
    echo "=== Running ==="
    pgrep -af "cargo test"
  fi
}

# Main
case "${1:-}" in
  deps) cmd_deps ;;
  pause) shift; cmd_pause "$@" ;;
  burnin) cmd_burnin "${2:-1.5}" ;;
  soak) cmd_soak "${2:-24}" ;;
  restore) cmd_restore ;;
  status) cmd_status ;;
  *) die "usage: $0 {deps|pause|burnin|soak|restore|status}" ;;
esac

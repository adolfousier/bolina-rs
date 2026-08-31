#!/usr/bin/env bash
# g3-soak-rs.sh - G3 adversarial soak kit for Rust port (D-096 gate G3).
#
# Runs entirely OUTSIDE src/: evidence tooling only.
# Target: the frozen tag checkout this script lives in.
#
# Subcommands:
#   deps              install pinned Rust toolchain + warm build (repo + chaos-rs + cross-diff)
#   pause [--auto|SVC...]  pause co-tenants, lock sleep/updates
#   burnin [HOURS]    thermal observation under full test load (default 1.5h)
#   soak   [HOURS]    continuous chaos+differential until deadline (default 24h)
#   restore           reverse pause(), print human checklist tail
#   status            what is currently running / last heartbeat
set -uo pipefail
# NOTE: -e removed. Failures are logged, not fatal. A panic at hour 3 must be
# recorded, not silently terminate the soak. Each command is wrapped explicitly.

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

# --- deps: build repo + chaos-rs + cross-diff (bug #3 fix) ---
cmd_deps() {
  need_repo
  ensure_logdir
  log "checking Rust toolchain..."
  rust_bin >/dev/null
  log "toolchain version:"
  rustc --version 2>&1 | tee "$LOG_DIR/toolchain.txt"
  log "warming build (repo)..."
  cd "$REPO_ROOT"
  cargo build --release 2>&1 | tail -5
  log "building chaos-rs..."
  cd "$REPO_ROOT/tools/chaos-rs"
  cargo build --release 2>&1 | tail -3
  log "building cross-diff..."
  cd "$REPO_ROOT/tools/cross-diff"
  cargo build --release 2>&1 | tail -3
  log "deps ready"
}

# --- pause: --auto or explicit service list (bug #6 fix) ---
AUTO_SERVICES=(orbit-discord-bot opencrabs gitlab-runner)

cmd_pause() {
  need_repo
  ensure_logdir
  local services=()

  if [ "${1:-}" = "--auto" ]; then
    shift
    services=("${AUTO_SERVICES[@]}")
    log "--auto: pausing ${services[*]}"
  else
    services=("$@")
    [ "${#services[@]}" -gt 0 ] || die "usage: $0 pause [--auto|SVC...]"
  fi

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
          systemctl --user stop "$svc" && log "stopped $svc (user $SUDO_USER)" || log "FAILED to stop $svc (user $SUDO_USER)"
      else
        log "$svc not active (user $SUDO_USER)"
      fi
    else
      if systemctl --user is-active --quiet "$svc" 2>/dev/null; then
        systemctl --user stop "$svc" && log "stopped $svc (user)" || log "FAILED to stop $svc (user)"
      else
        log "$svc not active (user)"
      fi
    fi
  done

  # Pause system services
  log "pausing system services..."
  for svc in gitlab-runner; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      sudo systemctl stop "$svc" && log "stopped $svc (system)" || log "FAILED to stop $svc (system)"
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

  # Write co-tenancy log with OBSERVED state
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

# Thermal CSV helper — $3 is the temperature field from sensors(1) (bug #4 fix).
# Runs in background during both burnin and soak.
start_thermal_logger() {
  local csv_file="$1"
  echo "timestamp,label,temp_c" > "$csv_file"
  (
    while true; do
      if command -v sensors >/dev/null 2>&1; then
        sensors 2>/dev/null | grep -E "Core|Package" | head -9 | \
          awk -v ts="$(date -u +%FT%TZ)" '{
            if ($1 == "Package") { gsub(/[°+]/, "", $4); print ts","$1","$4 }
            else { gsub(/[°+]/, "", $3); print ts","$1","$3 }
          }' >> "$csv_file"
      fi
      sleep 30
    done
  ) &
  echo $!
}

cmd_burnin() {
  need_repo
  ensure_logdir
  local hours="${1:-1.5}"
  local secs=$(echo "$hours * 3600" | bc | cut -d. -f1)
  log "burn-in: ${hours}h (${secs}s) with thermal monitoring"

  local thermal_pid
  start_thermal_logger "$LOG_DIR/thermal-burnin.csv" >/dev/null 2>&1 &; thermal_pid=$!

  cd "$REPO_ROOT"
  local end_time=$(($(date +%s) + secs))
  local round=0
  while [ $(date +%s) -lt $end_time ]; do
    round=$((round + 1))
    log "burn-in round $round"
    if cargo test --release 2>&1 | tail -3; then :; else
      log "WARN: cargo test failed at burn-in round $round"
    fi
    sleep 5
  done

  kill $thermal_pid 2>/dev/null || true
  log "burn-in complete"
}

# --- soak: failures logged, not fatal; tee to soak.log; chaos seeded with round (bugs #1,#2,#5) ---
cmd_soak() {
  need_repo
  ensure_logdir
  local hours="${1:-24}"
  local secs=$(echo "$hours * 3600" | bc | cut -d. -f1)
  log "soak: ${hours}h (${secs}s) with chaos + conformance"

  local SOAK_LOG="$LOG_DIR/soak.log"
  local FAIL_LOG="$LOG_DIR/failures.log"
  : > "$SOAK_LOG"
  : > "$FAIL_LOG"

  # Thermal logging during soak too (bug #4: was burn-in only)
  local thermal_pid
  start_thermal_logger "$LOG_DIR/thermal-soak.csv" >/dev/null 2>&1 &; thermal_pid=$!

  cd "$REPO_ROOT"
  local end_time=$(($(date +%s) + secs))
  local round=0
  local max_temp=""
  local throttle_samples=0

  while [ $(date +%s) -lt $end_time ]; do
    round=$((round + 1))
    log "soak round $round" | tee -a "$SOAK_LOG"

    # cargo test — wrapped: failure is logged, not fatal (bug #1 fix)
    log "running cargo test..." | tee -a "$SOAK_LOG"
    if cargo test --release 2>&1 | tail -5 | tee -a "$SOAK_LOG"; then
      :
    else
      echo "$(date -u +%FT%TZ) round $round: cargo test FAILED" >> "$FAIL_LOG"
      log "FAIL: cargo test round $round (logged to failures.log)" | tee -a "$SOAK_LOG"
    fi

    # chaos-rs — with round as seed modifier (bug #5 fix: distinct inputs per round)
    log "running chaos-rs (round=$round)..." | tee -a "$SOAK_LOG"
    if ./tools/chaos-rs/target/release/chaos-rs "$round" 2>&1 | tail -10 | tee -a "$SOAK_LOG"; then
      :
    else
      echo "$(date -u +%FT%TZ) round $round: chaos-rs FAILED (panic?)" >> "$FAIL_LOG"
      log "FAIL: chaos-rs round $round (logged to failures.log)" | tee -a "$SOAK_LOG"
    fi

    # conformance: cross-diff validates frozen vectors (bug #3 fix)
    log "running cross-diff..." | tee -a "$SOAK_LOG"
    if [ -x "$REPO_ROOT/tools/cross-diff/target/release/cross-diff" ]; then
      if ./tools/cross-diff/target/release/cross-diff 2>&1 | tail -5 | tee -a "$SOAK_LOG"; then
        :
      else
        echo "$(date -u +%FT%TZ) round $round: cross-diff FAILED" >> "$FAIL_LOG"
        log "FAIL: cross-diff round $round" | tee -a "$SOAK_LOG"
      fi
    else
      log "WARN: cross-diff binary missing" | tee -a "$SOAK_LOG"
    fi

    # Heartbeat every 10 rounds — includes max_temp and throttle_samples (like Zig)
    if [ $((round % 10)) -eq 0 ]; then
      if [ -f "$LOG_DIR/thermal-soak.csv" ]; then
        max_temp=$(awk -F, 'NR>1 && $3+0 > max {max=$3+0} END {printf "%.1f", max}' "$LOG_DIR/thermal-soak.csv" 2>/dev/null || echo "?")
        thermal_samples=$(wc -l < "$LOG_DIR/thermal-soak.csv" 2>/dev/null || echo 0)
      fi
      log "HEARTBEAT: round $round | max_temp=${max_temp}°C | thermal_samples=$throttle_samples | failures=$(wc -l < "$FAIL_LOG")" | tee -a "$SOAK_LOG"
    fi

    sleep 10
  done

  kill $thermal_pid 2>/dev/null || true

  log "soak complete after $round rounds" | tee -a "$SOAK_LOG"
  log "total failures: $(wc -l < "$FAIL_LOG")" | tee -a "$SOAK_LOG"

  # Hash the evidence (bug #2 fix: soak.log now exists because of tee)
  # Hash ALL evidence files
  {
    sha256sum "$SOAK_LOG"
    [ -f "$FAIL_LOG" ] && sha256sum "$FAIL_LOG"
    [ -f "$LOG_DIR/thermal-soak.csv" ] && sha256sum "$LOG_DIR/thermal-soak.csv"
    [ -f "$LOG_DIR/co-tenancy.log" ] && sha256sum "$LOG_DIR/co-tenancy.log"
    [ -f "$LOG_DIR/toolchain.txt" ] && sha256sum "$LOG_DIR/toolchain.txt"
  } > "$LOG_DIR/soak.sha256"
  log "evidence hashes: $(wc -l < "$LOG_DIR/soak.sha256") files"
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
    grep "running" "$LOG_DIR/services-before.txt" | awk '{print $1}' | while read -r svc; do
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
  echo "  5. Check failures: cat $LOG_DIR/failures.log"
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
  if [ -f "$LOG_DIR/failures.log" ]; then
    echo "=== Failures ==="
    wc -l "$LOG_DIR/failures.log"
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

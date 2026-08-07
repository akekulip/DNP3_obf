#!/usr/bin/env bash
# Disconnection-safe watchdog. Launched detached (setsid nohup) so it survives the
# initiating session dying (incl. SIGKILL of the runner). It sleeps until a hard
# deadline; if the completion marker does NOT exist by then, it FORCE-RESTORES Defense 3.
# The marker is written by the runner ONLY after Defense 3 is restored AND forwarding is
# verified, so the watchdog firing can never undo a good restore, and a dead runner
# always ends with Defense 3 back.
#   $1 = deadline seconds from now   $2 = marker file   $3 = rollback script path
set -u
DEADLINE_S="${1:-900}"
MARKER="${2:-/home/decps/d4_build/d4_complete.marker}"
ROLLBACK="${3:-/home/decps/d4_build/rollback_defense3.sh}"
LOG=/home/decps/d4_build/watchdog.log
echo "[watchdog $(date -u +%H:%M:%S)] armed: deadline=${DEADLINE_S}s marker=$MARKER pid=$$" >> "$LOG"
END=$(( $(date +%s) + DEADLINE_S ))
while [ "$(date +%s)" -lt "$END" ]; do
  if [ -f "$MARKER" ]; then
    echo "[watchdog $(date -u +%H:%M:%S)] completion marker present -> stand down" >> "$LOG"
    exit 0
  fi
  sleep 5
done
echo "[watchdog $(date -u +%H:%M:%S)] DEADLINE hit, no marker -> FORCE-RESTORE Defense 3" >> "$LOG"
bash "$ROLLBACK" >> "$LOG" 2>&1
echo "[watchdog $(date -u +%H:%M:%S)] rollback invoked, exit" >> "$LOG"

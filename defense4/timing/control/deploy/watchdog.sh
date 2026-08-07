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

D3_PROG=case_a_defense3
loaded_ok(){   # true only if exactly one bf_switchd is running Defense 3
  local pid conf prog n
  n=$(pgrep -cx bf_switchd || echo 0); [ "$n" = "1" ] || return 1
  pid=$(pgrep -ox bf_switchd || true); [ -n "$pid" ] || return 1
  conf=$(tr '\0' '\n' < /proc/$pid/cmdline 2>/dev/null | awk '/^--conf-file$/{getline;print;exit}')
  [ -n "$conf" ] && [ -r "$conf" ] || return 1
  prog=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['p4_devices'][0]['p4_programs'][0]['program-name'])" "$conf" 2>/dev/null)
  [ "$prog" = "$D3_PROG" ]
}

# Retry the restore until it VERIFIES (Defense 3 loaded, one daemon). Do not treat
# "rollback invoked" as proof of restoration; escalate visibly if it will not come back.
restored=0
for attempt in 1 2 3 4 5; do
  echo "[watchdog $(date -u +%H:%M:%S)] restore attempt $attempt ..." >> "$LOG"
  bash "$ROLLBACK" >> "$LOG" 2>&1 || true
  if loaded_ok; then
    echo "[watchdog $(date -u +%H:%M:%S)] RESTORE VERIFIED: Defense 3 loaded, one daemon" >> "$LOG"
    restored=1; break
  fi
  echo "[watchdog $(date -u +%H:%M:%S)] restore NOT yet verified (attempt $attempt), retrying" >> "$LOG"
  sleep 10
done
if [ "$restored" != "1" ]; then
  echo "[watchdog $(date -u +%H:%M:%S)] ***ESCALATION*** Defense 3 NOT restored after 5 attempts. MANUAL INTERVENTION REQUIRED: bash $ROLLBACK" >> "$LOG"
  # also drop a loud sentinel next to the log so it is visible out-of-band
  echo "WATCHDOG ESCALATION $(date -u +%Y-%m-%dT%H:%M:%SZ): Defense 3 not restored" > /home/decps/d4_build/WATCHDOG_ESCALATION
  exit 1
fi
exit 0

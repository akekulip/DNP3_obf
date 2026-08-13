#!/usr/bin/env bash
# ============================================================================
# watchdog_rrc.sh — disconnection-safe safety net for the unified-program load.
# Launched DETACHED (setsid nohup) so it survives the runner dying (incl. SIGKILL).
# It FORCE-RESTORES the proven RRC via the snapshot-based rollback_rrc.sh if EITHER:
#   (1) the completion marker is absent by a hard deadline (the runner died / never
#       signalled a deliberate safe terminal state), OR
#   (2) bf_switchd is ABSENT continuously for > GRACE seconds (a load that crashed
#       and did not come back — the intended cold reload is down only ~40 s, well
#       under GRACE, so this never false-fires on the deliberate unified load).
#
# The marker is written by the runner ONLY after a deliberate SAFE terminal state
# (H0 passed and the unified program is up+configured, OR a failure-triggered RRC
# restore verified). So the watchdog firing can never undo a good state, and a dead
# runner always ends with RRC restored.
#
# NOTE ON SCOPE: this watchdog runs on the SWITCH, which cannot reach the relay
# (192.168.10.7 is behind the data plane, reachable only from the master/Vision).
# Relay ping/TCP:20000/READ-probe and BFRT/H0 checks are the RUNNER's job — the
# runner invokes rollback_rrc.sh immediately on any of those failures. This watchdog
# covers the cases the runner cannot: the runner itself dying, and bf_switchd dying.
#   $1 = deadline seconds   $2 = marker file   $3 = rollback script   [$4 = grace s]
set -u
DEADLINE_S="${1:-900}"
MARKER="${2:-/home/decps/rrc_build/hw_campaign.marker}"
ROLLBACK="${3:-/home/decps/rrc_build/rollback_rrc.sh}"
GRACE_S="${4:-120}"
LOG=/home/decps/rrc_build/watchdog_rrc.log
RRC_PROG=defense4_rrc_kernel

echo "[watchdog $(date -u +%H:%M:%S)] armed: deadline=${DEADLINE_S}s grace=${GRACE_S}s marker=$MARKER rollback=$ROLLBACK pid=$$" >> "$LOG"
END=$(( $(date +%s) + DEADLINE_S ))
absent_since=""
FIRE=""
while [ "$(date +%s)" -lt "$END" ]; do
  if [ -f "$MARKER" ]; then
    echo "[watchdog $(date -u +%H:%M:%S)] completion marker present -> stand down" >> "$LOG"
    exit 0
  fi
  n=$(pgrep -cx bf_switchd || echo 0)
  if [ "$n" = "0" ]; then
    now=$(date +%s)
    [ -z "$absent_since" ] && absent_since=$now
    if [ $(( now - absent_since )) -ge "$GRACE_S" ]; then
      echo "[watchdog $(date -u +%H:%M:%S)] bf_switchd ABSENT > ${GRACE_S}s -> FIRE" >> "$LOG"
      FIRE="switchd-absent"; break
    fi
  else
    absent_since=""
  fi
  sleep 5
done
[ -z "$FIRE" ] && [ ! -f "$MARKER" ] && FIRE="deadline"

if [ -f "$MARKER" ]; then
  echo "[watchdog $(date -u +%H:%M:%S)] marker appeared at exit -> stand down" >> "$LOG"; exit 0
fi
echo "[watchdog $(date -u +%H:%M:%S)] FIRING ($FIRE) -> FORCE-RESTORE RRC via $ROLLBACK" >> "$LOG"

loaded_ok(){   # true only if exactly one bf_switchd is running the RRC program
  local pid conf prog n
  n=$(pgrep -cx bf_switchd || echo 0); [ "$n" = "1" ] || return 1
  pid=$(pgrep -ox bf_switchd || true); [ -n "$pid" ] || return 1
  conf=$(tr '\0' '\n' < /proc/$pid/cmdline 2>/dev/null | awk '/^--conf-file$/{getline;print;exit}')
  [ -n "$conf" ] && [ -r "$conf" ] || return 1
  prog=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['p4_devices'][0]['p4_programs'][0]['program-name'])" "$conf" 2>/dev/null)
  [ "$prog" = "$RRC_PROG" ]
}

restored=0
for attempt in 1 2 3 4 5; do
  echo "[watchdog $(date -u +%H:%M:%S)] restore attempt $attempt ..." >> "$LOG"
  bash "$ROLLBACK" >> "$LOG" 2>&1 || true
  if loaded_ok; then
    echo "[watchdog $(date -u +%H:%M:%S)] RESTORE VERIFIED: RRC loaded, one daemon" >> "$LOG"
    restored=1; break
  fi
  echo "[watchdog $(date -u +%H:%M:%S)] restore NOT yet verified (attempt $attempt), retrying" >> "$LOG"
  sleep 10
done
if [ "$restored" != "1" ]; then
  echo "[watchdog $(date -u +%H:%M:%S)] ***ESCALATION*** RRC NOT restored after 5 attempts. MANUAL: bash $ROLLBACK" >> "$LOG"
  echo "WATCHDOG ESCALATION $(date -u +%Y-%m-%dT%H:%M:%SZ): RRC not restored" > /home/decps/rrc_build/WATCHDOG_ESCALATION
  exit 1
fi
exit 0

#!/bin/bash
# Stop the running bf_switchd and cold-launch another program. Runs on the switch host.
#   switch_swap.sh LOG LAUNCH_SCRIPT [LAUNCH_ARGS...]
# The stop/launch/wait pattern of vepa_reflect_01/hw_ab_20261011/swap.sh and the rehearsed restoration
# (audit_current/framework_20261005/RESTORATION_REHEARSAL_20261006.md), with two additions: LAUNCH_ARGS are
# forwarded, and the exit status is nonzero unless the daemon is serving :50052 with no device_add error.
LOG=$1; LAUNCH=$2
[ -n "$LOG" ] && [ -f "$LAUNCH" ] || { echo "usage: switch_swap.sh LOG LAUNCH_SCRIPT [ARGS...]"; exit 2; }
shift 2
for p in $(pgrep -x bf_switchd); do sudo kill "$p"; done
sudo pkill -x -f 'tail -f /dev/null' 2>/dev/null
for i in $(seq 1 20); do pgrep -x bf_switchd >/dev/null || break; sleep 1; done
pgrep -x bf_switchd && { echo STILL_RUNNING; exit 1; }
echo stopped
sudo setsid nohup bash "$LAUNCH" "$@" > "$LOG" 2>&1 < /dev/null &
for i in $(seq 1 90); do ss -lnt | grep -q ':50052 ' && break; sleep 1; done
sleep 5
if grep -E 'device_add failed|cannot be assigned' "$LOG"; then echo LAUNCH_ERRORS; exit 1; fi
ss -lnt | grep -q ':50052 ' || { echo NO_LISTENER_50052; exit 1; }
echo serving

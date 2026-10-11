#!/bin/bash
# usage: swap.sh LAUNCH_SCRIPT LOG
for p in $(pgrep -x bf_switchd); do sudo kill $p; done
pkill -x -f 'tail -f /dev/null' 2>/dev/null; sudo pkill -x -f 'tail -f /dev/null' 2>/dev/null
for i in $(seq 1 20); do pgrep -x bf_switchd >/dev/null || break; sleep 1; done
pgrep -x bf_switchd && { echo STILL_RUNNING; exit 1; }
echo stopped
sudo setsid nohup bash "$1" > "$2" 2>&1 < /dev/null &
for i in $(seq 1 90); do ss -lnt | grep -q ':50052 ' && break; sleep 1; done
sleep 5
grep -E 'initialized|ERROR|failed' "$2" | head
ss -lnt | grep -c ':50052 '

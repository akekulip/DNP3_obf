#!/bin/bash
set -euo pipefail
root=/home/decps/dnp3_timing7_20260925
if pgrep -x bf_switchd >/dev/null; then
  pid=$(pgrep -x bf_switchd)
  test "$(pgrep -cx bf_switchd)" = 1
  sudo -n kill -TERM "$pid"
  for attempt in $(seq 1 30); do
    if ! pgrep -x bf_switchd >/dev/null; then break; fi
    sleep 1
  done
  if pgrep -x bf_switchd >/dev/null; then echo 'Daemon did not stop; refusing second owner'; exit 1; fi
fi
cd /home/decps/ml_p4
sudo -n nohup ./launch_mvm.sh > "$root/restore_mvm.log" 2>&1 < /dev/null &
for attempt in $(seq 1 45); do
  if python3 -c 'import socket; s=socket.create_connection(("127.0.0.1",50052),1);s.close()' 2>/dev/null; then
    python3 "$root/preflight/controller.py" setup --model "$root/preflight/model.json"
    exit 0
  fi
  sleep 1
done
echo 'MVM load did not expose BFRT; inspect restore_mvm.log'
exit 1

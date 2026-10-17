#!/bin/bash
# m9_01 gate-4 silicon sequence: freeze check, then one guarded block at a time; stop everything on exit 2.
cd /home/philip/Projects/DNP3
H=defense4/timing/case4_architecture/integration/evidence/rearm_01/hw
F=defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/evidence/m9_01/freeze.py
while read tool cfg run args; do
  echo "=== $(date -Is) $run"
  python3 $F --check || { echo "STOP: freeze check failed before $run"; exit 3; }
  bash $H/run_block.sh $tool $cfg $run $args < /dev/null
  rc=$?
  echo "RC=$rc $run $(tail -1 $H/run_block.log | grep -o 'restore_verify_rc=[0-9]*')"
  if [ $rc -eq 2 ]; then echo "STOP: restoration not verified after $run"; exit 2; fi
done < /tmp/claude-1002/-home-philip-Projects-DNP3/e12214e0-85db-4a92-b338-303a7bee1455/scratchpad/m9_blocks.txt
echo DONE

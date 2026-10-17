#!/bin/bash
# Detached continuation of the m9_01 silicon sequence: waits for the first runner (pid $1) to finish its current
# block and restore, then runs the remaining blocks with the same freeze check and stop rule.
OLD=$1
while kill -0 $OLD 2>/dev/null; do sleep 5; done
echo "=== $(date -Is) first runner $OLD has exited; continuing"
cd /home/philip/Projects/DNP3
H=defense4/timing/case4_architecture/integration/evidence/rearm_01/hw
F=defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/evidence/m9_01/freeze.py
if ! tail -1 $H/run_block.log | grep -q 'restore_verify_rc=0'; then echo "STOP: last block's restore not verified"; exit 2; fi
while read tool cfg run args; do
  echo "=== $(date -Is) $run"
  python3 $F --check || { echo "STOP: freeze check failed before $run"; exit 3; }
  bash $H/run_block.sh $tool $cfg $run $args < /dev/null
  rc=$?
  echo "RC=$rc $run $(tail -1 $H/run_block.log | grep -o 'restore_verify_rc=[0-9]*')"
  if [ $rc -eq 2 ]; then echo "STOP: restoration not verified after $run"; exit 2; fi
done < /tmp/claude-1002/-home-philip-Projects-DNP3/e12214e0-85db-4a92-b338-303a7bee1455/scratchpad/m9_blocks_rest.txt
echo DONE

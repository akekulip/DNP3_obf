#!/bin/bash
# m10 Step 4 (review af7bd434): the five predefined recovery blocks on the exact m10_03 image
# (ctl_timing_01/evidence/m10_03/STEP4_PLAN_20261017.md). Each block goes through run_block_frozen.sh: the freeze
# check binds the block config to the one frozen candidate and is retained, then run_block.sh, then restore_verify.
# Only 0 (passed) and 1 continue. 1 is either a failed block with a verified restore, or a plan refused before
# anything was touched (run_block.sh PLAN-REFUSED / NO-CONFIG). Anything else stops everything: 2 restore NOT
# verified, 3 freeze refused or config not bound, or any signal/shell failure (no verified restore). No block is
# repeated or added. After each block the restart counter count_busy[5] (after - before) is printed. Started detached.
cd /home/philip/Projects/DNP3
H=defense4/timing/case4_architecture/integration/evidence/rearm_01/hw
SEQ=defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/evidence/hw_campaigns/m10_step4_sequence
CAMP=defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/evidence/hw_campaigns
while read freeze tool cfg run args; do
  while pgrep -af 'run_model\.py' > /dev/null; do echo "$(date -Is) waiting: a model run is active on this host"; sleep 30; done
  echo "=== $(date -Is) $run"
  bash $H/run_block_frozen.sh $freeze $tool $cfg $run $args < /dev/null
  rc=$?
  echo "RC=$rc $run $(tail -1 $H/run_block.log | grep -o 'restore_verify_rc=[0-9]*')"
  python3 $SEQ/restart_count.py $CAMP/$run < /dev/null
  if [ $rc -ne 0 ] && [ $rc -ne 1 ]; then echo "STOP rc=$rc after $run (2 restore not verified, 3 freeze refused, other: no verified restore)"; exit $rc; fi
done < $SEQ/blocks.txt
echo DONE

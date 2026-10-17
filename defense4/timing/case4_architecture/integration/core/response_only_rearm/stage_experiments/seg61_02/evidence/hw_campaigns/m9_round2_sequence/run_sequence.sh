#!/bin/bash
# m9 qualification round 2 (directive of 2026-10-17): the six predefined ACK-localization blocks
# (ctl_timing_01/evidence/m9d_01/ACK_DIAG_PLAN_20261017.md), then one instrumented isolation block. Each block goes
# through run_block_frozen.sh (freeze check retained, then run_block.sh, restore_verify). Stop everything on an
# unverified restore (2) or a refused freeze (3). No block is repeated or added. Started detached (setsid nohup).
cd /home/philip/Projects/DNP3
H=defense4/timing/case4_architecture/integration/evidence/rearm_01/hw
SEQ=defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/evidence/hw_campaigns/m9_round2_sequence
while read freeze tool cfg run args; do
  while pgrep -f "run_model.py" > /dev/null; do echo "$(date -Is) waiting: a model run is active on this host"; sleep 30; done
  echo "=== $(date -Is) $run"
  bash $H/run_block_frozen.sh $freeze $tool $cfg $run $args < /dev/null
  rc=$?
  echo "RC=$rc $run $(tail -1 $H/run_block.log | grep -o 'restore_verify_rc=[0-9]*')"
  if [ $rc -eq 2 ]; then echo "STOP: restoration not verified after $run"; exit 2; fi
  if [ $rc -eq 3 ]; then echo "STOP: freeze check refused $run"; exit 3; fi
  if [ "$tool" = candidate_isolation ]; then
    python3 defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/analysis/isolation_v3.py \
      defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/evidence/hw_campaigns/$run
    echo "V3_EVALUATED $run rc=$?"
  fi
done < $SEQ/blocks.txt
echo DONE

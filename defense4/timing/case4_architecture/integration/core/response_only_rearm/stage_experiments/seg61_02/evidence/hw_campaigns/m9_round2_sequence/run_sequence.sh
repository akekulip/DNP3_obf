#!/bin/bash
# m9 qualification round 2 (directive of 2026-10-17): the six predefined ACK-localization blocks
# (ctl_timing_01/evidence/m9d_01/ACK_DIAG_PLAN_20261017.md), then one instrumented isolation block. Each block goes
# through run_block_frozen.sh (freeze check retained, then run_block.sh, restore_verify). Only 0 (passed) and 1
# (block failed, restore verified) continue; anything else stops everything: 2 restore NOT verified, 3 freeze
# refused, or any signal/shell failure (no verified restore). No block is repeated or added. Started detached.
cd /home/philip/Projects/DNP3
H=defense4/timing/case4_architecture/integration/evidence/rearm_01/hw
SEQ=defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/evidence/hw_campaigns/m9_round2_sequence
while read freeze tool cfg run args; do
  while pgrep -a -x python3 | grep -q ' run_model.py '; do echo "$(date -Is) waiting: a model run is active on this host"; sleep 30; done
  echo "=== $(date -Is) $run"
  bash $H/run_block_frozen.sh $freeze $tool $cfg $run $args < /dev/null
  rc=$?
  echo "RC=$rc $run $(tail -1 $H/run_block.log | grep -o 'restore_verify_rc=[0-9]*')"
  if [ $rc -ne 0 ] && [ $rc -ne 1 ]; then echo "STOP rc=$rc after $run (2 restore not verified, 3 freeze refused, other: no verified restore)"; exit $rc; fi
  if [ "$tool" = candidate_isolation ]; then
    python3 defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/analysis/isolation_v3.py \
      defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/evidence/hw_campaigns/$run --config $cfg < /dev/null
    echo "V3_EVALUATED $run rc=$?"
  fi
done < $SEQ/blocks.txt
echo DONE

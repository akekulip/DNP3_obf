#!/usr/bin/env bash
# Run the prepared c75 confirmation campaigns one at a time; stop at the first block whose restoration is not
# verified. Run from the repository root after c75_prepare.sh (same folder) passed for every block.
set -u
D=${D:?set D=YYYYMMDD}
for ID in rc01_hw_c75_sc20_${D}_01 rc01_hw_c75_sc5_${D}_01 \
          rc01_hw_c75diag_e2c_${D}_01 rc01_hw_c75diag_e2o_${D}_01 \
          rc01_hw_c75_recovery_r1_${D}_01 rc01_hw_c75_recovery_r2_${D}_01 rc01_hw_c75_recovery_r3_${D}_01 \
          rc01_hw_c75_e4b_${D}_01; do
  C=results/hardware/campaigns/$ID
  echo "== $(date +%T) $ID"
  python3 scripts/hardware/evaluation_campaign.py init "$C/manifest.json" > /dev/null 2>&1 || { echo "init failed"; break; }
  python3 scripts/hardware/evaluation_campaign.py start "$C/$ID" > /dev/null 2>&1 || { echo "start failed"; break; }
  sleep 20
  while python3 scripts/hardware/evaluation_campaign.py status "$C/$ID" 2>/dev/null | python3 -c "import json,sys;s=json.load(sys.stdin);sys.exit(0 if s['phase']=='running' else 1)"; do sleep 30; done
  R=$(python3 scripts/hardware/evaluation_campaign.py status "$C/$ID" | python3 -c "import json,sys;s=json.load(sys.stdin);b=s['blocks'][0];print(s['phase'],s['result'],b['status'],b['rc'],(b['restoration'] or {}).get('ok'))")
  echo "   $(date +%T) $R"
  case "$R" in *True) ;; *) echo "STOP: restoration not verified"; break;; esac
done
echo "== $(date +%T) done"

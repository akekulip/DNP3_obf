#!/usr/bin/env bash
# Rewrite the (unrun) campaign freeze, freeze-check every config, then dry-run every manifest argv exactly.
set -u
cd /home/philip/Projects/DNP3
ID=rc01_hw_c72_recovery_20261028_01; C=results/hardware/campaigns/$ID; P=results/analysis/recovery_e3/preparation
BLOCKS="r1_d20_combined r2_d20_size_only r3_d5_combined"
{
  echo "# $(date -u +%FT%TZ) freeze+dry-run"
  echo "\$ python3 scripts/hardware/freeze_gate.py write results/builds/c72 -o $C/freeze.json --configs $(for b in $BLOCKS; do printf '%s ' $C/configs/$b.json; done)"
  python3 scripts/hardware/freeze_gate.py write results/builds/c72 -o $C/freeze.json --configs $(for b in $BLOCKS; do printf '%s ' $C/configs/$b.json; done) 2>&1; echo "rc=$?"
} > $P/02b_freeze_write.log
: > $P/03b_freeze_check.log
for b in $BLOCKS; do
  { echo "# $(date -u +%FT%TZ)"; echo "\$ python3 scripts/hardware/freeze_gate.py check $C/freeze.json --config $C/configs/$b.json --record $P/freeze_check_$b.json"
    python3 scripts/hardware/freeze_gate.py check $C/freeze.json --config $C/configs/$b.json --record $P/freeze_check_$b.json 2>&1; echo "rc=$?"; } >> $P/03b_freeze_check.log
done
mkdir -p $C/dry_run
: > $P/04_dry_run.log
for b in $BLOCKS; do
  mapfile -t ARGV < <(python3 -c "import json,sys;[print(a) for a in next(s for s in json.load(open('$C/manifest.json'))['steps'] if s['id']=='$b')['argv']]")
  { echo "# $(date -u +%FT%TZ) $b"; printf '$'; printf ' %q' "${ARGV[@]}" --dry-run; echo; } >> $P/04_dry_run.log
  "${ARGV[@]}" --dry-run < /dev/null > $C/dry_run/$b.out 2>&1
  echo "rc=$?" >> $P/04_dry_run.log
done

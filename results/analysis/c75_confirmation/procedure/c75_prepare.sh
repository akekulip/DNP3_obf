#!/usr/bin/env bash
# Prepare, freeze and dry-run every c75 confirmation block (results/analysis/c75_confirmation/DESIGN.json).
# No hardware contact. Run from the repository root.
set -u
NATIVE=results/hardware/native/c72_native_20261027_01/relay_wire.json
D=${D:?set D=YYYYMMDD}
SPECS=(
  "rc01_hw_c75_sc20_${D}_01 strict_cycle_c75_d20 results/builds/c75"
  "rc01_hw_c75_sc5_${D}_01 strict_cycle_c75_d5 results/builds/c75"
  "rc01_hw_c75diag_e2c_${D}_01 diag_e2_combined_c75 results/builds/c75_diag_mirror"
  "rc01_hw_c75diag_e2o_${D}_01 diag_e2_off_c75 results/builds/c75_diag_mirror"
  "rc01_hw_c75_recovery_r1_${D}_01 recovery_c75_r1 results/builds/c75"
  "rc01_hw_c75_recovery_r2_${D}_01 recovery_c75_r2 results/builds/c75"
  "rc01_hw_c75_recovery_r3_${D}_01 recovery_c75_r3 results/builds/c75"
  "rc01_hw_c75_e4b_${D}_01 e4b_select_only_c75 results/builds/c75"
)
for spec in "${SPECS[@]}"; do
  set -- $spec; ID=$1; DEF=$2; BUILD=$3
  C=results/hardware/campaigns/$ID; P=results/analysis/c75_confirmation/runs/$ID
  mkdir -p "$P"
  python3 scripts/hardware/matrix.py prepare "$BUILD" --native-observation "$NATIVE" --output "$C" \
      --campaign-id "$ID" --definition "$DEF" > "$P/00_prepare.log" 2>&1
  rc=$?; echo "$ID prepare rc=$rc"; [ $rc -eq 0 ] || exit 1
  B=$(ls "$C/configs" | sed 's/.json$//')
  { python3 scripts/hardware/freeze_gate.py write "$BUILD" -o "$C/freeze.json" --configs "$C/configs/$B.json" 2>&1
    echo "rc=$?"
    python3 scripts/hardware/freeze_gate.py check "$C/freeze.json" --config "$C/configs/$B.json" \
        --record "$P/freeze_check_$B.json" 2>&1 | tail -2; } > "$P/01_freeze.log"
  tail -2 "$P/01_freeze.log"
  grep -q "freeze check: OK 0 changed, 0 missing" "$P/01_freeze.log" || { echo "STOP: freeze check"; exit 1; }
  mkdir -p "$C/dry_run"
  mapfile -t ARGV < <(python3 -c "import json;[print(a) for a in next(s for s in json.load(open('$C/manifest.json'))['steps'] if s['id']=='$B')['argv']]")
  { printf '$'; printf ' %q' "${ARGV[@]}" --dry-run; echo; } > "$P/02_dry_run.log"
  timeout 900 "${ARGV[@]}" --dry-run < /dev/null > "$C/dry_run/$B.out" 2>&1
  rc=$?
  echo " dry-run rc=$rc trials=$(grep -c 'vision_run.py run' "$C/dry_run/$B.out") strict=$(grep -c -- '--sbo-strict-cycle 1' "$C/dry_run/$B.out") select_only=$(grep -c -- '--sbo-select-only' "$C/dry_run/$B.out") mirror=$(grep -c -- '--mirror-iface' "$C/dry_run/$B.out") diagon=$(grep -c -- '--diag-mirror on' "$C/dry_run/$B.out") drop=$(grep -c -- '--drop' "$C/dry_run/$B.out")" | tee -a "$P/02_dry_run.log"
  [ $rc -eq 0 ] || { echo "STOP: dry-run"; exit 1; }
done

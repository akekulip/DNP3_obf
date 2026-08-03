#!/usr/bin/env bash
# =============================================================================
#  ksweep_hold_refine.sh — refinement pass for the §5.8 hold-continuity sweep.
#
#  The main pass (ksweep_hold.sh) located the continuity floor between K = 32
#  (EARLY: all-stale, ~0.5-0.9 us hold) and K = 48 (CLEAN: all-deadline,
#  release bias = K/rate) at D = 2 ms. This pass walks the 36..44 gap and
#  brackets the same 32..48 range at D = 8 and 16 ms, whose main-pass points
#  topped out at K = 24. Run it with SWEEP_OUT pointed at the SAME evidence
#  directory so there is ONE manifest for the whole experiment:
#
#      SWEEP_OUT=defense3/evidence/ksweep_hold/<ts> bash ksweep_hold_refine.sh
#
#  Same contract as the main pass: D3_SKIP_RESTORE=1 everywhere, the caller
#  owns the final --restore-only.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -n "${SWEEP_OUT:-}" ] || { echo "SWEEP_OUT must point at the main pass's evidence dir" >&2; exit 1; }
[ -f "$SWEEP_OUT/manifest.jsonl" ] || { echo "no manifest at $SWEEP_OUT" >&2; exit 1; }
REPS="${REPS:-3}"
MANIFEST="$SWEEP_OUT/manifest.jsonl"
LOG="$SWEEP_OUT/sweep.log"

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$LOG" >&2; }

budget_for() {
  python3 - "$1" "$2" <<'PY'
import math, sys
k, d = int(sys.argv[1]), float(sys.argv[2])
print(max(18000, math.ceil((d + 6.5) * 1e-3 * 37.4e6 / k)))
PY
}

run_one() {
  local k="$1" d="$2" rep="$3" b rc t0 t1
  b="$(budget_for "$k" "$d")"
  log "refine trial K=$k D=${d}ms B=$b rep=$rep"
  t0=$(date +%s)
  OUTDIR="$SWEEP_OUT" KVAL="$k" D_MS="$d" BUDGET="$b" \
    D3_SKIP_RESTORE=1 D3_ALLOW_REDUCED_K_HOLD=1 D3_NO_TMUX=1 \
    bash "$HERE/run_defense3.sh" --gate2 >>"$LOG" 2>&1
  rc=$?
  t1=$(date +%s)
  local d_new
  d_new="$(ls -1dt "$SWEEP_OUT"/gate2_* 2>/dev/null | head -1)"
  printf '{"k": %s, "d_ms": %s, "budget": %s, "rep": %s, "rc": %s, "dir": "%s", "wall_s": %s, "phase": "refine"}\n' \
    "$k" "$d" "$b" "$rep" "$rc" "${d_new##*/}" "$((t1 - t0))" >> "$MANIFEST"
}

log "=== REFINEMENT pass -> $SWEEP_OUT (reps=$REPS) ==="
for rep in $(seq 1 "$REPS"); do
  for k in 36 40 44; do run_one "$k" 2 "$rep"; done
  for k in 32 40 48; do run_one "$k" 8 "$rep"; done
  for k in 32 40 48; do run_one "$k" 16 "$rep"; done
done
log "=== refinement complete ==="

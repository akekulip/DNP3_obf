#!/usr/bin/env bash
# =============================================================================
#  ksweep_hold.sh — the §5.8 HOLD-CONTINUITY K-SWEEP (post-freeze experiment,
#  explicitly authorized 2026-08-03).
#
#  QUESTION: at each D, how many reservoir tokens K are needed to keep the held
#  packet in Q_HOLD all the way to the deadline t_ACK + D?
#
#  MODEL UNDER TEST (fig13): K_req(D) = max(K_cov, ceil((D + c) * rate / B)),
#  with the coverage floor K_cov ~= 16 ESTIMATED from loop RTT x rate and never
#  measured between the proven endpoints (K=1 fails, K=64 works).
#
#  DESIGN. One Gate-2 synthetic transaction per trial (run_defense3.sh --gate2),
#  entirely in-chip: the classification of an early release needs no host
#  capture — reg_ts_ack_arm / reg_ts_ack_release give the achieved hold, the
#  termination counters separate deadline releases from fail-open.
#    * B is scaled per (K, D) as max(18000, ceil((D + 6.5 ms) * rate / K)) so
#      the policy horizon H = B*K/rate always clears the deadline requirement
#      (D + ~6.005 ms) — the budget is never the binding constraint, coverage is.
#      These B values are SWEEP-ONLY; nothing here changes the deployed K=64,
#      B=18000 artifact.
#    * The K=64 safety pin is relaxed by name (D3_ALLOW_REDUCED_K_HOLD=1) and
#      every manifest records the relaxation (reduced_k_hold_sweep: true).
#    * K runs DESCENDING from 64 so the first trials re-validate the loaded
#      build before the sweep walks down into the expected failure region.
#    * Every invocation leaves the switch on Defense 3 (D3_SKIP_RESTORE=1);
#      the caller owns the final --restore-only. A failed trial records rc and
#      the sweep continues — a refusal or FAIL verdict is data here, not abort.
#
#  MATRIX (3 reps each):
#      D = 2 ms : K in 64 48 32 24 20 16 12 8 4 2 1
#      D = 8 ms : K in 64 24 16 12 8
#      D = 16 ms: K in 64 24 16 12 8
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
SWEEP_OUT="${SWEEP_OUT:-$ROOT/evidence/ksweep_hold/$TS}"
REPS="${REPS:-3}"
mkdir -p "$SWEEP_OUT"
MANIFEST="$SWEEP_OUT/manifest.jsonl"
LOG="$SWEEP_OUT/sweep.log"

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$LOG" >&2; }

budget_for() {  # budget_for <k> <d_ms>  -> policy-admissible B, floor 18000
  python3 - "$1" "$2" <<'PY'
import math, sys
k, d = int(sys.argv[1]), float(sys.argv[2])
print(max(18000, math.ceil((d + 6.5) * 1e-3 * 37.4e6 / k)))
PY
}

run_one() {  # run_one <k> <d_ms> <rep>
  local k="$1" d="$2" rep="$3" b rc t0 t1
  b="$(budget_for "$k" "$d")"
  log "trial K=$k D=${d}ms B=$b rep=$rep"
  t0=$(date +%s)
  OUTDIR="$SWEEP_OUT" KVAL="$k" D_MS="$d" BUDGET="$b" \
    D3_SKIP_RESTORE=1 D3_ALLOW_REDUCED_K_HOLD=1 D3_NO_TMUX=1 \
    bash "$HERE/run_defense3.sh" --gate2 >>"$LOG" 2>&1
  rc=$?
  t1=$(date +%s)
  # newest gate2_* dir in SWEEP_OUT is this trial's record
  local d_new
  d_new="$(ls -1dt "$SWEEP_OUT"/gate2_* 2>/dev/null | head -1)"
  printf '{"k": %s, "d_ms": %s, "budget": %s, "rep": %s, "rc": %s, "dir": "%s", "wall_s": %s}\n' \
    "$k" "$d" "$b" "$rep" "$rc" "${d_new##*/}" "$((t1 - t0))" >> "$MANIFEST"
}

log "=== HOLD-CONTINUITY K-SWEEP $TS -> $SWEEP_OUT (reps=$REPS) ==="

for rep in $(seq 1 "$REPS"); do
  for k in 64 48 32 24 20 16 12 8 4 2 1; do run_one "$k" 2 "$rep"; done
done
for rep in $(seq 1 "$REPS"); do
  for k in 64 24 16 12 8; do run_one "$k" 8 "$rep"; done
done
for rep in $(seq 1 "$REPS"); do
  for k in 64 24 16 12 8; do run_one "$k" 16 "$rep"; done
done

log "=== sweep complete: $(wc -l < "$MANIFEST") trials recorded ==="
log "the switch is LEFT ON DEFENSE 3 (D3_SKIP_RESTORE=1) — the caller owns the restore:"
log "    bash $HERE/run_defense3.sh --restore-only"

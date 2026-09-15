#!/usr/bin/env bash
# Rebuild the timing evidence.
#
# TWO corpora live in this tree and they are NOT interchangeable. This script defaults to the
# one the paper reports and puts the retired one behind an explicit flag, so old-corpus output
# cannot be mistaken for current paper evidence.
#
#   ./reproduce.sh [OUT_DIR]        ACTIVE: campaign_v1, 22 grouped runs, 132 captures,
#                                   63,360 exchanges, size carve disabled. This is what the
#                                   manuscript reports. Delegates to
#                                   evidence/campaign_v1/repro/reproduce.sh, which is the
#                                   single authority for the campaign and carries its own
#                                   pinned environment.
#
#   ./reproduce.sh --historical [--outdir DIR]
#                                   RETIRED: final_read_sbo, one capture per arm. Kept for
#                                   provenance only. Nothing in the manuscript rests on it.
#
# The raw captures are immutable inputs under either mode. Everything is written under the
# output directory; nothing in evidence/ is modified.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAMPAIGN_REPRO="$HERE/evidence/campaign_v1/repro/reproduce.sh"

MODE="campaign"
OUTDIR="$HERE/build"
PASSTHROUGH=()
while [ $# -gt 0 ]; do
  case "$1" in
    --historical) MODE="historical"; shift ;;
    --outdir) OUTDIR="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    -*) echo "unknown argument: $1" >&2; exit 2 ;;
    *) PASSTHROUGH+=("$1"); shift ;;
  esac
done

if [ "$MODE" = "campaign" ]; then
  [ -x "$CAMPAIGN_REPRO" ] || { echo "missing $CAMPAIGN_REPRO" >&2; exit 2; }
  echo "=============================================================================="
  echo " ACTIVE CORPUS: campaign_v1 - the evidence the manuscript reports"
  echo " delegating to evidence/campaign_v1/repro/reproduce.sh"
  echo "=============================================================================="
  exec "$CAMPAIGN_REPRO" "${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}"
fi

[ ${#PASSTHROUGH[@]} -eq 0 ] || { echo "--historical takes --outdir, not a positional directory" >&2; exit 2; }
cat <<'BANNER'
==============================================================================
 RETIRED CORPUS: final_read_sbo, one capture per arm.
 Provenance only. NO manuscript claim rests on these outputs. Do not present
 them as current paper evidence; the active corpus is campaign_v1.
==============================================================================
BANNER

ANALYSIS="$HERE/analysis"
FIGSRC="$HERE/figures/source"
RAW="$HERE/evidence/final_read_sbo/raw_pcaps"
FROZEN="$HERE/evidence/final_read_sbo/derived_csv"
CSV="$OUTDIR/derived_csv"
FIGS="$OUTDIR/figures"
mkdir -p "$CSV" "$FIGS"

# ---------------------------------------------------------------- interpreter resolution
resolve_python() {
  if [ -n "${TIMING_PYTHON:-}" ]; then
    echo "$TIMING_PYTHON"; return
  fi
  if command -v uv >/dev/null 2>&1; then
    echo "__uv__"; return
  fi
  for cand in python3 python; do
    command -v "$cand" >/dev/null 2>&1 || continue
    if "$cand" - <<'PY' >/dev/null 2>&1
import numpy, scipy, sklearn, matplotlib   # noqa: F401
PY
    then echo "$cand"; return; fi
  done
  echo "" ; return
}

PY_SEL="$(resolve_python)"
if [ -z "$PY_SEL" ]; then
  cat >&2 <<'MSG'
No usable Python found.
Install uv (https://docs.astral.sh/uv/) and re-run, or point TIMING_PYTHON at an
interpreter that satisfies analysis/requirements.txt:
    TIMING_PYTHON=/path/to/python ./reproduce.sh
MSG
  exit 1
fi

if [ "$PY_SEL" = "__uv__" ]; then
  RUN=(uv run --quiet --project "$HERE" python)
  echo "interpreter: uv run (pinned by pyproject.toml)"
else
  RUN=("$PY_SEL")
  echo "interpreter: $PY_SEL"
fi
export PYTHONPATH="$ANALYSIS${PYTHONPATH:+:$PYTHONPATH}"
py() { "${RUN[@]}" "$@"; }

echo
echo "== environment =="
py "$ANALYSIS/env_report.py" | tee "$OUTDIR/ENVIRONMENT.txt"

echo
echo "== transaction CSVs from raw captures =="
py "$ANALYSIS/extract_clrt.py" "$RAW/e1_native.pcap"   ALL native   "$CSV/native_txn.csv"
py "$ANALYSIS/extract_clrt.py" "$RAW/e2_def_read.pcap" ALL defended "$CSV/defended_read_txn.csv"
py "$ANALYSIS/extract_clrt.py" "$RAW/e2_def.pcap"      ALL defended "$CSV/defended_txn.csv"

echo
echo "== SBO OPERATE timing CSVs =="
for J in 2 6 12; do
  py "$ANALYSIS/extract_sbo.py" "$RAW/sbo_j$J.pcap" "J=${J}ms" "$CSV/sbo_j$J.csv"
done
CSVDIR="$CSV" && export CSVDIR
py - <<'PY'
import os, pathlib
csvdir = pathlib.Path(os.environ["CSVDIR"])
out = csvdir / "sbo_all.csv"
with open(out, "w") as f:
    for i, j in enumerate((2, 6, 12)):
        for k, line in enumerate(open(csvdir / f"sbo_j{j}.csv")):
            if k == 0 and i > 0:
                continue
            f.write(line)
print(f"  sbo_all.csv    <- concat(sbo_j2, sbo_j6, sbo_j12), header kept once")
PY

echo
echo "== statistics =="
py "$ANALYSIS/timing_stats.py" "$OUTDIR"

echo
echo "== comparison against the frozen CSVs =="
py "$ANALYSIS/compare_frozen.py" "$CSV" "$FROZEN" || true

echo
echo "== figures 1-5 =="
for f in fig01_clrt_read_select_before_after.py fig02_clrt_ecdf_before_after.py \
         fig03_timing_feature_overlap_before_after.py fig04_sbo_operate_timing_by_j.py \
         fig05_timing_leakage_summary.py; do
  py "$FIGSRC/$f" "$OUTDIR"
done

echo
echo "reproduce: complete. Artifacts under $OUTDIR"

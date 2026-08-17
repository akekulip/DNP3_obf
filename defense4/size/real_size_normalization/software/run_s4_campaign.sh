#!/usr/bin/env bash
# Gate S4 campaign: drive run_s4_namespace.sh through the full case matrix and
# analyze each pipeline run into a single evidence directory.
#
# Cases: direct-veth baseline, 100-exchange no-fault main run, a 3-reconnect
# lifecycle run, and post-emission fault runs (drop / duplicate / reorder /
# replay) that must recover the application stream (drop -> TCP retransmit) or
# fail closed (replay -> rejected). Auth / overflow / timeout faults are covered
# deterministically by the offline + software unit suites.
#
# Software only: rootless user+net namespaces, veth, AF_PACKET. No hardware.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../../.." && pwd)"
RUN="$HERE/run_s4_namespace.sh"
EVID=""
QUICK=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --evidence) EVID="$2"; shift 2;;
    --quick) QUICK=1; shift;;   # smaller exchange counts for a fast validation
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done
[[ -z "$EVID" ]] && { echo "--evidence DIR is required" >&2; exit 2; }

MAIN_EX=100; MAIN_DUR=200; MAIN_TO=190
FAULT_EX=25; FAULT_DUR=70; FAULT_TO=65
if [[ -n "$QUICK" ]]; then MAIN_EX=30; MAIN_DUR=80; MAIN_TO=75; FAULT_EX=15; FAULT_DUR=50; FAULT_TO=45; fi

mkdir -p "$EVID"
export PYTHONPATH="$REPO"
analyze() {  # $1=run_dir  $2=optional expect-fault JSON
  local d="$1"; shift || true
  local args=(--out "$d" --report "$d/s4_report.json")
  [[ $# -gt 0 && -n "${1:-}" ]] && args+=(--expect-fault "$1")
  python3 -m defense4.size.real_size_normalization.software.analyze_s4 "${args[@]}"
}
plan() { printf '%s\n' "$1" > "$2"; }

echo "### baseline (direct veth latency reference)"
bash "$RUN" --mode baseline --out "$EVID/baseline" --exchanges 20 --timeout 40 >/dev/null 2>&1 || true

echo "### main: ${MAIN_EX}-exchange no-fault pipeline"
bash "$RUN" --mode pipeline --out "$EVID/main" --exchanges "$MAIN_EX" \
  --duration "$MAIN_DUR" --timeout "$MAIN_TO" >/dev/null 2>&1 || true
analyze "$EVID/main" || true

echo "### lifecycle: 3 sequential reconnects"
bash "$RUN" --mode pipeline --out "$EVID/lifecycle" --exchanges 5 --connections 3 \
  --duration 90 --timeout 85 >/dev/null 2>&1 || true
analyze "$EVID/lifecycle" || true

# Fault runs: a deterministic post-emission impairment on the observed link.
declare -A FAULTS=(
  [drop]='{"rules":[{"action":"drop","direction":"forward","position":40}]}'
  [duplicate]='{"rules":[{"action":"duplicate","direction":"reverse","position":50}]}'
  [reorder]='{"rules":[{"action":"reorder","direction":"forward","position":30}]}'
  [replay]='{"rules":[{"action":"replay","direction":"reverse","position":60,"replay_direction":"reverse","position_replay":0}]}'
)
declare -A EXPECT=(
  [drop]='{"link_dropped":1}'
  [duplicate]='{"link_duplicated":1}'
  [reorder]='{"link_reordered":1}'
  [replay]='{"link_replayed":1}'
)
for name in drop duplicate reorder replay; do
  echo "### fault: $name"
  d="$EVID/fault_$name"; mkdir -p "$d"
  plan "${FAULTS[$name]}" "$d/fault_plan.json"
  bash "$RUN" --mode pipeline --out "$d" --exchanges "$FAULT_EX" \
    --duration "$FAULT_DUR" --timeout "$FAULT_TO" --fault-plan "$d/fault_plan.json" >/dev/null 2>&1 || true
  analyze "$d" "${EXPECT[$name]}" || true
done

echo "### campaign complete -> $EVID"

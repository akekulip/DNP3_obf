#!/usr/bin/env bash
# reproduce.sh - rebuild every campaign_v2 result from the raw captures, then compare what was
# rebuilt against what the repository publishes.
#
# This is campaign_v1/repro/reproduce.sh with two differences and no others. policy_config.json
# carries D_R = 8 ms and a release budget of 28 ms rather than 4 and 24, and the hardware policy
# sweep is skipped: campaign_v1's sweep characterises the acknowledgment-anchored build, whose
# release tail is a function of arrival phase, and says nothing about this one. A budget sweep on
# the corrected build is a separate run; until it exists, step 2 is absent rather than wrong.
#
# Raw captures and frozen driver logs are inputs and are never written. Everything else is
# regenerated into a temporary tree, and step 7 is a real comparison against the published
# artefacts, not a restatement of them.
#
#   ./reproduce.sh [OUT_DIR]      default OUT_DIR: /tmp/cv1_out
#
# Environment: created or synchronised from the committed lock file, so the same dependency
# versions are used on every machine.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-/tmp/cv2_out}"
mkdir -p "$OUT"

echo "[0/8] synchronise the pinned environment from uv.lock"
if ! command -v uv >/dev/null 2>&1; then
    echo "error: uv is required to build the pinned environment (https://docs.astral.sh/uv/)" >&2
    exit 2
fi
( cd "$HERE" && uv sync --frozen --python 3.13 )
PY="$HERE/.venv/bin/python"
[ -x "$PY" ] || { echo "error: uv sync did not produce $PY" >&2; exit 2; }

# ---- record the environment this run actually used -------------------------------------------
"$PY" - "$OUT/environment.json" <<'PYENV'
import json, platform, subprocess, sys, os
import importlib.metadata as md
here = os.path.dirname(os.path.abspath(__file__)) if "__file__" in dir() else os.getcwd()
def cmd(*a):
    try:
        return subprocess.run(a, capture_output=True, text=True, timeout=20).stdout.strip() or None
    except Exception:
        return None
tect = os.environ.get("TECTONIC") or cmd("bash", "-lc", "command -v tectonic")
env = {
    "python_version": sys.version.split()[0],
    "python_implementation": platform.python_implementation(),
    "platform": platform.platform(),
    "machine": platform.machine(),
    "dependencies": {n: md.version(n) for n in
                     ("numpy", "scipy", "scikit-learn", "matplotlib", "joblib", "pytest")},
    "tectonic_path": tect,
    "tectonic_version": cmd(tect, "--version") if tect else None,
    "git_commit": cmd("git", "rev-parse", "HEAD"),
    "git_dirty": bool(cmd("git", "status", "--porcelain")),
    "deterministic_seeds": {"leakage_campaign.SEED": 20260828,
                            "RandomForest.random_state": 0,
                            "mutual_info_classif.random_state": 0},
}
json.dump(env, open(sys.argv[1], "w"), indent=1)
print("  python %s | numpy %s | scikit-learn %s | matplotlib %s"
      % (env["python_version"], env["dependencies"]["numpy"],
         env["dependencies"]["scikit-learn"], env["dependencies"]["matplotlib"]))
print("  tectonic: %s" % (env["tectonic_version"] or "not found (only needed for the manuscript build)"))
PYENV

echo "[1/7] verify all 22 dataset manifests, validate every capture, build the canonical table"
"$PY" "$HERE/validate_campaign.py" "$OUT"

echo "[2/7] summary statistics, read and control lanes kept separate"
"$PY" "$HERE/stats_campaign.py" "$OUT/transactions_canonical.csv" \
      "$("$PY" -c "import json;print(json.load(open('$HERE/policy_config.json'))['release_budget_D_ms'])")" \
      "$OUT/stats.json"

echo "[3/7] shift-versus-replacement: variance ratios and deadline coverage"
"$PY" "$HERE/replacement_stats.py" "$OUT/transactions_canonical.csv" "$OUT/replacement_stats.json"

echo "[4/7] leakage: mutual information against a permutation null, two attacker models"
"$PY" "$HERE/leakage_campaign.py" "$OUT/transactions_canonical.csv" "$OUT/leakage.json"

echo "[4b/7] leakage when the adversary pools several exchanges instead of one"
"$PY" "$HERE/multiobs_leakage.py" "$OUT/transactions_canonical.csv" "$OUT/multiobs.json"

echo "[5/7] figures: vector PDF, 600-dpi PNG, figure-data CSV, provenance sidecar"
"$PY" "$HERE/make_ndss_figures.py" "$OUT/transactions_canonical.csv" "$OUT/stats.json" \
      "$OUT/leakage.json" "$HERE/policy_config.json" "$OUT/figs"

echo "[6/7] tests"
CV1_OUT="$OUT" "$PY" -m pytest "$HERE/tests" -q

echo "[7/7] publication gate: compare what was just rebuilt against what the repository publishes"
"$PY" "$HERE/publication_gate.py" "$OUT"

echo
echo "hash manifest -> $OUT/REPRODUCED.sha256"
( cd "$OUT" && sha256sum transactions_canonical.csv per_capture.csv validation_report.json \
    stats.json replacement_stats.json leakage.json environment.json figs/*.pdf figs/*.png > REPRODUCED.sha256 )
echo "done. outputs in $OUT"

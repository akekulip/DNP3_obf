#!/usr/bin/env bash
# build.sh - reproducible "draft -> compiled PDF + Lin-style score" gate.
#
# Layer B of the writing-pipeline rebuild. Two steps, in order:
#   1. Compile the manuscript with tectonic (offline: --only-cached, no network).
#   2. Run lin_check.py against the .tex source and emit the scorecard
#      (human report + JSON) into pipeline/reports/.
#
# Fail-closed: exits non-zero if EITHER the compile OR the lin_check gate fails.
# The gate always runs even if the compile fails, so the scorecard is always
# produced.
#
# Usage:
#   ./build.sh [path/to/draft.tex]
# Defaults to ../main.tex (the canonical manuscript entry point).
#
# NON-REGRESSION GATE (guard a humanize/edit pass): this build produces a JSON
# scorecard in reports/. To enforce "an edit must not lower the Lin-voice score",
# snapshot the score before editing and compare after:
#     RP=/home/philip/.venvs/research/bin/python
#     $RP lin_check.py DRAFT.tex --json > before.json     # before humanizing
#     # ... run academic-humanizer on DRAFT.tex ...
#     $RP lin_check.py --compare before.json DRAFT.tex     # exit 3 = regression
# See README.md "Non-regression gate" for the worked example.

set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAPER_DIR="$(cd "${HERE}/.." && pwd)"
DRAFT="${1:-${PAPER_DIR}/main.tex}"

# Any python3 with numpy works for the gate; $RESEARCH_PYTHON overrides.
RESEARCH_PYTHON="${RESEARCH_PYTHON:-$(command -v python3)}"
TECTONIC="${TECTONIC:-/home/philip/.local/bin/tectonic}"

BUILD_DIR="${HERE}/build"
REPORT_DIR="${HERE}/reports"
mkdir -p "${BUILD_DIR}" "${REPORT_DIR}"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
base="$(basename "${DRAFT}" .tex)"
report_txt="${REPORT_DIR}/${base}_${stamp}.txt"
report_json="${REPORT_DIR}/${base}_${stamp}.json"

echo "=============================================================================="
echo "build.sh  draft=${DRAFT}"
echo "=============================================================================="

# ---- Step 1: compile (offline) --------------------------------------------
rc_build=0
if [[ ! -x "${TECTONIC}" ]]; then
    echo "[build] tectonic not found at ${TECTONIC}; skipping compile."
    rc_build=127
elif [[ "${DRAFT}" != *.tex ]]; then
    echo "[build] draft is not a .tex file; skipping compile."
else
    echo "[build] tectonic --only-cached --keep-logs -o ${BUILD_DIR}"
    "${TECTONIC}" -X compile --only-cached --keep-logs \
        -o "${BUILD_DIR}" "${DRAFT}"
    rc_build=$?
    if [[ ${rc_build} -eq 0 ]]; then
        echo "[build] PDF -> ${BUILD_DIR}/${base}.pdf"
    else
        echo "[build] tectonic FAILED (rc=${rc_build})."
    fi
fi

# ---- Step 2: lin_check gate ------------------------------------------------
# lin_check scores one file and does not follow \input. The canonical manuscript is a thin
# main.tex over section files, so the gate scores a flattened copy (every \input{...} inlined
# recursively, comment lines dropped). The flat file is a build product, never the source.
GATE_INPUT="${DRAFT}"
if grep -q '\\input{' "${DRAFT}"; then
    GATE_INPUT="${BUILD_DIR}/${base}_flat.tex"
    "${RESEARCH_PYTHON}" - "${DRAFT}" "${GATE_INPUT}" <<'PYFLAT'
import re, sys, pathlib
src, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
def flat(p, seen=()):
    text = []
    for line in p.read_text().splitlines():
        if line.lstrip().startswith('%'):
            continue
        m = re.match(r'\s*\\input\{([^}]+)\}', line)
        if m:
            q = (p.parent / m.group(1)).with_suffix('.tex') if not m.group(1).endswith('.tex') else p.parent / m.group(1)
            if q.exists() and str(q) not in seen:
                text.append(flat(q, seen + (str(q),)))
                continue
        text.append(line)
    return "\n".join(text)
out.write_text(flat(src))
PYFLAT
    echo "[gate] flattened ${DRAFT} -> ${GATE_INPUT}"
fi
echo
echo "[gate] ${RESEARCH_PYTHON} lin_check.py ${GATE_INPUT}"
"${RESEARCH_PYTHON}" "${HERE}/lin_check.py" "${GATE_INPUT}" | tee "${report_txt}"
rc_gate=${PIPESTATUS[0]}
"${RESEARCH_PYTHON}" "${HERE}/lin_check.py" "${GATE_INPUT}" --json > "${report_json}"

echo
echo "[gate] report  -> ${report_txt}"
echo "[gate] json    -> ${report_json}"

# ---- Combined fail-closed status ------------------------------------------
echo "------------------------------------------------------------------------------"
echo "compile rc=${rc_build}   gate rc=${rc_gate}"
if [[ ${rc_build} -ne 0 || ${rc_gate} -ne 0 ]]; then
    echo "BUILD RESULT: FAIL"
    exit 1
fi
echo "BUILD RESULT: PASS"
exit 0

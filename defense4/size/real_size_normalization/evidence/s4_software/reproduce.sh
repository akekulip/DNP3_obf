#!/usr/bin/env bash
# Regenerate the Gate S4 software evidence package.
#
# Re-runs the rootless-namespace campaign, re-analyzes each run, rebuilds the
# summary + claim matrix, and rewrites the SHA-256 manifest. The regenerated
# package is FUNCTIONALLY equivalent, not byte-identical: cells carry fresh AEAD
# nonces and captures carry fresh wall-clock timestamps, so hashes differ by
# design. The stable, reproducible facts are the gate outcomes (byte equality,
# fixed 256-byte cells, zero size/count leakage, fault recovery).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"                       # .../evidence/s4_software
REPO="$(cd "$HERE/../../../../.." && pwd)"
SW="$REPO/defense4/size/real_size_normalization/software"
EVID="${1:-$HERE}"
export PYTHONPATH="$REPO"

bash "$SW/run_s4_campaign.sh" --evidence "$EVID"
python3 -m defense4.size.real_size_normalization.software.s4_summarize --evidence "$EVID"

# prune redundant/forbidden artifacts, then hash everything but the manifest
find "$EVID" -name '*_observed.pcap' -delete
find "$EVID" -name 'observer_l_left.jsonl' -delete
find "$EVID" -type d -name ready -exec rm -rf {} + 2>/dev/null || true
find "$EVID" -name '*.key' -delete
( cd "$EVID" && find . -type f ! -name manifest.sha256 -print0 | sort -z \
    | xargs -0 sha256sum > manifest.sha256 )
echo "S4 evidence regenerated at $EVID"

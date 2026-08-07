#!/usr/bin/env bash
# =============================================================================
#  run_tests.sh — fail-closed test suite for the Defense 4 evidence pipeline.
#
#  Regenerates deterministic fixtures, then proves with captured exit codes that every tool REJECTS
#  bad input (nonzero) and ACCEPTS the one clean input (zero). Covers the scorer, the paired byte
#  comparator, the SHA256 manifest, run_campaign.sh (DRY_RUN, no ssh), and the analyzer.
#
#  Exits nonzero if ANY assertion fails. This is the offline gate for Phase 1.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY="$(cd "$HERE/.." && pwd)"
RP="${RESEARCH_PYTHON:-$HOME/.venvs/research/bin/python}"
GEN="$(mktemp -d)"
trap 'rm -rf "$GEN"' EXIT

PASS=0; FAIL=0
# check <name> <expected_exit> <cmd...>
check(){ local name="$1" exp="$2"; shift 2
  "$@" >/dev/null 2>&1; local got=$?
  if [ "$got" = "$exp" ]; then printf '  ok   %-42s exit=%s\n' "$name" "$got"; PASS=$((PASS+1))
  else printf '  FAIL %-42s exit=%s expected=%s\n' "$name" "$got" "$exp"; FAIL=$((FAIL+1)); fi
}

echo "=== regenerating fixtures ==="
"$RP" "$HERE/build_fixtures.py" "$GEN" || { echo "fixture build failed"; exit 2; }
SC="$GEN/scorer"; PR="$GEN/pairs"

echo "=== score_campaign.py (python3) — bad input must fail, clean must pass ==="
score(){ python3 "$DEPLOY/score_campaign.py" "$@"; }
check "scorer clean"            0 score "$SC/clean/block.json" "$SC/clean/ev_pre.json" "$SC/clean/ev_post.json" --scenario normal --mode D2 --n-expected 60 --expected-protected 60 --pcap "$SC/clean/blk.pcap"
check "scorer injected bypass"  1 score "$SC/bypass/block.json" "$SC/bypass/ev_pre.json" "$SC/bypass/ev_post.json" --scenario normal --mode D2 --n-expected 60 --expected-protected 60
check "scorer ordering inv"     1 score "$SC/ordering/block.json" "$SC/ordering/ev_pre.json" "$SC/ordering/ev_post.json" --scenario normal --mode D2 --n-expected 60 --expected-protected 60
check "scorer stale reg_tag"    1 score "$SC/stale/block.json" "$SC/stale/ev_pre.json" "$SC/stale/ev_post.json" --scenario normal --mode D2 --n-expected 60 --expected-protected 60
check "scorer counter mismatch" 1 score "$SC/countermismatch/block.json" "$SC/countermismatch/ev_pre.json" "$SC/countermismatch/ev_post.json" --scenario normal --mode D2 --n-expected 60 --expected-protected 60
check "scorer token escape"     1 score "$SC/tokenescape/block.json" "$SC/tokenescape/ev_pre.json" "$SC/tokenescape/ev_post.json" --scenario normal --mode D2 --n-expected 60 --expected-protected 60
check "scorer queue drop"       1 score "$SC/queuedrop/block.json" "$SC/queuedrop/ev_pre.json" "$SC/queuedrop/ev_post.json" --scenario normal --mode D2 --n-expected 60 --expected-protected 60
check "scorer malformed json"   2 score "$SC/malformed.json" "$SC/clean/ev_pre.json" "$SC/clean/ev_post.json" --scenario normal --mode D2
check "scorer empty json"       2 score "$SC/empty.json" "$SC/clean/ev_pre.json" "$SC/clean/ev_post.json" --scenario normal --mode D2
check "scorer missing file"     2 score "$GEN/nope.json" "$SC/clean/ev_pre.json" "$SC/clean/ev_post.json"
check "scorer missing pcap"     1 score "$SC/clean/block.json" "$SC/clean/ev_pre.json" "$SC/clean/ev_post.json" --scenario normal --mode D2 --n-expected 60 --expected-protected 60 --pcap "$GEN/nope.pcap"

echo "=== pair_bytes.py ($RP) — a one-byte mutation must fail ==="
pair(){ "$RP" "$DEPLOY/pair_bytes.py" --ingress "$PR/ingress.pcap" --egress "$1"; }
check "pair clean"              0 pair "$PR/egress_clean.pcap"
check "pair one-byte mutation"  1 pair "$PR/egress_1byte.pcap"
check "pair dropped frame"      1 pair "$PR/egress_drop.pcap"
check "pair injected frame"     1 pair "$PR/egress_inject.pcap"

echo "=== make_manifest.sh + sha256sum -c — a tampered file must fail verification ==="
MAN="$GEN/manifest"
bash "$DEPLOY/make_manifest.sh" "$MAN" >/dev/null 2>&1
check "manifest verifies clean" 0 bash -c "cd '$MAN' && sha256sum -c SHA256SUMS"
echo "tampered after manifest" >> "$MAN/a.txt"
check "manifest tamper detected" 1 bash -c "cd '$MAN' && sha256sum -c SHA256SUMS"

echo "=== run_campaign.sh DRY_RUN — orchestration must fail closed ==="
runc(){ DRY_RUN=1 DRY_FIXTURES="$1" SPEC="$1/spec.txt" OUT="$2" bash "$DEPLOY/run_campaign.sh"; }
OUTC="$GEN/out_clean"; check "run_campaign clean" 0 runc "$GEN/dry" "$OUTC"
# clean run's manifest must independently verify
check "run_campaign manifest verifies" 0 bash -c "cd '$OUTC' && sha256sum -c SHA256SUMS >/dev/null"
# injected bypass
BYP="$GEN/dry_byp"; cp -r "$GEN/dry" "$BYP"
"$RP" - "$BYP/ev_post_T_D2.json" <<'PY'
import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["cf"]["RESP_BYPASS"]=d["cf"].get("RESP_BYPASS",0)+5; json.dump(d,open(p,"w"))
PY
check "run_campaign injected bypass" 1 runc "$BYP" "$GEN/out_byp"
# missing pcap
NOPC="$GEN/dry_nopcap"; cp -r "$GEN/dry" "$NOPC"; rm -f "$NOPC/blk_T_D2.pcap"
check "run_campaign missing pcap"    1 runc "$NOPC" "$GEN/out_nopcap"
# invalid block json
BADJ="$GEN/dry_badjson"; cp -r "$GEN/dry" "$BADJ"; : > "$BADJ/block_T_D2.json"
check "run_campaign invalid json"    1 runc "$BADJ" "$GEN/out_badjson"

echo "=== analyze_campaign.py ($RP) — malformed/failed blocks must fail ==="
an(){ "$RP" "$DEPLOY/analyze_campaign.py" "$1"; }
check "analyze clean campaign"  0 an "$OUTC"
BADAN="$GEN/an_bad"; cp -r "$OUTC" "$BADAN"; echo 'not json' > "$BADAN/block_T_D2.json"
check "analyze malformed block" 1 an "$BADAN"
FAILAN="$GEN/an_fail"; cp -r "$OUTC" "$FAILAN"
echo '{"mode":"D2","verdict":"FAIL","hard_anomalies":["x"]}' >> "$FAILAN/blocks.jsonl"
check "analyze failed-score block" 1 an "$FAILAN"

echo ""
echo "=== SUMMARY: $PASS passed, $FAIL failed ==="
[ "$FAIL" = 0 ] && echo "ALL FAIL-CLOSED TESTS PASS" || echo "SUITE FAILED"
exit "$FAIL"

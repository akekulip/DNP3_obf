#!/usr/bin/env bash
# =============================================================================
#  run_tests.sh — fail-closed test suite for the Defense 4 evidence pipeline.
#
#  Regenerates deterministic REAL-pcap fixtures, then proves with captured exit codes that every tool
#  REJECTS the bad input the independent audit found and ACCEPTS the clean input. Prints every test
#  name with its expected and actual exit code, and exits nonzero if ANY assertion fails.
#
#  Environment: needs a Python with scapy for pair_bytes/build_fixtures. Resolution order:
#    $RESEARCH_PYTHON, else a python3 on PATH that can import scapy. No hard-coded home path.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY="$(cd "$HERE/.." && pwd)"

# resolve a scapy-capable python; verify it, do not assume a path
RP="${RESEARCH_PYTHON:-}"
if [ -z "$RP" ] || ! "$RP" -c "import scapy" >/dev/null 2>&1; then
  for cand in "$HOME/.venvs/research/bin/python" "$(command -v python3 || true)"; do
    if [ -n "$cand" ] && "$cand" -c "import scapy" >/dev/null 2>&1; then RP="$cand"; break; fi
  done
fi
if [ -z "$RP" ] || ! "$RP" -c "import scapy" >/dev/null 2>&1; then
  echo "no scapy-capable python found (set RESEARCH_PYTHON). scapy is required." >&2; exit 2
fi
echo "research python: $RP ($($RP -c 'import scapy;print("scapy",scapy.__version__)'))"

GEN="$(mktemp -d)"
trap 'rm -rf "$GEN"' EXIT
PASS=0; FAIL=0
check(){ local name="$1" exp="$2"; shift 2
  "$@" >/dev/null 2>&1; local got=$?
  if [ "$got" = "$exp" ]; then printf '  ok   %-46s expected=%s actual=%s\n' "$name" "$exp" "$got"; PASS=$((PASS+1))
  else printf '  FAIL %-46s expected=%s actual=%s\n' "$name" "$exp" "$got"; FAIL=$((FAIL+1)); fi
}
check_file(){ local name="$1" path="$2"; if [ -s "$path" ]; then printf '  ok   %-46s (present)\n' "$name"; PASS=$((PASS+1)); else printf '  FAIL %-46s (MISSING %s)\n' "$name" "$path"; FAIL=$((FAIL+1)); fi; }
check_grep(){ local name="$1" pat="$2" file="$3"; if grep -q "$pat" "$file" 2>/dev/null; then printf '  ok   %-46s (found)\n' "$name"; PASS=$((PASS+1)); else printf '  FAIL %-46s (NOT in %s)\n' "$name" "$file"; FAIL=$((FAIL+1)); fi; }

echo "=== regenerating REAL-pcap fixtures ==="
"$RP" "$HERE/build_fixtures.py" "$GEN" || { echo "fixture build failed"; exit 2; }
SC="$GEN/scorer"; PB="$GEN/pairs"; RL="192.168.10.7"; MA="192.168.10.1"

echo "=== score_campaign.py (python3) ==="
sc(){ python3 "$DEPLOY/score_campaign.py" "$@"; }
common="--mode D2 --n-expected 60 --expected-protected 60"
check "scorer clean"                 0 sc "$SC/clean/block.json" "$SC/clean/ev_pre.json" "$SC/clean/ev_post.json" --scenario normal $common --pcap "$GEN/real.pcap"
for c in dupack dupresp retransmit ordering inconclusive multiseg stale noregtag noport nocounter negdelta bypass countermismatch tokenescape queuedrop drivererr respshort; do
  check "scorer $c" 1 sc "$SC/$c/block.json" "$SC/$c/ev_pre.json" "$SC/$c/ev_post.json" --scenario normal $common
done
check "scorer missing queue snapshot" 1 sc "$SC/noqueue/block.json" "$SC/noqueue/ev_pre.json" "$SC/noqueue/ev_post.json" --scenario normal $common
check "scorer block-mode mismatch"   1 sc "$SC/badmode_block/block.json" "$SC/badmode_block/ev_pre.json" "$SC/badmode_block/ev_post.json" --scenario normal $common
check "scorer unknown --mode (argparse)" 2 sc "$SC/clean/block.json" "$SC/clean/ev_pre.json" "$SC/clean/ev_post.json" --scenario normal --mode FOO
check "scorer text-file pcap"        1 sc "$SC/clean/block.json" "$SC/clean/ev_pre.json" "$SC/clean/ev_post.json" --scenario normal $common --pcap "$SC/text.pcap"
check "scorer malformed json"        2 sc "$SC/malformed.json" "$SC/clean/ev_pre.json" "$SC/clean/ev_post.json" --scenario normal --mode D2
check "scorer empty json"            2 sc "$SC/empty.json" "$SC/clean/ev_pre.json" "$SC/clean/ev_post.json" --scenario normal --mode D2
check "scorer missing file"          2 sc "$GEN/nope.json" "$SC/clean/ev_pre.json" "$SC/clean/ev_post.json" --scenario normal --mode D2
# declared negatives: not-exercised must FAIL, exercised must PASS
check "scorer missing_ack not exercised" 1 sc "$SC/clean/block.json" "$SC/clean/ev_pre.json" "$SC/clean/ev_post.json" --scenario missing_ack --mode D2 --n-expected 60
check "scorer missing_ack exercised"     0 sc "$SC/missingack_ok/block.json" "$SC/missingack_ok/ev_pre.json" "$SC/missingack_ok/ev_post.json" --scenario missing_ack --mode D2 --expect-negative 4
check "scorer missing_resp not exercised" 1 sc "$SC/clean/block.json" "$SC/clean/ev_pre.json" "$SC/clean/ev_post.json" --scenario missing_resp --mode D2 --n-expected 60
check "scorer missing_resp exercised"     0 sc "$SC/missingresp_ok/block.json" "$SC/missingresp_ok/ev_pre.json" "$SC/missingresp_ok/ev_post.json" --scenario missing_resp --mode D2 --expect-negative 3
check "scorer late not exercised"     1 sc "$SC/clean/block.json" "$SC/clean/ev_pre.json" "$SC/clean/ev_post.json" --scenario late_response --mode D2 --n-expected 60
check "scorer late exercised"         0 sc "$SC/late_ok/block.json" "$SC/late_ok/ev_pre.json" "$SC/late_ok/ev_post.json" --scenario late_response --mode D2 --expect-negative 6
check "scorer fail_open not exercised" 1 sc "$SC/clean/block.json" "$SC/clean/ev_pre.json" "$SC/clean/ev_post.json" --scenario fail_open --mode D2
check "scorer fail_open exercised"     0 sc "$SC/failopen_ok/block.json" "$SC/failopen_ok/ev_pre.json" "$SC/failopen_ok/ev_post.json" --scenario fail_open --mode FAIL_OPEN --expect-negative 4
check "scorer D3 inconclusive PASSES (mode-aware)" 0 sc "$SC/d3_inconclusive/block.json" "$SC/d3_inconclusive/ev_pre.json" "$SC/d3_inconclusive/ev_post.json" --scenario normal --mode D3 --n-expected 60 --expected-protected 60 --d-a-ms 4 --d-r-ms 0

echo "=== pair_bytes.py ($RP) ==="
pb(){ "$RP" "$DEPLOY/pair_bytes.py" --relay-ip "$RL" --master-ip "$MA" "$@"; }
check "pair clean"                   0 pb --ingress "$PB/ingress.pcap" --egress "$PB/egress_clean.pcap"
check "pair one-byte mutation"       1 pb --ingress "$PB/ingress.pcap" --egress "$PB/egress_1byte.pcap"
check "pair dropped ACK"             1 pb --ingress "$PB/ingress.pcap" --egress "$PB/egress_dropack.pcap"
check "pair dropped RESPONSE"        1 pb --ingress "$PB/ingress.pcap" --egress "$PB/egress_dropresp.pcap"
check "pair injected frame"          1 pb --ingress "$PB/ingress.pcap" --egress "$PB/egress_inject.pcap"
check "pair MAC mutation"            1 pb --ingress "$PB/ingress.pcap" --egress "$PB/egress_macmut.pcap"
check "pair checksum mutation"       1 pb --ingress "$PB/ingress.pcap" --egress "$PB/egress_cksum.pcap"
check "pair reordered"               1 pb --ingress "$PB/ingress2.pcap" --egress "$PB/egress_reorder.pcap"
check "pair wrong flow/master IP"    1 pb --ingress "$PB/ingress_other.pcap" --egress "$PB/egress_other.pcap"
check "pair ACK-only zero protected" 1 pb --ingress "$PB/ingress_ackonly.pcap" --egress "$PB/egress_ackonly.pcap"
check "pair intended correct"        0 pb --ingress "$PB/ingress.pcap" --egress "$PB/egress_clean.pcap" --intended "$PB/intended.jsonl"
check "pair intended wrong"          1 pb --ingress "$PB/ingress.pcap" --egress "$PB/egress_clean.pcap" --intended "$PB/intended_wrong.jsonl"
check "pair malformed pcap"          2 pb --ingress "$PB/text.pcap" --egress "$PB/egress_clean.pcap"
check "pair truncated pcap"          2 pb --ingress "$PB/truncated.pcap" --egress "$PB/egress_clean.pcap"
check "pair missing pcap"            2 pb --ingress "$GEN/nope.pcap" --egress "$PB/egress_clean.pcap"
check "pair VLAN clean"              0 pb --ingress "$PB/ingress_vlan.pcap" --egress "$PB/egress_vlan.pcap"

echo "=== make_manifest.sh — hash ALL files, tamper must fail ==="
MAN="$GEN/manifest"
bash "$DEPLOY/make_manifest.sh" "$MAN" >/dev/null 2>&1
check "manifest verifies clean"      0 bash -c "cd '$MAN' && sha256sum -c SHA256SUMS"
check_grep "manifest includes .err"  "driver.err" "$MAN/SHA256SUMS"
check_grep "manifest includes .csv"  "results.csv" "$MAN/SHA256SUMS"
check_grep "manifest includes .record" "environment.record" "$MAN/SHA256SUMS"
echo "tampered after manifest" >> "$MAN/a.txt"
check "manifest tamper detected"     1 bash -c "cd '$MAN' && sha256sum -c SHA256SUMS"

echo "=== run_campaign.sh DRY_RUN — orchestration fail-closed ==="
runc(){ DRY_RUN=1 RESEARCH_PYTHON="$RP" DRY_FIXTURES="$1" SPEC="$1/spec.txt" OUT="$2" bash "$DEPLOY/run_campaign.sh"; }
OUTC="$GEN/out_clean"; check "run_campaign clean"        0 runc "$GEN/dry" "$OUTC"
check_file "clean run: analysis.json"        "$OUTC/analysis.json"
check_file "clean run: spec copied"          "$OUTC/spec.txt"
check_file "clean run: provenance"           "$OUTC/meta/provenance.txt"
check_file "clean run: offload record"       "$OUTC/meta/offload_master.txt"
check_file "clean run: relay pcap"           "$OUTC/pcaps_relay/blk_T_D2_relay.pcap"
check_file "clean run: intended record"      "$OUTC/intended_T_D2.jsonl"
check_file "clean run: paired report"        "$OUTC/pair/pair_T_D2.json"
check_file "clean run: manifest"             "$OUTC/SHA256SUMS"
check "clean run: manifest verifies"         0 bash -c "cd '$OUTC' && sha256sum -c SHA256SUMS >/dev/null"
# injected bypass
BYP="$GEN/dry_byp"; cp -r "$GEN/dry" "$BYP"
"$RP" - "$BYP/ev_post_T_D2.json" <<'PY'
import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["cf"]["RESP_BYPASS"]=d["cf"].get("RESP_BYPASS",0)+5; json.dump(d,open(p,"w"))
PY
check "run_campaign injected bypass" 1 runc "$BYP" "$GEN/out_byp"
NOPC="$GEN/dry_nopcap"; cp -r "$GEN/dry" "$NOPC"; rm -f "$NOPC/blk_T_D2.pcap"
check "run_campaign missing pcap"    1 runc "$NOPC" "$GEN/out_nopcap"
BADJ="$GEN/dry_badjson"; cp -r "$GEN/dry" "$BADJ"; : > "$BADJ/block_T_D2.json"
check "run_campaign invalid json"    1 runc "$BADJ" "$GEN/out_badjson"
check "run_campaign paired-compare fail" 1 runc "$GEN/dry_pairfail" "$GEN/out_pairfail"
# stale/nonempty OUT dir refused
STALE="$GEN/out_stale"; mkdir -p "$STALE"; echo junk > "$STALE/leftover.txt"
check "run_campaign refuses stale OUT" 2 runc "$GEN/dry" "$STALE"
# extra pcap at finalize -> nonzero (via documented test hook)
check "run_campaign extra pcap at finalize" 1 bash -c "DRY_RUN=1 RESEARCH_PYTHON='$RP' TEST_INJECT_EXTRA_PCAP=blk_STRAY.pcap DRY_FIXTURES='$GEN/dry' SPEC='$GEN/dry/spec.txt' OUT='$GEN/out_extra' bash '$DEPLOY/run_campaign.sh'"

echo "=== analyze_campaign.py ($RP) — fail-closed completeness ==="
an(){ "$RP" "$DEPLOY/analyze_campaign.py" "$@"; }
check "analyze clean campaign"       0 an "$OUTC" --spec "$OUTC/spec.txt"
NB="$GEN/an_noblocks"; cp -r "$OUTC" "$NB"; rm -f "$NB/blocks.jsonl"
check "analyze no blocks.jsonl"      2 an "$NB" --spec "$NB/spec.txt"
NS="$GEN/an_nospec"; cp -r "$OUTC" "$NS"; rm -f "$NS/spec.txt"
check "analyze no spec"              2 an "$NS"
MB="$GEN/an_malblock"; cp -r "$OUTC" "$MB"; echo 'not json' > "$MB/block_T_D2.json"
check "analyze malformed block"      1 an "$MB" --spec "$MB/spec.txt"
FL="$GEN/an_fail"; cp -r "$OUTC" "$FL"; echo '{"label":"T_D2","mode":"D2","scenario":"normal","verdict":"FAIL","exit_code":1}' >> "$FL/blocks.jsonl"
check "analyze duplicate/FAIL score" 1 an "$FL" --spec "$FL/spec.txt"
MS="$GEN/an_missing"; cp -r "$OUTC" "$MS"; grep -v '"label": "T_D4"' "$OUTC/blocks.jsonl" > "$MS/blocks.jsonl"
check "analyze missing score"        1 an "$MS" --spec "$MS/spec.txt"
UM="$GEN/an_unknownmode"; cp -r "$OUTC" "$UM"
"$RP" - "$UM/blocks.jsonl" <<'PY'
import json,sys
p=sys.argv[1]; lines=[json.loads(l) for l in open(p) if l.strip()]
for d in lines:
    if d.get("label")=="T_D2": d["mode"]="FOO"
open(p,"w").write("\n".join(json.dumps(d) for d in lines)+"\n")
PY
check "analyze unknown mode in score" 1 an "$UM" --spec "$UM/spec.txt"

echo ""
echo "=== SUMMARY: $PASS passed, $FAIL failed ==="
[ "$FAIL" = 0 ] && echo "ALL FAIL-CLOSED TESTS PASS" || echo "SUITE FAILED"
exit "$FAIL"

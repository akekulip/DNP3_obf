#!/usr/bin/env bash
# Defense 4 release — run every offline check. No hardware, no Barefoot SDE required.
# Steps that need optional libs (scapy for pcap analysis, pdfinfo for PDF sanity) are marked SKIP
# if the tool is absent. Expected outputs: tests/EXPECTED_RESULTS.md.
set -uo pipefail
cd "$(dirname "$0")/.."           # -> defense4_release/
ROOT="$(pwd)"
PY="${RESEARCH_PYTHON:-$HOME/.venvs/research/bin/python}"; [ -x "$PY" ] || PY="python3"
export PYTHONPATH="$ROOT/code/harness:${PYTHONPATH:-}"   # analysis scripts import dnp3_wire
pass=0; fail=0; skip=0
ok(){ echo "  PASS: $1"; pass=$((pass+1)); }
no(){ echo "  FAIL: $1"; fail=$((fail+1)); }
sk(){ echo "  SKIP: $1"; skip=$((skip+1)); }
hdr(){ echo; echo "== $1 =="; }

hdr "1. Python syntax check (py_compile)"
if find code -name '*.py' -print0 | xargs -0 "$PY" -m py_compile 2>/tmp/pyc.err; then ok "all code/*.py compile"
else no "syntax errors:"; cat /tmp/pyc.err; fi

hdr "2. Offline unified lifecycle (invariants + mutants)"
out=$("$PY" code/analysis/bor_unified_lifecycle.py 2>&1); echo "$out" | tail -3
echo "$out" | grep -qiE 'mutants killed: *([0-9]+)/\1' && echo "$out" | grep -qv 'SURVIVED' && ok "lifecycle: all invariants + mutants" || no "lifecycle did not fully pass"

hdr "3. Decision-table vs oracle equivalence"
out=$("$PY" code/analysis/validate_decide_vs_oracle.py 2>&1); echo "$out" | tail -2
echo "$out" | grep -qiE 'MISMATCH' && no "decision-table MISMATCH" || ok "decision-table equivalence holds"

hdr "4. Guarded-control safety test"
if out=$("$PY" code/harness/test_relay_operate_guard.py 2>&1); then echo "$out" | tail -2; ok "guard refuses forbidden index sets"
else echo "$out" | tail -5; no "guard test failed"; fi

hdr "5. E_FINAL manifest verification"
if ( cd evidence/E_FINAL && sha256sum -c MANIFEST.sha256 >/tmp/man.out 2>&1 ); then
  ok "E_FINAL manifest: $(grep -c ': OK' /tmp/man.out) files OK"
else no "manifest mismatch:"; grep -v ': OK' /tmp/man.out | head; fi

hdr "6. Size reconstruction spot-check (needs scapy)"
if "$PY" -c 'import scapy' 2>/dev/null; then
  # CSV cols: ...,segment_vector(9),total_bytes,contiguous,crc_valid,cksum_valid,source_copy_escape(14)
  nat=$("$PY" code/analysis/size_reconstruct.py evidence/E_FINAL/raw_pcaps/e1_native_size_shapeoff.pcap native 2>/dev/null \
        | awk -F, 'NR>1{n++; if($9=="49")v++} END{print n"/"v}')
  def=$("$PY" code/analysis/size_reconstruct.py evidence/E_FINAL/raw_pcaps/e2_def_read.pcap defended 2>/dev/null \
        | awk -F, 'NR>1{n++; if($9=="28|21")v++; if($14!="0")esc++} END{print n"/"v"/"esc+0}')
  echo "  native rows/with[49]: $nat ; defended rows/with[28|21]/escapes: $def"
  if [ "${nat%/*}" = "${nat#*/}" ] && [ "${nat%/*}" -gt 0 ] \
     && [ "$(echo "$def"|cut -d/ -f1)" = "$(echo "$def"|cut -d/ -f2)" ] \
     && [ "$(echo "$def"|cut -d/ -f3)" = "0" ]; then
    ok "size reconstruction: native all [49], defended all [28,21], 0 escapes"
  else no "size reconstruction did not match native[49]/defended[28,21]/0-escapes"; fi
else sk "scapy not installed (pip install scapy) — pcap analysis skipped"; fi

hdr "7. Document render sanity (needs pdfinfo)"
if command -v pdfinfo >/dev/null 2>&1; then
  for f in docs/DEFENSE4_EXPLAINER.pdf docs/DEFENSE4_SIMPLE.pdf docs/MEETING_REFERENCE.pdf; do
    p=$(pdfinfo "$f" 2>/dev/null | awk '/Pages/{print $2}'); echo "  $f: ${p:-?} pages"
    [ -n "${p:-}" ] && [ "$p" -ge 1 ] && ok "$(basename "$f") renders" || no "$(basename "$f") not a valid PDF"
  done
else sk "pdfinfo not installed (poppler-utils) — PDF sanity skipped"; fi

echo; echo "==================================================="
echo "PASS=$pass  FAIL=$fail  SKIP=$skip"
[ "$fail" -eq 0 ] && { echo "ALL OFFLINE CHECKS PASSED (skips are optional-dependency only)"; exit 0; } || { echo "SOME CHECKS FAILED"; exit 1; }

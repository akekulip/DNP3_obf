#!/usr/bin/env bash
# Offline verification of the 2026-10-13 candidates (rearm_57s strict, rearm_57a all-58), runnable from a fresh
# checkout with python3 and pytest only. No SDK, model, switch or network. Exit 0 only if every step passes.
#   bash integration/evidence/rearm_01/verify_offline.sh        (from defense4/timing/case4_architecture)
# Not covered here (explicit prerequisites): local compiles (bf-sde-9.13.1), installed compiles (switch 9.13.2),
# compiled-model suites (tofino-model via integration/core/launch_model.sh), silicon runs (campaign tooling).
set -u
C4=$(cd "$(dirname "$0")/../../.." && pwd)
SE=$C4/integration/core/response_only_rearm/stage_experiments
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fail=0
step() { local name=$1; shift; if "$@" > "$TMP/log" 2>&1; then echo "PASS  $name"; else echo "FAIL  $name"; tail -15 "$TMP/log"; fail=1; fi; }

# 1. Test suites: IEEE 1815 checker + READ oracle + capture verifier; campaign/loss tooling; rearm hardware helpers.
step "read_reencode_01 tests" bash -c "cd '$SE/read_reencode_01' && python3 -B -m pytest -q -p no:cacheprovider tests"
step "hw_vepa tests" bash -c "cd '$C4/protocol/hw_vepa' && python3 -B -m pytest -q -p no:cacheprovider tests"
step "rearm hw helper tests" bash -c "cd '$C4/integration/evidence/rearm_01/hw' && python3 -B -m pytest -q -p no:cacheprovider tests"

# 2. Every generated source reproduces byte for byte from its pinned input.
step "read_reencode_01 full_01/02/04 reproduce" bash -c "cd '$SE/read_reencode_01' && python3 -B -c '
import generate as g
for d, kw in ((\"full_01\", {}), (\"full_02\", dict(late=True)), (\"full_04\", dict(strict=True))):
    assert g.full_source(**kw) == open(\"evidence/%s/response_only.p4\" % d).read(), d
'"
step "dup_hold_01 full_01/full_02_strict reproduce" bash -c "cd '$SE/dup_hold_01' && python3 -B -c '
import generate as g
assert g.full_source(\"all58\") == open(\"evidence/full_01/response_only.p4\").read()
assert g.full_source(\"strict\") == open(\"evidence/full_02_strict/response_only.p4\").read()
'"

# 3. Campaign configs reproduce from their generators (written to a scratch copy, compared).
step "candidate57s/57a configs reproduce" bash -c "
  CFG='$C4/integration/evidence/rearm_01/config' && mkdir '$TMP/orig' && cp \"\$CFG\"/candidate57[sa]_*.json '$TMP/orig/' &&
  cd \"\$CFG\" && python3 -B make_candidate57s.py > /dev/null && python3 -B make_candidate57s.py --all58 > /dev/null &&
  python3 -B make_candidate57s_eval.py > /dev/null; rc=0
  for f in '$TMP'/orig/*.json; do n=\$(basename \"\$f\"); cmp -s \"\$f\" \"\$CFG/\$n\" || { echo \"differs: \$n\"; rc=1; }; done
  cp '$TMP'/orig/*.json \"\$CFG\"/; exit \$rc"

# 4. IEEE 1815 verdict on committed silicon captures of the strict candidate (one per gate family).
for run in candidate57s_graceful_800_01 candidate57s_rst_950_01 candidate57s_fourarm_smoke_01 candidate57s_dup_hold_350_02; do
  step "IEEE 1815 conformant: $run" bash -c "
    cd '$C4/integration/evidence/campaign_hw_vepa' &&
    for d in \$(find '$run' -name in.pcap -printf '%h\n' | sort); do
      python3 -B '$SE/read_reencode_01/check_capture.py' \"\$d\" > /dev/null || { echo \"non-conformant: \$d\"; exit 1; }
    done"
done

[ $fail -eq 0 ] && echo "ALL OFFLINE CHECKS PASS" || echo "SOME OFFLINE CHECKS FAILED"
exit $fail

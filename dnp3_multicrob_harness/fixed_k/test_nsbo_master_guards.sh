#!/bin/bash
# Negative-test matrix for the hardened nsbo_master: asserts exit codes for the fail-closed
# target guard, input validation, evidence-path, and no-comms paths. No traffic to any real host
# except a loopback no-comms probe. Run: bash fixed_k/test_nsbo_master_guards.sh
M="$(cd "$(dirname "$0")" && pwd)/nsbo_master"
[ -x "$M" ] || { echo "build first: bash fixed_k/build.sh"; exit 2; }
FAIL=0
chk() { # desc expected  -- remaining args are nsbo_master args
  local desc="$1" exp="$2"; shift 2
  "$M" "$@" >/dev/null 2>&1; local rc=$?
  if [ "$rc" = "$exp" ]; then printf "  ok   %-34s exit %s\n" "$desc" "$rc"
  else printf "  FAIL %-34s exit %s (expected %s)\n" "$desc" "$rc" "$exp"; FAIL=1; fi
}
OKARGS=(--reps 1 --indexes 0,1 --mode alt --out /tmp/nsbo_ok.json --expect-k 2)
echo "nsbo_master guard/validation matrix:"
chk "physical relay refused"        3 --host 192.168.10.7 "${OKARGS[@]}"
chk "arbitrary 10.10.54.5 refused"  3 --host 10.10.54.5   "${OKARGS[@]}"
chk "malformed 999.1.1.1 refused"   3 --host 999.1.1.1    "${OKARGS[@]}"
chk "trailing-space addr refused"   3 --host "127.0.0.1 " "${OKARGS[@]}"
chk "suffixed .158x refused"        3 --host 10.10.54.158x "${OKARGS[@]}"
chk "out-of-range index refused"    4 --host 127.0.0.1 --reps 1 --indexes 0,99 --mode alt --out /tmp/x.json --expect-k 2
chk "wrapped index refused"         4 --host 127.0.0.1 --reps 1 --indexes 0,65537 --mode alt --out /tmp/x.json --expect-k 2
chk "duplicate index refused"       4 --host 127.0.0.1 --reps 1 --indexes 0,0 --mode alt --out /tmp/x.json --expect-k 2
chk "K mismatch refused"            4 --host 127.0.0.1 --reps 1 --indexes 0,1 --mode alt --out /tmp/x.json --expect-k 3
chk "invalid mode refused"          4 --host 127.0.0.1 --reps 1 --indexes 0,1 --mode toggle --out /tmp/x.json --expect-k 2
chk "non-numeric index (parse)"     2 --host 127.0.0.1 --reps 1 --indexes 0,x --mode alt --out /tmp/x.json --expect-k 2
chk "missing --expect-k (usage)"    2 --host 127.0.0.1 --reps 1 --indexes 0,1 --mode alt --out /tmp/x.json
chk "unwritable evidence path"      5 --host 127.0.0.1 --reps 1 --indexes 0,1 --mode alt --out /nonexistent_dir/x.json --expect-k 2
chk "no-comms (nothing listening)"  6 --host 127.0.0.1 --reps 1 --indexes 0,1 --mode alt --out /tmp/nc.json --expect-k 2
[ "$FAIL" = 0 ] && echo "ALL GUARD TESTS PASS" || { echo "SOME GUARD TESTS FAILED"; exit 1; }

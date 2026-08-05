#!/bin/bash
# Negative-test matrix for the hardened nsbo_master: fail-closed target guard, strict numeric
# validation, fixed-K constraints (K in {4,8,16}, 1<=R<=K, exactly R real 0..15 + K-R decoy 16..31),
# option hygiene (duplicate/unknown/trailing), evidence-path, and no-comms paths. No traffic to any
# real host except a loopback no-comms probe. Run: bash fixed_k/test_nsbo_master_guards.sh
M="$(cd "$(dirname "$0")" && pwd)/nsbo_master"
[ -x "$M" ] || { echo "build first: bash fixed_k/build.sh"; exit 2; }
FAIL=0
chk() { local desc="$1" exp="$2"; shift 2
  "$M" "$@" >/dev/null 2>&1; local rc=$?
  if [ "$rc" = "$exp" ]; then printf "  ok   %-38s exit %s\n" "$desc" "$rc"
  else printf "  FAIL %-38s exit %s (expected %s)\n" "$desc" "$rc" "$exp"; FAIL=1; fi
}
# valid fixed-K baseline: K=4, R=2 (real 0,1 + decoy 16,17) -> passes validation, exit 6 (no emulator)
B=(--reps 7 --indexes 0,1,16,17 --mode alt --out /tmp/nsbo_ok.json --expect-k 4 --expect-r 2)
echo "nsbo_master guard / validation / fixed-K matrix:"
chk "valid fixed-K baseline (no comms)"   6 --host 127.0.0.1 "${B[@]}"
# target guard (exit 3)
chk "physical relay refused"              3 --host 192.168.10.7 "${B[@]}"
chk "arbitrary 10.10.54.5 refused"        3 --host 10.10.54.5   "${B[@]}"
chk "malformed 999.1.1.1 refused"         3 --host 999.1.1.1    "${B[@]}"
chk "trailing-space addr refused"         3 --host "127.0.0.1 " "${B[@]}"
chk "suffixed .158x refused"              3 --host 10.10.54.158x "${B[@]}"
# option hygiene (exit 2)
chk "unknown option refused"              2 --host 127.0.0.1 --foo bar "${B[@]}"
chk "duplicate option refused"            2 --host 127.0.0.1 --reps 7 "${B[@]}"
chk "trailing arg (no value) refused"     2 --host 127.0.0.1 --reps 7 --indexes 0,1,16,17 --mode alt --out /tmp/x.json --expect-k 4 --expect-r
chk "non-numeric index (parse)"           2 --host 127.0.0.1 --reps 7 --indexes 0,x,16,17 --mode alt --out /tmp/x.json --expect-k 4 --expect-r 2
chk "malformed --seed refused"            2 --host 127.0.0.1 --reps 7 --indexes 0,1,16,17 --mode alt --out /tmp/x.json --expect-k 4 --expect-r 2 --seed xyz
chk "reps overflow refused"               2 --host 127.0.0.1 --reps 99999999999999 --indexes 0,1,16,17 --mode alt --out /tmp/x.json --expect-k 4 --expect-r 2
# fixed-K + validation (exit 4)
chk "K not in {4,8,16} refused"           4 --host 127.0.0.1 --reps 7 --indexes 0,1 --mode alt --out /tmp/x.json --expect-k 2 --expect-r 1
chk "R > K refused"                       4 --host 127.0.0.1 --reps 7 --indexes 0,1,16,17 --mode alt --out /tmp/x.json --expect-k 4 --expect-r 5
chk "wrong real count refused"            4 --host 127.0.0.1 --reps 7 --indexes 0,16,17,18 --mode alt --out /tmp/x.json --expect-k 4 --expect-r 2
chk "wrong decoy count refused"           4 --host 127.0.0.1 --reps 7 --indexes 0,1,2,17 --mode alt --out /tmp/x.json --expect-k 4 --expect-r 2
chk "out-of-range index refused"          4 --host 127.0.0.1 --reps 7 --indexes 0,1,16,99 --mode alt --out /tmp/x.json --expect-k 4 --expect-r 2
chk "duplicate index refused"             4 --host 127.0.0.1 --reps 7 --indexes 0,0,16,17 --mode alt --out /tmp/x.json --expect-k 4 --expect-r 2
chk "K mismatch (count!=K) refused"       4 --host 127.0.0.1 --reps 7 --indexes 0,1,16 --mode alt --out /tmp/x.json --expect-k 4 --expect-r 2
chk "invalid mode refused"                4 --host 127.0.0.1 --reps 7 --indexes 0,1,16,17 --mode toggle --out /tmp/x.json --expect-k 4 --expect-r 2
chk "malformed --expect-r refused"        4 --host 127.0.0.1 --reps 7 --indexes 0,1,16,17 --mode alt --out /tmp/x.json --expect-k 4 --expect-r abc
# evidence path (exit 5)
chk "unwritable evidence path"            5 --host 127.0.0.1 --reps 7 --indexes 0,1,16,17 --mode alt --out /nonexistent_dir/x.json --expect-k 4 --expect-r 2
[ "$FAIL" = 0 ] && echo "ALL GUARD TESTS PASS" || { echo "SOME GUARD TESTS FAILED"; exit 1; }

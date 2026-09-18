#!/usr/bin/env bash
# run_tail_sweep.sh - the release tail against the release deadline, on both lanes.
#
# campaign_v1 measures one configuration, and its sweep installs each policy once, so the release
# tail could only be read at four budgets and its error bars were a bootstrap over exchanges
# inside a single install. This sweep answers the two questions that leaves open: how the tail
# moves with the deadline, and how much of what we see is the install rather than the mechanism.
#
# Three series, because the two lanes do not admit the same deadlines.
#
# 1. Read lane. The configured CLRT_new stays at 4 ms and D_A walks 2 to 32 ms, moving the budget
#    D = D_A + CLRT_new from 6 to 36 ms and crossing the saturation knee campaign_v1's sweep
#    found near 31 ms. The control-lane offsets stay at the campaign's 20 and 24 throughout,
#    because they are not what this series varies.
#
# 2. Control lane, campaign codebook {2,6,12}. The offset A walks its whole feasible range. That
#    range is three settings wide and the control plane itself decides the ends: below, A must
#    exceed J_max plus the outstation's acknowledgment latency, which refuses A = 14; above, R
#    must stay under ceiling(H) = 31 ms, which refuses A = 28 since R = A + 4. The 256 ns
#    deadline grid quantises whole milliseconds to multiples of 4. So A is 16, 20 or 24, and
#    nothing else is installable. Measuring that is the point.
#
# 3. Control lane, reduced codebook {2,4,6}. Same sweep with a smaller J_max, which moves the
#    floor from 16 to 12 ms and adds a fourth setting. It shows the lower bound is set by the
#    codebook rather than being a fixed property of the mechanism.
#
# Replication. Three passes over the whole grid rather than three blocks back to back at a point.
# A repeat is then separated by twenty minutes and a full reconfiguration, so install-to-install
# variation and drift appear as between-pass spread instead of hiding inside a point.
#
# Baseline. A Timing OFF block at each end of a pass and one every four policy blocks. The tail is
# a difference against this baseline, so the baseline has to track the session.
#
# A block that cannot prove the size carve was off, or whose capture did not come back, fails
# itself and is recorded as failed. The sweep continues: one bad block should not cost the session.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
LOG="$ROOT/RUN.log"
MANIFEST="$ROOT/blocks.csv"

READ_N=300; READ_SBO=20          # read-lane series: the curve is READ, SELECT rides along
CTL_N=100;  CTL_SBO=60           # control-lane series: OPERATE is the measurement
CLRT=4
PASSES=3

READ_DA="2 4 6 8 10 12 14 16 18 20 22 24 26 28 29 30 31 32"
CTL_A_FULL="16 20 24"            # J_max = 12
CTL_A_RED="12 16 20 24"          # J_max = 6

: > "$LOG"
echo "tag,pass,series,mode,D_A_ms,CLRT_new_ms,D_ms,A_ms,R_ms,j_set,n_read,n_sbo,seed,status" > "$MANIFEST"

run_block () {   # tag series mode D_A D_R A R nread nsbo seed pass jset
  local tag="$1" series="$2" mode="$3" da="$4" dr="$5" a="$6" r="$7"
  local nr="$8" ns="$9" seed="${10}" pass="${11}" jset="${12}"
  local status="ok"
  if ! "$HERE/tail_block.sh" "$tag" "$mode" "$da" "$dr" "$a" "$r" "$nr" "$ns" "$seed" "$jset" \
        >> "$LOG" 2>&1; then
    status="failed"; echo "  !! $tag failed" >> "$LOG"
  fi
  local d=""; [ "$mode" = "D4" ] && d=$((da + dr))
  echo "$tag,$pass,$series,$mode,$da,$dr,$d,$a,$r,\"$jset\",$nr,$ns,$seed,$status" >> "$MANIFEST"
}

seed=20260918
start=$(date +%s)
{ echo "release-tail sweep, $PASSES passes"
  echo "  read lane    : $(echo $READ_DA | wc -w) points, D_A $READ_DA"
  echo "  control full : $(echo $CTL_A_FULL | wc -w) points, A $CTL_A_FULL   J={2,6,12}"
  echo "  control red  : $(echo $CTL_A_RED | wc -w) points, A $CTL_A_RED   J={2,4,6}"; } >> "$LOG"

for pass in $(seq 1 $PASSES); do
  echo "== pass $pass ==" >> "$LOG"
  seed=$((seed + 1000)); i=0
  run_block "off_p${pass}_a" baseline OFF 0 0 0 0 $READ_N $READ_SBO $seed "$pass" "2 6 12"

  for da in $READ_DA; do
    seed=$((seed + 1)); i=$((i + 1))
    run_block "rd_p${pass}_da${da}" readlane D4 "$da" "$CLRT" 20 24 \
              $READ_N $READ_SBO "$seed" "$pass" "2 6 12"
    if [ $((i % 4)) -eq 0 ]; then
      seed=$((seed + 1))
      run_block "off_p${pass}_r${i}" baseline OFF 0 0 0 0 $READ_N $READ_SBO $seed "$pass" "2 6 12"
    fi
  done

  for a in $CTL_A_FULL; do
    seed=$((seed + 1))
    run_block "cf_p${pass}_a${a}" ctl_full D4 20 "$CLRT" "$a" "$((a + 4))" \
              $CTL_N $CTL_SBO "$seed" "$pass" "2 6 12"
  done
  seed=$((seed + 1))
  run_block "off_p${pass}_c" baseline OFF 0 0 0 0 $CTL_N $CTL_SBO $seed "$pass" "2 6 12"

  for a in $CTL_A_RED; do
    seed=$((seed + 1))
    run_block "cr_p${pass}_a${a}" ctl_reduced D4 20 "$CLRT" "$a" "$((a + 4))" \
              $CTL_N $CTL_SBO "$seed" "$pass" "2 4 6"
  done
  seed=$((seed + 1))
  run_block "off_p${pass}_z" baseline OFF 0 0 0 0 $READ_N $READ_SBO $seed "$pass" "2 6 12"
done

echo "done in $(( ($(date +%s) - start) / 60 )) min; ok=$(grep -c ',ok$' "$MANIFEST") failed=$(grep -c ',failed$' "$MANIFEST")" >> "$LOG"

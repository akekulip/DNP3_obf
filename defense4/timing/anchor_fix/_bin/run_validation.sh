#!/usr/bin/env bash
# The anchor-fix validation run: 8 rounds x 3 arms, interleaved so that any drift in the relay,
# the host or the link falls on all three arms alike. Arm order rotates by round so no arm always
# follows the same predecessor.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NREAD=600; NSBO=100
for r in $(seq 1 8); do
  case $((r % 3)) in
    0) ORDER="A1 OFF A0" ;;
    1) ORDER="OFF A0 A1" ;;
    2) ORDER="A0 A1 OFF" ;;
  esac
  for arm in $ORDER; do
    TAG=$(printf "r%02d_%s" "$r" "$arm")
    "$HERE/anchor_block.sh" "$TAG" "$arm" "$NREAD" "$NSBO" $((1000 + r)) || echo "  !! block $TAG FAILED (rc=$?)"
  done
done
echo "VALIDATION RUN COMPLETE"

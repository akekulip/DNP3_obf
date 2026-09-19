#!/usr/bin/env bash
# The arrival-phase control: the same arm, the same policy, the same device work, at four
# different master inter-request spacings. If the separation that survives the anchor fix is
# arrival phase rather than device execution time, the released interval's tail must move with
# the spacing, and it must move the same way for a class whose execution time did not change.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for gap in 20 13 7 3; do
  for arm in A1 A0; do
    TAG=$(printf "g%02d_%s" "$gap" "$arm")
    "$HERE/gap_block.sh" "$TAG" "$arm" 500 80 $((2000 + gap)) "$gap" || echo "  !! block $TAG FAILED (rc=$?)"
  done
done
echo "PHASE TEST COMPLETE"

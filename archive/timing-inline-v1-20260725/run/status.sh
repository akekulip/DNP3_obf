#!/bin/bash
# status.sh — is the inline defense actually live? Run this before any measurement.
# Safe to run any time: it reads state and sends 2 pings. It changes nothing.
set -o nounset
SW="${SW:-decps@10.10.54.81}"
RELAY="${RELAY:-192.168.10.7}"
IF="${IF:-enp59s0f0np0}"
FAIL=0

echo "=== 1. Tofino: which program is loaded? ==="
# Vision has no SSH key to the switch, so this check is best-effort and never fatal.
SWOUT="$(timeout 10 ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=6 \
         "$SW" 'pgrep -a bf_switchd | head -1' 2>/dev/null)"
if [[ -z "$SWOUT" ]]; then
  echo "   SKIP no SSH from this host to the switch — check it from gambit with:"
  echo "        ssh $SW 'pgrep -a bf_switchd'   (want: tn_inline_abs.conf)"
elif grep -q 'tn_inline_abs.conf' <<<"$SWOUT"; then
  echo "   OK   dnp3_timing_normalizer_inline is loaded"
else
  echo "   FAIL a DIFFERENT program is loaded:"; echo "        $SWOUT"; FAIL=$((FAIL+1))
fi

echo "=== 2. Master leg (this host -> dp9) ==="
if ip link show "$IF" 2>/dev/null | grep -q 'state UP'; then
  echo "   OK   $IF up, $(ip -4 -br addr show "$IF" | awk '{print $3}')"
else
  echo "   FAIL $IF is down"; FAIL=$((FAIL+1))
fi

echo "=== 3. Relay reachable THROUGH the Tofino ==="
if ping -c 2 -W 2 "$RELAY" >/dev/null 2>&1; then
  echo "   OK   $RELAY answers"
else
  echo "   FAIL $RELAY unreachable — the switch is not forwarding, or the relay leg is down"
  FAIL=$((FAIL+1))
fi

echo "=== 4. DNP3 port open ==="
if timeout 3 bash -c "cat < /dev/null > /dev/tcp/${RELAY}/20000" 2>/dev/null; then
  echo "   OK   tcp/20000 accepts"
else
  echo "   FAIL tcp/20000 refused"; FAIL=$((FAIL+1))
fi

echo
if [[ "$FAIL" -eq 0 ]]; then
  echo "READY  ->  ./run.sh native    then    ./run.sh protected"
else
  echo "$FAIL check(s) FAILED — see README.md §6 before running a measurement."
fi
exit "$FAIL"

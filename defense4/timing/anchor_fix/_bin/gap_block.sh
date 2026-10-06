#!/usr/bin/env bash
# gap_block.sh <tag> <arm OFF|A0|A1> <n_read> <n_sbo> <seed> <gap_ms>
#
# anchor_block.sh with the master's inter-request spacing as an argument. It exists to test one
# claim causally: that whatever separation survives the anchor fix is a property of WHEN a
# request arrives relative to the blocker loop, not of how long the device takes. Moving the
# spacing moves the arrival phase and nothing else -- the relay does the same work either way.
#
# One block of the anchor-fix validation. Three arms, one binary:
#   OFF  Timing OFF, the undefended baseline
#   A0   obfuscated, anchor_req=0 -- the schedule campaign_v1 evaluated (positive control)
#   A1   obfuscated, anchor_req=1 -- the request-anchored read lane (the fix)
#
# This is evidence/tail_sweep_20260918/_bin/tail_block.sh with the control tree repointed at
# anchor_fix_build and the new --anchor-req knob threaded through. Every guard it carries is
# kept, because each of them caught a real failure: the size carve is proved off from a
# hardware readback, the policy the switch actually holds is recorded per block, the capture is
# stopped in its own ssh (pkill -f matches the launch line, so a combined command kills its own
# shell), and the block fails on a missing, short, or still-open capture.
set -uo pipefail

TAG="$1"; ARM="$2"; NREAD="$3"; NSBO="$4"; SEED="$5"; GAPMS="${6:-20}"
DA=20; DR=4; A_MS=20; R_MS=24; JSET="2 6 12"

PW="$(. ~/.lab_env 2>/dev/null; printf %s "$SSHPASS")"
SW="ssh -o BatchMode=yes -o ConnectTimeout=10 decps@10.10.54.81"
VI="ssh -o BatchMode=yes -o ConnectTimeout=10 decps@10.10.54.166"
SDE=/home/decps/Downloads/bf-sde-9.13.2
ENV="SDE_INSTALL=$SDE/install PYTHONPATH=$SDE/install/lib/python3.8/site-packages/tofino:$SDE/install/lib/python3.8/site-packages"
REPO=/home/decps/Philip_repo/dnp3-defense4
CTL2=$REPO/anchor_fix_build/control
CTL1=$REPO/rrc_bor_build/control
CASEA=$REPO/d4_build/control/defense4_caseA_setup.py
OUT=/home/decps/anchor_fix_20260918
TAGDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/params"
mkdir -p "$TAGDIR"
IFACE=enp59s0f0np0

case "$ARM" in
  OFF) ARGS="--mode OFF --read-len 0 --anchor-req 0"; COND=native ;;
  A0)  ARGS="--mode D4 --read-len 0 --d-a-ms $DA --d-r-ms $DR --op-a-ms $A_MS --op-r-ms $R_MS --j-set '$JSET' --anchor-req 0"; COND=obfuscated ;;
  A1)  ARGS="--mode D4 --read-len 0 --d-a-ms $DA --d-r-ms $DR --op-a-ms $A_MS --op-r-ms $R_MS --j-set '$JSET' --anchor-req 1"; COND=obfuscated ;;
  *)   echo "unknown arm $ARM" >&2; exit 9 ;;
esac
MODE=$( [ "$ARM" = OFF ] && echo OFF || echo D4 )

printf "%-22s arm=%-3s gap=%-4s " "$TAG" "$ARM" "$GAPMS"

CFG=$(timeout 300 $SW "cd $CTL2 && $ENV DEFENSE4_HW_AUTHORIZED=1 D4_CASEA_SETUP=$CASEA \
  python3 defense4_rrc_bor_unified12_setup.py configure-all $ARGS 2>&1 | grep -E '^RESULT|\[FAIL\]|anchor_req'")
if printf '%s' "$CFG" | grep -qE '^RESULT: PASS'; then
  printf "cfg=PASS "
else
  printf "cfg=REFUSED\n%s\n" "$CFG" >&2; exit 2
fi
# The knob is asserted from the switch, not from the command line: a block whose anchor state
# cannot be proved is a block whose capture cannot be attributed to an arm.
WANT=$( [ "$ARM" = A1 ] && echo 1 || echo 0 )
if ! printf '%s' "$CFG" | grep -qE "\[ok\] tbl_bor_params anchor_req - got=$WANT want=$WANT"; then
  printf "anchor=UNPROVED\n%s\n" "$CFG" >&2; exit 6
fi
printf "anchor=%s " "$WANT"
printf '%s' "$CFG" | grep -oE "anchor_req - got=[01]" > "$TAGDIR/${TAG}.anchor.txt" 2>/dev/null || true

SHAPE=$(timeout 120 $SW "cd $CTL1 && $ENV python3 shape_set.py 0 2>&1 | tail -3")
SHAPE_VAL=$(printf '%s' "$SHAPE" | grep -oE "'shape_enable': *[01]" | grep -oE '[01]$' | tail -1)
SHAPE_OK=$(printf '%s' "$SHAPE" | grep -cE '^RESULT: PASS')
printf "shape=%s " "${SHAPE_VAL:-NONE}"
if [ "${SHAPE_VAL:-x}" != "0" ] || [ "$SHAPE_OK" -lt 1 ]; then
  printf "\n  the size carve could not be proved off:\n%s\n" "$SHAPE" >&2; exit 3
fi
printf '%s' "$SHAPE" | grep -oE "tbl_params=\{.*\}" > "$TAGDIR/${TAG}.params.txt" 2>/dev/null || true

RUN=$(timeout 400 $VI "echo '$PW' | sudo -S -p '' true 2>/dev/null
  mkdir -p $OUT; sudo -n rm -f $OUT/${TAG}.pcap
  sudo -n nohup timeout 300 tcpdump -i $IFACE -s0 -w $OUT/${TAG}.pcap 'host 192.168.10.7 and tcp' >/dev/null 2>&1 &
  sleep 3
  cd /home/decps/native_parity && python3 campaign_run.py --session anchorfix --block $TAG \
    --condition $COND --mode $MODE --j-ms '$(echo $JSET | tr " " ",")' --n-read $NREAD --n-sbo $NSBO \
    --min-gap 5 --gap-ms $GAPMS --seed $SEED --out $OUT/${TAG}.jsonl 2>&1 | tail -1" 2>&1)

STOP=$(timeout 120 $VI "echo '$PW' | sudo -S -p '' true 2>/dev/null
  sudo -n pkill -f '[t]cpdump -i $IFACE'; sleep 2
  sudo -n chmod 644 $OUT/${TAG}.pcap 2>/dev/null
  printf 'ALIVE=%s\\n' \$(pgrep -cf '[t]cpdump -i $IFACE' | head -1)
  stat -c 'PCAPBYTES=%s' $OUT/${TAG}.pcap 2>/dev/null || echo PCAPBYTES=0" 2>&1)

printf '%s' "$RUN" | tr '\n' ' '
BYTES=$(printf '%s' "$STOP" | grep -oE 'PCAPBYTES=[0-9]+' | cut -d= -f2)
printf "pcap=%s " "${BYTES:-0}"
if [ "${BYTES:-0}" -lt 20000 ]; then
  printf "\n  capture missing or too small (%s bytes)\n" "${BYTES:-0}" >&2; exit 4
fi
ALIVE=$(printf '%s' "$STOP" | grep -oE 'ALIVE=[0-9]+' | cut -d= -f2 | head -1)
printf "alive=%s " "${ALIVE:-?}"
if [ "${ALIVE:-1}" != "0" ]; then
  printf "\n  a capture is still running after this block (%s)\n" "${ALIVE:-unknown}" >&2; exit 5
fi
printf "\n"
exit 0

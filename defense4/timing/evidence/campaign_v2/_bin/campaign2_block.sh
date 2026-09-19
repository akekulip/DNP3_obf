#!/usr/bin/env bash
# campaign2_block.sh <session> <blockid> <cond OFF|D4> <n_read> <n_sbo> <seed>
#
# One block of campaign_v2: the corrected, request-anchored build at D_A = 20 ms and D_R = 8 ms.
#
# This is campaign_v1/_bin/campaign_block.sh with the four corrections the 2026-09-18 tail sweep
# introduced and the two the anchor fix adds. The corrections are kept because each caught a real
# failure, and campaign_v1's configuration provenance is PARTIAL precisely because it lacked them.
#   1. The control trees moved under ~/Philip_repo; the original absolute paths no longer exist.
#   2. shape_enable is read back after being forced to 0 rather than assumed.
#   3. The capture is stopped in its own ssh (pkill -f matches the launch line, so a combined
#      command kills its own shell and the capture runs on into the next block).
#   4. The block fails loudly: a missing, short, or still-open capture aborts it.
#   5. The control plane is the anchor-fix tree, and anchor_req is asserted back from the switch.
#      A block whose anchor state cannot be proved is a block whose capture cannot be attributed.
#   6. D_R is 8 ms, not 4. Request anchoring measures the response deadline from the request, so
#      the budget must cover the relay's whole request-to-response latency; 20 + 8 = 28 ms is the
#      smallest total on the 4 ms tick grid that covers this relay's worst observed response
#      (24.691 ms over 6,288 Timing OFF exchanges). A and R follow: 20 and 28.
set -uo pipefail

SESS="$1"; BID="$2"; COND="$3"; NREAD="$4"; NSBO="$5"; SEED="$6"
DA=20; DR=8; A_MS=20; R_MS=28; JSET="2 6 12"

PW="$(. ~/.lab_env 2>/dev/null; printf %s "$SSHPASS")"
SW="ssh -o BatchMode=yes -o ConnectTimeout=10 decps@10.10.54.81"
VI="ssh -o BatchMode=yes -o ConnectTimeout=10 decps@10.10.54.166"
SDE=/home/decps/Downloads/bf-sde-9.13.2
ENV="SDE_INSTALL=$SDE/install PYTHONPATH=$SDE/install/lib/python3.8/site-packages/tofino:$SDE/install/lib/python3.8/site-packages"
REPO=/home/decps/Philip_repo/dnp3-defense4
CTL2=$REPO/anchor_fix_build/control
CTL1=$REPO/rrc_bor_build/control
CASEA=$REPO/d4_build/control/defense4_caseA_setup.py
OUT=/tmp/${SESS}
IFACE=enp59s0f0np0

if [ "$COND" = "OFF" ]; then
  CONDNAME=native; ARGS="--mode OFF --read-len 0 --anchor-req 0"; MODE=OFF; WANT=0
else
  CONDNAME=obfuscated; MODE=D4; WANT=1
  ARGS="--mode D4 --read-len 0 --d-a-ms $DA --d-r-ms $DR --op-a-ms $A_MS --op-r-ms $R_MS --j-set '$JSET' --anchor-req 1"
fi
TAG="${SESS}_${BID}_${CONDNAME}"
PROV="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/provenance"
mkdir -p "$PROV"

printf "%-24s cond=%-3s " "$TAG" "$COND"

CFG=$(timeout 300 $SW "cd $CTL2 && $ENV DEFENSE4_HW_AUTHORIZED=1 D4_CASEA_SETUP=$CASEA \
  python3 defense4_rrc_bor_unified12_setup.py configure-all $ARGS 2>&1 | grep -E '^RESULT|\[FAIL\]|anchor_req'")
if printf '%s' "$CFG" | grep -qE '^RESULT: PASS'; then printf "cfg=PASS "; else
  printf "cfg=REFUSED\n%s\n" "$CFG" >&2; exit 2; fi
if ! printf '%s' "$CFG" | grep -qE "\[ok\] tbl_bor_params anchor_req - got=$WANT want=$WANT"; then
  printf "anchor=UNPROVED\n%s\n" "$CFG" >&2; exit 6; fi
printf "anchor=%s " "$WANT"

SHAPE=$(timeout 120 $SW "cd $CTL1 && $ENV python3 shape_set.py 0 2>&1 | tail -3")
SHAPE_VAL=$(printf '%s' "$SHAPE" | grep -oE "'shape_enable': *[01]" | grep -oE '[01]$' | tail -1)
SHAPE_OK=$(printf '%s' "$SHAPE" | grep -cE '^RESULT: PASS')
printf "shape=%s " "${SHAPE_VAL:-NONE}"
if [ "${SHAPE_VAL:-x}" != "0" ] || [ "$SHAPE_OK" -lt 1 ]; then
  printf "\n  the size carve could not be proved off:\n%s\n" "$SHAPE" >&2; exit 3; fi
{ printf '%s' "$CFG" | grep -oE "anchor_req - got=[01]"
  printf '%s' "$SHAPE" | grep -oE "tbl_params=\{.*\}"; } > "$PROV/${TAG}.params.txt" 2>/dev/null || true

RUN=$(timeout 400 $VI "echo '$PW' | sudo -S -p '' true 2>/dev/null
  mkdir -p $OUT; sudo -n rm -f $OUT/${TAG}.pcap
  sudo -n nohup timeout 300 tcpdump -i $IFACE -s0 -w $OUT/${TAG}.pcap 'host 192.168.10.7 and tcp' >/dev/null 2>&1 &
  sleep 3
  cd /home/decps/native_parity && python3 campaign_run.py --session $SESS --block $TAG \
    --condition $CONDNAME --mode $MODE --j-ms '$(echo $JSET | tr " " ",")' --n-read $NREAD --n-sbo $NSBO \
    --min-gap 5 --gap-ms 20 --seed $SEED --out $OUT/${TAG}.jsonl 2>&1 | tail -1" 2>&1)

STOP=$(timeout 120 $VI "echo '$PW' | sudo -S -p '' true 2>/dev/null
  sudo -n pkill -f '[t]cpdump -i $IFACE'; sleep 2
  sudo -n chmod 644 $OUT/${TAG}.pcap 2>/dev/null
  printf 'ALIVE=%s\\n' \$(pgrep -cf '[t]cpdump -i $IFACE' | head -1)
  stat -c 'PCAPBYTES=%s' $OUT/${TAG}.pcap 2>/dev/null || echo PCAPBYTES=0" 2>&1)

printf '%s' "$RUN" | tr '\n' ' '
BYTES=$(printf '%s' "$STOP" | grep -oE 'PCAPBYTES=[0-9]+' | cut -d= -f2)
printf "pcap=%s " "${BYTES:-0}"
if [ "${BYTES:-0}" -lt 20000 ]; then
  printf "\n  capture missing or too small (%s bytes)\n" "${BYTES:-0}" >&2; exit 4; fi
ALIVE=$(printf '%s' "$STOP" | grep -oE 'ALIVE=[0-9]+' | cut -d= -f2 | head -1)
printf "alive=%s " "${ALIVE:-?}"
if [ "${ALIVE:-1}" != "0" ]; then
  printf "\n  a capture is still running after this block (%s)\n" "${ALIVE:-unknown}" >&2; exit 5; fi
printf "\n"
exit 0

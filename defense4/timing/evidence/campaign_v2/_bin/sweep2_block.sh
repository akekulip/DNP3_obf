#!/usr/bin/env bash
# sweep2_block.sh <tag> <mode OFF|D2|D3|D4> <D_A ms> <D_R ms> <n_read> <n_sbo> <seed>
#
# One policy point of the campaign_v2 hardware sweep, on the corrected request-anchored build.
#
# This is campaign_v1/_bin/sweep_block.sh with the guards the 2026-09-18 tail sweep added and the
# anchor readback the fix adds. campaign_v1's version assumed the size carve was off, stopped its
# capture inside the same ssh that launched it, and accepted whatever came back; each of those
# produced a capture that could not be attributed, which is why that dataset's configuration
# provenance is PARTIAL.
#
# The control-lane offsets stay at the shipped 20 and 28 throughout. They are not what this sweep
# varies, and moving them would confound the read-lane series with a control-lane change.
set -uo pipefail

TAG="$1"; MODE="$2"; DA="$3"; DR="$4"; NREAD="$5"; NSBO="$6"; SEED="$7"
A_MS=20; R_MS=28; JSET="2 6 12"

PW="$(. ~/.lab_env 2>/dev/null; printf %s "$SSHPASS")"
SW="ssh -o BatchMode=yes -o ConnectTimeout=10 decps@10.10.54.81"
VI="ssh -o BatchMode=yes -o ConnectTimeout=10 decps@10.10.54.166"
SDE=/home/decps/Downloads/bf-sde-9.13.2
ENV="SDE_INSTALL=$SDE/install PYTHONPATH=$SDE/install/lib/python3.8/site-packages/tofino:$SDE/install/lib/python3.8/site-packages"
REPO=/home/decps/Philip_repo/dnp3-defense4
CTL2=$REPO/anchor_fix_build/control
CTL1=$REPO/rrc_bor_build/control
CASEA=$REPO/d4_build/control/defense4_caseA_setup.py
OUT=/tmp/sweep2
IFACE=enp59s0f0np0
PROV="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/sweep/provenance"
mkdir -p "$PROV"

# The anchor knob belongs to the read lane's hold, so it is set exactly on the points that hold:
# the D4 series. OFF, D2 and D3 establish the operating envelope and hold nothing, so they run with
# it clear, which is also what makes them a control for it.
if [ "$MODE" = "OFF" ]; then
  ARGS="--mode OFF --read-len 0 --anchor-req 0"; COND=native; WANT=0
elif [ "$MODE" = "D4" ]; then
  ARGS="--mode D4 --read-len 0 --d-a-ms $DA --d-r-ms $DR --op-a-ms $A_MS --op-r-ms $R_MS --j-set '$JSET' --anchor-req 1"
  COND=obfuscated; WANT=1
else
  ARGS="--mode $MODE --read-len 0 --d-a-ms $DA --d-r-ms $DR --op-a-ms $A_MS --op-r-ms $R_MS --j-set '$JSET' --anchor-req 0"
  COND=obfuscated; WANT=0
fi

printf "%-16s mode=%-3s D_A=%-3s D_R=%-3s " "$TAG" "$MODE" "$DA" "$DR"

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
  cd /home/decps/native_parity && python3 campaign_run.py --session sweep2 --block $TAG \
    --condition $COND --mode $MODE --j-ms '$(echo $JSET | tr " " ",")' --n-read $NREAD --n-sbo $NSBO \
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
  printf "\n  a capture is still running after this point (%s)\n" "${ALIVE:-unknown}" >&2; exit 5; fi
printf "\n"
exit 0

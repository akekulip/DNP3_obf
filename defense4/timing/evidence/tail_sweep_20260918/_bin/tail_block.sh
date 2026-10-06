#!/usr/bin/env bash
# tail_block.sh <tag> <mode OFF|D4> <D_A ms> <D_R ms> <A ms> <R ms> <n_read> <n_sbo> <seed> [J codebook]
#
# One parameter point of the release-tail sweep: configure the switch, force the size carve off
# and read it back, capture the master-facing link, run the interleaved READ + SBO driver.
#
# This is campaign_v1/_bin/sweep_block.sh with four corrections.
#   1. The control trees moved under ~/Philip_repo (PATH_MAP.tsv); the old absolute paths are gone
#      and the original script would have failed at the first ssh with "No such file or directory".
#   2. The control-lane offsets A and R were hardcoded at 20 and 24. They are arguments here,
#      because a sweep that never moves them cannot say anything about the control lane's deadline.
#   3. shape_enable is read back after being forced to 0 rather than assumed. configure-all leaves
#      it at 1, observed five times on hardware on 2026-09-15, and a block that ran with the size
#      carve on would be outside every claim boundary in this paper.
#   4. The block fails loudly. Any step that does not report what it was asked to report aborts
#      the block instead of writing a capture nobody can attribute.
#
# SBO indices stay at the driver default 1,3 (RB02/RB04), which drive no relay output; index 6,
# breaker-close, is refused at frame construction inside the driver and is not overridden here.
set -uo pipefail

TAG="$1"; MODE="$2"; DA="$3"; DR="$4"; A_MS="$5"; R_MS="$6"; NREAD="$7"; NSBO="$8"; SEED="$9"
JSET="${10:-2 6 12}"

PW="$(. ~/.lab_env 2>/dev/null; printf %s "$SSHPASS")"
SW="ssh -o BatchMode=yes -o ConnectTimeout=10 decps@10.10.54.81"
VI="ssh -o BatchMode=yes -o ConnectTimeout=10 decps@10.10.54.166"
SDE=/home/decps/Downloads/bf-sde-9.13.2
ENV="SDE_INSTALL=$SDE/install PYTHONPATH=$SDE/install/lib/python3.8/site-packages/tofino:$SDE/install/lib/python3.8/site-packages"
REPO=/home/decps/Philip_repo/dnp3-defense4
CTL2=$REPO/rrc_bor_build_v2/control
CTL1=$REPO/rrc_bor_build/control
CASEA=$REPO/d4_build/control/defense4_caseA_setup.py
OUT=/home/decps/tail_sweep_20260918
TAGDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/params"
mkdir -p "$TAGDIR"
IFACE=enp59s0f0np0

if [ "$MODE" = "OFF" ]; then
  ARGS="--mode OFF --read-len 0"; COND=native
else
  ARGS="--mode $MODE --read-len 0 --d-a-ms $DA --d-r-ms $DR --op-a-ms $A_MS --op-r-ms $R_MS --j-set '$JSET'"
  COND=obfuscated
fi

printf "%-24s mode=%-3s D_A=%-4s D_R=%-4s A=%-4s R=%-4s " "$TAG" "$MODE" "$DA" "$DR" "$A_MS" "$R_MS"

CFG=$(timeout 240 $SW "cd $CTL2 && $ENV DEFENSE4_HW_AUTHORIZED=1 D4_CASEA_SETUP=$CASEA \
  python3 defense4_rrc_bor_unified12_setup.py configure-all $ARGS 2>&1 | grep -E '^RESULT|\[FAIL\]'")
if printf '%s' "$CFG" | grep -qE '^RESULT: PASS'; then
  printf "cfg=PASS "
else
  printf "cfg=REFUSED\n  the control plane refused this point:\n%s\n" "$CFG" >&2; exit 2
fi

# The size carve, off and then proved off. shape_set.py prints the whole tbl_params readback;
# the block aborts unless that readback says shape_enable 0 and the check reports PASS. An
# empty or unparsed answer aborts too, because a block that cannot prove the carve was off is
# a block whose captures cannot be used.
SHAPE=$(timeout 120 $SW "cd $CTL1 && $ENV python3 shape_set.py 0 2>&1 | tail -3")
SHAPE_VAL=$(printf '%s' "$SHAPE" | grep -oE "'shape_enable': *[01]" | grep -oE '[01]$' | tail -1)
SHAPE_OK=$(printf '%s' "$SHAPE" | grep -cE '^RESULT: PASS')
printf "shape=%s " "${SHAPE_VAL:-NONE}"
if [ "${SHAPE_VAL:-x}" != "0" ] || [ "$SHAPE_OK" -lt 1 ]; then
  printf "\n  the size carve could not be proved off:\n%s\n" "$SHAPE" >&2; exit 3
fi
# The same readback carries the policy the switch actually holds. Recording it per block is what
# campaign_v1 could not do: its configuration provenance is PARTIAL for exactly this reason.
printf '%s' "$SHAPE" | grep -oE "tbl_params=\{.*\}" > "$TAGDIR/${TAG}.params.txt" 2>/dev/null || true

# Two ssh calls, not one. pkill -f matches against whole command lines, and the shell running a
# single combined command would carry the tcpdump launch line in its own command line, so the
# stop step killed the shell and everything after it -- the chmod and the byte count -- never ran.
# Bracketing the pattern does not help: the match is against the launch line, not the pkill line.
RUN=$(timeout 300 $VI "echo '$PW' | sudo -S -p '' true 2>/dev/null
  mkdir -p $OUT; sudo -n rm -f $OUT/${TAG}.pcap
  sudo -n nohup timeout 200 tcpdump -i $IFACE -s0 -w $OUT/${TAG}.pcap 'host 192.168.10.7 and tcp' >/dev/null 2>&1 &
  sleep 3
  cd /home/decps/native_parity && python3 campaign_run.py --session tailsweep --block $TAG \
    --condition $COND --mode $MODE --j-ms '$(echo $JSET | tr " " ",")' --n-read $NREAD --n-sbo $NSBO \
    --min-gap 5 --gap-ms 20 --seed $SEED --out $OUT/${TAG}.jsonl 2>&1 | tail -1" 2>&1)

# sudo's credential cache is per session, so this ssh has to prime it exactly as the run above
# does. Without that priming "sudo -n pkill" answers "a password is required", the capture is
# never stopped, and tcpdump keeps writing for its full 200 s timeout -- so every later block's
# traffic lands in this block's file. That is not a subtle failure: a Timing OFF capture came
# back holding 2,254 READ exchanges at an obfuscated 4.0 ms CLRT instead of 300 at 2.1 ms.
STOP=$(timeout 120 $VI "echo '$PW' | sudo -S -p '' true 2>/dev/null
  sudo -n pkill -f '[t]cpdump -i $IFACE'; sleep 2
  sudo -n chmod 644 $OUT/${TAG}.pcap 2>/dev/null
  printf 'ALIVE=%s\\n' \$(pgrep -cf '[t]cpdump -i $IFACE' | head -1)
  stat -c 'PCAPBYTES=%s' $OUT/${TAG}.pcap 2>/dev/null || echo PCAPBYTES=0" 2>&1)

printf '%s' "$RUN" | tr '\n' ' '
BYTES=$(printf '%s' "$STOP" | grep -oE 'PCAPBYTES=[0-9]+' | cut -d= -f2)
printf "pcap=%s " "${BYTES:-0}"

# The block is only finished if a capture of a plausible size came back. ssh exits 255 on a
# dropped connection and the driver can report success into a capture that was never written,
# so the byte count is the thing that decides, not the exit status of the last command in a pipe.
if [ "${BYTES:-0}" -lt 20000 ]; then
  printf "\n  capture missing or too small (%s bytes)\n" "${BYTES:-0}" >&2; exit 4
fi
# A byte count alone cannot tell a finished capture from one still being written, which is how
# the contaminated blocks passed. No tcpdump may survive this block.
ALIVE=$(printf '%s' "$STOP" | grep -oE 'ALIVE=[0-9]+' | cut -d= -f2 | head -1)
printf "alive=%s " "${ALIVE:-?}"
if [ "${ALIVE:-1}" != "0" ]; then
  printf "\n  a capture is still running after this block (%s); its file would absorb the next one\n" \
    "${ALIVE:-unknown}" >&2; exit 5
fi
printf "\n"
exit 0

#!/usr/bin/env bash
# campaign_block.sh <session> <blockid> <cond OFF|D4> <n_read> <n_sbo> <seed>
# Configure the chip (shape forced 0), capture master-facing, run interleaved READ+SBO.
set -u
SESS="$1"; BID="$2"; COND="$3"; NREAD="$4"; NSBO="$5"; SEED="$6"
PW="$(. ~/.lab_env 2>/dev/null; printf %s "$SSHPASS")"
SW="ssh -o BatchMode=yes -o ConnectTimeout=10 decps@10.10.54.81"
VI="ssh -o BatchMode=yes -o ConnectTimeout=10 decps@10.10.54.166"
ENV='SDE_INSTALL=/home/decps/Downloads/bf-sde-9.13.2/install PYTHONPATH=/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages/tofino:/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages'
CTL2=/home/decps/rrc_bor_build_v2/control
CTL1=/home/decps/rrc_bor_build/control
OUT=/tmp/${SESS}
if [ "$COND" = "OFF" ]; then CONDNAME=native; J=""; ARGS="--mode OFF --read-len 0"
else CONDNAME=obfuscated; J="2,6,12"; ARGS="--mode D4 --read-len 0 --d-a-ms 20 --d-r-ms 4 --op-a-ms 20 --op-r-ms 24 --j-set '2 6 12'"; fi
TAG="${SESS}_${BID}_${CONDNAME}"
echo "### block $BID cond=$COND($CONDNAME) n_read=$NREAD n_sbo=$NSBO seed=$SEED  $(date -u +%FT%TZ)"
# 1. configure (readback in the tail line) + force shape=0
echo -n "  cfg: "; timeout 200 $SW "cd $CTL2 && $ENV DEFENSE4_HW_AUTHORIZED=1 D4_CASEA_SETUP=/home/decps/d4_build/control/defense4_caseA_setup.py python3 defense4_rrc_bor_unified12_setup.py configure-all $ARGS 2>&1 | tail -1"
echo -n "  shape0: "; timeout 90 $SW "cd $CTL1 && $ENV python3 shape_set.py 0 2>/dev/null | grep -E 'RESULT'"
# 2. capture + interleaved driver on Vision
timeout 260 $VI "echo '$PW' | sudo -S -p '' true 2>/dev/null
  mkdir -p $OUT; sudo -n rm -f $OUT/${TAG}.pcap
  sudo -n nohup timeout 200 tcpdump -i enp59s0f0np0 -s0 -w $OUT/${TAG}.pcap 'host 192.168.10.7 and tcp' >/dev/null 2>&1 &
  sleep 4; date -u +'  cap_start %FT%TZ'
  cd /home/decps/native_parity && python3 campaign_run.py --session $SESS --block $BID --condition $CONDNAME --mode $COND --j-ms '${J}' --n-read $NREAD --n-sbo $NSBO --min-gap 6 --gap-ms 20 --seed $SEED --out $OUT/${TAG}.jsonl 2>&1 | tail -1
  date -u +'  cap_end   %FT%TZ'
  sleep 3; sudo -n pkill -f 'tcpdump -i enp59s0f0np0'; sleep 1; sudo -n chmod 644 $OUT/${TAG}.pcap
  echo -n '  pcap_bytes='; stat -c%s $OUT/${TAG}.pcap"

#!/usr/bin/env bash
# sweep_block.sh <tag> <mode OFF|D2|D3|D4> <D_A ms> <D_R ms> <n_read> <n_sbo> <seed>
# One parameter point: configure, force shape=0, capture master-facing, run interleaved driver.
set -u
TAG="$1"; MODE="$2"; DA="$3"; DR="$4"; NREAD="$5"; NSBO="$6"; SEED="$7"
PW="$(. ~/.lab_env 2>/dev/null; printf %s "$SSHPASS")"
SW="ssh -o BatchMode=yes -o ConnectTimeout=10 decps@10.10.54.81"
VI="ssh -o BatchMode=yes -o ConnectTimeout=10 decps@10.10.54.166"
ENV='SDE_INSTALL=/home/decps/Downloads/bf-sde-9.13.2/install PYTHONPATH=/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages/tofino:/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages'
CTL2=/home/decps/rrc_bor_build_v2/control; CTL1=/home/decps/rrc_bor_build/control
OUT=/tmp/sweep
if [ "$MODE" = "OFF" ]; then ARGS="--mode OFF --read-len 0"; COND=native
else ARGS="--mode $MODE --read-len 0 --d-a-ms $DA --d-r-ms $DR --op-a-ms 20 --op-r-ms 24 --j-set '2 6 12'"; COND=obfuscated; fi
printf "%-22s mode=%-3s D_A=%-3s D_R=%-3s " "$TAG" "$MODE" "$DA" "$DR"
CFG=$(timeout 200 $SW "cd $CTL2 && $ENV DEFENSE4_HW_AUTHORIZED=1 D4_CASEA_SETUP=/home/decps/d4_build/control/defense4_caseA_setup.py python3 defense4_rrc_bor_unified12_setup.py configure-all $ARGS 2>&1 | tail -1")
printf "cfg=%s " "$(echo "$CFG" | grep -o 'PASS\|FAIL' | head -1)"
timeout 90 $SW "cd $CTL1 && $ENV python3 shape_set.py 0 >/dev/null 2>&1"
timeout 200 $VI "echo '$PW' | sudo -S -p '' true 2>/dev/null
  mkdir -p $OUT; sudo -n rm -f $OUT/${TAG}.pcap
  sudo -n nohup timeout 150 tcpdump -i enp59s0f0np0 -s0 -w $OUT/${TAG}.pcap 'host 192.168.10.7 and tcp' >/dev/null 2>&1 &
  sleep 3
  cd /home/decps/native_parity && python3 campaign_run.py --session sweep --block $TAG --condition $COND --mode $MODE --j-ms '2,6,12' --n-read $NREAD --n-sbo $NSBO --min-gap 5 --gap-ms 20 --seed $SEED --out $OUT/${TAG}.jsonl 2>&1 | tail -1
  sleep 2; sudo -n pkill -f 'tcpdump -i enp59s0f0np0'; sleep 1; sudo -n chmod 644 $OUT/${TAG}.pcap"

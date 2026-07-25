#!/bin/bash
# §5 campaign runner for dnp3_timing_normalizer — review-hardened (W1/W2 + C1-C4 + fail_open gate).
set -u; source ~/.lab_env
SSHO="-o ConnectTimeout=15 -o StrictHostKeyChecking=no -o LogLevel=ERROR"
SW=decps@10.10.54.81; HULK=decps@10.10.54.158; VIS=decps@10.10.54.19
E='export SDE=/home/decps/Downloads/bf-sde-9.13.2; export SDE_INSTALL=$SDE/install; export LD_LIBRARY_PATH=$SDE_INSTALL/lib:$LD_LIBRARY_PATH; export PYTHONPATH=$(echo $SDE_INSTALL/lib/python*/site-packages):$(echo $SDE_INSTALL/lib/python*/site-packages/tofino):$PYTHONPATH'
REGS=reg_tag,reg_deadline,reg_native_clrt,reg_protection
CTRS=ctr_arm,ctr_ack_arm,ctr_ack_bypass,ctr_resp_enq,ctr_resp_release,ctr_block_enq,ctr_block_term_deadline,ctr_block_term_timeout,ctr_block_term_stale,ctr_response_actually_held,ctr_response_zero_hold,ctr_release_deadline,ctr_release_fail_open
OUT=/home/philip/Projects/DNP3/research/timing_final/evidence/protected
N=${N:-30}; G_MS=${G_MS:-25}; K=${K:-64}; BUDGET=${BUDGET:-2000000}; RUNID=${RUNID:-g$G_MS}
mkdir -p $OUT
G_TICKS=$(python3 -c "print(($G_MS*1000000//256)*256)")
rm -f $OUT/$RUNID.pcap $OUT/$RUNID.read.json    # W1: clear stale artifacts
sshpass -e ssh $SSHO $SW "bash -lc '$E; cd ~/timing_final && python3 p13_guard.py --prog dnp3_timing_normalizer --param g_ticks --set-g-ms $(python3 -c "print($G_TICKS/1e6)") 2>&1 | grep -o \"verified..: [a-z]*\"'"
sshpass -e ssh $SSHO $SW "bash -lc '$E; cd ~/part11 && python3 ibspg_paired_setup.py --prog dnp3_timing_normalizer --reset --regs $REGS --counters $CTRS >/dev/null 2>&1'"
sshpass -e ssh $SSHO $VIS "echo '$SSHPASS' | sudo -S -p '' bash -c 'rm -f /tmp/$RUNID.pcap; nohup tcpdump -i enp59s0f0np0 -Q in -s 0 -w /tmp/$RUNID.pcap \"tcp port 20000 or ether proto 0x88c1\" >/dev/null 2>&1 & true'" >/dev/null 2>&1
sleep 1.2
FAIL=0
for i in $(seq 0 $((N-1))); do
  g=$(python3 /tmp/gen_of2.py $((i % 30)))
  sshpass -e ssh $SSHO $VIS "echo '$SSHPASS' | sudo -S -p '' python3 /tmp/live_inject.py vision enp59s0f0np0 $((i%30)) $((i%30+1))" >/dev/null 2>&1 || FAIL=1   # W2
  sshpass -e ssh $SSHO $HULK "echo '$SSHPASS' | sudo -S -p '' python3 /tmp/relaytok.py $g $K $BUDGET enp59s0f0np0" >/dev/null 2>&1 || FAIL=1
  sshpass -e ssh $SSHO $HULK "echo '$SSHPASS' | sudo -S -p '' python3 /tmp/live_inject.py hulk enp59s0f0np0 $((i%30)) $((i%30+1))" >/dev/null 2>&1 || FAIL=1
  sleep 0.45
done
sleep 1.5
sshpass -e ssh $SSHO $VIS "echo '$SSHPASS' | sudo -S -p '' bash -c 'pkill tcpdump; sleep 0.4'" >/dev/null 2>&1
sshpass -e scp $SSHO $VIS:/tmp/$RUNID.pcap $OUT/$RUNID.pcap >/dev/null 2>&1 || { echo "RESULT $RUNID SCP_FAIL"; exit 1; }   # W1
sshpass -e ssh $SSHO $SW "bash -lc '$E; cd ~/timing_final && python3 ~/part13/ibspg_p12_read.py --prog dnp3_timing_normalizer --g-ns $G_TICKS --regs $REGS --counters $CTRS 2>/dev/null | grep P12READ'" > $OUT/$RUNID.read.json
echo "DONE $RUNID N=$N G=$G_MS injector_fail=$FAIL"

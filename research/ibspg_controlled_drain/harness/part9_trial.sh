#!/bin/bash
# part9_trial.sh — run ONE controlled-drain trial and print a machine-readable result line.
# Coordinates switch (10.10.54.81), Hulk (dp11 ingress, 10.10.54.158), Vision (dp9 egress capture,
# 10.10.54.19). Reset -> Vision capture -> ARM -> K blockers -> H HELD -> hold -> drain -> read
# counters+ts -> verify byte-identity/FIFO on the Vision pcap. Injected frames are reconstructed.
#
# Env in: K H HOLD_MS DRAIN(match|unrel|stale|none) BUDGET GEN IDSTART PAD RUNID
# Prints: RESULT k=.. h=.. drain=.. enq=.. rel=.. ctrl=.. stale=.. tmo=.. dm=.. ru=.. rs=.. \
#         verify=PASS|FAIL drain_reco_ns=.. e2e_ns=.. burst_ns=..
set -u
source ~/.lab_env 2>/dev/null
SSHO="-o ConnectTimeout=15 -o StrictHostKeyChecking=no -o LogLevel=ERROR"
SW=decps@10.10.54.81; HULK=decps@10.10.54.158; VIS=decps@10.10.54.19
HIF=enp59s0f0np0; VIF=enp59s0f0np0; VMAC=3cfdfecc5dc0; SNEUTRAL=02000000000a
E='export SDE=/home/decps/Downloads/bf-sde-9.13.2; export SDE_INSTALL=$SDE/install; export PATH=$SDE_INSTALL/bin:$PATH; export LD_LIBRARY_PATH=$SDE_INSTALL/lib:$LD_LIBRARY_PATH; export PYTHONPATH=$(echo $SDE_INSTALL/lib/python*/site-packages):$(echo $SDE_INSTALL/lib/python*/site-packages/tofino):$PYTHONPATH; cd ~/part9'
V=/home/philip/Projects/DNP3/research/ibspg_controlled_drain/harness/ibspg_part9_verify.py
SCR=/tmp/claude-1002/-home-philip-Projects-DNP3/256681ec-f9c4-46e4-af3a-68b726da95b2/scratchpad

K=${K:-64}; H=${H:-32}; HOLD_MS=${HOLD_MS:-800}; DRAIN=${DRAIN:-match}; BUDGET=${BUDGET:-200000000}
GEN=${GEN:-7}; IDSTART=${IDSTART:-1}; PAD=${PAD:-60}; RUNID=${RUNID:-trial}
REGS="reg_active,reg_gen,reg_drain_req,reg_ts_first_hold_admit,reg_ts_drain_match,reg_ts_block_term,reg_ts_first_release,reg_ts_last_release"
CTRS="ctr_hold_enq,ctr_hold_release,ctr_block_term_controlled,ctr_block_term_stale,ctr_block_term_timeout,ctr_drain_match,ctr_drain_reject_unrelated,ctr_drain_reject_stale"
gen() { sshpass -e ssh $SSHO $HULK "echo '$SSHPASS' | sudo -S -p '' python3 ~/ibspg_part9_gen.py --iface $HIF $* >/dev/null 2>&1"; }

sshpass -e ssh $SSHO $SW "bash -lc '$E; python3 ibspg_part9_setup.py --prog ibspg_controlled_drain --reset --regs $REGS --counters $CTRS >/dev/null 2>&1'" >/dev/null 2>&1
sshpass -e ssh $SSHO $VIS "echo '$SSHPASS' | sudo -S -p '' bash -c 'rm -f /tmp/rel.pcap; nohup tcpdump -i $VIF -Q in -w /tmp/rel.pcap -s 256 \"ether proto 0x88c0\" >/dev/null 2>&1 & true'" >/dev/null 2>&1
sleep 1.2
[ "$K" -gt 0 ] && { gen --role arm --slot 0 --gen $GEN; gen --role blocker --slot 0 --gen $GEN --count $K --budget $BUDGET; }
gen --role held --slot 0 --gen $GEN --count $H --id-start $IDSTART --dst-mac $VMAC --src-mac $SNEUTRAL --pad-to $PAD
python3 -c "import time; time.sleep($HOLD_MS/1000.0)"
case "$DRAIN" in
  match) gen --role drain-match --slot 0 --gen $GEN ;;
  unrel) gen --role drain-unrel --slot 9 --gen $GEN ;;
  stale) gen --role drain-match --slot 0 --gen $((GEN-1)) ;;
  none)  : ;;   # budget-expiry regression: wait for timeout
esac
sleep 1.0
sshpass -e ssh $SSHO $VIS "echo '$SSHPASS' | sudo -S -p '' pkill tcpdump 2>/dev/null; sleep 0.4" >/dev/null 2>&1
J=$(sshpass -e ssh $SSHO $SW "bash -lc '$E; python3 ibspg_part9_read.py --prog ibspg_controlled_drain --regs reg_ts_drain_match,reg_ts_block_term,reg_ts_first_release,reg_ts_last_release --counters $CTRS 2>&1 | grep PART9READ'" 2>&1 | sed 's/^PART9READ //')
sshpass -e scp $SSHO $VIS:/tmp/rel.pcap $SCR/${RUNID}.pcap >/dev/null 2>&1
VZ=$($RESEARCH_PYTHON $V --held-spec "$H:$IDSTART:$GEN:0:$VMAC:$SNEUTRAL:$PAD" --released $SCR/${RUNID}.pcap --expect $H 2>/dev/null | grep -oE '(PASS|FAIL)' | head -1)
echo "$J" | $RESEARCH_PYTHON -c "
import sys,json
d=json.loads(sys.stdin.read()); c=d['counters']; r=d['registers']
def gi(x):
    v=r.get(x) or 0; return v if isinstance(v,int) else 0
tdm,tbt,tfr,tlr=gi('reg_ts_drain_match'),gi('reg_ts_block_term'),gi('reg_ts_first_release'),gi('reg_ts_last_release')
print('RESULT k=$K h=$H drain=$DRAIN enq=%s rel=%s ctrl=%s stale=%s tmo=%s dm=%s ru=%s rs=%s verify=$VZ drain_reco_ns=%d e2e_ns=%d burst_ns=%d'%(
 c.get('ctr_hold_enq'),c.get('ctr_hold_release'),c.get('ctr_block_term_controlled'),c.get('ctr_block_term_stale'),
 c.get('ctr_block_term_timeout'),c.get('ctr_drain_match'),c.get('ctr_drain_reject_unrelated'),c.get('ctr_drain_reject_stale'),
 (tbt-tdm) if tdm and tbt else 0,(tfr-tdm) if tdm and tfr else 0,(tlr-tfr) if tfr and tlr else 0))
"

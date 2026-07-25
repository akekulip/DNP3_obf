#!/bin/bash
# part11_trial.sh — one paired ACK-before-response trial. Prints a machine-readable RESULT line.
# reset -> Vision capture -> ARM -> K blockers -> inject ACK+RESP (order per INJORDER) -> hold -> drain
# -> read counters+ts -> verify per-role byte-id/FIFO + ACK-before-RESPONSE (host PCAP order + on-chip ts).
#
# Env: K NACK NRESP HOLD_MS DRAIN(match|unrel|stale|none) BUDGET GEN INJORDER(ack-first|resp-first) PAD RUNID
# Prints: RESULT k=.. nack=.. nresp=.. drain=.. aenq=.. arel=.. renq=.. rrel=.. ctrl=.. tmo=.. dm=.. \
#         ru=.. rs=.. order_ts=OK|BAD verify=PASS|FAIL abr=true|false lastack_ns=.. firstresp_ns=.. gap_ns=..
set -u
source ~/.lab_env 2>/dev/null
SSHO="-o ConnectTimeout=15 -o StrictHostKeyChecking=no -o LogLevel=ERROR"
SW=decps@10.10.54.81; HULK=decps@10.10.54.158; VIS=decps@10.10.54.19
HIF=enp59s0f0np0; VIF=enp59s0f0np0; VMAC=3cfdfecc5dc0; SNEUTRAL=02000000000a
E='export SDE=/home/decps/Downloads/bf-sde-9.13.2; export SDE_INSTALL=$SDE/install; export PATH=$SDE_INSTALL/bin:$PATH; export LD_LIBRARY_PATH=$SDE_INSTALL/lib:$LD_LIBRARY_PATH; export PYTHONPATH=$(echo $SDE_INSTALL/lib/python*/site-packages):$(echo $SDE_INSTALL/lib/python*/site-packages/tofino):$PYTHONPATH; cd ~/part11'
V=/home/philip/Projects/DNP3/research/ibspg_paired/harness/ibspg_paired_verify.py
SCR=/tmp/claude-1002/-home-philip-Projects-DNP3/256681ec-f9c4-46e4-af3a-68b726da95b2/scratchpad

K=${K:-64}; NACK=${NACK:-1}; NRESP=${NRESP:-1}; HOLD_MS=${HOLD_MS:-700}; DRAIN=${DRAIN:-match}
BUDGET=${BUDGET:-200000000}; GEN=${GEN:-7}; INJORDER=${INJORDER:-ack-first}; PAD=${PAD:-60}; RUNID=${RUNID:-p11}
REGS="reg_active,reg_gen,reg_drain_req,reg_ts_drain_match,reg_ts_block_term,reg_ts_first_ack_release,reg_ts_last_ack_release,reg_ts_first_resp_release"
CTRS="ctr_ack_enq,ctr_ack_release,ctr_resp_enq,ctr_resp_release,ctr_block_term_controlled,ctr_block_term_timeout,ctr_block_term_stale,ctr_drain_match,ctr_drain_reject_unrelated,ctr_drain_reject_stale"
gen() { sshpass -e ssh $SSHO $HULK "echo '$SSHPASS' | sudo -S -p '' python3 ~/ibspg_paired_gen.py --iface $HIF $* >/dev/null 2>&1"; }

sshpass -e ssh $SSHO $SW "bash -lc '$E; python3 ibspg_paired_setup.py --prog ibspg_paired --reset --regs $REGS --counters $CTRS >/dev/null 2>&1'" >/dev/null 2>&1
sshpass -e ssh $SSHO $VIS "echo '$SSHPASS' | sudo -S -p '' bash -c 'rm -f /tmp/rel.pcap; nohup tcpdump -i $VIF -Q in -w /tmp/rel.pcap -s 256 \"ether proto 0x88c0\" >/dev/null 2>&1 & true'" >/dev/null 2>&1
sleep 1.2
[ "$K" -gt 0 ] && { gen --role arm --slot 0 --gen $GEN; gen --role blocker --slot 0 --gen $GEN --count $K --budget $BUDGET; }
# inject the two held roles (order controls whether ordering is FIFO-natural or structural-against-arrival)
if [ "$INJORDER" = "resp-first" ]; then
  gen --role resp --slot 0 --gen $GEN --count $NRESP --id-start 1 --dst-mac $VMAC --src-mac $SNEUTRAL --pad-to $PAD
  gen --role ack  --slot 0 --gen $GEN --count $NACK  --id-start 1 --dst-mac $VMAC --src-mac $SNEUTRAL --pad-to $PAD
else
  gen --role ack  --slot 0 --gen $GEN --count $NACK  --id-start 1 --dst-mac $VMAC --src-mac $SNEUTRAL --pad-to $PAD
  gen --role resp --slot 0 --gen $GEN --count $NRESP --id-start 1 --dst-mac $VMAC --src-mac $SNEUTRAL --pad-to $PAD
fi
python3 -c "import time; time.sleep($HOLD_MS/1000.0)"
case "$DRAIN" in
  match) gen --role drain-match --slot 0 --gen $GEN ;;
  unrel) gen --role drain-unrel --slot 9 --gen $GEN ;;
  stale) gen --role drain-match --slot 0 --gen $((GEN-1)) ;;
  none)  : ;;
esac
sleep 1.0
sshpass -e ssh $SSHO $VIS "echo '$SSHPASS' | sudo -S -p '' pkill tcpdump 2>/dev/null; sleep 0.4" >/dev/null 2>&1
J=$(sshpass -e ssh $SSHO $SW "bash -lc '$E; python3 ibspg_paired_read.py --prog ibspg_paired --regs $REGS --counters $CTRS 2>&1 | grep PART9READ'" 2>&1 | sed 's/^PART9READ //')
sshpass -e scp $SSHO $VIS:/tmp/rel.pcap $SCR/${RUNID}.pcap >/dev/null 2>&1
VZ=$($RESEARCH_PYTHON $V --paired-spec "$NACK:$NRESP:1:1:$GEN:0:$VMAC:$SNEUTRAL:$PAD" --released $SCR/${RUNID}.pcap 2>/dev/null)
verify=$(echo "$VZ" | grep -oE '"verdict": "[A-Z]+"' | grep -oE '(PASS|FAIL)' | head -1)
abr=$(echo "$VZ" | grep -oE '"ack_before_resp": (true|false)' | grep -oE '(true|false)' | head -1)
echo "$J" | $RESEARCH_PYTHON -c "
import sys,json
d=json.loads(sys.stdin.read()); c=d['counters']; r=d['registers']
def gi(x):
    v=r.get(x) or 0; return v if isinstance(v,int) else 0
la=gi('reg_ts_last_ack_release'); fr=gi('reg_ts_first_resp_release')
order = 'OK' if (la and fr and la < fr) else ('OK' if (la and not fr) else 'BAD')
print('RESULT k=$K nack=$NACK nresp=$NRESP drain=$DRAIN inj=$INJORDER aenq=%s arel=%s renq=%s rrel=%s ctrl=%s tmo=%s dm=%s ru=%s rs=%s order_ts=%s verify=$verify abr=$abr lastack_ns=%d firstresp_ns=%d gap_ns=%d'%(
 c.get('ctr_ack_enq'),c.get('ctr_ack_release'),c.get('ctr_resp_enq'),c.get('ctr_resp_release'),
 c.get('ctr_block_term_controlled'),c.get('ctr_block_term_timeout'),c.get('ctr_drain_match'),
 c.get('ctr_drain_reject_unrelated'),c.get('ctr_drain_reject_stale'),order,la,fr,(fr-la) if (la and fr) else 0))
"

#!/bin/bash
# burst_sweep.sh — isolated burst-credit sweep (run from gambit). AUTHORIZED SCOPE ONLY:
# burst B in {256,512,1024,2048,4096,8192,16384} x target T in {5,10,17,25,40 ms}, rate=100000,
# samples>=100, concurrency=1, bg=0, cover=OFF, metronome=OFF, telemetry=ON. Per (B,T): calibration
# search -> freeze hold_passes -> >=100-packet measurement. Switch-side digest = hold; Hulk hairpin
# = count/seq only. Writes per-run manifests + a JSONL results row per point. Does NOT touch rate/
# concurrency/bg/physical. STOPS after the sweep.
set -u
source ~/.lab_env
SW=decps@10.10.54.15; HULK=decps@10.10.54.158
H=/home/decps/queue_microbench/harness
REPO=/home/philip/Projects/DNP3
OUT="$REPO/research/tofino_dcrn_feasibility/p4/queue_microbench/runs/burst_sweep"
mkdir -p "$OUT"
COMMIT=$(git -C "$REPO" rev-parse --short HEAD)
P4SHA=$(sha256sum "$REPO/research/tofino_dcrn_feasibility/p4/queue_microbench/queue_microbench.p4" | cut -c1-12)
RATE=100000; SAMPLES=110; SPACING=200
RESULTS="$OUT/results.jsonl"; : > "$RESULTS"
CID=1000; RUNID=100
SSHO="-o ConnectTimeout=12"

set_te1() { ssh $SSHO "$SW" 'cd /home/decps/queue_microbench && python3.8 - 2>/dev/null <<PY
import sys
SDE="/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"
sys.path.insert(0,SDE+"/tofino"); sys.path.insert(0,SDE)
import bfrt_grpc.client as gc
i=gc.ClientInterface("localhost:50052",client_id=41,device_id=0,notifications=None)
i.bind_pipeline_config("queue_microbench"); bi=i.bfrt_info_get("queue_microbench"); t=gc.Target(device_id=0,pipe_id=0xffff)
r=bi.table_get("pipe.Ingress.telemetry_enable"); r.entry_mod(t,[r.make_key([gc.KeyTuple("$REGISTER_INDEX",0)])],[r.make_data([gc.DataTuple("Ingress.telemetry_enable.f1",1)])])
PY'; }

setcfg() { ssh $SSHO "$SW" "cd /home/decps/queue_microbench && python3.8 harness/hold_probe.py --hold-passes $1 --burst $2 --rate $RATE >/dev/null 2>&1"; }

gen() { sshpass -e ssh $SSHO "$HULK" "sudo -S -p '' python3 $H/mb_gen_raw.py --iface enp59s0f0np0 --dports 20001 --count $1 --interval-ms $2 >/dev/null 2>&1" <<< "$SSHPASS" >/dev/null 2>&1; }

# single-frame switch-side hold (ms) for calibration
hold1() {
  setcfg "$1" "$2"; gen 1 10; sleep 1; CID=$((CID+1))
  local ns=$(ssh $SSHO "$SW" "python3.8 $H/last_hold.py $CID 2>/dev/null")
  python3 -c "print('%.3f'%(${ns:-0}/1e6))"
}

# calibrate (B,T) -> frozen hold_passes (Newton on last_hold_reg; <=5 iters; tol ~1ms/4%)
calib() {
  local B=$1 T=$2
  local hp=$(python3 -c "B=$B;T=$T;pb=B*0.617/1000.0
print(max(1,min(65535, int(round(T*1000/0.617)) if T<=pb else int(round(B+(T-pb)/0.01)))))")
  local hold=0
  for it in 1 2 3 4 5; do
    hold=$(hold1 $hp $B)
    local done=$(python3 -c "print(1 if abs($hold-$T)<=max(0.8,0.04*$T) else 0)")
    [ "$done" = 1 ] && break
    hp=$(python3 -c "B=$B;hp=$hp;h=$hold;T=$T
slope=0.617 if hp<=B else 10.0
print(max(1,min(65535,int(round(hp+(T-h)*1000.0/slope)))))")
  done
  echo "$hp $hold"
}

measure() {
  local B=$1 T=$2 hp=$3 rid=$4
  setcfg $B $hp
  # manifest (TM readback via hold_probe already set; record config)
  local tm=$(ssh $SSHO "$SW" "cd /home/decps/queue_microbench && python3.8 harness/hold_probe.py --hold-passes $hp --burst $B --rate $RATE 2>&1 | grep sched_shaping")
  cat > "$OUT/manifest_run${rid}.json" <<M
{"run_id":$rid,"commit":"$COMMIT","p4_sha":"$P4SHA","burst":$B,"rate":$RATE,"target_ms":$T,
 "hold_passes":$hp,"samples":$SAMPLES,"background_load":0,"concurrency":1,"cover":"off","metronome":"off",
 "telemetry":"on","tm_readback":"$tm"}
M
  # baseline counters (recirc, failopen) + queue
  local base=$(ssh $SSHO "$SW" "cd /home/decps/queue_microbench && python3.8 harness/mb_read.py x 2>/dev/null | grep MBREAD")
  # collector + Hulk capture
  ssh $SSHO "$SW" "nohup python3.8 $H/mb_digest_collector.py --run-id $rid --out /tmp/sw_$rid.jsonl --seconds 34 --expect $SAMPLES >/tmp/coll_$rid.log 2>&1 </dev/null & echo ok" >/dev/null
  sleep 4
  sshpass -e ssh $SSHO "$HULK" "sudo -S -p '' bash -c '
    timeout 30 tcpdump -i enp59s0f0np0 -Q in -w /tmp/rx_$rid.pcap -s0 udp 2>/dev/null & TP=\$!
    sleep 1; python3 $H/mb_gen_raw.py --iface enp59s0f0np0 --dports 20001 --count $SAMPLES --interval-ms $SPACING >/dev/null 2>&1
    wait \$TP'" <<< "$SSHPASS" >/dev/null 2>&1
  scp $SSHO "$HULK":/tmp/rx_$rid.pcap "$OUT/rx_$rid.pcap" >/dev/null 2>&1
  sleep 8
  local coll=$(ssh $SSHO "$SW" "tail -1 /tmp/coll_$rid.log")
  scp $SSHO "$SW":/tmp/sw_$rid.jsonl "$OUT/sw_$rid.jsonl" >/dev/null 2>&1
  local after=$(ssh $SSHO "$SW" "cd /home/decps/queue_microbench && python3.8 harness/mb_read.py x 2>/dev/null | grep MBREAD")
  # analyze in python: digest holds + Hulk count + counter deltas + queue
  "$RESEARCH_PYTHON" - "$OUT/sw_$rid.jsonl" "$OUT/rx_$rid.pcap" "$B" "$T" "$hp" "$rid" "$coll" "$base" "$after" >> "$RESULTS" <<'PY'
import sys,json,statistics as st,re
from scapy.all import PcapReader
jf,pf,B,T,hp,rid,coll,base,after=sys.argv[1],sys.argv[2],int(sys.argv[3]),float(sys.argv[4]),int(sys.argv[5]),int(sys.argv[6]),sys.argv[7],sys.argv[8],sys.argv[9]
recs=[json.loads(l) for l in open(jf)]
ms=sorted(r["hold_ns"]/1e6 for r in recs); pc=sorted(set(r["pass_count"] for r in recs))
def pct(x,p):
    if not x: return None
    k=(len(x)-1)*p/100.0; lo=int(k); hi=min(lo+1,len(x)-1); return round(x[lo]+(x[hi]-x[lo])*(k-lo),4)
seqs=[]
for pkt in PcapReader(pf):
    raw=bytes(pkt)
    if len(raw)>64:
        i=raw.find(b"MBQ1")
        if i>=0: seqs.append(int.from_bytes(raw[i+4:i+8],"big"))
def g(s,k):
    m=re.search(r"'%s': (\d+)"%k,s); return int(m.group(1)) if m else None
d_recirc=(g(after,"ctr_recirc")or 0)-(g(base,"ctr_recirc")or 0)
d_fail=(g(after,"ctr_failopen")or 0)-(g(base,"ctr_failopen")or 0)
qm=re.search(r"q_HOLD.*?use.: (\S+?),.*?wm.: (\S+?),.*?drop.: (\S+?)}",after)  # may be absent
# HOLD queue is dp68; mb_read reads dp9 queues -> read q_REAL_S1 (release queue) instead
qr=re.search(r"'q_REAL_S1': {'use': (\d+), 'wm': (\d+), 'drop': (\d+)}",after)
qu=qr.groups() if qr else ("na","na","na")
cj=json.loads(coll) if coll.strip().startswith("{") else {}
med=pct(ms,50)
row={"run_id":rid,"burst":B,"target_ms":T,"hold_passes":hp,
     "n_digest":len(ms),"median_ms":med,"p95_ms":pct(ms,95),"p99_ms":pct(ms,99),
     "mean_ms":round(st.mean(ms),4) if ms else None,"std_ms":round(st.pstdev(ms),4) if len(ms)>1 else 0,
     "min_ms":round(min(ms),4) if ms else None,"max_ms":round(max(ms),4) if ms else None,
     "abs_target_err_ms":round(abs(med-T),4) if med is not None else None,
     "pass_counts":pc,"internal_recirc_delta":d_recirc,"failopen_delta":d_fail,
     "real_q_use":qu[0],"real_q_wm":qu[1],"real_q_drop":qu[2],
     "digest_valid":cj.get("VALID"),"digest_records":cj.get("records"),
     "ctr_grad_delta":cj.get("ctr_grad_delta"),"ctr_digest_emit_delta":cj.get("ctr_digest_emit_delta"),
     "rx_count":len(seqs),"rx_unique":len(set(seqs)),"rx_dup":len(seqs)-len(set(seqs)),
     "rx_missing":(max(seqs)-min(seqs)+1-len(set(seqs))) if seqs else -1,
     "loss":(len(recs)-len(set(seqs)))}
print(json.dumps(row))
PY
  echo "[$(date +%H:%M:%S)] done B=$B T=$T hp=$hp $coll" >> "$OUT/progress.log"
}

echo "=== burst sweep start $(date) commit=$COMMIT p4=$P4SHA ===" > "$OUT/progress.log"
set_te1
for B in 256 512 1024 2048 4096 8192 16384; do
  for T in 5 10 17 25 40; do
    read HP HOLD <<< "$(calib $B $T)"
    RUNID=$((RUNID+1))
    echo "[$(date +%H:%M:%S)] calib B=$B T=$T -> hp=$HP (single-frame ${HOLD}ms) run=$RUNID" >> "$OUT/progress.log"
    measure $B $T $HP $RUNID
  done
done
# leave switch clean: telemetry off
ssh $SSHO "$SW" 'cd /home/decps/queue_microbench && python3.8 - 2>/dev/null <<PY
import sys
SDE="/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"
sys.path.insert(0,SDE+"/tofino"); sys.path.insert(0,SDE)
import bfrt_grpc.client as gc
i=gc.ClientInterface("localhost:50052",client_id=42,device_id=0,notifications=None)
i.bind_pipeline_config("queue_microbench"); bi=i.bfrt_info_get("queue_microbench"); t=gc.Target(device_id=0,pipe_id=0xffff)
r=bi.table_get("pipe.Ingress.telemetry_enable"); r.entry_mod(t,[r.make_key([gc.KeyTuple("$REGISTER_INDEX",0)])],[r.make_data([gc.DataTuple("Ingress.telemetry_enable.f1",0)])])
PY'
echo "=== burst sweep DONE $(date) ===" >> "$OUT/progress.log"

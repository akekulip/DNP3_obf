#!/bin/bash
# D-SWEEP CAMPAIGN, blocked within session.
# Arms are INTERLEAVED round by round rather than run one after another, because
# session-to-session drift on this relay exceeds the effect (CONSENSUS §9: C1/C2/C3
# native-vs-native AUROC to 0.985). D = 1 ms is a PRE-REGISTERED NULL CONTROL.
SW="ssh -o BatchMode=yes -o ConnectTimeout=10 decps@10.10.54.81"
VI="ssh -o BatchMode=yes -o ConnectTimeout=10 decps@10.10.54.19"
SWENV='cd /home/decps/d3 && export SDE=/home/decps/Downloads/bf-sde-9.13.2; export SDE_INSTALL=$SDE/install; export LD_LIBRARY_PATH=$SDE_INSTALL/lib:${LD_LIBRARY_PATH:-}; export PYTHONPATH=$SDE_INSTALL/lib/python3.8/site-packages/tofino:$SDE_INSTALL/lib/python3.8/site-packages:$PYTHONPATH;'
OUT="$1"; ROUNDS="${2:-4}"; NPOLL="${3:-20}"; GAP="${4:-0.2}"
: > "$OUT"
CID=40
for r in $(seq 1 "$ROUNDS"); do
  for arm in "native:2:0" "d1:1:1" "d2:2:1" "d4:4:1" "d8:8:1" "d16:16:1"; do
    NAME=${arm%%:*}; REST=${arm#*:}; DMS=${REST%%:*}; ARMV=${REST#*:}
    LBL="r${r}_${NAME}"
    CID=$((CID+1))
    SA=$(timeout 120 $SW "$SWENV python3 setarm.py $DMS $ARMV $CID" 2>&1 | grep -o 'SETARM .*' | head -1)
    BK=$(timeout 300 $VI "cd ~/d3phys && python3 block.py $LBL $NPOLL $GAP" 2>&1 | grep -o 'BLOCK .*' | head -1)
    ST=$(timeout 120 $SW "$SWENV python3 - <<'EOF' 2>/dev/null | grep -o 'CTR .*'
import json,sys; sys.path.insert(0,'/home/decps/d3')
import bfrt_grpc.client as gc
i=gc.ClientInterface('localhost:50052',client_id=$((CID+500)),device_id=0,notifications=None)
i.bind_pipeline_config('case_a_defense3_fixed_ack_delay')
b=i.bfrt_info_get('case_a_defense3_fixed_ack_delay'); t=gc.Target(device_id=0,pipe_id=0xffff)
CF={'ARM_FRESH':2,'ARM_DUP':3,'ARM_BUSY':4,'ACK_HOLD':5,'ACK_DUP_HOLD':6,'ACK_REJECT':7,
    'RESP_HOLD_EARLY':8,'RESP_HOLD_LATE':9,'RESP_BYPASS':10,'PKTGEN_ADMIT':13,
    'PKTGEN_DROP':14,'RESP_DUP_SUPP':16}
CD={'BLOCK_TERM_STALE':1,'BLOCK_TERM_DL':2,'BLOCK_TERM_TMO':3,'RELEASE_DEADLINE':4,
    'RELEASE_FAILOPEN':5,'ACK_RELEASE':6,'ACK_REL_RETIRE':7}
def c(n,s):
    tb=b.table_get(n); o={}
    for k,ix in s.items():
        v=0
        for d,_ in tb.entry_get(t,[tb.make_key([gc.KeyTuple('\$COUNTER_INDEX',ix)])],{'from_hw':True}):
            x=d.to_dict().get('\$COUNTER_SPEC_PKTS',0); v=max(v,x if isinstance(x,int) else 0)
        o[k]=v
    return o
q={}
tb=b.table_get('tf1.tm.counter.queue')
for qq in (1,7):
    for d,_ in tb.entry_get(gc.Target(device_id=0,pipe_id=0),[tb.make_key([gc.KeyTuple('pg_id',2),gc.KeyTuple('pg_queue',qq)])],{'from_hw':True}):
        q['qid%d'%qq]=d.to_dict().get('drop_count_packets')
print('CTR '+json.dumps({'fresh':c('ctr_fresh',CF),'deq':c('ctr_deq',CD),'qdrops':q}))
EOF" 2>&1 | head -1)
    python3 - "$OUT" "$LBL" "$NAME" "$DMS" "$ARMV" "$SA" "$BK" "$ST" <<'PYE'
import json, sys
out, lbl, name, dms, armv, sa, bk, st = sys.argv[1:9]
def j(s, tag):
    try: return json.loads(s.split(tag + " ", 1)[1])
    except Exception: return {"parse_error": s[:120]}
rec = {"label": lbl, "arm": name, "d_ms": float(dms), "reservoir_armed": bool(int(armv)),
       "setarm": j(sa, "SETARM"), "block": j(bk, "BLOCK"), "counters": j(st, "CTR")}
with open(out, "a") as f: f.write(json.dumps(rec, default=str) + "\n")
b = rec["block"]; n = len(b.get("rows", []))
print("%-12s D=%-4s armed=%s attempted=%s responded=%s rows=%d" %
      (lbl, dms, armv, b.get("attempted"), b.get("responded"), n))
PYE
  done
done
echo "CAMPAIGN DONE -> $OUT  ($(wc -l < "$OUT") blocks)"

#!/bin/bash
# D-SWEEP CAMPAIGN, blocked within session.
# Arms are INTERLEAVED round by round rather than run one after another, because
# session-to-session drift on this relay exceeds the effect (CONSENSUS §9: C1/C2/C3
# native-vs-native AUROC to 0.985). D = 1 ms is a PRE-REGISTERED NULL CONTROL.
#
# CORRECTIONS.md §4.3 — FAIL CLOSED. A failed setarm, a program/hash mismatch, a failed
# capture, an empty counter read or a short block must NOT silently become a data row:
#   setarm unsuccessful        -> mark the arm invalid, do not write a treatment row
#   program/hash mismatch      -> abort the whole campaign (preflight)
#   capture / block failed     -> mark the block invalid
#   attempted != requested     -> mark the block invalid
#   counter read parse error   -> mark the block invalid
# Each block still writes ONE row, but an invalid block is tagged {"valid": false, ...}
# with its reason, so a downstream analyzer excludes it instead of averaging garbage.
set -uo pipefail

SW="ssh -o BatchMode=yes -o ConnectTimeout=10 decps@10.10.54.81"
VI="ssh -o BatchMode=yes -o ConnectTimeout=10 decps@10.10.54.19"
# FINAL repaired build is the default (CORRECTIONS.md §2.2).
PROG="${D3_PROG:-case_a_defense3}"
EXPECT_SHA="${D3_EXPECT_SHA:-}"
SWENV='cd /home/decps/d3 && export D3_PROG='"$PROG"';  export SDE=/home/decps/Downloads/bf-sde-9.13.2; export SDE_INSTALL=$SDE/install; export LD_LIBRARY_PATH=$SDE_INSTALL/lib:${LD_LIBRARY_PATH:-}; export PYTHONPATH=$SDE_INSTALL/lib/python3.8/site-packages/tofino:$SDE_INSTALL/lib/python3.8/site-packages:$PYTHONPATH;'
OUT="$1"; ROUNDS="${2:-4}"; NPOLL="${3:-20}"; GAP="${4:-0.2}"

abort() { echo "CAMPAIGN ABORT: $*" >&2; exit 1; }

# ---- preflight: the loaded program MUST be the final repaired build (§2.2/§4.3) -------
# Program or source-hash mismatch aborts the campaign BEFORE the destination is touched.
PF=$(timeout 90 $SW "$SWENV python3 preflight.py $EXPECT_SHA" 2>&1 | grep -o 'PREFLIGHT .*' | head -1)
[ -n "$PF" ] || abort "preflight produced no output (switch unreachable or program not bound)"
echo "$PF"
echo "$PF" | python3 -c 'import json,sys; d=json.loads(sys.stdin.read().split(" ",1)[1]); sys.exit(0 if d.get("ok") else 2)' \
    || abort "preflight failed: the loaded program is not the final R1+R2+R3 build (see PREFLIGHT above)"

# preflight passed -> now it is safe to create the destination (do NOT truncate earlier).
: > "$OUT"
CID=40

for r in $(seq 1 "$ROUNDS"); do
  for arm in "native:2:0" "d1:1:1" "d2:2:1" "d4:4:1" "d8:8:1" "d16:16:1"; do
    NAME=${arm%%:*}; REST=${arm#*:}; DMS=${REST%%:*}; ARMV=${REST#*:}
    LBL="r${r}_${NAME}"
    CID=$((CID+1))
    INVALID=""

    # ---- arm: setarm exit != 0 (e.g. parameter policy rejected D) invalidates the arm --
    SA_RAW=$(timeout 120 $SW "$SWENV python3 setarm.py $DMS $ARMV $CID" 2>&1)
    SA_RC=$?
    SA=$(echo "$SA_RAW" | grep -o 'SETARM .*' | head -1)
    if [ "$SA_RC" -ne 0 ] || [ -z "$SA" ]; then
      INVALID="setarm_failed(rc=$SA_RC)"
    fi

    # ---- capture + polls on Vision; a failed block invalidates the row -----------------
    BK_RAW=$(timeout 300 $VI "cd ~/d3phys && python3 block.py $LBL $NPOLL $GAP" 2>&1)
    BK_RC=$?
    BK=$(echo "$BK_RAW" | grep -o 'BLOCK .*' | head -1)
    if [ "$BK_RC" -ne 0 ] || [ -z "$BK" ]; then
      INVALID="${INVALID:+$INVALID,}block_failed(rc=$BK_RC)"
    fi

    # ---- counters: synchronized read via the shared map; parse error invalidates -------
    ST_RAW=$(timeout 120 $SW "$SWENV python3 read_counters.py $((CID+500))" 2>&1)
    ST_RC=$?
    ST=$(echo "$ST_RAW" | grep -o 'CTR .*' | head -1)
    if [ "$ST_RC" -ne 0 ] || [ -z "$ST" ]; then
      INVALID="${INVALID:+$INVALID,}counter_read_failed(rc=$ST_RC)"
    fi

    # ---- assemble the row; the python side adds attempted!=requested invalidation ------
    python3 - "$OUT" "$LBL" "$NAME" "$DMS" "$ARMV" "$NPOLL" "$INVALID" "$SA" "$BK" "$ST" <<'PYE'
import json, sys
out, lbl, name, dms, armv, npoll, invalid, sa, bk, st = sys.argv[1:11]
def j(s, tag):
    try: return json.loads(s.split(tag + " ", 1)[1])
    except Exception: return {"parse_error": s[:120]}
block = j(bk, "BLOCK")
reasons = [x for x in invalid.split(",") if x]
# attempted != requested -> invalid block (CORRECTIONS.md §4.3)
att = block.get("attempted")
if att is not None and int(npoll) != att:
    reasons.append("attempted(%s)!=requested(%s)" % (att, npoll))
# responded != attempted -> keep evidence but flag (an aborted poll loop)
resp = block.get("responded")
if att is not None and resp is not None and resp != att:
    reasons.append("responded(%s)!=attempted(%s)" % (resp, att))
rec = {"label": lbl, "arm": name, "d_ms": float(dms),
       "reservoir_armed": bool(int(armv)),
       "valid": not reasons, "invalid_reasons": reasons,
       "setarm": j(sa, "SETARM"), "block": block, "counters": j(st, "CTR")}
with open(out, "a") as f: f.write(json.dumps(rec, default=str) + "\n")
n = len(block.get("rows", []))
print("%-12s D=%-4s armed=%s attempted=%s responded=%s rows=%d valid=%s%s" %
      (lbl, dms, armv, att, resp, n, rec["valid"],
       "" if rec["valid"] else "  <- " + ";".join(reasons)))
PYE
  done
done
echo "CAMPAIGN DONE -> $OUT  ($(wc -l < "$OUT") blocks; $(grep -c '"valid": true' "$OUT" 2>/dev/null || echo 0) valid)"

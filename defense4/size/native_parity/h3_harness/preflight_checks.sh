#!/usr/bin/env bash
# preflight_checks.sh — attended-session gate for the physical-SEL BOR OPERATE run.
# Run AFTER arming captures/watchdog and BEFORE the first OPERATE. Exit 0 only if every
# check passes; any FAIL exits non-zero -> ABORT the session and roll back.
#
# Optional env: MIRROR_CAP_HOST (e.g. decps@10.10.54.30), MIRROR_CAP_IFACE, SYN_PCAP (a
# pcap containing the connection SYN/SYN-ACK for the TCP-timestamp check).
set -u
SW="${SW_HOST:-decps@10.10.54.81}"
VI="${VI_HOST:-decps@10.10.54.19}"
SSH="ssh -o BatchMode=yes -o ConnectTimeout=10"
REPO="/home/philip/Projects/DNP3-size-probe/defense4/size/native_parity"
AUDIT="$REPO/evidence/hw_campaign_20260813T172014Z/sel_isolation_audit"
DRV="$REPO/h3_harness/relay_sbo_operate_guarded.py"
FAIL=0
pass(){ echo "  [PASS] $1"; }
fail(){ echo "  [FAIL] $1 -- $2"; FAIL=1; }
num(){ echo "$1" | tr -cd '0-9' | head -c 6; }   # keep digits only

echo "### preflight checks ###"

# 1. Driver enforces EXACTLY {1,3}: refuses index 6 and subset {1}, accepts {1,3}.
python3 "$DRV" --indices 6 --count 1 >/dev/null 2>&1; r6=$?
python3 "$DRV" --indices 1 --count 1 >/dev/null 2>&1; r1=$?
python3 "$DRV" --indices 1,3 --dry-run >/dev/null 2>&1; r13=$?
if [ "$r6" = 2 ] && [ "$r1" = 2 ] && [ "$r13" = 0 ]; then
  pass "driver enforces EXACTLY {1,3} (idx6 refused, subset {1} refused, {1,3} ok)"
else fail "driver point-set enforcement" "idx6=$r6 subset1=$r1 set13=$r13"; fi

# 2. RB02/RB04 have ZERO equation fanout: they may appear ONLY as the DNP map target
#    (BO_nn := RBnn) and in TAR status. Any OTHER ':=' equation referencing them = real fanout.
bad=$(grep -rhiE ":=.*\b(RB02|RB04)\b" "$AUDIT"/*.txt 2>/dev/null | grep -vE "^\s*BO_[0-9]+\s*:=")
if [ -z "$bad" ]; then pass "RB02/RB04 zero output/protection-equation fanout (audit dumps)"
else fail "RB02/RB04 fanout non-empty" "$(echo "$bad" | head -1)"; fi

# 3. All relay physical outputs OPEN.
op=$(timeout 30 $SSH "$VI" 'cd ~/native_parity && python3 check_all_outputs.py' 2>/dev/null \
       | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["all_open"], d["closed_points"])' 2>/dev/null)
if echo "$op" | grep -q "^True \[\]"; then pass "all relay outputs OPEN ($op)"
else fail "relay outputs not all OPEN" "$op"; fi

# 4. Watchdog armed + snapshot present + snapshot-driven rollback present.
wd=$(num "$(timeout 15 $SSH "$SW" 'pgrep -cf watchdog_rrc.sh' 2>/dev/null)"); wd=${wd:-0}
snap=$(timeout 15 $SSH "$SW" '[ -f /home/decps/rrc_build/live_rrc_snapshot.json ] && echo Y || echo N' 2>/dev/null)
rb=$(num "$(timeout 15 $SSH "$SW" 'grep -cE "^SNAPSHOT=" /home/decps/rrc_bor_build/rollback_rrc.sh' 2>/dev/null)"); rb=${rb:-0}
if [ "$wd" -ge 1 ] && [ "$snap" = Y ] && [ "$rb" -ge 1 ]; then
  pass "watchdog armed ($wd) + snapshot present + snapshot-rollback present"
else fail "safety net not fully armed" "watchdog=$wd snapshot=$snap rollback_snap=$rb"; fi

# 5. Both captures running: master-facing (Vision) and dp68 mirror (host TBD).
mcap=$(num "$(timeout 15 $SSH "$VI" 'pgrep -cf "tcpdump.*192.168.10.7"' 2>/dev/null)"); mcap=${mcap:-0}
[ "$mcap" -ge 1 ] && pass "master-facing capture running ($mcap)" \
                  || fail "master-facing capture NOT running" "mcap=$mcap"
if [ -n "${MIRROR_CAP_HOST:-}" ]; then
  dcap=$(num "$(timeout 15 $SSH "$MIRROR_CAP_HOST" "pgrep -cf 'tcpdump'" 2>/dev/null)"); dcap=${dcap:-0}
  [ "$dcap" -ge 1 ] && pass "dp68 mirror capture running on $MIRROR_CAP_HOST ($dcap)" \
                    || fail "dp68 mirror capture NOT running" "host=$MIRROR_CAP_HOST dcap=$dcap"
else
  fail "dp68 mirror capture host UNSET" "set MIRROR_CAP_HOST/MIRROR_CAP_IFACE (relay-facing T0+J leg)"
fi

# 6. TCP timestamps NOT negotiated (scan the SYN/SYN-ACK of a supplied pcap).
if [ -n "${SYN_PCAP:-}" ] && [ -f "${SYN_PCAP:-}" ]; then
  ts=$(python3 - "$SYN_PCAP" <<'PY'
import sys
from scapy.all import rdpcap, TCP
n=bad=0
for p in rdpcap(sys.argv[1]):
    if TCP in p and (int(p[TCP].flags) & 0x02):
        n += 1
        if any(o[0] == 'Timestamp' for o in p[TCP].options):
            bad += 1
print("%d %d" % (n, bad))
PY
)
  set -- $ts; nsyn="${1:-0}"; nts="${2:-0}"
  if [ "$nsyn" -ge 1 ] && [ "$nts" = 0 ]; then pass "TCP timestamps ABSENT ($nsyn SYN/SYN-ACK, 0 with TS)"
  else fail "TCP timestamp check" "syn=$nsyn with_ts=$nts (need >=1 SYN, 0 TS)"; fi
else
  fail "TCP-timestamp check: SYN_PCAP unset/missing" "capture the connection SYN and set SYN_PCAP"
fi

echo
if [ "$FAIL" = 0 ]; then echo "PREFLIGHT: ALL PASS"; exit 0
else echo "PREFLIGHT: FAIL -> DO NOT OPERATE; abort + rollback"; exit 1; fi

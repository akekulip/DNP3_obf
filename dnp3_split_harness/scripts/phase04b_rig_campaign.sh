#!/usr/bin/env bash
# phase04b_rig_campaign.sh -- Two-host rig paired campaign, orchestrated FROM gambit over SSH.
# Vision (master/client + authoritative capture) <-> Hulk (outstation/replay server + DCRN load).
# DCRN attaches on Hulk eno1 (outstation egress); the authoritative capture is on Vision eno1
# (external-observer vantage, corrective.md sec 6). Same source transactions/order/seed across
# conditions. See reports/phases/phase_04b_dual_case_timing/two_host_rig_runbook.md.
#
# SECRET HANDLING: the rig `decps` sudo password is read from $RIG_PW and used ONLY transiently
# for `sudo -S` over SSH. It is never echoed, logged, or written to disk. Do NOT hardcode it.
#
# Safe by default: DRYRUN=1 prints the plan and does nothing privileged. To execute:
#   DRYRUN=0 RIG_PW='<rig decps sudo pw>' RUN_DIR=/tmp/phase04b_rig RUNS=5 \
#       bash scripts/phase04b_rig_campaign.sh
# NOTE: not yet wire-verified on the rig; the run itself is the verification.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"; HARNESS="$(cd "$DIR/.." && pwd)"
: "${DRYRUN:=1}"; : "${RUN_DIR:=/tmp/phase04b_rig}"; : "${RUNS:=5}"; : "${TXNS:=5}"
VISION=10.10.54.19; HULK=10.10.54.158; USER_RIG=decps; IFACE=eno1; PORT=20000
RDIR='~/dnp3_split_harness'                       # deploy target on each rig host
FIXED="$RDIR/bpf/phase04b_dcrn.o"; BOUNDED="$RDIR/bpf/phase04b_dcrn_bounded.o"
mkdir -p "$RUN_DIR"

log(){ printf '[rig] %s\n' "$*"; }
# ssh wrapper. rsh HOST "cmd"  -> non-privileged. rsudo HOST "cmd" -> sudo -S via $RIG_PW (transient).
rsh(){ local h="$1"; shift; ssh -o BatchMode=yes -o ConnectTimeout=8 "$USER_RIG@$h" "$@"; }
rsudo(){ local h="$1"; shift; printf '%s\n' "${RIG_PW:?set RIG_PW for privileged rig steps}" \
         | ssh -o BatchMode=yes -o ConnectTimeout=8 "$USER_RIG@$h" "sudo -S -p '' bash -lc '$*'"; }
do_(){ if [ "$DRYRUN" = "1" ]; then printf '[dry] %s\n' "$*"; else eval "$*"; fi; }

log "deploy harness -> Hulk + Vision (non-privileged rsync)"
for h in "$HULK" "$VISION"; do
  do_ "rsync -a --delete --exclude '.git' --exclude 'captures' --exclude 'logs' \
        '$HARNESS/' '$USER_RIG@$h:$RDIR/'"
done

log "Gate A on Hulk: DCRN loads + verifier-accepts on the rig kernel, then detaches"
do_ "rsudo $HULK \"IFACE=$IFACE bash $RDIR/scripts/phase04b_capability_probe.sh\""

log "build the shared spec (same transactions for every condition)"
do_ "python3 $HARNESS/phase04b_dcrn_harness.py build --out $RUN_DIR/spec.json --max-per-pcap $TXNS"
do_ "scp $RUN_DIR/spec.json $USER_RIG@$HULK:$RDIR/spec.json"
do_ "scp $RUN_DIR/spec.json $USER_RIG@$VISION:$RDIR/spec.json"

run_condition(){  # $1 name  $2 bpf-obj-or-empty
  local cond="$1" obj="${2:-}"
  local rpc="$RDIR/captures/${cond}.pcap"
  log "=== condition $cond (runs=$RUNS) ==="
  # 1. Hulk: attach DCRN (or ensure detached for NATIVE)
  if [ -n "$obj" ]; then
    do_ "rsudo $HULK \"IFACE=$IFACE BPF_OBJ=$obj RUN_DIR=$RDIR/captures bash $RDIR/scripts/phase04b_prepare.sh\""
  else
    do_ "rsudo $HULK \"IFACE=$IFACE RUN_DIR=$RDIR/captures bash $RDIR/scripts/phase04b_cleanup.sh\""
  fi
  # 2. Hulk: replay server (background)
  do_ "rsh $HULK \"mkdir -p $RDIR/captures; nohup python3 $RDIR/phase05_rig_replay.py --role server --spec $RDIR/spec.json --iface $IFACE >$RDIR/captures/${cond}_server.log 2>&1 &\""
  do_ "sleep 2"
  # 3. Vision: authoritative capture on eno1 (background, sudo)
  do_ "rsudo $VISION \"mkdir -p $RDIR/captures; (nohup tcpdump -i $IFACE -w $rpc 'tcp port $PORT' >/dev/null 2>&1 & echo \\\$! >$RDIR/captures/${cond}.cap.pid)\""
  do_ "sleep 1"
  # 4. Vision: replay client x RUNS
  local r; for r in $(seq 1 "$RUNS"); do
    do_ "rsh $VISION \"python3 $RDIR/phase05_rig_replay.py --role client --spec $RDIR/spec.json --hulk-ip $HULK >/dev/null 2>&1 || true\""
  done
  # 5. teardown: capture, server, DCRN
  do_ "sleep 1; rsudo $VISION \"kill \\\$(cat $RDIR/captures/${cond}.cap.pid) 2>/dev/null || true\""
  do_ "rsh $HULK \"pkill -f 'phase05_rig_[r]eplay.py --role server' 2>/dev/null || true\""
  [ -n "$obj" ] && do_ "rsudo $HULK \"IFACE=$IFACE RUN_DIR=$RDIR/captures bash $RDIR/scripts/phase04b_cleanup.sh\"" || true
  # 6. pull the pcap to the analysis host
  do_ "scp $USER_RIG@$VISION:$rpc $RUN_DIR/${cond}.pcap"
}

run_condition NATIVE ""
run_condition DCRN_FIXED "$FIXED"
run_condition DCRN_COMMON_BOUNDED "$BOUNDED"

log "rig captures under $RUN_DIR. Now (unprivileged):"
echo "  python3 $HARNESS/phase04b_dcrn_analyze.py       --run-dir $RUN_DIR"
echo "  python3 $HARNESS/phase04b_dcrn_attacker_eval.py --run-dir $RUN_DIR"

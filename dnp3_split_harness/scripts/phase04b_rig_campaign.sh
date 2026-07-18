#!/usr/bin/env bash
# phase04b_rig_campaign.sh -- two-host paired campaign, orchestrated FROM gambit over SSH.
# Vision (10.10.54.19) = master/client + AUTHORITATIVE capture on eno1 (external-observer, sec 6).
# Hulk  (10.10.54.158) = outstation/replay server + DCRN load point on eno1 (outstation egress).
# The replay server is one-shot, so it is restarted per run while ONE tcpdump spans all runs.
# See reports/phases/phase_04b_dual_case_timing/two_host_rig_runbook.md.
#
# SECRET: the rig decps sudo password is read from $RIG_PW and used ONLY transiently for `sudo -S`.
# It is never echoed, logged, or written to disk. Do NOT hardcode it.
#   RIG_PW='...' RUN_DIR=/tmp/phase04b_rig RUNS=5 bash scripts/phase04b_rig_campaign.sh
set -uo pipefail
: "${RIG_PW:?set RIG_PW (rig decps sudo password), used transiently for sudo -S}"
: "${RUN_DIR:=/tmp/phase04b_rig}"; : "${RUNS:=5}"
VISION=10.10.54.19; HULK=10.10.54.158; U=decps; IFACE=eno1
RDIR=/home/decps/dnp3_split_harness; SPEC="$RDIR/spec.json"
FIXED="$RDIR/bpf/phase04b_dcrn.libbpf.o"; BOUNDED="$RDIR/bpf/phase04b_dcrn_bounded.libbpf.o"
mkdir -p "$RUN_DIR"
SSH="ssh -o BatchMode=yes -o ConnectTimeout=8"

rsh()   { $SSH "$U@$1" "$2"; }                                   # non-privileged remote command
rsshf() { $SSH -f "$U@$1" "$2"; }                                # background remote (detaches)
rsudo() { printf '%s\n' "$RIG_PW" | $SSH "$U@$1" "sudo -S -p '' $2"; }  # transient sudo

log(){ printf '[rig] %s\n' "$*"; }

# ONE-TIME safety watchdog: force-restore Hulk eno1 after 1200 s even if orchestration dies.
log "arming eno1 safety watchdog on Hulk (auto-restore in 1200 s)"
rsudo "$HULK" "bash -c 'setsid bash -c \"sleep 1200; tc filter del dev $IFACE ingress; tc filter del dev $IFACE egress; tc qdisc del dev $IFACE clsact; tc qdisc del dev $IFACE root; rm -f /sys/fs/bpf/tc/globals/dcrn_*\" </dev/null >/tmp/phase04b_wd.log 2>&1 & echo wd=\$!'" || true

run_condition() {  # $1 name  $2 bpf-obj-or-empty
  local cond="$1" obj="${2:-}"
  local out="$RDIR/captures/${cond}.pcap"
  log "=== condition $cond (runs=$RUNS) ==="
  # 1. Hulk: attach DCRN (or ensure detached for NATIVE). Mount bpffs first (pin-by-name sharing).
  if [ -n "$obj" ]; then
    rsudo "$HULK" "mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true" >/dev/null 2>&1 || true
    rsudo "$HULK" "env IFACE=$IFACE BPF_OBJ=$obj RUN_DIR=$RDIR/captures bash $RDIR/scripts/phase04b_prepare.sh" >/dev/null 2>&1 \
      && log "  DCRN attached ($obj)" || { log "  ATTACH FAILED for $cond"; return 1; }
  else
    rsudo "$HULK" "env IFACE=$IFACE RUN_DIR=$RDIR/captures bash $RDIR/scripts/phase04b_cleanup.sh" >/dev/null 2>&1 || true
  fi
  # 2. Vision: start the authoritative capture (spans all runs).
  rsudo "$VISION" "bash $RDIR/scripts/phase04b_rig_capture.sh start $out" | sed 's/^/[rig]   /'
  # 3. per run: restart the one-shot server on Hulk, then run one client on Vision.
  local r okc=0
  for r in $(seq 1 "$RUNS"); do
    rsshf "$HULK" "cd $RDIR && python3 phase05_rig_replay.py --role server --spec $SPEC --iface $IFACE >/tmp/phase04b_srv_${cond}_$r.log 2>&1"
    sleep 1
    rsh "$VISION" "cd $RDIR && python3 phase05_rig_replay.py --role client --spec $SPEC --hulk-ip $HULK >/dev/null 2>&1" && okc=$((okc+1)) || true
    sleep 0.4
  done
  # 4. Vision: stop capture, make readable, pull to gambit.
  rsudo "$VISION" "bash $RDIR/scripts/phase04b_rig_capture.sh stop $out; chmod 0644 $out 2>/dev/null" | sed 's/^/[rig]   /'
  # 5. Hulk: detach DCRN.
  [ -n "$obj" ] && rsudo "$HULK" "env IFACE=$IFACE RUN_DIR=$RDIR/captures bash $RDIR/scripts/phase04b_cleanup.sh" >/dev/null 2>&1 || true
  scp -q "$U@$VISION:$out" "$RUN_DIR/${cond}.pcap" && log "  pulled $cond ($okc/$RUNS runs ok, $(stat -c%s "$RUN_DIR/${cond}.pcap" 2>/dev/null)B)"
}

cp "$RUN_DIR/spec.json" "$RUN_DIR/spec.json" 2>/dev/null || rsh "$VISION" "cat $SPEC" > "$RUN_DIR/spec.json"
run_condition NATIVE ""
run_condition DCRN_FIXED "$FIXED"
run_condition DCRN_COMMON_BOUNDED "$BOUNDED"
# final safety detach
rsudo "$HULK" "env IFACE=$IFACE RUN_DIR=$RDIR/captures bash $RDIR/scripts/phase04b_cleanup.sh" >/dev/null 2>&1 || true
log "rig captures in $RUN_DIR. Analyze (unprivileged):"
echo "  python3 phase04b_dcrn_analyze.py       --run-dir $RUN_DIR"
echo "  python3 phase04b_dcrn_attacker_eval.py --run-dir $RUN_DIR"
echo "  python3 phase04b_dcrn_audit.py         --run-dir $RUN_DIR"

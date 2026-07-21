#!/usr/bin/env bash
# c3_matrix.sh — gambit-side orchestrator for the Case-A C3 matrix.
#   usage: HULK_SUDO=... bash c3_matrix.sh <native|case-a> <n_txns> [intervals_csv]
# Per mode it sets the switch mode + RE-APPLIES the dp8 loopback (defense1_setup resets it) + a ping gate,
# then per txn runs the containment cycle (capture -> txn -> stop -> telemetry BEFORE close -> reset ->
# closeok -> close) and pulls the pcap. Results: /tmp/c3res/<mode>_<rms>ms_<i>.{pcap,tel.json}.
set -u
MODE="${1:?native|case-a}"; N="${2:?n_txns}"; INTERVALS="${3:-2,5,10,16,20}"
SW=decps@10.10.54.15; HULK=decps@10.10.54.158
source ~/.lab_env 2>/dev/null
: "${HULK_SUDO:?set HULK_SUDO}"
OUT=/tmp/c3res; mkdir -p "$OUT"
SETMODE="forward"; [ "$MODE" = "case-a" ] && SETMODE="case-a"

hsudo() { printf '%s\n' "$HULK_SUDO" | sshpass -e ssh "$HULK" "sudo -S -p '' $1"; }

# Cold-reload dcrn_defense1 (clears ALL recirc state — held frames from prior txns) then re-setup the
# mode + dp8 loopback. Called before EACH interval so accumulation never exceeds one interval's txns.
reload_setup() {
  ssh "$SW" 'sudo pkill -x bf_switchd; sleep 1; sudo bash -c "nohup bash /home/decps/dcrn_m1/launch_defense1.sh >/home/decps/dcrn_m1/switchd_ackA.log 2>&1 </dev/null &"; sleep 18'
  ssh "$SW" "cd /home/decps/dcrn_m1; python3.8 defense1_setup.py --mode $SETMODE >/dev/null 2>&1; python3.8 dp8_loopback_ackA.py >/dev/null 2>&1; sleep 2; python3.8 defense1_read.py --reset >/dev/null 2>&1"
}

echo "########## MODE=$MODE (switch mode=$SETMODE) n=$N intervals=$INTERVALS ##########"

IFS=',' read -ra RMS_ARR <<< "$INTERVALS"
for RMS in "${RMS_ARR[@]}"; do
  echo "=== $MODE readiness=${RMS}ms (cold-reload for clean state) ==="
  reload_setup
  G=$(hsudo "ip netns exec ns_master ping -c 2 -W 1 10.0.2.10" 2>/dev/null | grep -oE '[0-9]+ received' | head -1)
  echo "  ping gate: $G"
  [ "$G" = "2 received" ] || { echo "  PING GATE FAILED — aborting"; exit 1; }
  for i in $(seq 1 "$N"); do
    LABEL="${MODE}_${RMS}ms_${i}"
    ssh "$SW" "cd /home/decps/dcrn_m1; python3.8 defense1_read.py --reset >/dev/null 2>&1"
    hsudo "bash -c 'C3_CAPDIR=/tmp/c3caps nohup bash /tmp/c3_hulk_cycle.sh $RMS $LABEL $MODE >/tmp/c3caps/$LABEL.run 2>&1 </dev/null & echo -n'" >/dev/null 2>&1
    # poll for capture-done (sockets held open)
    for _ in $(seq 1 40); do sshpass -e ssh "$HULK" "test -f /tmp/c3caps/$LABEL.captured" 2>/dev/null && break; sleep 0.5; done
    # telemetry BEFORE close
    ssh "$SW" "cd /home/decps/dcrn_m1; python3.8 defense1_read.py --json 2>/dev/null" > "$OUT/$LABEL.tel.json"
    ssh "$SW" "cd /home/decps/dcrn_m1; python3.8 defense1_read.py --reset >/dev/null 2>&1"
    hsudo "touch /tmp/c3caps/$LABEL.closeok" >/dev/null 2>&1
    sleep 1
    sshpass -e scp -q "$HULK:/tmp/c3caps/$LABEL.pcap" "$OUT/$LABEL.pcap" 2>/dev/null
    printf "  txn %2d/%d %-16s pcap=%s\n" "$i" "$N" "$LABEL" "$([ -s "$OUT/$LABEL.pcap" ] && echo ok || echo MISSING)"
  done
done
echo "########## $MODE done -> $OUT ##########"

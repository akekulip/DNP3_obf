#!/usr/bin/env bash
# phase04b_smoke.sh -- staged Gate A (capability) + Gate B (dual-case smoke) (corrective.md sec 10).
# PI-run. Loads DCRN (fixed), replays a small 3-profile workload, captures on the authoritative
# vantage, and checks the Gate-B criteria (combined+separate reach target, ACK-before-response,
# byte-identical, no established-session retrans/reset). STOPS (does not run the full campaign) on
# failure. Replay reuses phase05_rig_replay.py; capture stays unprivileged.
#
#   sudo IFACE=<dcrn-iface> BPF_OBJ=/abs/phase04b_dcrn.o VANTAGE_IFACE=<observer-iface> \
#        SERVER=<dcrn-host-ip> RUN_DIR=/tmp/phase04b_smoke bash scripts/phase04b_smoke.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
HARNESS="$(cd "$DIR/.." && pwd)"
# shellcheck source=phase04b_common.sh
. "$DIR/phase04b_common.sh"
: "${VANTAGE_IFACE:=$IFACE}"       # where the authoritative capture is taken (Vision-side on the rig)
: "${SERVER:=127.0.0.1}"           # DCRN/replay-server address the client connects to
: "${SESSIONS:=20}"; : "${TXNS:=5}"

mkdir -p "$RUN_DIR"
log "GATE A: capability probe"
BPF_OBJ="$BPF_OBJ" RUN_DIR="$RUN_DIR/probe" bash "$DIR/phase04b_capability_probe.sh"

log "GATE B: dual-case smoke (fixed target), 3 profiles x $SESSIONS sessions x $TXNS txns"
run python3 "$HARNESS/phase04b_dcrn_harness.py" build --out "$RUN_DIR/spec.json" --max-per-pcap "$TXNS"

cleanup_bpf() { IFACE="$IFACE" RUN_DIR="$RUN_DIR" bash "$DIR/phase04b_cleanup.sh" >/dev/null 2>&1 || true; }
trap cleanup_bpf EXIT

log "attach DCRN (fixed) on $IFACE"
IFACE="$IFACE" BPF_OBJ="$BPF_OBJ" RUN_DIR="$RUN_DIR" bash "$DIR/phase04b_prepare.sh"

CAP="$RUN_DIR/smoke_dcrn_fixed.pcap"
log "start capture on $VANTAGE_IFACE -> $CAP  (filter: tcp port 20000)"
if [ "$DRYRUN" != "1" ]; then dumpcap -i "$VANTAGE_IFACE" -f "tcp port 20000" -w "$CAP" & CAPPID=$!; sleep 1; fi

log "replay: server (DCRN host) + client (master) via phase05_rig_replay.py"
# NOTE: on the two-host rig, the server runs on the DCRN host and the client on the master (Vision);
# on a local veth setup both run here bound to the veth peers. Exact invocation is host-specific:
echo "  server: python3 $HARNESS/phase05_rig_replay.py --role server --spec $RUN_DIR/spec.json --iface $IFACE"
echo "  client: python3 $HARNESS/phase05_rig_replay.py --role client --spec $RUN_DIR/spec.json --hulk-ip $SERVER"

if [ "$DRYRUN" != "1" ]; then sleep 1; kill "${CAPPID:-0}" 2>/dev/null || true; fi
log "analyze -> Gate-B criteria"
run python3 "$HARNESS/phase04b_dcrn_analyze.py" --pcap "$CAP" --condition DCRN_FIXED --gate-b \
    --out "$RUN_DIR/smoke_result.json" || die "GATE B FAILED -- do not run the full campaign; inspect $RUN_DIR"
log "GATE B complete. Review $RUN_DIR/smoke_result.json before running scripts/phase04b_campaign.sh"

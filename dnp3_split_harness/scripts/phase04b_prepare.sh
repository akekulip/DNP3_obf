#!/usr/bin/env bash
# phase04b_prepare.sh -- PRIVILEGED: attach the DCRN data plane on $IFACE (corrective.md sec 9).
# Sets fq root (EDT enforcement) + clsact, loads the DCRN object on ingress AND egress. Idempotent
# (deletes any prior DCRN state first), disables NIC offloads (recorded for restore), trap-cleans on
# failure so DCRN is never left attached after an error.
#   sudo IFACE=eno1 BPF_OBJ=/abs/phase04b_dcrn.o RUN_DIR=/tmp/phase04b_run bash scripts/phase04b_prepare.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=phase04b_common.sh
. "$DIR/phase04b_common.sh"

need_root
[ -n "${BPF_OBJ}" ] || die "set BPF_OBJ=/abs/path/to/phase04b_dcrn(.bounded).o"
[ "$DRYRUN" = "1" ] || [ -f "$BPF_OBJ" ] || die "BPF_OBJ not found: $BPF_OBJ"
mkdir -p "$RUN_DIR"

attached=0
cleanup_on_err() {
  [ "$attached" = "1" ] || return 0
  log "error during prepare -- detaching DCRN so it is not left attached"
  tc filter del dev "$IFACE" ingress 2>/dev/null || true
  tc filter del dev "$IFACE" egress  2>/dev/null || true
  tc qdisc  del dev "$IFACE" clsact  2>/dev/null || true
}
trap cleanup_on_err ERR

record_env "$RUN_DIR/env.txt"
save_offloads "$RUN_DIR/offloads_before.txt"
disable_offloads

# fq root enforces skb->tstamp (EDT). 'replace' is idempotent for the root qdisc.
run tc qdisc replace dev "$IFACE" root fq
# clsact hosts the ingress+egress bpf hooks; del+add for idempotency (no clean 'replace').
run tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
run tc qdisc add dev "$IFACE" clsact

# delete any prior DCRN filters, then attach (direct-action; legacy no-BTF object).
run tc filter del dev "$IFACE" ingress 2>/dev/null || true
run tc filter del dev "$IFACE" egress  2>/dev/null || true
run tc filter add dev "$IFACE" ingress bpf da obj "$BPF_OBJ" sec ingress
run tc filter add dev "$IFACE" egress  bpf da obj "$BPF_OBJ" sec egress
attached=1
trap - ERR

log "DCRN attached on $IFACE (ingress+egress); fq root active; obj=$BPF_OBJ"
run tc -s filter show dev "$IFACE" ingress | tee "$RUN_DIR/filter_ingress.txt" || true
run tc -s filter show dev "$IFACE" egress  | tee "$RUN_DIR/filter_egress.txt"  || true
log "prepare complete. Run replay+capture, then scripts/phase04b_cleanup.sh"

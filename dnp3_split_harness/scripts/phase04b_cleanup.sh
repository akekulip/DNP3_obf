#!/usr/bin/env bash
# phase04b_cleanup.sh -- PRIVILEGED: fully detach DCRN and restore $IFACE (corrective.md sec 9).
# Idempotent and safe to run anytime; leaves the interface in its default (offloads restored, DCRN
# filters + clsact removed, root qdisc reset). Never fails hard on a missing element.
#   sudo IFACE=eno1 RUN_DIR=/tmp/phase04b_run bash scripts/phase04b_cleanup.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=phase04b_common.sh
. "$DIR/phase04b_common.sh"

need_root
log "detaching DCRN from $IFACE"
run tc filter del dev "$IFACE" ingress 2>/dev/null || true
run tc filter del dev "$IFACE" egress  2>/dev/null || true
run tc qdisc  del dev "$IFACE" clsact  2>/dev/null || true
# remove our fq root; the kernel restores the interface default (e.g. pfifo_fast / mq).
run tc qdisc  del dev "$IFACE" root    2>/dev/null || true
restore_offloads "$RUN_DIR/offloads_before.txt"

log "verify: no DCRN filters remain --"
run tc filter show dev "$IFACE" ingress 2>/dev/null || true
run tc filter show dev "$IFACE" egress  2>/dev/null || true
run tc qdisc  show dev "$IFACE" 2>/dev/null || true
log "cleanup complete: DCRN detached, offloads restored, transparent forwarding."

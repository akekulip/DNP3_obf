#!/usr/bin/env bash
# phase04b_capability_probe.sh -- PRIVILEGED capability + verifier probe (corrective.md sec 5, Gate A).
# Verifies the DCRN object loads and the kernel accepts it on BOTH tc hooks, on an ISOLATED scratch
# veth pair (so real interfaces are untouched). Records kernel/tool versions, qdisc before/after,
# program/map ids, and the verifier result. Does NOT itself measure skb->tstamp enforcement -- that is
# already proven on this host by reports/phases/phase_04/edt_test (PI-run, PASS) and is re-confirmed by
# the Gate-B smoke test. Fails loudly (not with a netem substitute) if a required capability is absent.
#   sudo BPF_OBJ=/abs/phase04b_dcrn.o RUN_DIR=/tmp/phase04b_probe bash scripts/phase04b_capability_probe.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=phase04b_common.sh
. "$DIR/phase04b_common.sh"

need_root
[ -n "${BPF_OBJ}" ] || die "set BPF_OBJ=/abs/path/to/phase04b_dcrn.o"
[ "$DRYRUN" = "1" ] || [ -f "$BPF_OBJ" ] || die "BPF_OBJ not found: $BPF_OBJ"
mkdir -p "$RUN_DIR"
A=veth-dcrn-a; B=veth-dcrn-b; RESULT="$RUN_DIR/capability_probe.txt"

teardown() {
  tc filter del dev "$B" ingress 2>/dev/null || true
  tc filter del dev "$B" egress  2>/dev/null || true
  tc qdisc  del dev "$B" clsact  2>/dev/null || true
  tc qdisc  del dev "$B" root    2>/dev/null || true
  ip link del "$A" 2>/dev/null || true
}
trap teardown EXIT

record_env "$RESULT"
{
  echo "--- fq availability ---"
  tc qdisc add dev lo root fq 2>&1 && echo "fq: OK" && tc qdisc del dev lo root 2>/dev/null || echo "fq: UNAVAILABLE"
} >> "$RESULT" 2>&1 || true

log "creating scratch veth pair $A <-> $B"
run ip link add "$A" type veth peer name "$B"
run ip link set "$A" up
run ip link set "$B" up

log "qdisc + DCRN load on $B (verifier check on both hooks)"
run tc qdisc replace dev "$B" root fq
run tc qdisc add dev "$B" clsact
if run tc filter add dev "$B" ingress bpf da obj "$BPF_OBJ" sec ingress \
   && run tc filter add dev "$B" egress bpf da obj "$BPF_OBJ" sec egress; then
  {
    echo "--- verifier: ACCEPTED on ingress + egress ---"
    echo "--- qdisc after ---"; tc qdisc show dev "$B"
    echo "--- ingress filter ---"; tc -s filter show dev "$B" ingress
    echo "--- egress filter ---";  tc -s filter show dev "$B" egress
  } >> "$RESULT" 2>&1
  log "CAPABILITY PROBE PASS -- DCRN verifier-accepted on both hooks. Detail -> $RESULT"
else
  echo "--- verifier: REJECTED ---" >> "$RESULT"
  die "DCRN failed to load/attach. See $RESULT. Do NOT substitute netem -- report the unsupported capability."
fi

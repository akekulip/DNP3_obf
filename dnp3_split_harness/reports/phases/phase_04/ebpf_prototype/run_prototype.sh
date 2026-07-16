#!/usr/bin/env bash
# Phase 04 eBPF EDT prototype -- RUN ONCE AS ROOT:
#     sudo bash reports/phases/phase_04/ebpf_prototype/run_prototype.sh
#
# Why root: loading a tc BPF program needs real CAP_BPF (kernel.unprivileged_bpf_disabled=2).
# Isolated in a throwaway network namespace -- no effect on the host loopback.
#
# It compiles ack_edt.c, loads it on lo egress with fq, drives the replay server (separate-ACK
# regime) + client, captures, and reports whether the pure ACK and the DNP3 response were
# INDEPENDENTLY pinned to their per-flow EDT targets (request->ACK 20 ms, request->response 40 ms),
# byte-identical and without breakage.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
HARNESS="$(cd "$DIR/../../../.." && pwd)"          # dnp3_split_harness/
NS="ebpftest$$"
RUN="$HARNESS/runs/$(date -u +%Y%m%dT%H%M%SZ)_phase04_ebpf_prototype"

if [ "$(id -u)" -ne 0 ]; then echo "must run as root: sudo bash $0"; exit 1; fi

echo "[*] compiling ack_edt.c (no -g, to avoid the old-iproute2 .BTF rejection) ..."
clang -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu \
      -c "$DIR/ack_edt.c" -o "$DIR/ack_edt.o" || { echo "compile FAILED"; exit 1; }

cleanup() { ip netns del "$NS" 2>/dev/null; }
trap cleanup EXIT

echo "[*] creating isolated netns $NS ..."
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up

echo "[*] driving the eBPF EDT prototype inside $NS ..."
mkdir -p "$RUN"
ip netns exec "$NS" python3 "$HARNESS/phase04_ebpf_prototype.py" --run-dir "$RUN" --obj "$DIR/ack_edt.o" --reps 10
rc=$?

echo
echo "[*] run dir: $RUN"
exit $rc

#!/usr/bin/env bash
# Phase 04 EDT load-and-release test -- RUN ONCE AS ROOT:
#     sudo bash reports/phases/phase_04/edt_test/run_edt_test.sh
#
# Why root: loading a tc BPF program needs real CAP_BPF (kernel.unprivileged_bpf_disabled=2 on this
# host), and there is no non-sudo path for it (unlike netem, which is namespace-scoped and ran under
# `unshare -rn`). This grants the privilege once, for this one isolated test.
#
# What it does (fully isolated in a throwaway network namespace -- no effect on the host loopback):
#   1. compile edt.c (no privilege needed);
#   2. create a temp netns; bring up its lo;
#   3. baseline ping 127.0.0.1;
#   4. add `fq` root qdisc + `clsact`, load edt.o on egress (sets skb->tstamp = now + 30 ms);
#   5. ping again -- if fq enforces the BPF-set EDT, RTT jumps to ~60 ms (30 ms each direction);
#   6. tear the netns down.
#
# Interpretation: RTT ~60 ms => PASS (loaded BPF sets tstamp AND fq enforces it on this host).
#                 RTT ~0 ms  => FAIL (fq did not honor the BPF tstamp -- likely a clock-domain /
#                               mono_delivery_time issue that must be solved before the eBPF prototype).
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
NS="edttest$$"
DELAY_MS=30

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root: sudo bash $0"; exit 1
fi

echo "[*] compiling edt.c ..."
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu \
      -c "$DIR/edt.c" -o "$DIR/edt.o" || { echo "compile FAILED"; exit 1; }

cleanup() { ip netns del "$NS" 2>/dev/null; }
trap cleanup EXIT

echo "[*] creating isolated netns $NS ..."
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up

echo "[*] BASELINE ping (no EDT):"
ip netns exec "$NS" ping -c 3 -i 0.2 127.0.0.1 | tail -1

echo "[*] installing fq (root) + clsact, loading the BPF EDT program ..."
ip netns exec "$NS" tc qdisc add dev lo root fq
ip netns exec "$NS" tc qdisc add dev lo clsact
if ! ip netns exec "$NS" tc filter add dev lo egress bpf da obj "$DIR/edt.o" sec tc; then
  echo "BPF LOAD FAILED"; exit 2
fi
echo "[*] filter loaded:"; ip netns exec "$NS" tc filter show dev lo egress

echo "[*] ping WITH EDT (${DELAY_MS} ms per egress; expect RTT ~ $((DELAY_MS * 2)) ms if fq enforces):"
ip netns exec "$NS" ping -c 3 -i 0.2 127.0.0.1 | tail -1

echo
echo "[=] RESULT: RTT ~ $((DELAY_MS * 2)) ms => PASS (BPF-set EDT enforced by fq)."
echo "           RTT ~ 0 ms          => FAIL (fq did not honor the BPF tstamp)."

#!/usr/bin/env bash
# phase04b_build_bpf.sh -- compile the DCRN objects (fixed + bounded). Unprivileged. Reproducible.
set -euo pipefail
BPF="$(cd "$(dirname "$0")/../bpf" && pwd)"
FLAGS="-O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu"

# Legacy iproute2 internal-loader objects (no BTF) -- for the dev box (iproute2 ss200127).
clang $FLAGS -c "$BPF/phase04b_dcrn.c" -o "$BPF/phase04b_dcrn.o"
clang $FLAGS -DDCRN_MODE_CFG=DCRN_MODE_BOUNDED -c "$BPF/phase04b_dcrn.c" -o "$BPF/phase04b_dcrn_bounded.o"

# libbpf BTF objects (-g emits BTF; DCRN_LIBBPF_MAPS selects .maps) -- for a libbpf-linked tc
# (iproute2 >= 5.x, e.g. the kernel-6.8 rig with iproute2-6.1 + libbpf 1.3).
LIBBPF_FLAGS="$FLAGS -g -DDCRN_LIBBPF_MAPS"
clang $LIBBPF_FLAGS -c "$BPF/phase04b_dcrn.c" -o "$BPF/phase04b_dcrn.libbpf.o"
clang $LIBBPF_FLAGS -DDCRN_MODE_CFG=DCRN_MODE_BOUNDED -c "$BPF/phase04b_dcrn.c" -o "$BPF/phase04b_dcrn_bounded.libbpf.o"

echo "built legacy: $BPF/phase04b_dcrn.o, $BPF/phase04b_dcrn_bounded.o"
echo "built libbpf: $BPF/phase04b_dcrn.libbpf.o, $BPF/phase04b_dcrn_bounded.libbpf.o"

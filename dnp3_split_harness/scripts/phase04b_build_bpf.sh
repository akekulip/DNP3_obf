#!/usr/bin/env bash
# phase04b_build_bpf.sh -- compile the DCRN objects (fixed + bounded). Unprivileged. Reproducible.
set -euo pipefail
BPF="$(cd "$(dirname "$0")/../bpf" && pwd)"
FLAGS="-O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu"
clang $FLAGS -c "$BPF/phase04b_dcrn.c" -o "$BPF/phase04b_dcrn.o"
clang $FLAGS -DDCRN_MODE_CFG=DCRN_MODE_BOUNDED -c "$BPF/phase04b_dcrn.c" -o "$BPF/phase04b_dcrn_bounded.o"
echo "built: $BPF/phase04b_dcrn.o (fixed), $BPF/phase04b_dcrn_bounded.o (bounded)"

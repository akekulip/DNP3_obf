#!/usr/bin/env bash
# phase04b_common.sh -- shared helpers for the DCRN privileged scripts (corrective.md sec 9).
# Sourced, never executed directly. Provides logging, dry-run, and state-recording helpers.
# All privileged scripts are idempotent, trap-cleaned, and support DRYRUN=1.
set -euo pipefail

: "${DRYRUN:=0}"
: "${IFACE:=veth-dcrn-b}"          # interface DCRN attaches to (Hulk eno1 on the rig; a veth peer locally)
: "${BPF_OBJ:=}"                    # path to the compiled DCRN object (fixed or bounded variant)
: "${RUN_DIR:=/tmp/phase04b_run}"

log()  { printf '[phase04b] %s\n' "$*" >&2; }
die()  { printf '[phase04b][FATAL] %s\n' "$*" >&2; exit 1; }

# run: echo the command; execute it unless DRYRUN=1.
run() {
  if [ "$DRYRUN" = "1" ]; then printf '[dry-run] %s\n' "$*" >&2; return 0; fi
  printf '[exec] %s\n' "$*" >&2
  "$@"
}

need_root() {
  [ "$DRYRUN" = "1" ] && return 0
  [ "$(id -u)" = "0" ] || die "must run as root (sudo) -- BPF load needs CAP_BPF on this host"
}

record_env() {
  local out="$1"; mkdir -p "$(dirname "$out")"
  {
    echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "kernel=$(uname -r)"
    echo "tc_version=$(tc -V 2>&1 | head -1)"
    echo "clang_version=$(clang --version 2>&1 | head -1)"
    echo "bpftool=$(command -v bpftool || echo not-installed)"
    echo "iface=$IFACE"
    echo "bpf_obj=$BPF_OBJ"
  } > "$out"
  log "environment recorded -> $out"
}

# snapshot / restore NIC offloads (sec 7). Records before/after; restores on cleanup.
save_offloads() {
  local out="$1"
  if command -v ethtool >/dev/null 2>&1 && [ "$DRYRUN" != "1" ]; then
    ethtool -k "$IFACE" 2>/dev/null | grep -E 'generic-receive-offload|generic-segmentation-offload|tcp-segmentation-offload|large-receive-offload' > "$out" || true
    log "offloads saved -> $out"
  else
    log "ethtool unavailable or dry-run: offload snapshot skipped"
  fi
}
disable_offloads() {
  command -v ethtool >/dev/null 2>&1 || { log "ethtool absent: cannot disable offloads (document effect)"; return 0; }
  run ethtool -K "$IFACE" gro off gso off tso off lro off || log "some offloads could not be disabled (document)"
}
restore_offloads() {
  local saved="$1"; [ -f "$saved" ] || return 0
  command -v ethtool >/dev/null 2>&1 || return 0
  # best-effort restore of the four we touch
  run ethtool -K "$IFACE" gro on gso on tso on || true
}

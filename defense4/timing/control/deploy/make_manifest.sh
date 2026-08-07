#!/usr/bin/env bash
# B4: SHA-256 manifest for every evidence artifact under a directory.
# usage: make_manifest.sh <dir> [out]   (default out: <dir>/SHA256SUMS)
set -u
DIR="${1:?usage: make_manifest.sh <dir> [out]}"
OUT="${2:-$DIR/SHA256SUMS}"
cd "$DIR" || exit 1
: > "$OUT"
find . -type f \( -name '*.pcap' -o -name '*.json' -o -name '*.jsonl' -o -name '*.txt' \
  -o -name '*.log' -o -name '*.p4' -o -name '*.py' -o -name '*.md' -o -name '*.conf' \) \
  ! -name "$(basename "$OUT")" -print0 | sort -z | xargs -0 sha256sum >> "$OUT"
echo "manifest: $OUT ($(wc -l < "$OUT") files)"

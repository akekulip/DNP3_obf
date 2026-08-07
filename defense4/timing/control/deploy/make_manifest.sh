#!/usr/bin/env bash
# SHA-256 manifest for EVERY file under an evidence directory (no extension allowlist).
#
# The old allowlist silently dropped driver error files, CSV results, environment records, and
# figures. This hashes every regular file, excluding only the manifest itself and the files that are
# written strictly AFTER the manifest (the verification output and the finalize log), which cannot be
# hashed without changing after the fact.
#
# usage: make_manifest.sh <dir> [out]   (default out: <dir>/SHA256SUMS)
set -euo pipefail
DIR="${1:?usage: make_manifest.sh <dir> [out]}"
OUT="${2:-$DIR/SHA256SUMS}"
case "$OUT" in /*) : ;; *) OUT="$PWD/$OUT" ;; esac
cd "$DIR"
: > "$OUT"
# exclude the manifest and the post-manifest artifacts (created after this runs)
find . -type f \
  ! -name "$(basename "$OUT")" \
  ! -name 'manifest.out' \
  ! -name 'manifest_verify.out' \
  ! -name 'finalize.out' \
  -print0 | sort -z | xargs -0 sha256sum >> "$OUT"
echo "manifest: $OUT ($(wc -l < "$OUT") files)"

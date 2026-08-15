#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../../../.."
python3 -m defense4.size.real_size_normalization.offline.s3_trace_driver "$@"

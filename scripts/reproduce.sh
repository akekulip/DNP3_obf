#!/bin/bash
set -euo pipefail
HERE=$(dirname "$(readlink -f "$0")")
exec python3 "$HERE/reproduce.py" "$@"

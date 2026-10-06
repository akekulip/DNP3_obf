#!/usr/bin/env bash
# One entry point for the framework track's offline tests. No hardware, no network.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
for suite in active_harness active_control active_probe response_ready framework; do
    d=defense4/timing/$suite/tests
    [ "$suite" = framework ] && d=defense4/timing/framework/tests
    echo "== $suite"
    python3 -B -m unittest discover -s "$d" -q
done

#!/bin/bash
# Launch bf_switchd on a composite build's conf (made by hw/make_conf.py). Runs on the switch host, via
# switch_swap.sh:   launch_composite.sh CONF [SDE]
# Same invocation as hw/README.md step 2 and stage_reduction/hardware/20260925/switch/launch_timing.sh.
set -e
CONF=$1
export SDE=${2:-/home/decps/Downloads/bf-sde-9.13.2}
export SDE_INSTALL=$SDE/install
export LD_LIBRARY_PATH=$SDE_INSTALL/lib:${LD_LIBRARY_PATH:-}
cd "$(dirname "$CONF")"
tail -f /dev/null | "$SDE_INSTALL/bin/bf_switchd" --install-dir "$SDE_INSTALL" --conf-file "$CONF" --init-mode=cold --status-port 7777

#!/bin/bash
set -e
export SDE=/home/decps/Downloads/bf-sde-9.13.2
export SDE_INSTALL=$SDE/install
export LD_LIBRARY_PATH=$SDE_INSTALL/lib:${LD_LIBRARY_PATH:-}
cd /home/decps/dnp3_timing7_20260925
tail -f /dev/null | "$SDE_INSTALL/bin/bf_switchd" --install-dir "$SDE_INSTALL" --conf-file /home/decps/dnp3_timing7_20260925/defense4_timing.conf --init-mode=cold --status-port 7777

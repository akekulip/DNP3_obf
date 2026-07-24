#!/usr/bin/env bash
#
# launch_defense1.sh — start bf_switchd with the Defense-1 (dcrn_defense1) program on the shared Tofino.
#   Mirrors launch_dcrn.sh. RUN ON THE SWITCH ONLY (decps@10.10.54.81), and ONLY inside an
#   authorized, gated window after gc-switchd is stopped+masked (it auto-seizes the chip otherwise).
#   This is a GATED operation — do not run it as part of an off-switch task.
#
# Prereqs on the switch before this runs:
#   - /home/decps/dcrn_m1/dcrn_defense1.conf present (copied from this repo's dcrn_defense1.conf)
#   - /home/decps/dcrn_m1/build_ackA_9132/ present (the on-switch bf-p4c 9.13.2 build:
#       bfrt.json, pipe/context.json, pipe/tofino.bin)
#   - sudo systemctl stop gc-switchd ; sudo systemctl mask gc-switchd ; pkill -f launch_switchd.sh
#
# After bf_switchd is up, drive the control plane from defense1_setup.py (separate process).
#
set -euo pipefail

export SDE=/home/decps/Downloads/bf-sde-9.13.2
export SDE_INSTALL="$SDE/install"
export LD_LIBRARY_PATH="$SDE_INSTALL/lib:${LD_LIBRARY_PATH:-}"

# `tail -f /dev/null |` keeps stdin open so bf_switchd's interactive CLI does not read EOF and exit.
tail -f /dev/null | "$SDE_INSTALL/bin/bf_switchd" \
    --install-dir "$SDE_INSTALL" \
    --conf-file /home/decps/dcrn_m1/dcrn_defense1.conf \
    --init-mode=cold \
    --status-port 7777

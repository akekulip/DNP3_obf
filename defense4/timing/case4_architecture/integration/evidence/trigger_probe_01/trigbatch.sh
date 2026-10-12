#!/bin/bash
cd /home/philip/Projects/DNP3/defense4/timing/case4_architecture
SP=/tmp/claude-1002/-home-philip-Projects-DNP3/db04a002-eb4e-45b0-ac5b-b5c1bc10aaf5/scratchpad
O=integration/evidence/trigger_probe_01
SH="--shape-ack-pps 14892 --shape-resp-pps 14892 --shape-op-pps 14892 --shape-ack-blk-pps 14892 --shape-resp-blk-pps 14892 --shape-op-blk-pps 14892 --block-burst 64"
bash $SP/idleblock.sh 54611 $O idle_shaped_r1   1 "$SH" 2>&1 | grep -E 'INSTALLED|FAIL|REFUSED|BLOCK'
bash $SP/closeblock.sh 54612 $O shaped_r5   5  "$SH" 2>&1 | grep -E 'INSTALLED|FAIL|REFUSED|BLOCK'
bash $SP/closeblock.sh 54613 $O unshaped_r20 20 ""   2>&1 | grep -E 'INSTALLED|FAIL|REFUSED|BLOCK'
echo ALLDONE

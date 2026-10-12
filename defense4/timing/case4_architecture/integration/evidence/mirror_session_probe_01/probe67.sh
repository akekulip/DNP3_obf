#!/bin/bash
cd /home/philip/Projects/DNP3/defense4/timing/case4_architecture
SP=/tmp/claude-1002/-home-philip-Projects-DNP3/db04a002-eb4e-45b0-ac5b-b5c1bc10aaf5/scratchpad
O=integration/evidence/mirror_session_probe_01
SH="--shape-ack-pps 14892 --shape-resp-pps 14892 --shape-op-pps 14892 --shape-ack-blk-pps 14892 --shape-resp-blk-pps 14892 --shape-op-blk-pps 14892 --block-burst 64"
bash $SP/closeblock.sh 54651 $O shaped_r6  6 "$SH" 2>&1 | grep -E 'INSTALLED|FAIL|REFUSED|BLOCK' | cut -c1-60
bash $SP/closeblock.sh 54652 $O shaped_r7  7 "$SH" 2>&1 | grep -E 'INSTALLED|FAIL|REFUSED|BLOCK' | cut -c1-60
bash $SP/closeblock.sh 54653 $O shaped_r8  8 "$SH" 2>&1 | grep -E 'INSTALLED|FAIL|REFUSED|BLOCK' | cut -c1-60
bash $SP/closeblock.sh 54654 $O unshaped_r7 7 ""   2>&1 | grep -E 'INSTALLED|FAIL|REFUSED|BLOCK' | cut -c1-60
echo ALLDONE

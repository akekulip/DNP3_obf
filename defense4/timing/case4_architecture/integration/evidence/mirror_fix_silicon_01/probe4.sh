#!/bin/bash
cd /home/philip/Projects/DNP3/defense4/timing/case4_architecture
SP=/tmp/claude-1002/-home-philip-Projects-DNP3/db04a002-eb4e-45b0-ac5b-b5c1bc10aaf5/scratchpad
O=integration/evidence/mirror_fix_silicon_01
SH="--shape-ack-pps 14892 --shape-resp-pps 14892 --shape-op-pps 14892 --shape-ack-blk-pps 14892 --shape-resp-blk-pps 14892 --shape-op-blk-pps 14892 --block-burst 64"
for spec in "s_r7:54661:7" "s_r10:54662:10" "s_r20:54663:20" "s_r50:54664:50"; do
  IFS=: read l p n <<< "$spec"
  bash $SP/mirrorblock.sh $p $O $l $n "$SH" 2>&1 | grep -E 'INSTALLED|FAIL|REFUSED|BLOCK' | cut -c1-60
done
bash $SP/mirrorblock.sh 54665 $O u_r20 20 "" 2>&1 | grep -E 'INSTALLED|FAIL|REFUSED|BLOCK' | cut -c1-60
echo ALLDONE

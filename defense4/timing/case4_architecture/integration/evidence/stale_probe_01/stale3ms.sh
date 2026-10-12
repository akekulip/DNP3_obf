#!/bin/bash
cd /home/philip/Projects/DNP3/defense4/timing/case4_architecture
SP=/tmp/claude-1002/-home-philip-Projects-DNP3/db04a002-eb4e-45b0-ac5b-b5c1bc10aaf5/scratchpad
O=integration/evidence/stale_probe_01
S3="--shape-ack-pps 3723 --shape-resp-pps 3723 --shape-op-pps 3723 --shape-ack-blk-pps 3723 --shape-resp-blk-pps 3723 --shape-op-blk-pps 3723 --block-burst 64"
S14="--shape-ack-pps 14892 --shape-resp-pps 14892 --shape-op-pps 14892 --shape-ack-blk-pps 14892 --shape-resp-blk-pps 14892 --shape-op-blk-pps 14892 --block-burst 64"
bash $SP/mirrorblock.sh 54711 $O d3_s3723_a 50 "$S3"  2>&1 | grep -E 'INSTALLED|FAIL|REFUSED|BLOCK' | cut -c1-50
bash $SP/mirrorblock.sh 54712 $O d3_s3723_b 50 "$S3"  2>&1 | grep -E 'INSTALLED|FAIL|REFUSED|BLOCK' | cut -c1-50
bash $SP/mirrorblock.sh 54713 $O d3_s14892  50 "$S14" 2>&1 | grep -E 'INSTALLED|FAIL|REFUSED|BLOCK' | cut -c1-50
bash $SP/mirrorblock.sh 54714 $O d3_unshaped 50 ""    2>&1 | grep -E 'INSTALLED|FAIL|REFUSED|BLOCK' | cut -c1-50
echo ALLDONE

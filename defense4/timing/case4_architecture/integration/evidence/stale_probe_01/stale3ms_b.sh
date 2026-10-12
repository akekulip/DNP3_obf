#!/bin/bash
cd /home/philip/Projects/DNP3/defense4/timing/case4_architecture
SP=/tmp/claude-1002/-home-philip-Projects-DNP3/db04a002-eb4e-45b0-ac5b-b5c1bc10aaf5/scratchpad
O=integration/evidence/stale_probe_01
S3="--shape-ack-pps 3723 --shape-resp-pps 3723 --shape-op-pps 3723 --shape-ack-blk-pps 3723 --shape-resp-blk-pps 3723 --shape-op-blk-pps 3723 --block-burst 64"
for spec in "d3_s3723_r1a:54721:1" "d3_s3723_r1b:54722:1" "d3_s3723_r10a:54723:10" "d3_s3723_r10b:54724:10" "d3_s3723_r50c:54725:50" "d3_s3723_r50d:54726:50"; do
  IFS=: read l p n <<< "$spec"
  bash $SP/mirrorblock.sh $p $O $l $n "$S3" 2>&1 | grep -E 'INSTALLED|FAIL|REFUSED|BLOCK' | cut -c1-50
done
echo ALLDONE

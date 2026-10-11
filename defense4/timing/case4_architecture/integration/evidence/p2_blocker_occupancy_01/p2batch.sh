#!/bin/bash
cd /home/philip/Projects/DNP3/defense4/timing/case4_architecture
SB=/tmp/claude-1002/-home-philip-Projects-DNP3/db04a002-eb4e-45b0-ac5b-b5c1bc10aaf5/scratchpad/shapeblock.sh
O=integration/evidence/p2_blocker_occupancy_01
run() { # label port args
  ssh -o BatchMode=yes decps@10.10.54.81 "rm -f /home/decps/Philip_repo/dnp3-defense4/response_only_diag_01/m_$1.json" 
  bash $SB $2 $O $1 "$3" 2>&1 | grep -E 'INSTALLED|FAIL|REFUSED|BLOCK'
}
run h3723        54471 "--shape-ack-pps 3723 --shape-resp-pps 3723 --shape-op-pps 3723"
run h14892       54472 "--shape-ack-pps 14892 --shape-resp-pps 14892 --shape-op-pps 14892"
run h3723_b3723  54473 "--shape-ack-pps 3723 --shape-resp-pps 3723 --shape-op-pps 3723 --shape-ack-blk-pps 3723 --shape-resp-blk-pps 3723 --shape-op-blk-pps 3723 --block-burst 64"
run h14892_b14892 54474 "--shape-ack-pps 14892 --shape-resp-pps 14892 --shape-op-pps 14892 --shape-ack-blk-pps 14892 --shape-resp-blk-pps 14892 --shape-op-blk-pps 14892 --block-burst 64"
echo ALLDONE

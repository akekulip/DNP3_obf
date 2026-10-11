#!/bin/bash
cd /home/philip/Projects/DNP3/defense4/timing/case4_architecture
PB=/tmp/claude-1002/-home-philip-Projects-DNP3/db04a002-eb4e-45b0-ac5b-b5c1bc10aaf5/scratchpad/prodblock.sh
O=integration/evidence/p2_production_01
run() { bash $PB $2 $O $1 50 "$3" 2>&1 | grep -E 'INSTALLED|FAIL|REFUSED|BLOCK|rror'; }
sh() { echo "--shape-ack-pps $1 --shape-resp-pps $1 --shape-op-pps $1 --shape-ack-blk-pps $1 --shape-resp-blk-pps $1 --shape-op-blk-pps $1 --block-burst 64"; }
run q_all3723    54501 "$(sh 3723)"
run q_all14892   54502 "$(sh 14892)"
run q_all59570   54503 "$(sh 59570)"
echo ALLDONE

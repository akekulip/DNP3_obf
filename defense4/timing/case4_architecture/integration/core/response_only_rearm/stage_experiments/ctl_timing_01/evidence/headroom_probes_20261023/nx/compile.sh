#!/bin/bash
# usage: compile.sh NAME   (compiles NAME.p4 into build_NAME/, one at a time via flock)
set -u
D=/home/philip/Projects/DNP3/.scratch_p4
N=$1
exec 9>$D/.compile.lock
flock 9
rm -rf $D/build_$N; mkdir -p $D/build_$N/source
cp $D/$N.p4 $D/build_$N/source/response_only.p4
start=$(date +%s)
/home/philip/bf-sde-9.13.1/install/bin/bf-p4c --target tofino --arch tna -g -o $D/build_$N/out $D/build_$N/source/response_only.p4 > $D/build_$N/compile.log 2>&1
rc=$?
echo "exit=$rc elapsed=$(( $(date +%s)-start ))s" > $D/build_$N/status
sha256sum $D/$N.p4 >> $D/build_$N/status
if [ $rc -eq 0 ]; then python3 $D/metrics.py $D/build_$N/out > $D/build_$N/metrics.txt 2>&1; fi

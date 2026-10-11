#!/bin/bash
# prodblock.sh MASTERPORT OUTDIR LABEL READS "EXTRA_ARGS" — cold bring-up of the PRODUCTION build, one T-on run
set -e
MP=$1; OUT=$2; LABEL=$3; READS=$4; EXTRA=$5
S="ssh -o BatchMode=yes decps@10.10.54.81"; V="ssh -o BatchMode=yes decps@10.10.54.19"
R=/home/decps/Philip_repo/dnp3-defense4/response_only_sbo_01
H=$R/src/integration/core/response_only/hw
BF=ee9986058d520fcb11e6c869ba6962f33b9dde89d1cfceb67f79a73bfd40e118
P0=741fee7ee23c720d3b7490bc29767db4d1cb8354290060d8d10e60b879e068a3
P1=084e496313f981190e099d86e00022803d26843a4336a75a7ab61d9e0a59de1f
mkdir -p "$OUT/$LABEL"
SNAP=$(echo "$EXTRA" | sed -E "s/--block-burst [0-9]+//")   # snapshot_counters has no --block-burst
$S "rm -f $R/m_$LABEL.json; bash /tmp/swap.sh $R/launch.sh $R/sw_$LABEL.log >/dev/null 2>&1; grep -c 'initialized 1 devices' $R/sw_$LABEL.log"
$S "cd /home/decps/framework_build_20261006 && python3 restore_ports.py response_only /tmp/pre_p2prod.json --apply --wait 35 2>&1 | grep -c 'dp9 enable=True'"
teardown() { $S "cd $H && DEFENSE4_HW_AUTHORIZED=1 python3 bringup_teardown.py --manifest $R/m_$LABEL.json --apply 2>/dev/null | grep -E 'UNDONE|STOPPED' || true"; }
trap teardown EXIT
$S "cd $H && DEFENSE4_HW_AUTHORIZED=1 python3 bringup_composite.py --build-out $R/out --expect bfrt.json=$BF --expect p0/tofino.bin=$P0 --expect p1/tofino.bin=$P1 --master-ip 192.168.10.61 --master-port $MP --master-dev 9 --relay-ip 192.168.10.62 --relay-port 20000 --relay-dev 9 --read-dst 0x0a00 --read-src 0x0100 --t-enabled 1 $EXTRA --manifest-out $R/m_$LABEL.json --enable-pktgen --apply 2>&1 | grep -E '^(INSTALLED|FAIL|REFUSED)'"
$S "cd $H && DEFENSE4_HW_AUTHORIZED=1 python3 snapshot_counters.py --build-out $R/out $SNAP -o $R/snb_$LABEL.json >/dev/null 2>&1; echo snb"
$V "sudo python3 /home/decps/pad58b_20261011/vision_run.py run $LABEL --master-port $MP --reads $READS --range 8 --gap-ms 20" | tail -1
$S "cd $H && DEFENSE4_HW_AUTHORIZED=1 python3 snapshot_counters.py --build-out $R/out $SNAP -o $R/sna_$LABEL.json >/dev/null 2>&1; echo sna"
scp -q "decps@10.10.54.81:$R/snb_$LABEL.json" "decps@10.10.54.81:$R/sna_$LABEL.json" "$OUT/$LABEL/" 2>/dev/null
$V "cd /home/decps/pad58b_20261011/runs/$LABEL && tar c master.json outstation.json result.json out.pcap in.pcap state.txt" | tar x -C "$OUT/$LABEL" 2>/dev/null
echo "BLOCK $LABEL done [$EXTRA]"

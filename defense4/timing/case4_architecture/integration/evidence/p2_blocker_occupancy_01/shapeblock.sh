#!/bin/bash
# shapeblock.sh MASTERPORT OUTDIR LABEL "EXTRA_SHAPE_ARGS" — cold bring-up of diag build with optional shaping, one T-on 5ms run
set -e
MP=$1; OUT=$2; LABEL=$3; SHAPE=$4
S="ssh -o BatchMode=yes decps@10.10.54.81"; V="ssh -o BatchMode=yes decps@10.10.54.19"
R=/home/decps/Philip_repo/dnp3-defense4/response_only_diag_01
H=$R/src/integration/core/response_only/hw
BF=8c687b7266c87a5672e3331d20bb9b9bacbfd9f57cac49b49484887550b67cee
P0=2855def33c0c651ac875c1d0567f19eaa3fed6f07a9feb51c0ca1359783fd4b8
P1=15d226e877ced41ee4d5ef17ace8da2ea1b5f9ea81a3a684270f46bc1ddc7044
mkdir -p "$OUT/$LABEL"
$S "bash /tmp/swap.sh $R/launch.sh $R/sw_$LABEL.log >/dev/null 2>&1; grep -c 'initialized 1 devices' $R/sw_$LABEL.log"
$S "cd /home/decps/framework_build_20261006 && python3 restore_ports.py response_only /tmp/pre_shape_snapshot.json --apply --wait 35 2>&1 | grep -c 'dp9 enable=True'"
$S "cd $H && DEFENSE4_HW_AUTHORIZED=1 python3 bringup_composite.py --build-out $R/out --expect bfrt.json=$BF --expect p0/tofino.bin=$P0 --expect p1/tofino.bin=$P1 --master-ip 192.168.10.61 --master-port $MP --master-dev 9 --relay-ip 192.168.10.62 --relay-port 20000 --relay-dev 9 --read-dst 0x0a00 --read-src 0x0100 --t-enabled 1 $SHAPE --manifest-out $R/m_$LABEL.json --enable-pktgen --apply 2>&1 | grep -E '^(INSTALLED|FAIL|REFUSED)'"
$S "cd $H && DEFENSE4_HW_AUTHORIZED=1 python3 snapshot_counters.py --build-out $R/out -o $R/snb_$LABEL.json >/dev/null 2>&1; echo snb"
$V "sudo python3 /home/decps/pad58b_20261011/vision_run.py run $LABEL --master-port $MP --reads 10 --range 8 --gap-ms 20" | tail -1
$S "cd $H && DEFENSE4_HW_AUTHORIZED=1 python3 snapshot_counters.py --build-out $R/out -o $R/sna_$LABEL.json >/dev/null 2>&1; echo sna"
scp -q "decps@10.10.54.81:$R/snb_$LABEL.json" "decps@10.10.54.81:$R/sna_$LABEL.json" "$OUT/$LABEL/" 2>/dev/null
$V "cd /home/decps/pad58b_20261011/runs/$LABEL && tar c master.json outstation.json result.json out.pcap in.pcap" | tar x -C "$OUT/$LABEL" 2>/dev/null
$S "cd $H && DEFENSE4_HW_AUTHORIZED=1 python3 bringup_teardown.py --manifest $R/m_$LABEL.json --apply 2>/dev/null | grep -E 'UNDONE|STOPPED' || true"
echo "BLOCK $LABEL done [$SHAPE]"

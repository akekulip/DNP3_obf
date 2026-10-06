#!/bin/bash
# Load a compiled build on the SDE's Tofino MODEL (no ASIC, no lab) inside an unprivileged user+network namespace, and report whether the
# driver instantiates the device. This is the offline stand-in for the load step that failed on the switch (`bf_device_add ... Not enough space`).
# usage: load_on_model.sh BUILD_OUT_DIR PROGRAM_NAME WORKDIR
set -u
OUT="$1"; PROG="$2"; W="$3"; mkdir -p "$W"
if [ -z "${INSIDE_NS:-}" ]; then INSIDE_NS=1 exec unshare -Urn bash "$0" "$@"; fi
export SDE=${SDE:-$HOME/bf-sde-9.13.1}; export SDE_INSTALL=$SDE/install
export PATH=$SDE_INSTALL/bin:$PATH
export LD_LIBRARY_PATH=$SDE_INSTALL/lib:/usr/local/lib:${LD_LIBRARY_PATH:-}
ip link set lo up
bash $SDE_INSTALL/bin/veth_setup.sh 64 > "$W/veth.log" 2>&1
python3 - "$OUT" "$PROG" "$W" <<'PY'
import json, sys
out, prog, w = sys.argv[1:4]
conf = {"chip_list": [{"chip_family": "tofino", "instance": 0, "pcie_sysfs_prefix": "/sys/devices/pci0000:00/0000:00:03.0/0000:05:00.0",
                       "sds_fw_path": "share/tofino_sds_fw/avago/firmware"}],
        "p4_devices": [{"device-id": 0, "p4_programs": [{"program-name": prog, "bfrt-config": out + "/bfrt.json",
            "p4_pipelines": [{"p4_pipeline_name": "pipe", "context": out + "/pipe/context.json", "config": out + "/pipe/tofino.bin",
                              "pipe_scope": [0, 1, 2, 3], "path": out}]}]}]}
json.dump(conf, open(w + "/model.conf", "w"), indent=1)
PY
tofino-model -d 1 -k 1 -f $SDE/pkgsrc/switch-p4-16/ptf/ports.json --p4-target-config "$W/model.conf" --install-dir $SDE_INSTALL --chip-type 2 --logs-disable > "$W/model.log" 2>&1 &
MP=$!
sleep 4
( tail -f /dev/null | timeout 60 bf_switchd --install-dir $SDE_INSTALL --conf-file "$W/model.conf" --init-mode=cold --status-port 7777 > "$W/switchd.log" 2>&1 ) &
for i in $(seq 1 90); do
  if grep -q "bf_device_add failed\|Device add failed" "$W/switchd.log" 2>/dev/null; then echo "RESULT: device add FAILED"; break; fi
  if (echo > /dev/tcp/127.0.0.1/50052) 2>/dev/null; then echo "RESULT: device instantiated, gRPC up"; break; fi
  sleep 1
done
grep -E "ERROR" "$W/switchd.log" | head -8 | cut -c1-200
pkill -P $$ -f bf_switchd 2>/dev/null; pkill tofino-model 2>/dev/null; kill $MP 2>/dev/null
exit 0

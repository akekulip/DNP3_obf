#!/bin/bash
# Corrected fixed-K loopback smoke that PRESERVES the full evidence package (directive §1).
# EMULATOR ONLY (gambit loopback 127.0.0.1). No rig, no switch, no physical relay.
# K=4, R=2: real points 0,1 + inert decoys 16,17. 1 warm-up + 6 scored SBOs on ONE connection.
set -uo pipefail
H=/home/philip/Projects/DNP3/dnp3_multicrob_harness
TS=$(date -u +%Y%m%dT%H%M%SZ)
EV="$H/../defense4/evidence/fixed_k_emulator/smoke_$TS"
mkdir -p "$EV"
cd "$H"
fuser -k 20000/tcp 2>/dev/null || true; sleep 1
DECOYS=$(python3 -c "print(','.join(str(i) for i in range(16,32)))")

# --- environment + version manifest ---
{
  echo "run_ts_utc: $TS"
  echo "host: $(hostname)"
  echo "git_commit: $(git -C "$H/.." rev-parse HEAD)"
  echo "python3: $(python3 --version 2>&1)"
  echo "pydnp3: $(python3 -c 'import pydnp3,os;print(getattr(pydnp3,"__file__",""))' 2>&1)"
  echo "gpp: $(g++ --version | head -1)"
  echo "opendnp3_repo: /home/philip/Projects/opendnp3-community"
  echo "opendnp3_git: $(git -C /home/philip/Projects/opendnp3-community rev-parse HEAD 2>/dev/null || echo 'n/a')"
  echo "libopendnp3_sha256: $(sha256sum /home/philip/Projects/opendnp3-community/build/cpp/lib/libopendnp3.so | cut -d' ' -f1)"
  echo "nsbo_master_src_sha256: $(sha256sum "$H/fixed_k/nsbo_master.cpp" | cut -d' ' -f1)"
} > "$EV/environment_manifest.txt"

# --- build command (recorded) ---
echo "bash fixed_k/build.sh" > "$EV/build_command.txt"
bash fixed_k/build.sh >> "$EV/build_command.txt" 2>&1

# --- start emulator (fixed-K: 32 points, decoys 16..31, known initial state, JSONL evidence) ---
EMU_LOG="$EV/outstation_console.log"
OJSONL="$EV/outstation_objects.jsonl"
OJSON="$EV/outstation_summary.json"
nohup python3 run_outstation.py --control-test --control-point-count 32 \
      --decoy-indexes "$DECOYS" --fixed-k-initial-state \
      --control-jsonl "$OJSONL" --control-json "$OJSON" \
      --host 127.0.0.1 --local-addr 10 --remote-addr 1 --run-id smoke_K4_R2 \
      > "$EMU_LOG" 2>&1 < /dev/null &
EMU=$!
for i in $(seq 1 40); do grep -q "Outstation running" "$EMU_LOG" && break; sleep 0.5; done
grep -q "Outstation running" "$EMU_LOG" || { echo "EMU NOT READY"; kill $EMU 2>/dev/null; exit 1; }

# --- capture ---
PCAP="$EV/smoke_K4_R2.pcap"
sg wireshark -c "dumpcap -i lo -q -f 'tcp port 20000' -w $PCAP" > /dev/null 2>&1 &
TD=$!; sleep 1.5

# --- exact execution command (recorded) + run the hardened master (7 SBOs = 1 warmup + 6 scored) ---
MJSON="$EV/master.json"
CMD="./fixed_k/nsbo_master --host 127.0.0.1 --reps 7 --indexes 0,1,16,17 --mode alt --out $MJSON --expect-k 4 --expect-r 2 --block-id smoke_K4_R2 --seed 0"
echo "$CMD" > "$EV/execution_command.txt"
$CMD > "$EV/master_console.log" 2>&1
MRC=$?
sleep 1; kill $TD 2>/dev/null; sleep 1; kill $EMU 2>/dev/null; fuser -k 20000/tcp 2>/dev/null || true; sleep 1

# --- verdicts ---
echo "master_exit: $MRC" >> "$EV/execution_command.txt"
echo "=== smoke verdicts ===" | tee "$EV/SMOKE_VERDICTS.txt"
python3 - "$MJSON" "$OJSON" "$EV/SMOKE_VERDICTS.txt" <<'PY' 2>&1 | tee -a "$EV/SMOKE_VERDICTS.txt"
import json,sys
mj=json.load(open(sys.argv[1])); oj=json.load(open(sys.argv[2]))
print("master: %d/%d SUCCESS, aborted=%s"%(mj['success'],mj['total'],mj['aborted']))
print("outstation real_effects_indexes:", oj['real_effects_indexes'])
print("outstation decoys_actuated:", oj['decoys_actuated'], "(MUST be [])")
print("outstation decoy_inertness_ok:", oj['decoy_inertness_ok'])
print("outstation actuation_count real 0/1:", oj['actuation_count'].get('0'), oj['actuation_count'].get('1'))
print("outstation actuation_count decoy 16/17:", oj['actuation_count'].get('16'), oj['actuation_count'].get('17'))
PY
{
echo "SYN(client): $(sg wireshark -c "tshark -r $PCAP -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' 2>/dev/null" | wc -l) (expect 1)"
echo "FIN: $(sg wireshark -c "tshark -r $PCAP -Y 'tcp.flags.fin==1' 2>/dev/null" | wc -l) (expect 2)"
echo "RST: $(sg wireshark -c "tshark -r $PCAP -Y 'tcp.flags.reset==1' 2>/dev/null" | wc -l) (expect 0)"
echo "SELECT: $(sg wireshark -c "tshark -r $PCAP -Y 'dnp3.al.func==3' 2>/dev/null" | wc -l) (expect 7)"
echo "OPERATE: $(sg wireshark -c "tshark -r $PCAP -Y 'dnp3.al.func==4' 2>/dev/null" | wc -l) (expect 7)"
} | tee -a "$EV/SMOKE_VERDICTS.txt"

# --- SHA-256 manifest of every artifact ---
( cd "$EV" && sha256sum * > SHA256SUMS.txt 2>/dev/null; sed -i '/SHA256SUMS.txt/d' SHA256SUMS.txt )
echo "EVIDENCE_DIR: $EV"
echo "$EV" > /tmp/fixedk_smoke_evdir.txt

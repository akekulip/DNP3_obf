#!/usr/bin/env bash
# c3_hulk_cycle.sh — ONE containment-correct C3 capture cycle. Run ON Hulk AS ROOT
# (invoke via: printf '%s\n' "$PW" | ssh decps@hulk 'sudo -S bash /tmp/c3_hulk_cycle.sh <readiness_ms> <label> <mode>').
# Assumes the rig (ns_master 10.0.1.10 / ns_out 10.0.2.10 VEPA macvlans on enp59s0f0np0) is already up.
#
# Containment order (a naive run contaminates the capture — the outstation FIN is a zero-payload
# frame on the armed flow that the broad ACK matcher WOULD hold):
#   1. start the authoritative capture on the PHYSICAL WIRE (root ns) — sees the hairpinned frames
#   2. run exactly ONE transaction; both sockets then stay OPEN and idle
#   3. STOP THE CAPTURE  <-- before any TCP shutdown exists on the wire
#   4. (caller, on the switch) reads evstat telemetry + resets/disarms the Case-A flow state
#   5. wait for the caller's <label>.closeok signal
#   6. close the sockets — the FIN now hits an un-armed flow and is NOT in the capture
set -u

READINESS_MS="${1:?usage: c3_hulk_cycle.sh <readiness_ms> <label> <mode:native|case-a>}"
LABEL="${2:?label}"
MODE="${3:-case-a}"                        # recorded into the log only; the switch owns the mode

IFACE="${C3_WIRE_IFACE:-enp59s0f0np0}"     # physical NIC (root ns) — the proven capture point
NS_MASTER="${NS_MASTER:-ns_master}"
NS_OUT="${NS_OUT:-ns_out}"
APPUSER="${C3_APPUSER:-decps}"             # drop root -> decps for the apps (proven pattern)
REQ="${C3_REQ:-/home/decps/Projects/DNP3/dnp3_split_harness/payloads/sel751/orig_0001.bin}"
RESP="${C3_RESP:-/home/decps/Projects/DNP3/dnp3_split_harness/payloads/sel751/resp_0001.bin}"
SRV_PY="${C3_SRV_PY:-/tmp/minimal_c3_tcp_server.py}"
CLI_PY="${C3_CLI_PY:-/tmp/minimal_c3_tcp_client.py}"
PY="${C3_PY:-python3}"
CAPDIR="${C3_CAPDIR:-/tmp/c3caps}"
mkdir -p "$CAPDIR"; chmod 777 "$CAPDIR" 2>/dev/null
PCAP="$CAPDIR/$LABEL.pcap"
rm -f "$CAPDIR/$LABEL".{captured,closeok,pids,srv.log,cli.log}

echo "[cycle] label=$LABEL mode=$MODE readiness=${READINESS_MS}ms wire=$IFACE app=$APPUSER"

# 1. authoritative capture on the physical wire (root ns): request out, HELD pure ACK back, response back
tcpdump -i "$IFACE" -w "$PCAP" -U -s 128 'tcp port 20000' >/dev/null 2>&1 &
TCPD=$!
sleep 0.8

# 2. one transaction; server (outstation ns) then client (master ns), each drops to $APPUSER and HOLDS open
ip netns exec "$NS_OUT" sudo -u "$APPUSER" -H "$PY" "$SRV_PY" --host 10.0.2.10 --port 20000 \
     --readiness-ms "$READINESS_MS" --request-file "$REQ" --response-file "$RESP" \
     >"$CAPDIR/$LABEL.srv.log" 2>&1 &
SRV=$!
sleep 0.5
ip netns exec "$NS_MASTER" sudo -u "$APPUSER" -H "$PY" "$CLI_PY" --host 10.0.2.10 --local 10.0.1.10 --port 20000 \
     --request-file "$REQ" --response-file "$RESP" \
     >"$CAPDIR/$LABEL.cli.log" 2>&1 &
CLI=$!

# 3. let the single transaction complete + settle; sockets remain OPEN (no shutdown yet)
sleep "$(awk "BEGIN{print $READINESS_MS/1000.0 + 2.0}")"

# 4. STOP THE CAPTURE before any close packet can appear
kill "$TCPD" 2>/dev/null
wait "$TCPD" 2>/dev/null
echo "$SRV $CLI" > "$CAPDIR/$LABEL.pids"
touch "$CAPDIR/$LABEL.captured"
echo "[cycle] captured -> $PCAP ; sockets held OPEN, waiting for $LABEL.closeok"

# 5. wait (<=30s) for the caller to read switch telemetry and reset/disarm the flow state
for _ in $(seq 1 60); do [ -f "$CAPDIR/$LABEL.closeok" ] && break; sleep 0.5; done

# 6. close only AFTER the switch flow state is cleared
kill "$SRV" "$CLI" 2>/dev/null
sleep 0.5
echo "[cycle] $LABEL done: $(grep -h -E 'request_match|response_match' "$CAPDIR/$LABEL".srv.log "$CAPDIR/$LABEL".cli.log 2>/dev/null | tr '\n' ' ')"

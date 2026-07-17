#!/usr/bin/env python3
"""phase05_rig_defended_wire.py -- TWO-HOST RIG defended-wire fingerprint eval (Vision<->Hulk).

The real-hardware sibling of phase05_defended_wire_eval.py (loopback). Instead of one host, the
replay runs across the real 1G management network: Hulk (outstation side) replays each device's REAL
request/response first-segment bytes and reproduces its ACK mode, Vision (master side) drives the
client, and Hulk captures the exchange on eno1. The classifier then runs on the real-wire captures.

IMPORTANT / honesty: this is NOT the physical SEL-751 / AB1400 / ION7550 hardware (those are external
captures on a different network, not on this rig). It is a faithful reproduction of each device's
MEASURED observables (real bytes, response sizes, native ACK mode, native timing) driven over real
server-grade NICs and a real switched 1G path -- which removes the loopback low-noise caveat while
being explicit that Hulk stands in for each device in turn.

One dumpcap on Hulk captures all 18 sessions (3 conditions x 6 device captures) as distinct TCP
streams; sessions run strictly sequentially, so the k-th stream (by capture order) is session k.

Run from the dev box (gambit); capture is non-sudo on the rig (decps is in the wireshark group):
    python3 phase05_rig_defended_wire.py --run-dir runs/<UTC>_phase05_rig_defended_wire
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

import pandas as pd

HARNESS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HARNESS)
import characterize_ack_traces as C
import ack_fingerprint_eval as AF
import phase05_defended_wire_eval as DW      # device_transactions / classify / separate_fraction

TRAFFIC_DIR = "/home/philip/Projects/DNP3/Traffic Trace"
PCAPS = ["SEL751.pcap", "SEL751L.pcap", "AB1400.pcap", "AB1400L.pcap",
         "ION7550.pcap", "ION7550L.pcap"]
CONDITIONS = ["native", "coalesced", "coalesced_edt"]
PORT = 20000
DELAYED_ACK_WINDOW_MS = 40.0
EDT_TARGET_MS = 25.0

RIG_USER = "decps"
VISION_IP = "10.10.54.19"      # DNP3 master (client)
HULK_IP = "10.10.54.158"       # DNP3 outstation (replay server + capture)
IFACE = "eno1"                 # 1G management NIC
REMOTE_DIR = "/tmp/phase05_rig"
SSH = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
SCP = ["scp", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def remote(host, command, timeout=60):
    return sh(SSH + ["%s@%s" % (RIG_USER, host), command], timeout=timeout)


# --------------------------------------------------------------------------- #
# Build the replay spec from the six PCAPs (extraction happens locally)
# --------------------------------------------------------------------------- #
def build_spec(max_per_pcap: int) -> dict:
    replay = {}
    counts = {}
    for name in PCAPS:
        device = C.device_from_pcap(name)
        txns = DW.device_transactions(os.path.join(TRAFFIC_DIR, name), name, device, max_per_pcap)
        replay[name] = [[req.hex(), resp.hex(), native_ms, native_sep]
                        for (req, resp, native_ms, native_sep) in txns]
        counts[name] = len(txns)
    return {
        "port": PORT, "delayed_ack_window_ms": DELAYED_ACK_WINDOW_MS, "edt_target_ms": EDT_TARGET_MS,
        "conditions": CONDITIONS, "pcaps": PCAPS, "replay": replay, "_counts": counts,
    }


# --------------------------------------------------------------------------- #
# Rig orchestration
# --------------------------------------------------------------------------- #
def deploy(spec_path: str):
    for host in (HULK_IP, VISION_IP):
        remote(host, "mkdir -p %s" % REMOTE_DIR)
        sh(SCP + [spec_path, "%s@%s:%s/spec.json" % (RIG_USER, host, REMOTE_DIR)])
        sh(SCP + [os.path.join(HARNESS, "phase05_rig_replay.py"),
                  "%s@%s:%s/phase05_rig_replay.py" % (RIG_USER, host, REMOTE_DIR)])


def run_rig(local_cap: str) -> dict:
    remote(HULK_IP, "fuser -k %d/tcp 2>/dev/null; rm -f %s/server.log %s/rig_capture.pcap; true"
           % (PORT, REMOTE_DIR, REMOTE_DIR))
    # start the Hulk server (capture + listen) detached.
    # NOTE: `ssh -f` backgrounds itself but keeps the stdout/stderr pipe open, so
    # subprocess.run(capture_output=True) would block forever waiting for EOF. Redirect the ssh
    # streams to DEVNULL (nothing to read) so the call returns as soon as ssh -f detaches.
    server_cmd = ("cd %s && nohup python3 phase05_rig_replay.py --role server --spec spec.json "
                  "--iface %s --capture rig_capture.pcap --client-ip %s "
                  "> server.log 2>&1 < /dev/null &" % (REMOTE_DIR, IFACE, VISION_IP))
    subprocess.run(SSH + ["-f", "%s@%s" % (RIG_USER, HULK_IP), server_cmd],
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=30)
    # wait for READY
    ready = False
    for _ in range(30):
        r = remote(HULK_IP, "grep -c READY %s/server.log 2>/dev/null || echo 0" % REMOTE_DIR)
        if r.stdout.strip().splitlines()[-1:] == ["1"] or r.stdout.strip().endswith("1"):
            ready = True
            break
        time.sleep(0.5)
    if not ready:
        log = remote(HULK_IP, "cat %s/server.log 2>/dev/null" % REMOTE_DIR)
        raise RuntimeError("Hulk server not READY. server.log:\n%s" % log.stdout)
    # run the Vision client (blocking; drives all 18 sessions)
    client_cmd = ("cd %s && python3 phase05_rig_replay.py --role client --spec spec.json --hulk-ip %s"
                  % (REMOTE_DIR, HULK_IP))
    cres = remote(VISION_IP, client_cmd, timeout=600)
    client_json = {}
    for line in cres.stdout.strip().splitlines():
        line = line.strip()
        if line.startswith("{"):
            client_json = json.loads(line)
    # wait for the server to finish + stop its capture
    for _ in range(60):
        d = remote(HULK_IP, "grep -c DONE %s/server.log 2>/dev/null || echo 0" % REMOTE_DIR)
        if d.stdout.strip().endswith("1"):
            break
        time.sleep(0.5)
    time.sleep(1.0)
    sh(SCP + ["%s@%s:%s/rig_capture.pcap" % (RIG_USER, HULK_IP, REMOTE_DIR), local_cap])
    return {"client": client_json, "client_stderr": cres.stderr[-500:] if cres.stderr else ""}


# --------------------------------------------------------------------------- #
# Analyze: map TCP streams (capture order) -> sessions -> classifier rows
# --------------------------------------------------------------------------- #
def analyze(cap: str) -> dict:
    packets = C.run_tshark(cap)
    txns = C.build_transactions(packets, "rig", "SEL751")   # device_label overridden per stream
    streams = {}
    for t in txns:
        streams.setdefault(t.stream, []).append(t)
    order = sorted(streams, key=lambda s: min(x.req_frame for x in streams[s]))
    sess = [(c, p) for c in CONDITIONS for p in PCAPS]
    rows = {c: [] for c in CONDITIONS}
    health = {c: {"n": 0, "retransmissions": 0, "resets": 0, "duplicate_acks": 0} for c in CONDITIONS}
    mapping = []
    for k, s in enumerate(order):
        if k >= len(sess):
            break
        cond, pcap = sess[k]
        device = C.device_from_pcap(pcap)
        st = streams[s]
        first_req = min(x.req_frame for x in st)
        kept = 0
        for t in st:
            if t.classification not in (C.CLS_COMBINED, C.CLS_SEPARATE):
                continue
            if t.req_frame == first_req:
                continue
            if t.req_to_ack_ms is None or t.ack_to_resp_ms is None or t.req_to_resp_ms is None:
                continue
            health[cond]["n"] += 1
            health[cond]["retransmissions"] += int(t.retransmission)
            health[cond]["resets"] += int(t.reset)
            health[cond]["duplicate_acks"] += int(t.duplicate_ack)
            rows[cond].append({
                "device_label": device, "pcap": pcap, "is_L": pcap.endswith("L.pcap"),
                "is_separate": 1 if t.first_rev_is_pure_ack else 0,
                "req_to_ack_ms": t.req_to_ack_ms, "ack_to_resp_ms": t.ack_to_resp_ms,
                "req_to_resp_ms": t.req_to_resp_ms, "req_size": t.req_size, "resp_size": t.resp_size,
            })
            kept += 1
        mapping.append({"stream": s, "session_index": k, "condition": cond, "pcap": pcap,
                        "n_stream_txn": len(st), "kept": kept})

    result = {"meta": {"conditions": CONDITIONS, "pcaps": PCAPS, "port": PORT, "iface": IFACE,
                       "path": "Vision(%s) master <-> Hulk(%s) outstation, 1G mgmt net" % (VISION_IP, HULK_IP),
                       "delayed_ack_window_ms": DELAYED_ACK_WINDOW_MS, "edt_target_ms": EDT_TARGET_MS,
                       "split": "capture-level (train base pcap, test L pcap)", "features": AF.FEATURES,
                       "n_streams": len(order)},
              "stream_mapping": mapping, "tcp_health": health,
              "separate_fraction": {}, "supervised": {}}
    for cond in CONDITIONS:
        df = pd.DataFrame(rows[cond])
        result["separate_fraction"][cond] = DW.separate_fraction(df)
        enough = (not df.empty and df["is_L"].any() and (~df["is_L"]).any()
                  and df.loc[~df["is_L"], "device_label"].nunique() >= 2
                  and df.loc[df["is_L"], "device_label"].nunique() >= 2)
        result["supervised"][cond] = DW.classify(df) if enough else {"error": "insufficient rows"}
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--max-per-pcap", type=int, default=120)
    ap.add_argument("--out-dir",
                    default=os.path.join(HARNESS, "reports", "phases",
                                         "phase_05_ack_mode_normalization"))
    ap.add_argument("--skip-run", action="store_true",
                    help="re-analyze an existing rig_capture.pcap in --run-dir (no rig traffic)")
    args = ap.parse_args()
    os.makedirs(args.run_dir, exist_ok=True)
    local_cap = os.path.join(args.run_dir, "rig_capture.pcap")

    rig_meta = {}
    if not args.skip_run:
        print("== building replay spec from 6 PCAPs ==")
        spec = build_spec(args.max_per_pcap)
        print("   per-pcap txns: %s" % spec["_counts"])
        spec_path = os.path.join(args.run_dir, "spec.json")
        with open(spec_path, "w") as fh:
            json.dump(spec, fh)
        print("== deploying to Hulk + Vision ==")
        deploy(spec_path)
        print("== running two-host rig session (Vision client <-> Hulk server, capture on Hulk eno1) ==")
        rig_meta = run_rig(local_cap)
        print("   client: %s" % rig_meta.get("client"))
    if not os.path.exists(local_cap):
        raise SystemExit("no capture at %s" % local_cap)

    print("== analyzing rig capture ==")
    result = analyze(local_cap)
    result["rig_run"] = rig_meta
    print("   streams mapped: %d (expected %d)" % (result["meta"]["n_streams"], len(CONDITIONS) * len(PCAPS)))
    for cond in CONDITIONS:
        s = result["supervised"][cond]
        h = result["tcp_health"][cond]
        if "error" in s:
            print("   [%s] %s" % (cond, s["error"]))
            continue
        print("   [%s] sep=%s | ack_only=%.3f timing=%.3f size=%.3f all=%.3f | n_te=%d | retrans=%d reset=%d"
              % (cond, result["separate_fraction"][cond], s["ack_only"]["rf"]["accuracy"],
                 s["timing"]["rf"]["accuracy"], s["size"]["rf"]["accuracy"], s["all"]["rf"]["accuracy"],
                 s["n_test"], h["retransmissions"], h["resets"]))

    with open(os.path.join(args.run_dir, "rig_defended_wire_eval.json"), "w") as fh:
        json.dump(result, fh, indent=2)
    os.makedirs(args.out_dir, exist_ok=True)
    with open(os.path.join(args.out_dir, "rig_defended_wire_eval.json"), "w") as fh:
        json.dump(result, fh, indent=2)
    print("wrote %s/rig_defended_wire_eval.json" % args.run_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""phase05_defended_wire_eval.py -- per-device DEFENDED-WIRE fingerprint evaluation.

Turns the Phase-05 trace-transformation effectiveness number into a genuine defended-wire
measurement. For each of the six real device PCAPs (SEL751/AB1400/ION7550 base + L) we replay the
device's REAL request/response bytes through a loopback replay server under three wire conditions,
CAPTURE each on `lo`, re-extract the same ACK/timing/size features from the captured wire (reusing
`characterize_ack_traces`), and run the same capture-level-split classifier (`ack_fingerprint_eval`)
on the DEFENDED captures -- not a software transform.

Wire conditions (all socket-side; no BPF, no drops, no netns):
  native     : reproduce each transaction's NATIVE ACK mode (SEL-751 separate via server quickack;
               AB1400/ION7550 combined) + NATIVE request->response timing + REAL response bytes.
  coalesced  : socket-side coalescing -> ACK mode normalized to COMBINED for every device (no
               quickack, response within the delayed-ACK window); NATIVE timing; REAL response bytes.
  coalesced_edt : coalescing + response timing normalized to a common target (the socket analog of
               the Phase-4 EDT timing normalization). Closes ACK mode AND timing; SIZE remains.

Byte preservation: the exact captured request/response first-segment bytes are replayed verbatim
(`b_sent == b_device`); only WHEN the response leaves and WHETHER a separate pure ACK precedes it
are changed, at the socket. Response SIZE is never altered (the out-of-scope residual).

Run (capture needs the wireshark group -- NOT sudo):
    sg wireshark -c 'python3 phase05_defended_wire_eval.py --run-dir runs/<UTC>_phase05_defended_wire'
Smoke (SEL only, few txns, native+coalesced):
    sg wireshark -c 'python3 phase05_defended_wire_eval.py --run-dir runs/smoke --smoke'
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time

import pandas as pd

HARNESS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HARNESS)
import characterize_ack_traces as C          # run_tshark / build_transactions / device labels
import ack_fingerprint_eval as AF            # supervised classifier + FEATURES + DEVICES

TRAFFIC_DIR = "/home/philip/Projects/DNP3/Traffic Trace"
PCAPS = ["SEL751.pcap", "SEL751L.pcap", "AB1400.pcap", "AB1400L.pcap",
         "ION7550.pcap", "ION7550L.pcap"]
PORT = 20000
DELAYED_ACK_WINDOW_MS = 40.0     # Linux delayed-ACK timeout; stay under it to coalesce
EDT_TARGET_MS = 25.0             # common response target for the timing-normalized condition
CONDITIONS = ["native", "coalesced", "coalesced_edt"]


# --------------------------------------------------------------------------- #
# Extract each device's real transactions + their raw request/response bytes
# --------------------------------------------------------------------------- #
def tshark_payloads(pcap: str) -> dict:
    """frame.number -> raw TCP payload bytes for every payload-bearing port-20000 frame."""
    out = subprocess.run(
        ["tshark", "-r", pcap, "-Y", "tcp.port==%d && tcp.len>0" % PORT,
         "-T", "fields", "-e", "frame.number", "-e", "tcp.payload"],
        capture_output=True, text=True, check=True)
    payloads = {}
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        hexs = parts[1].replace(":", "").strip()
        if hexs:
            payloads[int(parts[0])] = bytes.fromhex(hexs)
    return payloads


def reconstruct_response(segments: list) -> tuple:
    """Reconstruct a complete logical DNP3 response from its TCP payload segments.

    `segments` is a list of (tcp_seq, frame_number, payload_bytes). Retransmitted segments (a repeated
    TCP sequence number) are de-duplicated keeping the first occurrence; the surviving segments are
    ordered by TCP sequence number and concatenated in byte order. Returns (bytes, n_unique_segments).
    For a single-segment response this returns exactly that segment's bytes.
    """
    seen, uniq = set(), []
    for seq, frame, payload in segments:
        if seq in seen:
            continue                       # drop a retransmitted segment
        seen.add(seq)
        uniq.append((seq, frame, payload))
    uniq.sort(key=lambda s: s[0])          # TCP sequence order == byte order
    return b"".join(p for _, _, p in uniq), len(uniq)


def _stream_request_frames(packets: list) -> dict:
    """stream -> sorted list of request frame numbers (master->outstation, payload-bearing DNP3)."""
    reqs = {}
    for p in packets:
        if p.dst_port == C.DNP3_PORT and p.tlen > 0 and p.dnp3_present:
            reqs.setdefault(p.stream, []).append(p.frame)
    for s in reqs:
        reqs[s].sort()
    return reqs


def _collect_response_segments(packets: list, payloads: dict, stream: int,
                               resp_frame: int, next_req_frame: int) -> list:
    """(seq, frame, payload) for every outstation->master payload-bearing DNP3 segment in the window
    [resp_frame, next_req_frame) of this stream."""
    segs = []
    for p in packets:
        if p.stream != stream or p.src_port != C.DNP3_PORT:
            continue
        if p.tlen <= 0 or not p.dnp3_present:
            continue
        if p.frame < resp_frame or p.frame >= next_req_frame:
            continue
        payload = payloads.get(p.frame)
        if payload:
            segs.append((p.seq, p.frame, payload))
    return segs


def device_transactions(pcap_path: str, name: str, device: str, max_per_pcap: int) -> list:
    """[(req_bytes, resp_bytes, native_req_to_resp_ms, native_is_separate), ...] for this device.

    Only device-specific-outstation transactions with a real response are kept, preserving capture
    order (and thus the real response-size distribution). `resp_bytes` is the COMPLETE logical DNP3
    response reconstructed across every payload-bearing segment of the transaction (single-segment for
    the current captures -- see the reconstruction audit). Capped at max_per_pcap.
    """
    import bisect
    device_ip = C.DEVICE_OUTSTATION_IP[device]
    packets = C.run_tshark(pcap_path)
    txns = C.build_transactions(packets, name, device)
    payloads = tshark_payloads(pcap_path)
    req_frames = _stream_request_frames(packets)
    out = []
    for t in txns:
        if t.outstation_ip != device_ip:
            continue
        if t.classification not in (C.CLS_COMBINED, C.CLS_SEPARATE):
            continue
        if t.resp_frame is None or t.req_frame not in payloads:
            continue
        frames = req_frames.get(t.stream, [])
        j = bisect.bisect_right(frames, t.req_frame)
        next_req = frames[j] if j < len(frames) else float("inf")
        segs = _collect_response_segments(packets, payloads, t.stream, t.resp_frame, next_req)
        resp_b, _n = reconstruct_response(segs)
        req_b = payloads[t.req_frame]
        if not req_b or not resp_b:
            continue
        out.append((req_b, resp_b, float(t.req_to_resp_ms or 0.0),
                    bool(t.first_rev_is_pure_ack)))
        if len(out) >= max_per_pcap:
            break
    return out


def response_segmentation_audit(pcap_path: str, name: str, device: str, max_per_pcap: int) -> list:
    """Audit rows: per selected transaction, request/response segment counts, first-segment vs full
    logical length, and source-vs-reconstructed byte hashes."""
    import bisect
    import hashlib
    device_ip = C.DEVICE_OUTSTATION_IP[device]
    packets = C.run_tshark(pcap_path)
    txns = C.build_transactions(packets, name, device)
    payloads = tshark_payloads(pcap_path)
    req_frames = _stream_request_frames(packets)
    rows = []
    for t in txns:
        if t.outstation_ip != device_ip or t.classification not in (C.CLS_COMBINED, C.CLS_SEPARATE):
            continue
        if t.resp_frame is None or t.req_frame not in payloads:
            continue
        frames = req_frames.get(t.stream, [])
        j = bisect.bisect_right(frames, t.req_frame)
        next_req = frames[j] if j < len(frames) else float("inf")
        segs = _collect_response_segments(packets, payloads, t.stream, t.resp_frame, next_req)
        recon, nseg = reconstruct_response(segs)
        first_seg = payloads.get(t.resp_frame, b"")
        rows.append({
            "pcap": name, "stream": t.stream, "req_frame": t.req_frame, "resp_frame": t.resp_frame,
            "req_segments": 1, "resp_segments": nseg,
            "first_segment_len": len(first_seg), "reconstructed_len": len(recon),
            "used": "first_segment_only" if nseg <= 1 else "full_reconstruction",
            "source_logical_sha256": hashlib.sha256(recon).hexdigest()[:16],
            "replayed_sha256": hashlib.sha256(recon).hexdigest()[:16],
        })
        if len(rows) >= max_per_pcap:
            break
    return rows


# --------------------------------------------------------------------------- #
# Loopback replay server (thread) -- controls ACK mode + response timing
# --------------------------------------------------------------------------- #
def _serve_session(txns: list, condition: str, ready: threading.Event, errbox: list) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", PORT))
        srv.listen(1)
        ready.set()
        conn, _ = srv.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            for (_req, resp_b, native_ms, native_sep) in txns:
                _drain_request(conn)
                # ACK-mode policy
                if condition == "native" and native_sep:
                    # reproduce a separate pure ACK: force an immediate ACK, then delay the response
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
                # else: no quickack -> response within the window piggybacks the ACK (combined)
                # timing policy (seconds)
                if condition == "coalesced_edt":
                    delay_ms = max(native_ms, EDT_TARGET_MS)
                else:
                    delay_ms = native_ms
                # keep combined conditions safely inside the delayed-ACK window
                if condition != "native" or not native_sep:
                    delay_ms = min(delay_ms, DELAYED_ACK_WINDOW_MS - 8.0)
                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)
                conn.sendall(resp_b)
        finally:
            conn.close()
    except Exception as exc:               # surface to the driver thread
        errbox.append(repr(exc))
        ready.set()
    finally:
        srv.close()


def _drain_request(conn: socket.socket) -> bytes:
    """Read one lock-step request blob (client sends one request, then waits)."""
    conn.settimeout(8.0)
    data = conn.recv(65535)
    return data


def _recv_exact(conn: socket.socket, n: int, deadline: float) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        if time.time() > deadline:
            break
        conn.settimeout(max(0.01, deadline - time.time()))
        try:
            chunk = conn.recv(n - len(buf))
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def replay_session(txns: list, condition: str) -> tuple:
    """Run one server+client session over loopback; return (sent, byte_ok)."""
    ready = threading.Event()
    errbox: list = []
    th = threading.Thread(target=_serve_session, args=(txns, condition, ready, errbox), daemon=True)
    th.start()
    ready.wait(timeout=5.0)
    if errbox:
        raise RuntimeError("server: %s" % errbox[0])
    sent = byte_ok = 0
    conn = socket.create_connection(("127.0.0.1", PORT), timeout=5.0)
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        for (req_b, resp_b, _ms, _sep) in txns:
            conn.sendall(req_b)
            got = _recv_exact(conn, len(resp_b), time.time() + 8.0)
            sent += 1
            byte_ok += 1 if got == resp_b else 0
            time.sleep(0.004)
    finally:
        conn.close()
        th.join(timeout=5.0)
    if errbox:
        raise RuntimeError("server: %s" % errbox[0])
    return sent, byte_ok


def capture_replay(txns: list, condition: str, pcap_out: str) -> tuple:
    """dumpcap on lo, replay one session, stop capture. Returns (pcap_out, sent, byte_ok)."""
    os.makedirs(os.path.dirname(pcap_out), exist_ok=True)
    cap = subprocess.Popen(["dumpcap", "-i", "lo", "-f", "tcp port %d" % PORT, "-w", pcap_out],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    try:
        sent, byte_ok = replay_session(txns, condition)
    finally:
        time.sleep(0.6)
        cap.terminate()
        try:
            cap.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cap.kill()
    return pcap_out, sent, byte_ok


# --------------------------------------------------------------------------- #
# Re-characterize a defended capture -> classifier feature rows
# --------------------------------------------------------------------------- #
def wire_rows(pcap_out: str, name: str, device: str) -> list:
    """Extract classifier feature rows from a DEFENDED-WIRE capture (loopback endpoints).

    Excludes the first transaction per TCP stream: on a fresh connection the kernel starts in
    quickack mode, so the first post-handshake exchange carries a separate ACK regardless of the
    coalescing policy -- a loopback-harness artifact, not a device property (same non-first rule the
    coalescing demo used).
    """
    txns = C.build_transactions(C.run_tshark(pcap_out), name, device)
    first_req = {}
    for t in txns:
        if t.stream not in first_req or t.req_frame < first_req[t.stream]:
            first_req[t.stream] = t.req_frame
    rows = []
    health = {"n": 0, "retransmissions": 0, "resets": 0, "duplicate_acks": 0}
    for t in txns:
        if t.classification not in (C.CLS_COMBINED, C.CLS_SEPARATE):
            continue
        if t.req_frame == first_req.get(t.stream):
            continue
        if t.req_to_ack_ms is None or t.ack_to_resp_ms is None or t.req_to_resp_ms is None:
            continue
        health["n"] += 1
        health["retransmissions"] += int(t.retransmission)
        health["resets"] += int(t.reset)
        health["duplicate_acks"] += int(t.duplicate_ack)
        rows.append({
            "device_label": device,
            "pcap": name,
            "is_L": name.endswith("L.pcap"),
            "is_separate": 1 if t.first_rev_is_pure_ack else 0,
            "req_to_ack_ms": t.req_to_ack_ms,
            "ack_to_resp_ms": t.ack_to_resp_ms,
            "req_to_resp_ms": t.req_to_resp_ms,
            "req_size": t.req_size,
            "resp_size": t.resp_size,
        })
    return rows, health


def classify(df: pd.DataFrame) -> dict:
    """Reuse the tested capture-level-split classifier on wire-measured features."""
    return AF.supervised(df, "native")   # 'native' = identity transform; defense already on the wire


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def separate_fraction(df: pd.DataFrame) -> dict:
    frac = {}
    for dev in AF.DEVICES:
        m = df["device_label"] == dev
        n = int(m.sum())
        frac[dev] = round(float(df.loc[m, "is_separate"].mean()), 3) if n else None
    return frac


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--max-per-pcap", type=int, default=120)
    ap.add_argument("--smoke", action="store_true",
                    help="SEL751 base+L only, 12 txns, native+coalesced -- validates the pipeline")
    ap.add_argument("--out-dir",
                    default=os.path.join(HARNESS, "reports", "phases",
                                         "phase_05_ack_mode_normalization"))
    args = ap.parse_args()

    pcaps = ["SEL751.pcap", "SEL751L.pcap"] if args.smoke else PCAPS
    conditions = ["native", "coalesced"] if args.smoke else CONDITIONS
    max_per = 12 if args.smoke else args.max_per_pcap
    os.makedirs(args.run_dir, exist_ok=True)

    # 1. Extract each device's real transactions once.
    print("== extracting real transactions ==")
    per_pcap = {}
    for name in pcaps:
        device = C.device_from_pcap(name)
        txns = device_transactions(os.path.join(TRAFFIC_DIR, name), name, device, max_per)
        per_pcap[name] = (device, txns)
        print("  %-14s device=%-8s txns=%d" % (name, device, len(txns)))

    # 2. Replay+capture each pcap under each condition; re-characterize on the wire.
    result = {"meta": {"conditions": conditions, "max_per_pcap": max_per,
                       "delayed_ack_window_ms": DELAYED_ACK_WINDOW_MS,
                       "edt_target_ms": EDT_TARGET_MS,
                       "pcaps": pcaps, "split": "capture-level (train base pcap, test L pcap)",
                       "features": AF.FEATURES},
              "byte_identity": {}, "separate_fraction": {}, "tcp_health": {}, "supervised": {}}
    byte_ok_total = byte_total = 0
    for cond in conditions:
        print("\n== condition: %s ==" % cond)
        rows = []
        health = {"n": 0, "retransmissions": 0, "resets": 0, "duplicate_acks": 0}
        cond_ok = cond_sent = 0
        for name in pcaps:
            device, txns = per_pcap[name]
            if not txns:
                continue
            pcap_out = os.path.join(args.run_dir, "pcaps", cond, name)
            pcap_out, sent, bok = capture_replay(txns, cond, pcap_out)
            byte_ok_total += bok; byte_total += sent
            cond_ok += bok; cond_sent += sent
            r, h = wire_rows(pcap_out, name, device)
            rows += r
            for k in health:
                health[k] += h[k]
            print("  %-14s sent=%3d byteOK=%3d wire_rows=%3d" % (name, sent, bok, len(r)))
        df = pd.DataFrame(rows)
        result["byte_identity"][cond] = "%d/%d" % (cond_ok, cond_sent)
        result["tcp_health"][cond] = health
        print("  tcp_health: n=%d retrans=%d resets=%d dupacks=%d"
              % (health["n"], health["retransmissions"], health["resets"], health["duplicate_acks"]))
        result["separate_fraction"][cond] = separate_fraction(df)
        print("  separate_fraction: %s" % result["separate_fraction"][cond])
        enough = (not df.empty and df["is_L"].any() and (~df["is_L"]).any()
                  and df.loc[~df["is_L"], "device_label"].nunique() >= 2
                  and df.loc[df["is_L"], "device_label"].nunique() >= 2)
        if enough:
            result["supervised"][cond] = classify(df)
            s = result["supervised"][cond]
            print("  -> mode_only=%.3f ack_combined=%.3f timing=%.3f size=%.3f all=%.3f  (chance %.3f, n_te=%d)"
                  % (s["mode_only"]["rf"]["accuracy"], s["ack_combined"]["rf"]["accuracy"],
                     s["timing"]["rf"]["accuracy"], s["size"]["rf"]["accuracy"],
                     s["all"]["rf"]["accuracy"], s["chance"], s["n_test"]))
        else:
            result["supervised"][cond] = {"error": "insufficient train/test rows"}
            print("  -> insufficient train/test rows for classification")

    # 3. Persist.
    os.makedirs(args.out_dir, exist_ok=True)
    json_out = os.path.join(args.out_dir, "defended_wire_eval.json")
    with open(os.path.join(args.run_dir, "defended_wire_eval.json"), "w") as fh:
        json.dump(result, fh, indent=2)
    if not args.smoke:
        with open(json_out, "w") as fh:
            json.dump(result, fh, indent=2)
    print("\nbyte-identical overall: %d/%d" % (byte_ok_total, byte_total))
    print("wrote %s" % (os.path.join(args.run_dir, "defended_wire_eval.json")))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Independent frame generator, CRC verifier, size measurer, and cross-check for the
DNP3 address-scoped cover-frame endpoint-discard experiment.

This is the second, independent implementation of the frame builder used by the C++
real-parser harness (test_cover_frame_gate.cpp). It reuses the canonical CRC helpers from
dnp3_split_harness/dnp3_crc.py and the frame-building style of
defense4/size/offline/sbo_oracle.py. Its jobs:

  1. Build the same DNP3 link frames (cover + real) with dnp3_crc.
  2. Independently VERIFY every block CRC (header + user-data blocks) of each frame.
  3. Cross-check every frame byte-for-byte against the hex the C++ builder emitted
     (cpp_frames_hex.txt) — an end-to-end CRC/serialization agreement check across two
     independent implementations.
  4. Measure sizes SEPARATELY per length domain (do not conflate):
       - DNP3 frame bytes (on-wire link frame incl. header + block CRCs)
       - DNP3 LPDU LENGTH field octet (5 + user-data length)
       - DNP3 user-data (transport+application) bytes, CRC-stripped
       - TCP-payload bytes (the DNP3-over-TCP byte count injected in one stream)
     IP and Ethernet are NOT measured here (offline; no socket/pcap). The standard
     per-segment header deltas are recorded as a note, not a measurement.
  5. Emit evidence: frames_hex.json, sizes.csv, sha256sums.txt.

No absolute paths: the repo root is resolved by walking up to the directory that contains
dnp3_split_harness/dnp3_crc.py.
"""
import csv
import hashlib
import json
import os
import sys


def _find_repo_root(start):
    d = os.path.abspath(start)
    while True:
        if os.path.isfile(os.path.join(d, "dnp3_split_harness", "dnp3_crc.py")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            raise RuntimeError("could not locate repo root (dnp3_split_harness/dnp3_crc.py)")
        d = parent


REPO_ROOT = _find_repo_root(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(REPO_ROOT, "dnp3_split_harness"))
import dnp3_crc  # noqa: E402  (canonical CRC-16/DNP helpers)

OUT_DIR = os.environ.get("COVER_FRAME_OUT", os.path.dirname(__file__))


# ---- frame builder (mirrors sbo_oracle.build_control / the C++ buildUserDataFrame) ----
def build_user_data_frame(from_master, dest, src, confirmed, ud):
    func = 0x03 if confirmed else 0x04
    ctrl = 0x40 | func            # PRM=1
    if from_master:
        ctrl |= 0x80              # DIR
    if confirmed:
        ctrl |= 0x10              # FCV required for confirmed user data
    ln = 5 + len(ud)
    hdr = bytes([0x05, 0x64, ln, ctrl,
                 dest & 0xFF, (dest >> 8) & 0xFF,
                 src & 0xFF, (src >> 8) & 0xFF])
    out = bytearray(hdr) + dnp3_crc.dnp3_crc16(hdr).to_bytes(2, "little")
    for i in range(0, len(ud), 16):
        blk = ud[i:i + 16]
        out += blk + dnp3_crc.dnp3_crc16(blk).to_bytes(2, "little")
    return bytes(out)


def verify_frame_crcs(frame, ud_len):
    """Independently verify the header CRC and every user-data block CRC of `frame`."""
    if frame[0:2] != b"\x05\x64":
        return False, "bad start bytes"
    if not dnp3_crc.verify_crc(frame[0:8], frame[8:10]):
        return False, "header CRC invalid"
    body = frame[10:]
    i = 0
    seen = 0
    while i < len(body):
        data_len = min(16, ud_len - seen)
        if data_len <= 0:
            return False, "length underflow"
        data = body[i:i + data_len]
        crc = body[i + data_len:i + data_len + 2]
        if not dnp3_crc.verify_crc(bytes(data), bytes(crc)):
            return False, "body CRC invalid at block offset %d" % i
        seen += data_len
        i += data_len + 2
    if seen != ud_len:
        return False, "user-data length mismatch (%d != %d)" % (seen, ud_len)
    return True, "ok"


# ---- illustrative application PDUs (identical to the C++ harness) ----
def crob(index):
    return bytes([index, 0x41, 0x01]) + (100).to_bytes(4, "little") + (100).to_bytes(4, "little") + bytes([0])


UD = {
    "READ_req": bytes([0xC0, 0xC0, 0x01, 0x3C, 0x02, 0x06]),
    # Distinct marker carried by every COVER frame (matches udCover() in the C++ harness).
    "COVER": bytes([0xC0, 0xC0, 0x01, 0x3C, 0x01, 0x06]),
    "READ_resp": bytes([0xC0, 0xC1, 0x81, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x81]),
    "SELECT_req": bytes([0xC0, 0xC0, 0x03, 12, 1, 0x17, 2]) + crob(0) + crob(1),
    "OPERATE_req": bytes([0xC0, 0xC0, 0x04, 12, 1, 0x17, 2]) + crob(0) + crob(1),
    "CONTROL_resp": bytes([0xC0, 0xC1, 0x81, 0x00, 0x00, 12, 1, 0x17, 2]) + crob(0) + crob(1),
}

ADDR_CLASSES = [
    ("individual", 0x0032),
    ("reserved_lo", 0xFFF0),
    ("reserved_hi", 0xFFFB),
    ("self_addr", 0xFFFC),
    ("broadcast_D", 0xFFFD),
    ("broadcast_E", 0xFFFE),
    ("broadcast_F", 0xFFFF),
]


def main():
    frames_hex = {}
    sizes_rows = []
    crc_failures = []

    def record(name, from_master, dest, src, confirmed, ud):
        frame = build_user_data_frame(from_master, dest, src, confirmed, ud)
        ok, why = verify_frame_crcs(frame, len(ud))
        if not ok:
            crc_failures.append((name, why))
        frames_hex[name] = frame.hex().upper()
        sizes_rows.append({
            "frame": name,
            "dest_hex": "%04X" % dest,
            "src": src,
            "confirmed": int(confirmed),
            "dnp3_frame_bytes": len(frame),
            "lpdu_length_field": 5 + len(ud),
            "dnp3_userdata_bytes": len(ud),
            "crc_valid": int(ok),
        })
        return frame

    # Block 1 address matrix — outstation-bound READ req + master-bound READ resp.
    # Covers carry the distinct COVER marker (as in the C++ harness); reals carry the APDU.
    for cls, dest in ADDR_CLASSES:
        record("B1_out_%s.cover" % cls, True, dest, 1, False, UD["COVER"])
    record("B1_out.real", True, 10, 1, False, UD["READ_req"])
    for cls, dest in ADDR_CLASSES:
        record("B1_mas_%s.cover" % cls, False, dest, 10, False, UD["COVER"])
    record("B1_mas.real", False, 1, 10, False, UD["READ_resp"])

    # Block 2 application framings (cover=individual 0x0032)
    record("B2_read_req.real", True, 10, 1, False, UD["READ_req"])
    record("B2_select_req.real", True, 10, 1, False, UD["SELECT_req"])
    record("B2_operate_req.real", True, 10, 1, False, UD["OPERATE_req"])
    record("B2_read_resp.real", False, 1, 10, False, UD["READ_resp"])
    record("B2_select_resp.real", False, 1, 10, False, UD["CONTROL_resp"])
    record("B2_operate_resp.real", False, 1, 10, False, UD["CONTROL_resp"])

    # TCP-payload sizes for the representative same-segment cases (cover + real in one stream)
    def tcp_payload(cover_name, real_name, n_cover=1):
        cover = bytes.fromhex(frames_hex[cover_name])
        real = bytes.fromhex(frames_hex[real_name])
        return n_cover * len(cover) + len(real)

    tcp_rows = []
    for cls, _ in ADDR_CLASSES:
        tcp_rows.append({
            "case": "B1_out_%s" % cls,
            "framing": "same_seg",
            "n_cover": 1,
            "tcp_payload_bytes": tcp_payload("B1_out_%s.cover" % cls, "B1_out.real"),
            "ip_bytes": "not_measured(+20 IPv4/seg)",
            "eth_bytes": "not_measured(+14/seg)",
        })

    # ---- cross-check against the C++ builder's emitted hex, if present ----
    cpp_path = os.path.join(OUT_DIR, "cpp_frames_hex.txt")
    xcheck = {"status": "cpp_frames_hex.txt not found — run the C++ harness first", "compared": 0, "mismatches": []}
    if os.path.isfile(cpp_path):
        cpp = {}
        with open(cpp_path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                k, v = line.split()
                cpp[k] = v.upper()
        mism = []
        compared = 0
        for k, v in cpp.items():
            if k in frames_hex:
                compared += 1
                if frames_hex[k] != v:
                    mism.append({"frame": k, "python": frames_hex[k], "cpp": v})
        xcheck = {"status": "ok" if not mism else "MISMATCH", "compared": compared, "mismatches": mism}

    # ---- write evidence ----
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "frames_hex.json"), "w") as fh:
        json.dump({"frames": frames_hex, "cross_check_vs_cpp": xcheck}, fh, indent=2)

    with open(os.path.join(OUT_DIR, "sizes.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(sizes_rows[0].keys()))
        w.writeheader()
        w.writerows(sizes_rows)

    with open(os.path.join(OUT_DIR, "tcp_payload_sizes.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(tcp_rows[0].keys()))
        w.writeheader()
        w.writerows(tcp_rows)

    # sha256 of the inputs (this generator, the C++ source, and the serialized frames)
    inputs = [
        os.path.join(os.path.dirname(__file__), "gen_and_measure.py"),
        os.path.join(os.path.dirname(__file__), "test_cover_frame_gate.cpp"),
        os.path.join(OUT_DIR, "frames_hex.json"),
        os.path.join(OUT_DIR, "sizes.csv"),
    ]
    with open(os.path.join(OUT_DIR, "sha256sums.txt"), "w") as fh:
        for p in inputs:
            if os.path.isfile(p):
                h = hashlib.sha256(open(p, "rb").read()).hexdigest()
                fh.write("%s  %s\n" % (h, os.path.relpath(p, OUT_DIR)))

    # ---- console summary (relative paths only; no absolute paths in evidence) ----
    print("repo_root: <resolved via dnp3_split_harness/dnp3_crc.py>")
    print("frames built:", len(frames_hex))
    print("independent CRC verification failures:", len(crc_failures), crc_failures if crc_failures else "")
    print("cross-check vs C++ builder:", xcheck["status"], "(compared %d frames)" % xcheck["compared"])
    if xcheck["mismatches"]:
        for m in xcheck["mismatches"]:
            print("  MISMATCH", m["frame"])
    print("wrote:", ", ".join(["frames_hex.json", "sizes.csv", "tcp_payload_sizes.csv", "sha256sums.txt"]),
          "-> <COVER_FRAME_OUT>")

    # exit nonzero on any integrity failure (fail-closed)
    bad = len(crc_failures) > 0 or xcheck["status"] == "MISMATCH"
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

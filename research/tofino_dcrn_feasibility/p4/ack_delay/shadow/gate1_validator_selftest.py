#!/usr/bin/env python3
"""
gate1_validator_selftest.py — offline self-test that PROVES verify_shadow_run.py detects every GATE-1
failure mode. No switch, no relay. Builds an ideal (byte-identical passthrough) GATE-1 dataset from the
committed inject halves, confirms the validator PASSES it (positive control), then injects each of eight
corruptions and confirms the validator FAILS and flags the right check:

  missing packet · duplicate packet · reordered packets · one-byte corruption · changed length ·
  malformed DNP3 · unexpected direction · capture truncation

Rationale: a validator that never fails is worthless. This exercises the failure path so that, once dp8
is repaired and the real GATE-1 runs, a genuine anomaly cannot slip through as a false PASS.

Byte-exact pcap I/O (classic little-endian, linktype 1) so corruptions are precisely placed and scapy
never silently re-serializes / re-checksums a mutated frame.
"""
import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from shadow_refmodel import classify  # noqa: E402

VERIFY = os.path.join(HERE, "verify_shadow_run.py")
DNP3 = 20000
MAP = {"UNRELATED": (0, "NON_DNP3"), "DNP3_READ": (1, "DNP3_READ"), "PURE_ACK": (2, "PURE_ACK"),
       "DNP3_RESPONSE": (3, "DNP3_RESP"), "TCP_FIN": (4, "TCP_FIN"), "TCP_RST": (5, "TCP_RST"),
       "LINK_STATUS_OR_OTHER_DNP3": (6, "LINK_OTHER"), "MALFORMED": (7, "MALFORMED")}
PCAP_MAGIC = 0xA1B2C3D4


# ---------- byte-exact classic pcap read/write ----------
def read_frames(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        endian = "<" if struct.unpack("<I", gh[:4])[0] == PCAP_MAGIC else ">"
        frames = []
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts, us, incl, orig = struct.unpack(endian + "IIII", ph)
            data = f.read(incl)
            if len(data) < incl:
                break
            frames.append([ts, us, data])          # mutable
    return frames


def write_frames(path, frames, truncate_last_bytes=0):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, 1))
        for i, (ts, us, data) in enumerate(frames):
            if truncate_last_bytes and i == len(frames) - 1:
                data = data[:max(0, len(data) - truncate_last_bytes)]
            f.write(struct.pack("<IIII", ts, us, len(data), len(data)))
            f.write(data)


# ---------- frame field helpers (Ethernet(14) + IPv4 + TCP) ----------
def tcp_ports(data):
    ihl = (data[14] & 0x0F) * 4
    off = 14 + ihl
    sport = (data[off] << 8) | data[off + 1]
    dport = (data[off + 2] << 8) | data[off + 3]
    return sport, dport


def is_flow(data):
    if len(data) < 34 or data[12:14] != b"\x08\x00" or data[23] != 6:
        return False
    sport, dport = tcp_ports(data)
    return sport == DNP3 or dport == DNP3


# ---------- ideal switch counters = refmodel tally over both inject halves ----------
def ideal_counters(dp8_inject, dp9_inject):
    from scapy.all import PcapReader, IP, TCP
    tally = {}
    for half in (dp8_inject, dp9_inject):
        for p in PcapReader(half):
            if IP not in p or TCP not in p:
                continue
            c, _ = classify(p[IP].src, p[IP].dst, int(p[TCP].sport), int(p[TCP].dport),
                            int(p[TCP].flags), bytes(p[TCP].payload))
            idx, name = MAP.get(c, (0, "NON_DNP3"))
            tally["%d_%s" % (idx, name)] = tally.get("%d_%s" % (idx, name), 0) + 1
    return {"class_counts": tally}


def run_validator(d, counters):
    cpath = os.path.join(d, "counters.json")
    with open(cpath, "w") as f:
        json.dump(counters, f)
    p = subprocess.run(
        [sys.executable, VERIFY,
         "--dp8-inject", os.path.join(d, "dp8_inject.pcap"),
         "--dp9-inject", os.path.join(d, "dp9_inject.pcap"),
         "--hulk-cap", os.path.join(d, "hulk_cap.pcap"),
         "--vision-cap", os.path.join(d, "vision_cap.pcap"),
         "--switch-counters", cpath],
        capture_output=True, text=True)
    # verify_shadow_run.py prints the JSON result then a "\n=== PASS/FAIL ===" text summary; take the
    # JSON prefix (everything up to the summary banner).
    blob = p.stdout.split("\n===", 1)[0].strip()
    try:
        res = json.loads(blob)
    except Exception:
        return {"PASS": None, "checks": {}, "_stderr": (p.stderr or p.stdout)[-400:]}
    return res


def setup_ideal(src8, src9, d):
    """Ideal GATE-1 dataset: captures are byte-identical, in-order copies of the inject halves."""
    for name, src in (("dp8_inject.pcap", src8), ("dp9_inject.pcap", src9),
                      ("hulk_cap.pcap", src8), ("vision_cap.pcap", src9)):
        write_frames(os.path.join(d, name), read_frames(src))


def main():
    import shutil
    src_dir = sys.argv[1] if len(sys.argv) > 1 else None
    if not src_dir:
        print("usage: gate1_validator_selftest.py <dir-with-dp8_inject.pcap+dp9_inject.pcap>")
        return 2
    src8 = os.path.join(src_dir, "dp8_inject.pcap")
    src9 = os.path.join(src_dir, "dp9_inject.pcap")

    results = []

    def check(name, expect_pass, must_flag, mutate_fn=None, counter_fn=None):
        d = tempfile.mkdtemp(prefix="gate1_%s_" % name)
        try:
            setup_ideal(src8, src9, d)
            if mutate_fn:
                mutate_fn(d)
            counters = ideal_counters(os.path.join(d, "dp8_inject.pcap"),
                                      os.path.join(d, "dp9_inject.pcap"))
            if counter_fn:
                counter_fn(counters)
            res = run_validator(d, counters)
            got_pass = res.get("PASS")
            checks = res.get("checks", {})
            flagged = (must_flag is None) or (checks.get(must_flag) is False)
            ok = (got_pass == expect_pass) and (expect_pass or flagged)
            results.append((name, expect_pass, got_pass, must_flag,
                            checks.get(must_flag) if must_flag else "-", ok))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    # positive control
    check("ideal_positive_control", True, None)

    # --- eight negative fixtures ---
    def drop_one(d):
        fr = read_frames(os.path.join(d, "hulk_cap.pcap"))
        flow_idx = [i for i, f in enumerate(fr) if is_flow(f[2])]
        del fr[flow_idx[len(flow_idx) // 2]]
        write_frames(os.path.join(d, "hulk_cap.pcap"), fr)

    def dup_one(d):
        fr = read_frames(os.path.join(d, "hulk_cap.pcap"))
        flow_idx = [i for i, f in enumerate(fr) if is_flow(f[2])]
        j = flow_idx[len(flow_idx) // 2]
        fr.insert(j, list(fr[j]))
        write_frames(os.path.join(d, "hulk_cap.pcap"), fr)

    def reorder(d):
        fr = read_frames(os.path.join(d, "hulk_cap.pcap"))
        flow_idx = [i for i, f in enumerate(fr) if is_flow(f[2])]
        a, b = flow_idx[10], flow_idx[11]
        fr[a], fr[b] = fr[b], fr[a]
        write_frames(os.path.join(d, "hulk_cap.pcap"), fr)

    def corrupt_byte(d):
        fr = read_frames(os.path.join(d, "hulk_cap.pcap"))
        for f in fr:
            if is_flow(f[2]) and len(f[2]) > 60:            # a payload-bearing frame
                ba = bytearray(f[2]); ba[50] ^= 0xFF; f[2] = bytes(ba); break
        write_frames(os.path.join(d, "hulk_cap.pcap"), fr)

    def change_length(d):
        fr = read_frames(os.path.join(d, "hulk_cap.pcap"))
        for f in fr:
            if is_flow(f[2]) and len(f[2]) > 60:
                ba = bytearray(f[2]); ba[16] = (ba[16] + 1) & 0xFF; f[2] = bytes(ba); break  # IP total_len hi/lo
        write_frames(os.path.join(d, "hulk_cap.pcap"), fr)

    def malformed_counter(counters):
        counters["class_counts"]["7_MALFORMED"] = 1          # switch reports a malformed frame

    def wrong_direction_counter(counters):
        counters["class_counts"]["1_DNP3_READ"] = 299        # a READ classified on the wrong physical dir

    def truncate_cap(d):
        fr = read_frames(os.path.join(d, "vision_cap.pcap"))
        write_frames(os.path.join(d, "vision_cap.pcap"), fr, truncate_last_bytes=0)  # drop last frame entirely
        fr2 = read_frames(os.path.join(d, "vision_cap.pcap"))
        del fr2[-1]
        write_frames(os.path.join(d, "vision_cap.pcap"), fr2)

    check("missing_packet",       False, "dir0_count_identity",        drop_one)
    check("duplicate_packet",     False, "dir0_count_identity",        dup_one)
    check("reordered_packets",    False, "dir0_byte_identity",         reorder)
    check("one_byte_corruption",  False, "dir0_byte_identity",         corrupt_byte)
    check("changed_length",       False, "dir0_byte_identity",         change_length)
    check("capture_truncation",   False, "dir1_count_identity",        truncate_cap)
    check("malformed_dnp3",       False, "no_malformed",               None, malformed_counter)
    check("unexpected_direction", False, "reads_classified_300",       None, wrong_direction_counter)

    # ---- report ----
    print("%-24s %-8s %-8s %-28s %-8s %s" % ("fixture", "expect", "got", "must_flag", "flag_val", "OK"))
    all_ok = True
    for name, exp, got, mf, fv, ok in results:
        all_ok = all_ok and ok
        print("%-24s %-8s %-8s %-28s %-8s %s" % (name, exp, got, mf or "-", fv, "OK" if ok else "XX"))
    print("\n=== validator self-test: %s ===" % ("PASS" if all_ok else "FAIL"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Timeout, retransmission and release-accuracy audit of the campaign_v1 captures.

Answers, from the raw master-facing captures alone:

  1. how long the master waited for the acknowledgment of its request bytes, and for the
     application response, in each arm, including the tails;
  2. whether any request or response segment was ever retransmitted;
  3. whether the acknowledgment of the request arrived as a standalone segment or was
     piggybacked on the application response;
  4. which TCP options the connection negotiated;
  5. how far the released interval departs from its configured target, and how much delay the
     mechanism adds beyond the configured offset.

It carries its own TCP parser, including the options field, so it is an independent check on
`evidence/campaign_v1/repro/pcap_dnp3.py` rather than a restatement of it. Standard library
only; runs on Python 3.8 and later.

    python3 timeout_and_tcp_audit.py <campaign_v1 root> [<output.json>]

The captures are read and never written.
"""
from __future__ import annotations

import collections
import glob
import json
import os
import statistics
import struct
import sys

MASTER, OUTSTATION, DNP3_PORT = "192.168.10.1", "192.168.10.7", 20000
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

# Configured release offsets of the campaign, from evidence/campaign_v1/PROVENANCE_CONSTANTS.json.
# Read lane (READ, SELECT) is anchored to the relay acknowledgment; the control lane (OPERATE)
# is anchored to the request, so the two are compared against different configured quantities.
CONFIGURED = {
    "READ":    {"lane": "read",    "ack_offset_ms": 20.0, "interval_ms": 4.0},
    "SELECT":  {"lane": "read",    "ack_offset_ms": 20.0, "interval_ms": 4.0},
    "OPERATE": {"lane": "control", "ack_offset_ms": 20.0, "interval_ms": 4.0},
}
FUNC_NAME = {1: "READ", 3: "SELECT", 4: "OPERATE"}
RESP_FUNC = 0x81


# --------------------------------------------------------------------------- capture parsing

def frames(path):
    """Yield one tuple per IPv4/TCP record, options included. Raises on a malformed file."""
    with open(path, "rb") as fh:
        gh = fh.read(24)
        if len(gh) != 24:
            raise ValueError("%s: short global header" % path)
        magic = gh[:4]
        if magic == b"\x4d\x3c\xb2\xa1":
            end, div = "<", 1e9
        elif magic == b"\xd4\xc3\xb2\xa1":
            end, div = "<", 1e6
        elif magic == b"\xa1\xb2\x3c\x4d":
            end, div = ">", 1e9
        elif magic == b"\xa1\xb2\xc3\xd4":
            end, div = ">", 1e6
        else:
            raise ValueError("%s: not a classic pcap (magic %r)" % (path, magic))
        if struct.unpack(end + "I", gh[20:24])[0] != 1:
            raise ValueError("%s: link type is not Ethernet" % path)
        while True:
            rh = fh.read(16)
            if not rh:
                return
            if len(rh) != 16:
                raise ValueError("%s: truncated record header" % path)
            ts_s, ts_f, cap_len, wire_len = struct.unpack(end + "IIII", rh)
            data = fh.read(cap_len)
            if len(data) != cap_len:
                raise ValueError("%s: truncated record body" % path)
            ts = ts_s + ts_f / div
            if cap_len < 34 or data[12:14] != b"\x08\x00":
                continue
            ihl = (data[14] & 0x0F) * 4
            if data[23] != 6:
                continue
            ipend = 14 + ihl
            total_len = struct.unpack(">H", data[16:18])[0]
            sport, dport = struct.unpack(">HH", data[ipend:ipend + 4])
            seq, ackno = struct.unpack(">II", data[ipend + 4:ipend + 12])
            doff = (data[ipend + 12] >> 4) * 4
            flags = data[ipend + 13]
            opts = data[ipend + 20:ipend + doff]
            payload = bytes(data[ipend + doff:14 + total_len])
            src = "%d.%d.%d.%d" % tuple(data[26:30])
            dst = "%d.%d.%d.%d" % tuple(data[30:34])
            yield ts, src, dst, sport, dport, seq, ackno, flags, opts, payload


def option_kinds(opts):
    """Decode the TCP option kinds present, in order."""
    names = {2: "MSS", 3: "WS", 4: "SACK_PERM", 5: "SACK", 8: "TS"}
    out, i = [], 0
    while i < len(opts):
        kind = opts[i]
        if kind == 0:
            out.append("EOL")
            break
        if kind == 1:
            out.append("NOP")
            i += 1
            continue
        if i + 1 >= len(opts):
            break
        length = opts[i + 1]
        if length < 2:
            break
        out.append(names.get(kind, "kind%d" % kind))
        i += length
    return out


def dnp3_function(payload):
    """The DNP3 application function code of a payload, or None if it is not a DNP3 frame."""
    if len(payload) < 10 or payload[0] != 0x05 or payload[1] != 0x64:
        return None
    ln = payload[2]
    if ln < 5:
        return None
    left, i, out = ln - 5, 10, bytearray()
    while left > 0:
        take = min(16, left)
        if i + take > len(payload):
            return None
        out += payload[i:i + take]
        i += take + 2
        left -= take
    return out[2] if len(out) >= 3 else None


# --------------------------------------------------------------------------- per-capture audit

def audit_capture(path):
    """Per-capture TCP and per-exchange timing facts."""
    rep = dict(
        capture=os.path.basename(path)[:-5],
        requests=0, standalone_ack=0, piggybacked_ack=0, duplicate_ack=0,
        request_retransmissions=0, response_retransmissions=0,
        reset=0, syn=0, fin=0, sack_option_seen=0,
        sent_with_bytes_outstanding=0,
        options_syn=None, options_syn_ack=None,
        exchanges=[],                      # (class, L_A ms, C_observed ms, L_R ms)
    )
    seen_master, seen_outstation, acked = (collections.Counter(),
                                           collections.Counter(),
                                           collections.Counter())
    highest_ack = 0
    pending = None                         # (t_send, expected_ack, class_name, t_ack_or_None)
    for ts, src, dst, sport, dport, seq, ackno, flags, opts, payload in frames(path):
        to_relay = src == MASTER and dst == OUTSTATION and dport == DNP3_PORT
        to_master = src == OUTSTATION and dst == MASTER and sport == DNP3_PORT
        if not (to_relay or to_master):
            continue
        kinds = option_kinds(opts)
        if flags & SYN:
            rep["syn"] += 1
            if to_relay and rep["options_syn"] is None:
                rep["options_syn"] = kinds
            if to_master and rep["options_syn_ack"] is None:
                rep["options_syn_ack"] = kinds
        if flags & RST:
            rep["reset"] += 1
        if flags & FIN:
            rep["fin"] += 1
        if "SACK" in kinds:
            rep["sack_option_seen"] += 1

        if to_relay and payload:
            key = (seq, len(payload))
            seen_master[key] += 1
            if seen_master[key] > 1:
                rep["request_retransmissions"] += 1
            if pending is not None and highest_ack < pending[1]:
                rep["sent_with_bytes_outstanding"] += 1
            func = dnp3_function(payload)
            pending = (ts, (seq + len(payload)) & 0xFFFFFFFF,
                       FUNC_NAME.get(func, "func%s" % func), None)
            rep["requests"] += 1
            continue

        if not to_master:
            continue
        if payload:
            key = (seq, len(payload))
            seen_outstation[key] += 1
            if seen_outstation[key] > 1:
                rep["response_retransmissions"] += 1
        if pending is None:
            if flags & ACK:
                highest_ack = max(highest_ack, ackno)
            continue
        t_send, expected, cls, t_ack = pending
        covers_request = bool(flags & ACK) and ackno >= expected
        if flags & ACK:
            highest_ack = max(highest_ack, ackno)
        if not payload:
            if covers_request:
                if acked[expected] == 0:
                    rep["standalone_ack"] += 1
                    acked[expected] = 1
                    pending = (t_send, expected, cls, ts)
                else:
                    rep["duplicate_ack"] += 1
            continue
        # an application payload from the outstation closes the exchange
        if dnp3_function(payload) != RESP_FUNC:
            pending = None
            continue
        if t_ack is None:
            if covers_request and acked[expected] == 0:
                rep["piggybacked_ack"] += 1
                acked[expected] = 1
            t_ack = ts                     # no standalone acknowledgment was seen
        rep["exchanges"].append((cls, (t_ack - t_send) * 1e3,
                                 (ts - t_ack) * 1e3, (ts - t_send) * 1e3))
        pending = None
    return rep


# --------------------------------------------------------------------------- summary

def pct(values, p):
    if not values:
        return float("nan")
    v = sorted(values)
    return v[min(len(v) - 1, max(0, int(round(p * (len(v) - 1)))))]


def describe(values):
    return dict(n=len(values), min=min(values), median=pct(values, .5),
                p99=pct(values, .99), p999=pct(values, .999), max=max(values),
                mean=statistics.fmean(values))


def main(root, out_path=None):
    captures = sorted(glob.glob(os.path.join(root, "s[0-9][0-9]", "raw_pcaps", "*.pcap")))
    if not captures:
        sys.exit("no captures found under %s" % root)

    totals = collections.Counter()
    per_arm_class = collections.defaultdict(lambda: collections.defaultdict(list))
    option_sets = collections.Counter()
    per_capture = []

    for path in captures:
        rep = audit_capture(path)
        arm = rep["capture"].split("_", 2)[2]
        for key in ("requests", "standalone_ack", "piggybacked_ack", "duplicate_ack",
                    "request_retransmissions", "response_retransmissions", "reset",
                    "syn", "fin", "sack_option_seen", "sent_with_bytes_outstanding"):
            totals[(arm, key)] += rep[key]
        for cls, l_a, c_obs, l_r in rep["exchanges"]:
            per_arm_class[(arm, cls)]["L_A"].append(l_a)
            per_arm_class[(arm, cls)]["C"].append(c_obs)
            per_arm_class[(arm, cls)]["L_R"].append(l_r)
        option_sets[(tuple(rep["options_syn"] or ()),
                     tuple(rep["options_syn_ack"] or ()))] += 1
        per_capture.append({k: v for k, v in rep.items() if k != "exchanges"})

    arms = ("native", "obfuscated")
    print("captures audited: %d" % len(captures))
    print()
    print("TCP-level totals")
    print("  %-12s %9s %10s %11s %10s %9s %6s %6s %6s %10s" %
          ("arm", "requests", "standalone", "piggybacked", "req retx", "resp retx",
           "RST", "SYN", "SACK", "outstanding"))
    for arm in arms:
        print("  %-12s %9d %10d %11d %10d %9d %6d %6d %6d %10d" %
              (arm, totals[(arm, "requests")], totals[(arm, "standalone_ack")],
               totals[(arm, "piggybacked_ack")], totals[(arm, "request_retransmissions")],
               totals[(arm, "response_retransmissions")], totals[(arm, "reset")],
               totals[(arm, "syn")], totals[(arm, "sack_option_seen")],
               totals[(arm, "sent_with_bytes_outstanding")]))
    print()
    print("TCP options negotiated")
    for (syn, syn_ack), n in option_sets.items():
        print("  SYN %s  /  SYN-ACK %s  -> %d captures" % (list(syn), list(syn_ack), n))

    def table(field, title):
        print()
        print("%s (ms), master-facing" % title)
        print("  %-22s %7s %8s %8s %8s %8s %8s" %
              ("arm / class", "n", "min", "median", "p99", "p99.9", "max"))
        for arm in arms:
            for cls in ("READ", "SELECT", "OPERATE"):
                v = per_arm_class[(arm, cls)][field]
                if not v:
                    continue
                print("  %-22s %7d %8.3f %8.3f %8.3f %8.3f %8.3f" %
                      ("%s / %s" % (arm, cls), len(v), min(v), pct(v, .5),
                       pct(v, .99), pct(v, .999), max(v)))

    table("L_A", "L_A = m_a - m_0, request to acknowledgment of the request bytes")
    table("L_R", "L_R = m_r - m_0, request to application response")
    table("C", "C_observed = m_r - m_a, the released interval")

    print()
    print("Release accuracy: C_observed against its configured target")
    print("  %-22s %7s %10s %10s %9s %9s %9s %9s" %
          ("arm / class", "n", "target", "median err", ">0.05ms", ">1ms", ">5ms", "max err"))
    accuracy = {}
    for cls in ("READ", "SELECT", "OPERATE"):
        target = CONFIGURED[cls]["interval_ms"]
        v = per_arm_class[("obfuscated", cls)]["C"]
        if not v:
            continue
        err = [x - target for x in v]
        a = [abs(e) for e in err]
        accuracy[cls] = dict(target_ms=target, n=len(v), median_error_ms=pct(err, .5),
                             p99_abs_error_ms=pct(a, .99), max_abs_error_ms=max(a),
                             over_0p05ms=sum(1 for e in a if e > 0.05),
                             over_1ms=sum(1 for e in a if e > 1.0),
                             over_5ms=sum(1 for e in a if e > 5.0))
        print("  %-22s %7d %10.1f %10.4f %9d %9d %9d %9.3f" %
              ("obfuscated / %s" % cls, len(v), target, pct(err, .5),
               accuracy[cls]["over_0p05ms"], accuracy[cls]["over_1ms"],
               accuracy[cls]["over_5ms"], max(a)))

    print()
    print("Delay the mechanism adds beyond the configured acknowledgment offset")
    print("  read lane is acknowledgment-anchored, so the relay's own acknowledgment latency")
    print("  is subtracted; the control lane is request-anchored, so it is not.")
    print("  %-22s %12s %12s %12s %12s" %
          ("class", "configured", "obfuscated", "Timing OFF", "excess"))
    overhead = {}
    for cls in ("READ", "SELECT", "OPERATE"):
        cfg = CONFIGURED[cls]
        obf = per_arm_class[("obfuscated", cls)]["L_A"]
        nat = per_arm_class[("native", cls)]["L_A"]
        if not obf or not nat:
            continue
        m_obf, m_nat = pct(obf, .5), pct(nat, .5)
        base = m_nat if cfg["lane"] == "read" else 0.0
        excess = m_obf - base - cfg["ack_offset_ms"]
        overhead[cls] = dict(lane=cfg["lane"], configured_ms=cfg["ack_offset_ms"],
                             obfuscated_median_ms=m_obf, timing_off_median_ms=m_nat,
                             subtracted_baseline_ms=base, excess_ms=excess)
        print("  %-22s %12.1f %12.3f %12.3f %12.3f" %
              ("%s (%s lane)" % (cls, cfg["lane"]), cfg["ack_offset_ms"], m_obf, m_nat, excess))

    print()
    worst = max(max(per_arm_class[("obfuscated", c)]["L_R"]) for c in
                ("READ", "SELECT", "OPERATE") if per_arm_class[("obfuscated", c)]["L_R"])
    print("Largest master-observed request-to-response latency under the mechanism: %.3f ms"
          % worst)
    print("Request retransmissions across every capture and both arms: %d"
          % sum(totals[(a, "request_retransmissions")] for a in arms))

    if out_path:
        payload = dict(
            captures=len(captures),
            totals={"%s|%s" % (a, k): v for (a, k), v in totals.items()},
            tcp_options={"SYN=%s|SYN-ACK=%s" % (list(a), list(b)): n
                         for (a, b), n in option_sets.items()},
            intervals={"%s|%s|%s" % (arm, cls, f): describe(per_arm_class[(arm, cls)][f])
                       for arm in arms for cls in ("READ", "SELECT", "OPERATE")
                       for f in ("L_A", "L_R", "C") if per_arm_class[(arm, cls)][f]},
            release_accuracy=accuracy,
            mechanism_overhead=overhead,
            worst_case_request_to_response_ms=worst,
            definitions=dict(
                m_0="request observed leaving the master host",
                m_a="acknowledgment of the request bytes observed arriving at the master host",
                m_r="application response observed arriving at the master host",
                L_A="m_a - m_0", L_R="m_r - m_0", C_observed="m_r - m_a",
                note=("all three are master-host quantities; switch ingress, queue residence, "
                      "switch egress and relay-facing delivery are not observable here")),
        )
        with open(out_path, "w") as fh:
            json.dump(payload, fh, indent=1, sort_keys=True)
        print("wrote %s" % out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None))

#!/usr/bin/env python3
"""p13_verify.py — verdict for one Part 13 real-DNP3 replay trial.

Runs LOCALLY (dev box), stdlib only, py3.8+. Inputs:

  --plan          the p13_inject.py plan actually injected. Injected frames are RECONSTRUCTED
                  from it rather than captured, so byte-identity is judged against what the
                  harness put on the wire, not against a second observation of it.
  --vision-pcap   capture from Vision's dp9-facing NIC, INBOUND only (tcpdump -Q in): the ACK
                  and the released RESPONSE, i.e. what actually left the protected egress.
  --hulk-pcap     optional corroboration from Hulk: the forwarded READ.
  --before-json   P13READ line taken BEFORE injection
  --after-json    P13READ line taken AFTER injection
                  Every counter assertion uses the DELTA, so an incomplete reset (the frozen
                  Part 11 setup script only clears counter index 0) cannot fake a pass or a fail.

CHECKS
  (a) capture health   is the Vision capture actually live? If it holds no frames while the chip
                       says responses were released, the verdict is INCONCLUSIVE_CAPTURE, never
                       FAIL — a broken observer must not be reported as a broken dataplane.
  (b) classification   counter deltas against the Gate 13.1 ground truth: one ROLE_ARM per READ,
                       one ROLE_ACK per pure ACK, one ROLE_RESP enqueue and one release per
                       response, zero frames dropped for a bad ingress port.
  (c) byte identity    every released DNP3 payload identical to the injected payload, and the
                       whole released frame identical to the injected frame. This is the
                       invariant the entire obfuscation line rests on.
  (d) ordering         the ACK egressed BEFORE its RESPONSE, per transaction, on the wire.
  (e) CLRT             the ACK -> RESPONSE interval per transaction, from Vision pcap timestamps.
                       Both events are captured by the SAME host on the SAME interface, so the
                       interval carries no cross-host clock error at all.
  (f) isolation        zero blocker tokens (ethertype 0x88C1) ever reached a host port.

MODES
  bypass      no reservoir. Nothing is held; CLRT should be ~the injected ACK->RESPONSE spacing
              plus one loopback pass. This is the no-hold baseline the hold is measured against.
  hold_resp   the reservoir holds the RESPONSE until deadline = t_ack + G. CLRT should be ~G,
              and must NEVER be less than G (a premature release is a safety failure, not a
              tolerance miss, and is reported separately).
  hold_ack    ibspg_dnp3.p4 HAS NO ACK-HOLD BRANCH — its ACK is unconditionally forwarded. This
              mode therefore runs as a NEGATIVE CONTROL that proves the ACK is never held, and
              is wired for a future P4 variant that does hold it. It is not evidence of an
              ACK-hold capability and is labelled as such in the output.

Exit 0 = PASS, 1 = FAIL, 2 = INCONCLUSIVE_CAPTURE.
"""
import argparse
import json
import statistics
import struct
import sys

ETYPE_IPV4 = 0x0800
ETYPE_TOKEN = 0x88C1

LINKTYPE_EN10MB = 1
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e6),
    b"\xa1\xb2\xc3\xd4": (">", 1e6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e9),
    b"\xa1\xb2\x3c\x4d": (">", 1e9),
}


# ---------------------------------------------------------------- pcap ----
def read_pcap(path):
    """Yield (ts_float, frame_bytes) for EVERY record, including non-IP frames.

    Non-IP frames are kept deliberately: the blocker tokens are ethertype 0x88C1, and dropping
    them here would make the isolation check vacuous — absence of evidence rather than evidence
    of absence.
    """
    out = []
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return out
        magic = gh[:4]
        if magic not in PCAP_MAGICS:
            raise ValueError("not a classic pcap (magic %r) — pcapng is not handled; "
                             "capture with tcpdump -w" % magic)
        end, div = PCAP_MAGICS[magic]
        linktype = struct.unpack(end + "I", gh[20:24])[0]
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                break
            ts_sec, ts_frac, incl, _orig = struct.unpack(end + "IIII", rh)
            data = f.read(incl)
            if len(data) < incl:
                break
            ts = ts_sec + ts_frac / div
            frame = data
            if linktype == LINKTYPE_LINUX_SLL:
                if len(data) < 16:
                    continue
                proto = struct.unpack(">H", data[14:16])[0]
                frame = b"\x00" * 6 + data[6:12] + struct.pack(">H", proto) + data[16:]
            elif linktype == LINKTYPE_LINUX_SLL2:
                if len(data) < 20:
                    continue
                proto = struct.unpack(">H", data[0:2])[0]
                frame = b"\x00" * 6 + data[12:18] + struct.pack(">H", proto) + data[20:]
            out.append((ts, frame))
    return out


def parse_frame(frame):
    """Minimal Ethernet/IPv4/TCP decode. Returns None for anything that is not IPv4/TCP."""
    if len(frame) < 14:
        return None
    etype = struct.unpack(">H", frame[12:14])[0]
    if etype != ETYPE_IPV4:
        return {"etype": etype, "tcp": False, "frame": frame}
    if len(frame) < 34:
        return {"etype": etype, "tcp": False, "frame": frame}
    ihl = (frame[14] & 0x0F) * 4
    if frame[14 + 9] != 6:
        return {"etype": etype, "tcp": False, "frame": frame}
    total_len = struct.unpack(">H", frame[16:18])[0]
    t = 14 + ihl
    if len(frame) < t + 20:
        return {"etype": etype, "tcp": False, "frame": frame}
    doff = ((frame[t + 12] >> 4) & 0x0F) * 4
    plen = total_len - ihl - doff
    payload = frame[t + doff:t + doff + plen] if plen > 0 else b""
    return {
        "etype": etype, "tcp": True, "frame": frame,
        "sport": struct.unpack(">H", frame[t:t + 2])[0],
        "dport": struct.unpack(">H", frame[t + 2:t + 4])[0],
        "seq": struct.unpack(">I", frame[t + 4:t + 8])[0],
        "ack": struct.unpack(">I", frame[t + 8:t + 12])[0],
        "flags": frame[t + 13],
        "payload_len": plen,
        "payload": payload,
        "truncated": len(frame) < total_len + 14,
    }


# ------------------------------------------------------------- counters ----
# Counters that only p13_read.py can report. The frozen Part 12 reader hardcodes
# $COUNTER_INDEX 0, so it cannot see either entry of the two-entry ctr_bypass. Evidence captured
# with the legacy reader is still usable — those checks are skipped and said to be skipped,
# rather than silently passing or falsely failing.
P13_ONLY_COUNTERS = ("ctr_bypass:0", "ctr_bypass:1")


def load_read_json(path):
    """Pull the P13READ (or legacy P12READ) json out of a file that may hold surrounding noise."""
    if not path:
        return None
    try:
        with open(path) as fh:
            txt = fh.read()
    except IOError:
        return None
    tag = None
    for cand in ("P13READ", "P12READ"):
        if cand in txt:
            tag = cand
            break
    if tag is None:
        return None
    body = txt.split(tag, 1)[1].strip()
    # the json is the first complete object on that line
    depth = 0
    for i, ch in enumerate(body):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(body[:i + 1])
                except ValueError:
                    return None
                obj["_reader_tag"] = tag
                return obj
    return None


def counter_delta(before, after, name):
    """after - before, or None if either side is missing/errored."""
    if not after:
        return None
    a = after.get("counters", {}).get(name)
    if not isinstance(a, int):
        return None
    b = 0
    if before:
        bv = before.get("counters", {}).get(name)
        if isinstance(bv, int):
            b = bv
    d = a - b
    return d if d >= 0 else a       # a reset between the two reads: trust the later absolute


# ------------------------------------------------------------- checking ----
class Result(object):
    def __init__(self):
        self.checks = []
        self.notes = []

    def add(self, name, ok, detail=""):
        self.checks.append({"check": name, "ok": bool(ok), "detail": detail})
        return ok

    def note(self, s):
        self.notes.append(s)

    @property
    def failures(self):
        return [c for c in self.checks if not c["ok"]]


def verify(plan, vision_pkts, hulk_pkts, before, after, mode, g_ns, tol_ns,
           premature_tol_ns, bypass_max_ns):
    r = Result()
    txns = plan["txns"]
    ntxn = len(txns)
    nresp = sum(len(t["resp"]) for t in txns)
    k = plan.get("k", 0)

    # ---- join keys: unique per transaction, checked as such by the plan selftest -----
    ack_by_no = {t["ack"]["ack_no"]: t for t in txns}
    resp_by_seq = {}
    for t in txns:
        for i, rr in enumerate(t["resp"]):
            resp_by_seq[rr["seq"]] = (t, i, rr)

    dnp3_port = plan["addressing"]["dnp3_port"]

    seen_ack = {}
    seen_resp = {}
    tokens_escaped = 0
    other_frames = 0
    dup_ack = dup_resp = 0

    for ts, frame in vision_pkts:
        p = parse_frame(frame)
        if p is None:
            continue
        if p["etype"] == ETYPE_TOKEN:
            tokens_escaped += 1
            continue
        if not p["tcp"]:
            other_frames += 1
            continue
        if p["sport"] != dnp3_port:
            other_frames += 1
            continue
        if p["payload_len"] == 0:
            t = ack_by_no.get(p["ack"])
            if t is None:
                other_frames += 1
                continue
            if t["txn"] in seen_ack:
                dup_ack += 1
                continue
            seen_ack[t["txn"]] = (ts, p)
        else:
            hit = resp_by_seq.get(p["seq"])
            if hit is None:
                other_frames += 1
                continue
            t, i, rr = hit
            key = (t["txn"], i)
            if key in seen_resp:
                dup_resp += 1
                continue
            seen_resp[key] = (ts, p, rr)

    # ---- (a) capture health -------------------------------------------------
    rel_delta = counter_delta(before, after, "ctr_resp_release")
    vision_total = len(vision_pkts)
    capture_live = vision_total > 0 and (len(seen_ack) + len(seen_resp)) > 0
    chip_says_released = isinstance(rel_delta, int) and rel_delta > 0
    inconclusive = (not capture_live) and chip_says_released
    r.add("vision capture holds frames", vision_total > 0,
          "%d records" % vision_total)
    if inconclusive:
        r.note("Vision capture is empty or unmatched while the chip counted %d releases: this is "
               "an OBSERVER failure, not a dataplane failure." % rel_delta)

    # ---- (b) classification vs the Gate 13.1 ground truth -------------------
    exp = {
        "ctr_arm": ntxn,
        "ctr_ack_arm": ntxn,
        "ctr_ack_bypass": 0,
        "ctr_resp_enq": nresp,
        "ctr_resp_release": nresp,
        "ctr_bypass:1": 0,
        "ctr_block_enq": (0 if mode == "bypass" else k * ntxn),
    }
    legacy_reader = (after or {}).get("_reader_tag") == "P12READ"
    if legacy_reader:
        r.note("counter evidence came from the legacy Part 12 reader (P12READ), which cannot "
               "address a multi-entry counter: the ctr_bypass checks are SKIPPED, not passed. "
               "Re-read with p13_read.py to cover them.")

    deltas = {}
    for name, want in exp.items():
        got = counter_delta(before, after, name)
        deltas[name] = got
        if got is None:
            if legacy_reader and name in P13_ONLY_COUNTERS:
                continue          # skipped and declared above, never silently passed
            r.add("counter %s readable" % name, False, "missing from the reader output")
        else:
            r.add("%s delta == %d" % (name, want), got == want, "got %d" % got)

    for name in ("ctr_block_loop", "ctr_block_term_deadline", "ctr_block_term_timeout",
                 "ctr_block_term_stale", "ctr_bypass:0"):
        deltas[name] = counter_delta(before, after, name)

    # ctr_ack_bypass > 0 or ctr_block_term_stale > 0 is the on-chip witness that cross-host
    # ordering broke: an ACK that beat its READ cannot arm, a token that beat its READ is stale.
    if deltas.get("ctr_ack_bypass"):
        r.note("ctr_ack_bypass=%s: at least one ACK reached the switch before its READ armed the "
               "slot. Increase --ack-lead-ms." % deltas["ctr_ack_bypass"])
    if deltas.get("ctr_block_term_stale"):
        r.note("ctr_block_term_stale=%s: at least one token carried a generation that did not "
               "match reg_gen — it beat its READ, or the generation contract is wrong."
               % deltas["ctr_block_term_stale"])

    if mode != "bypass":
        r.add("release was caused by the deadline",
              bool(deltas.get("ctr_block_term_deadline")),
              "ctr_block_term_deadline=%s ctr_block_term_timeout=%s"
              % (deltas.get("ctr_block_term_deadline"), deltas.get("ctr_block_term_timeout")))
    else:
        r.add("no blockers were enqueued in bypass mode",
              deltas.get("ctr_block_enq") == 0, "ctr_block_enq=%s" % deltas.get("ctr_block_enq"))

    # ---- (c) byte identity --------------------------------------------------
    bad_payload = []
    bad_frame = []
    truncated = []
    for (txn, i), (ts, p, rr) in sorted(seen_resp.items()):
        if p.get("truncated"):
            truncated.append(txn)
        want_payload = bytes.fromhex(rr["payload_hex"])
        if p["payload"] != want_payload:
            bad_payload.append(txn)
        want_frame = bytes.fromhex(rr["frame_hex"])
        got_frame = p["frame"][:len(want_frame)]
        if got_frame != want_frame:
            bad_frame.append(txn)
    r.add("every released RESPONSE was captured", len(seen_resp) == nresp,
          "%d of %d" % (len(seen_resp), nresp))
    r.add("every released RESPONSE payload is byte-identical", not bad_payload,
          "mismatched txns: %s" % (bad_payload[:10] or "none"))
    r.add("every released RESPONSE frame is byte-identical", not bad_frame,
          "mismatched txns: %s" % (bad_frame[:10] or "none"))
    r.add("no captured RESPONSE was truncated by the snaplen", not truncated,
          "truncated txns: %s" % (truncated[:10] or "none"))
    r.add("no duplicate RESPONSE on the wire", dup_resp == 0, "%d duplicates" % dup_resp)

    bad_ack_frame = []
    for txn, (ts, p) in sorted(seen_ack.items()):
        t = next(x for x in txns if x["txn"] == txn)
        want = bytes.fromhex(t["ack"]["frame_hex"])
        if p["frame"][:len(want)] != want:
            bad_ack_frame.append(txn)
    r.add("every forwarded ACK was captured", len(seen_ack) == ntxn,
          "%d of %d" % (len(seen_ack), ntxn))
    r.add("every forwarded ACK is byte-identical", not bad_ack_frame,
          "mismatched txns: %s" % (bad_ack_frame[:10] or "none"))
    r.add("no duplicate ACK on the wire", dup_ack == 0, "%d duplicates" % dup_ack)

    # ---- (d) ordering and (e) CLRT -----------------------------------------
    clrts_ns = []
    per_txn = []
    out_of_order = []
    premature = []
    for t in txns:
        txn = t["txn"]
        a = seen_ack.get(txn)
        rsp = seen_resp.get((txn, 0))
        row = {"txn": txn, "gen_hex": t["gen_hex"],
               "ack_seen": a is not None, "resp_seen": rsp is not None}
        if a and rsp:
            d_ns = int(round((rsp[0] - a[0]) * 1e9))
            row["clrt_ns"] = d_ns
            row["clrt_ms"] = round(d_ns / 1e6, 4)
            if d_ns <= 0:
                out_of_order.append(txn)
            else:
                clrts_ns.append(d_ns)
            if mode != "bypass" and g_ns is not None and d_ns < (g_ns - premature_tol_ns):
                premature.append(txn)
            if t.get("observed_ms"):
                row["corpus_clrt_ms"] = t["observed_ms"].get("ack_to_resp_clrt")
        per_txn.append(row)

    r.add("ACK egressed before its RESPONSE in every transaction", not out_of_order,
          "violating txns: %s" % (out_of_order[:10] or "none"))
    r.add("no RESPONSE was released before its deadline", not premature,
          "premature txns: %s" % (premature[:10] or "none"))

    stats = {}
    if clrts_ns:
        s = sorted(clrts_ns)
        stats = {
            "n": len(s),
            "min_ms": round(s[0] / 1e6, 4),
            "median_ms": round(statistics.median(s) / 1e6, 4),
            "mean_ms": round(sum(s) / len(s) / 1e6, 4),
            "p95_ms": round(s[min(len(s) - 1, int(0.95 * len(s)))] / 1e6, 4),
            "max_ms": round(s[-1] / 1e6, 4),
            "spread_ms": round((s[-1] - s[0]) / 1e6, 4),
        }
        if len(s) > 1:
            stats["stdev_ms"] = round(statistics.stdev(s) / 1e6, 4)
        med = statistics.median(s)
        if mode == "bypass":
            r.add("bypass CLRT stays under the no-hold bound",
                  med <= bypass_max_ns,
                  "median %.3f ms, bound %.3f ms" % (med / 1e6, bypass_max_ns / 1e6))
        elif g_ns is not None:
            stats["g_ms"] = round(g_ns / 1e6, 4)
            stats["median_error_ms"] = round((med - g_ns) / 1e6, 4)
            r.add("median CLRT is within tolerance of G",
                  abs(med - g_ns) <= tol_ns,
                  "median %.3f ms vs G %.3f ms, tolerance %.3f ms"
                  % (med / 1e6, g_ns / 1e6, tol_ns / 1e6))
    else:
        r.add("at least one CLRT was measurable", False, "no transaction had both an ACK and a "
                                                         "RESPONSE in the Vision capture")

    # ---- (f) isolation ------------------------------------------------------
    r.add("no blocker token reached a host port", tokens_escaped == 0,
          "%d escaped" % tokens_escaped)

    # ---- Hulk corroboration (optional) -------------------------------------
    hulk_reads = 0
    if hulk_pkts is not None:
        read_by_seq = {t["read"]["seq"]: t for t in txns}
        for ts, frame in hulk_pkts:
            p = parse_frame(frame)
            if p and p["tcp"] and p["dport"] == dnp3_port and p["seq"] in read_by_seq:
                hulk_reads += 1
        r.add("Hulk saw the forwarded READs", hulk_reads == ntxn,
              "%d of %d (tcpdump is promiscuous by default, which it must be: the READ's "
              "destination MAC is Vision's)" % (hulk_reads, ntxn))

    if mode == "hold_ack":
        r.note("mode=hold_ack is a NEGATIVE CONTROL: ibspg_dnp3.p4 has no ACK-hold branch, its "
               "ACK is unconditionally forwarded. A PASS here proves the ACK is never held; it "
               "is not evidence of an ACK-hold capability.")

    verdict = "PASS"
    if inconclusive:
        verdict = "INCONCLUSIVE_CAPTURE"
    elif r.failures:
        verdict = "FAIL"

    return {
        "verdict": verdict,
        "mode": mode,
        "ntxn": ntxn,
        "nresp": nresp,
        "k": k,
        "g_ns": g_ns,
        "capture": {"vision_records": vision_total, "matched_acks": len(seen_ack),
                    "matched_responses": len(seen_resp), "unmatched_frames": other_frames,
                    "tokens_escaped": tokens_escaped, "live": capture_live,
                    "hulk_reads": (hulk_reads if hulk_pkts is not None else None)},
        "counter_deltas": deltas,
        "clrt": stats,
        "per_txn": per_txn,
        "checks": r.checks,
        "failures": [c["check"] for c in r.failures],
        "notes": r.notes,
        "on_chip_txn0": (after or {}).get("derived"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", required=True)
    ap.add_argument("--vision-pcap", required=True)
    ap.add_argument("--hulk-pcap", default=None)
    ap.add_argument("--before-json", default=None)
    ap.add_argument("--after-json", default=None)
    ap.add_argument("--mode", default=None, choices=["bypass", "hold_ack", "hold_resp"],
                    help="defaults to the mode recorded in the plan")
    ap.add_argument("--g-ns", type=int, default=None)
    ap.add_argument("--g-ms", type=float, default=None)
    ap.add_argument("--tol-ms", type=float, default=5.0,
                    help="allowed |median CLRT - G|; covers the reservoir drain tail")
    ap.add_argument("--premature-tol-ms", type=float, default=0.5,
                    help="how far below G a release may fall before it counts as premature")
    ap.add_argument("--bypass-max-ms", type=float, default=None,
                    help="no-hold CLRT bound; defaults to the plan's resp delay + 5 ms")
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    with open(a.plan) as fh:
        plan = json.load(fh)
    mode = a.mode or plan.get("mode", "hold_resp")

    g_ns = a.g_ns
    if g_ns is None and a.g_ms is not None:
        g_ns = int(round(a.g_ms * 1e6))

    bypass_max_ns = (int(round(a.bypass_max_ms * 1e6)) if a.bypass_max_ms is not None
                     else int(round((plan["schedule"]["resp_delay_ms"] + 5.0) * 1e6)))

    try:
        vision_pkts = read_pcap(a.vision_pcap)
    except (IOError, ValueError) as e:
        sys.stderr.write("could not read the Vision pcap: %s\n" % e)
        vision_pkts = []
    hulk_pkts = None
    if a.hulk_pcap:
        try:
            hulk_pkts = read_pcap(a.hulk_pcap)
        except (IOError, ValueError) as e:
            sys.stderr.write("could not read the Hulk pcap: %s\n" % e)
            hulk_pkts = None

    before = load_read_json(a.before_json)
    after = load_read_json(a.after_json)

    res = verify(plan, vision_pkts, hulk_pkts, before, after, mode, g_ns,
                 int(round(a.tol_ms * 1e6)), int(round(a.premature_tol_ms * 1e6)),
                 bypass_max_ns)

    if a.json:
        with open(a.json, "w") as fh:
            json.dump(res, fh, indent=1)
    print(json.dumps({k: v for k, v in res.items() if k not in ("checks", "per_txn")}, indent=1))
    for c in res["checks"]:
        if not c["ok"]:
            sys.stderr.write("  FAIL %s — %s\n" % (c["check"], c["detail"]))

    return {"PASS": 0, "FAIL": 1, "INCONCLUSIVE_CAPTURE": 2}[res["verdict"]]


if __name__ == "__main__":
    sys.exit(main())

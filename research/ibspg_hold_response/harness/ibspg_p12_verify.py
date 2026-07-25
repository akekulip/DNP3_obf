#!/usr/bin/env python3
"""ibspg_p12_verify.py — verdict for one Part 12 HOLD_RESPONSE trial.

Runs LOCALLY (gambit), stdlib only, py3.8+. Takes three inputs:

  --released    host PCAP captured on Vision (classic pcap; tcpdump -w), i.e. the
                frames that actually left the switch's protected egress dp9
  --reader-json file containing the "P12READ {...}" line from ibspg_p12_read.py
  --spec        what ibspg_p12_gen.py says it injected (lift the `spec` field of
                the P12GEN line verbatim), so injected frames are RECONSTRUCTED
                rather than captured — capturing on the inject interface fights
                with the AF_PACKET inject.

CHECKS
  (a) byte-identity   every released RESPONSE is byte-identical to its injected
                      twin (keyed by its unique seq packet_id) — count, FIFO
                      order, no dup / missing / corrupt / unexpected. Every
                      released ACK is byte-identical to the (uniform) injected
                      ACK frame.
  (b) ordering        the ACK egressed BEFORE the response, measured on the wire
                      (capture order in the Vision PCAP), cross-checked against
                      the on-chip stamp pair when the reader json is supplied.
                      In Part 12 this is structurally trivial — the ACK is never
                      held — but it is the invariant the whole line rests on, so
                      it is still measured rather than assumed.
  (c) interval        g_observed within tolerance of G, AND not premature: a
                      response must never leave before its deadline. Applies to
                      --scenario normal with --k > 0 (with no reservoir there is
                      no hold and no interval to normalise).
  (d) negatives       for stale-ack / unrelated-ack / no-ack: the deadline was
                      NOT armed (ctr_ack_arm == 0, ctr_ack_bypass as expected)
                      and the response was released by BUDGET EXHAUSTION instead
                      (ctr_block_term_timeout > 0, ctr_block_term_deadline == 0).

SPEC FORMAT (key=value, comma separated — a deviation from Part 11's positional
colon spec, because Part 12 needs the ACK's slot/gen/seq to differ from the
armed slot/gen per scenario and 11 positional fields is unreadable):
  nack=1,nresp=1,ack_seq=20000000,ack_gen=7,ack_slot=0,resp_id_start=1,
  gen=7,slot=0,dst=3cfdfecc5dc0,src=02000000000a,pad=60
  (ack_seq is G in ns — the ACK's seq field carries G, not a packet id.)

Exit 0 = PASS, 1 = FAIL. --json writes the full machine-readable result.
"""
import argparse
import json
import struct
import sys

ETYPE_REAL = 0x88C0
ETYPE_TOKEN = 0x88C1
ROLE_RESP = 2
ROLE_ACK = 7

MASK32 = 0xFFFFFFFF

LINKTYPE_EN10MB = 1
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

SPEC_INT_KEYS = ("nack", "nresp", "ack_seq", "ack_gen", "ack_slot",
                 "resp_id_start", "gen", "slot", "pad")
SPEC_STR_KEYS = ("dst", "src")


# ---------------------------------------------------------------- pcap ----
# (classic-pcap reader carried over verbatim from the Part 11 verifier, which is
#  frozen; copied rather than imported so this tree stands alone.)
def _read_pcap(path):
    """Yield (linktype, pkttype_or_None, frame_bytes) for each record."""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            end = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            end = ">"
        else:
            raise ValueError("not a classic pcap (magic %r) — is it pcapng? re-capture with -w"
                             % magic)
        linktype = struct.unpack(end + "I", gh[20:24])[0]
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                break
            _, _, incl, _orig = struct.unpack(end + "IIII", rh)
            data = f.read(incl)
            if len(data) < incl:
                break
            pkttype = None
            frame = data
            if linktype == LINKTYPE_LINUX_SLL:
                if len(data) < 16:
                    continue
                pkttype = struct.unpack(">H", data[0:2])[0]
                proto = struct.unpack(">H", data[14:16])[0]
                frame = b"\x00" * 6 + data[6:12] + struct.pack(">H", proto) + data[16:]
            elif linktype == LINKTYPE_LINUX_SLL2:
                if len(data) < 20:
                    continue
                proto = struct.unpack(">H", data[0:2])[0]
                pkttype = data[10]
                frame = b"\x00" * 6 + data[12:18] + struct.pack(">H", proto) + data[20:]
            yield linktype, pkttype, frame


def _parse_ibspg(frame):
    if len(frame) < 14 + 7:
        return None
    etype = struct.unpack(">H", frame[12:14])[0]
    if etype not in (ETYPE_REAL, ETYPE_TOKEN):
        return None
    role, slot, gen = frame[14], frame[15], frame[16]
    seq = struct.unpack(">I", frame[17:21])[0]
    return {"role": role, "slot": slot, "gen": gen, "seq": seq, "frame": frame,
            "etype": etype}


def _all_ibspg(records):
    """Every IBSPG frame in capture order, tagged with its capture index."""
    out = []
    for idx, (_lt, _pt, frame) in enumerate(records):
        p = _parse_ibspg(frame)
        if p:
            p["idx"] = idx
            p["pkttype"] = _pt
            out.append(p)
    return out


def _build(role, slot, gen, seq, dst_hex, src_hex, pad):
    ib = struct.pack("!BBBI", role & 0xFF, slot & 0xFF, gen & 0xFF, seq & 0xFFFFFFFF)
    frame = bytes.fromhex(dst_hex) + bytes.fromhex(src_hex) + struct.pack(">H", ETYPE_REAL) + ib
    if len(frame) < pad:
        frame += b"\x00" * (pad - len(frame))
    return frame


# ----------------------------------------------------------- verifiers ----
def verify_keyed(injected, released, expect):
    """Part 11's id-keyed check: count, byte-identity, FIFO, dup/missing/unexpected.
    Requires each injected frame to carry a UNIQUE seq (true for RESPONSE ids)."""
    inj_ids = [p["seq"] for p in injected]
    rel_ids = [p["seq"] for p in released]
    inj_by_id = {}
    dup_injected = []
    for p in injected:
        if p["seq"] in inj_by_id:
            dup_injected.append(p["seq"])
        inj_by_id[p["seq"]] = p

    seen, duplicates, corrupted, unexpected = {}, [], [], []
    for p in released:
        i = p["seq"]
        if i in seen:
            duplicates.append(i)
            continue
        seen[i] = p
        twin = inj_by_id.get(i)
        if twin is None:
            unexpected.append(i)
        elif twin["frame"] != p["frame"]:
            corrupted.append(i)

    missing = [i for i in inj_ids if i not in seen]
    inj_order = [i for i in inj_ids if i in seen]
    _s = set()
    rel_order_u = [x for x in rel_ids if x in inj_by_id and not (x in _s or _s.add(x))]
    fifo_ok = (inj_order == rel_order_u)

    ok = (not duplicates and not missing and not corrupted and not unexpected
          and fifo_ok and not dup_injected)
    if expect is not None:
        ok = ok and (len(seen) == expect) and (len(injected) == expect)
    return {
        "verdict": "PASS" if ok else "FAIL",
        "injected_count": len(injected),
        "released_count": len(released),
        "unique_released": len(seen),
        "expected": expect,
        "dup_injected": sorted(set(dup_injected)),
        "duplicate_released": sorted(set(duplicates)),
        "missing_ids": sorted(missing),
        "corrupted_ids": sorted(set(corrupted)),
        "unexpected_ids": sorted(set(unexpected)),
        "fifo_ok": fifo_ok,
        "injected_order": inj_order,
        "released_order": rel_order_u,
    }


def verify_uniform(expected_frame, released, expect):
    """Byte-identity for a set of IDENTICAL injected frames.

    The Part 12 ACK carries G in its seq field, not a unique packet id, so N ACKs
    are byte-identical and cannot be id-keyed the way Part 11 keyed them. Check
    the multiset instead: exact count, every released frame equal to the expected
    one."""
    mismatched = [i for i, p in enumerate(released) if p["frame"] != expected_frame]
    ok = (len(released) == expect) and not mismatched
    return {
        "verdict": "PASS" if ok else "FAIL",
        "expected": expect,
        "released_count": len(released),
        "mismatched_indices": mismatched,
    }


def parse_spec(s):
    d = {}
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        k, _, v = part.partition("=")
        d[k.strip()] = v.strip()
    missing = [k for k in SPEC_INT_KEYS + SPEC_STR_KEYS if k not in d]
    if missing:
        raise ValueError("spec is missing key(s): %s" % ",".join(missing))
    for k in SPEC_INT_KEYS:
        d[k] = int(d[k])
    return d


def load_reader_json(path):
    """Accept a file holding the raw 'P12READ {...}' line, or bare JSON."""
    with open(path) as f:
        txt = f.read()
    for line in txt.splitlines():
        line = line.strip()
        if line.startswith("P12READ "):
            return json.loads(line[len("P12READ "):])
    return json.loads(txt)


def _ctr(rd, name):
    v = rd.get("counters", {}).get(name)
    return v if isinstance(v, int) else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--released", required=True, help="Vision-side PCAP (classic pcap)")
    ap.add_argument("--spec", required=True, help="key=value spec from the P12GEN line")
    ap.add_argument("--reader-json", help="file containing the P12READ line (needed for (c)/(d))")
    ap.add_argument("--scenario", default="normal",
                    choices=("normal", "stale-ack", "unrelated-ack", "no-ack"))
    ap.add_argument("--k", type=int, default=64,
                    help="blocker reservoir size the trial used; with k=0 nothing holds the "
                         "response, so the interval checks do not apply")
    ap.add_argument("--tol-ns", type=int, default=1000000,
                    help="absolute tolerance on |g_observed - G| (default 1 ms). PLACEHOLDER — "
                         "calibrate from the first measured runs before quoting a gate.")
    ap.add_argument("--tol-frac", type=float, default=0.05,
                    help="relative tolerance; the effective tolerance is max(tol_ns, tol_frac*G)")
    ap.add_argument("--premature-slack-ns", type=int, default=0,
                    help="how far below G a release may land before it counts as premature")
    ap.add_argument("--json", help="write the full result here")
    a = ap.parse_args()

    sp = parse_spec(a.spec)
    checks = []

    def add(name, ok, detail):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    # ---------- wire evidence ----------
    allf = _all_ibspg(list(_read_pcap(a.released)))
    rel_ack = [p for p in allf if p["role"] == ROLE_ACK]
    rel_resp = [p for p in allf if p["role"] == ROLE_RESP]

    # (a) byte-identity
    exp_resp = [{"seq": sp["resp_id_start"] + i,
                 "frame": _build(ROLE_RESP, sp["slot"], sp["gen"], sp["resp_id_start"] + i,
                                 sp["dst"], sp["src"], sp["pad"])}
                for i in range(sp["nresp"])]
    r_resp = verify_keyed(exp_resp, rel_resp, sp["nresp"])
    add("a1_resp_byte_identity", r_resp["verdict"] == "PASS", r_resp)

    exp_ack_frame = _build(ROLE_ACK, sp["ack_slot"], sp["ack_gen"], sp["ack_seq"],
                           sp["dst"], sp["src"], sp["pad"])
    r_ack = verify_uniform(exp_ack_frame, rel_ack, sp["nack"])
    add("a2_ack_byte_identity", r_ack["verdict"] == "PASS", r_ack)

    # (b) ordering on the wire
    last_ack_idx = max([p["idx"] for p in rel_ack]) if rel_ack else None
    first_resp_idx = min([p["idx"] for p in rel_resp]) if rel_resp else None
    if rel_ack and rel_resp:
        order_ok = last_ack_idx < first_resp_idx
    else:
        # trivially ordered when one side is absent by design (no-ack / nresp=0)
        order_ok = (sp["nack"] == 0 or sp["nresp"] == 0)
    add("b_ack_before_resp_on_wire", order_ok,
        {"last_ack_idx": last_ack_idx, "first_resp_idx": first_resp_idx,
         "ack_frames": len(rel_ack), "resp_frames": len(rel_resp)})

    # (b2) internal-token visibility: a blocker token (ethertype 0x88C1) is internal to the
    # dp8 loopback and must NEVER reach a protected host port. Any token in a host-side
    # capture is a test failure and must not be relabelled after the fact.
    # NOTE: this check is only meaningful if the capture filter admits 0x88C1 — a filter of
    # "ether proto 0x88c0" alone makes its absence vacuous. part12_trial.sh captures both.
    escaped = [p for p in allf if p.get("etype") == ETYPE_TOKEN]
    add("b3_no_blocker_escape", not escaped,
        {"blocker_frames_seen": len(escaped),
         "first_seen": (escaped[0]["idx"] if escaped else None)})

    # ---------- on-chip evidence ----------
    rd = None
    if a.reader_json:
        rd = load_reader_json(a.reader_json)
        der = rd.get("derived", {})
        g_ns_spec = sp["ack_seq"]
        g_ns_read = der.get("g_ns")
        add("g_consistent", (g_ns_read is None or g_ns_read == g_ns_spec),
            {"g_ns_from_spec": g_ns_spec, "g_ns_passed_to_reader": g_ns_read})

        # on-chip corroboration of (b)
        t_ack = der.get("ts_ack_arm")
        t_rel = der.get("ts_first_resp_release")
        if t_ack and t_rel:
            add("b2_ack_before_resp_onchip", ((t_rel - t_ack) & MASK32) < (1 << 31),
                {"ts_ack_arm": t_ack, "ts_first_resp_release": t_rel,
                 "g_observed_ns": der.get("g_observed_ns")})

        rrel = _ctr(rd, "ctr_resp_release")
        renq = _ctr(rd, "ctr_resp_enq")
        add("resp_counts", (rrel == sp["nresp"] and renq is not None and renq >= sp["nresp"]),
            {"ctr_resp_enq": renq, "ctr_resp_release": rrel, "nresp": sp["nresp"]})

        aarm = _ctr(rd, "ctr_ack_arm")
        abyp = _ctr(rd, "ctr_ack_bypass")
        tdl = _ctr(rd, "ctr_block_term_deadline")
        ttmo = _ctr(rd, "ctr_block_term_timeout")

        if a.scenario == "normal":
            # (c) interval — only meaningful when a reservoir actually held the response
            add("c1_deadline_armed", aarm == sp["nack"] and abyp == 0,
                {"ctr_ack_arm": aarm, "ctr_ack_bypass": abyp, "nack": sp["nack"]})
            if a.k > 0:
                add("c2_released_by_deadline", (tdl is not None and tdl >= 1 and ttmo == 0),
                    {"ctr_block_term_deadline": tdl, "ctr_block_term_timeout": ttmo})
                g_obs = der.get("g_observed_ns")
                err = der.get("deadline_error_ns")
                tol = max(a.tol_ns, int(a.tol_frac * g_ns_spec))
                add("c3_interval_within_tolerance",
                    (err is not None and abs(err) <= tol),
                    {"g_observed_ns": g_obs, "g_ns": g_ns_spec,
                     "deadline_error_ns": err, "tolerance_ns": tol})
                add("c4_not_premature",
                    (g_obs is not None and g_obs >= g_ns_spec - a.premature_slack_ns),
                    {"g_observed_ns": g_obs, "g_ns": g_ns_spec,
                     "premature_slack_ns": a.premature_slack_ns})
        else:
            # (d) negatives — no arm, release by budget exhaustion instead
            exp_byp = 0 if a.scenario == "no-ack" else sp["nack"]
            add("d1_deadline_not_armed",
                (aarm == 0 and abyp == exp_byp),
                {"ctr_ack_arm": aarm, "ctr_ack_bypass": abyp,
                 "expected_bypass": exp_byp, "scenario": a.scenario})
            if a.k > 0:
                add("d2_released_by_budget_exhaustion",
                    (ttmo is not None and ttmo > 0 and tdl == 0),
                    {"ctr_block_term_timeout": ttmo, "ctr_block_term_deadline": tdl})

    ok = all(c["ok"] for c in checks)
    out = {
        "verdict": "PASS" if ok else "FAIL",
        "scenario": a.scenario,
        "k": a.k,
        "spec": sp,
        "ack_before_resp": order_ok,
        "g_observed_ns": (rd.get("derived", {}).get("g_observed_ns") if rd else None),
        "deadline_error_ns": (rd.get("derived", {}).get("deadline_error_ns") if rd else None),
        "release_tail_ns": (rd.get("derived", {}).get("release_tail_ns") if rd else None),
        "checks": checks,
    }
    if a.json:
        with open(a.json, "w") as f:
            json.dump(out, f, indent=2)
    print(json.dumps({
        "verdict": out["verdict"],
        "scenario": a.scenario,
        "ack_before_resp": order_ok,
        "g_observed_ns": out["g_observed_ns"],
        "deadline_error_ns": out["deadline_error_ns"],
        "release_tail_ns": out["release_tail_ns"],
        "failed": [c["check"] for c in checks if not c["ok"]],
    }, indent=2))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

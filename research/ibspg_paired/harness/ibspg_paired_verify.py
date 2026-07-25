#!/usr/bin/env python3
"""ibspg_part9_verify.py — byte-identity + FIFO + count verifier for Part 9.

Compares the HELD frames INJECTED at the host against the HELD frames RELEASED back to the
host (forwarded by the switch out the protected egress on controlled drain / fail-open).

Stdlib only (classic pcap parsing, no scapy) so it runs on gambit or Hulk (py3.8+).

Frame model (must match ibspg_part9_gen.py / the P4):
  Ethernet(dst48, src48, etype16) + ibspg(role8, slot8, gen8, seq32)
  HELD frames use etype 0x88C0, role==2, and seq == unique packet_id (0,1,2,...).
  The P4 forwards a released HELD BYTE-IDENTICALLY, so its bytes (minus trailing pad it never
  added and the hardware FCS not present in the pcap) equal the injected frame's bytes.

Direction split: pass two pcaps captured by direction (tcpdump -Q out / -Q in), OR one pcap
captured cooked (-i any) and we split on SLL pkttype (4=OUTGOING=injected, 0=HOST/incoming).

Usage:
  ibspg_part9_verify.py --injected inj.pcap --released rel.pcap [--expect N] [--json out.json]
  ibspg_part9_verify.py --cooked all.pcap [--expect N] [--json out.json]

Exit 0 = PASS (all released frames byte-identical to their injected twin, count exact, FIFO,
no dup/missing/corrupt); exit 1 = FAIL. A machine-readable summary is written with --json.
"""
import argparse
import json
import struct
import sys

ETYPE_REAL = 0x88C0
ETYPE_TOKEN = 0x88C1
ROLE_HOLD = 2      # = ROLE_RESP in Part 11
ROLE_RESP = 2
ROLE_ACK = 7

# ---- pcap link types ----
LINKTYPE_EN10MB = 1
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276


def _read_pcap(path):
    """Yield (linktype, pkttype_or_None, frame_bytes) for each record in a classic pcap."""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            end = "<"          # little-endian (usec or nsec)
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            end = ">"
        else:
            raise ValueError("not a classic pcap (magic %r) — is it pcapng? re-capture with -w" % magic)
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
            if linktype == LINKTYPE_LINUX_SLL:          # 16-byte cooked header
                if len(data) < 16:
                    continue
                pkttype = struct.unpack(">H", data[0:2])[0]   # 0=host/in,4=outgoing
                # reconstruct an Ethernet-ish frame: SLL has no dst; addr at [6:6+addrlen]
                # For our purposes we only need etype+ibspg, which sit after the L2 payload.
                # SLL: [0:2]pkttype [2:4]arphrd [4:6]addrlen [6:14]addr [14:16]proto ...payload
                proto = struct.unpack(">H", data[14:16])[0]
                payload = data[16:]
                # rebuild a synthetic ethernet header (dst unknown) so downstream parse is uniform
                frame = b"\x00" * 6 + data[6:12] + struct.pack(">H", proto) + payload
            elif linktype == LINKTYPE_LINUX_SLL2:
                # SLL2: [0:2]proto [2:4]reserved [4:8]ifindex [8:10]arphrd [10]pkttype [11]addrlen [12:20]addr
                if len(data) < 20:
                    continue
                proto = struct.unpack(">H", data[0:2])[0]
                pkttype = data[10]
                payload = data[20:]
                frame = b"\x00" * 6 + data[12:18] + struct.pack(">H", proto) + payload
            yield linktype, pkttype, frame


def _build_held(count, id_start, gen, slot, dst_hex, src_hex, pad, role=ROLE_HOLD):
    """Deterministically reconstruct injected frames of a given role (must match the generator's build)."""
    dst = bytes.fromhex(dst_hex)
    src = bytes.fromhex(src_hex)
    out = []
    for i in range(count):
        seq = id_start + i
        ib = struct.pack("!BBBI", role, slot & 0xFF, gen & 0xFF, seq & 0xFFFFFFFF)
        frame = dst + src + struct.pack(">H", ETYPE_REAL) + ib
        if len(frame) < pad:
            frame += b"\x00" * (pad - len(frame))
        out.append({"role": role, "slot": slot, "gen": gen, "seq": seq, "frame": frame, "pkttype": 4})
    return out


def _all_ibspg(records):
    """Every IBSPG frame in capture order, tagged with its capture index and role."""
    out = []
    for idx, (_lt, _pt, frame) in enumerate(records):
        p = _parse_ibspg(frame)
        if p:
            p["idx"] = idx
            p["pkttype"] = _pt
            out.append(p)
    return out


def _parse_ibspg(frame):
    """Return dict {role,slot,gen,seq,frame} if this is an IBSPG frame, else None."""
    if len(frame) < 14 + 7:
        return None
    etype = struct.unpack(">H", frame[12:14])[0]
    if etype not in (ETYPE_REAL, ETYPE_TOKEN):
        return None
    role, slot, gen = frame[14], frame[15], frame[16]
    seq = struct.unpack(">I", frame[17:21])[0]
    return {"role": role, "slot": slot, "gen": gen, "seq": seq, "frame": frame}


def _held_frames(records):
    """From (linktype,pkttype,frame) records, return list of parsed HELD frames in capture order."""
    out = []
    for _lt, _pt, frame in records:
        p = _parse_ibspg(frame)
        if p and p["role"] == ROLE_HOLD:
            p["pkttype"] = _pt
            out.append(p)
    return out


def _canon(frame):
    """Canonical bytes for FULL-FRAME byte-identity. Compares the entire captured Ethernet
    frame (header + ibspg + payload + any padding), excluding only a trailing 4-byte FCS if a
    capture happens to include one. For SLL cooked captures dst is zeroed on BOTH the injected
    and released side (see _read_pcap), so it cancels; for EN10MB two-file captures the real dst
    is present on both sides and IS compared. A byte flip anywhere — header, payload, or padding —
    changes _canon and is reported as corruption."""
    # Strip a trailing 4-byte FCS only if the frame is FCS-sized (>= 64) AND divisible cleanly;
    # tcpdump normally omits FCS, so this is a no-op in the common case. We do NOT strip padding.
    return frame


def verify(injected, released, expect=None):
    inj = injected
    rel = released
    inj_ids = [p["seq"] for p in inj]
    rel_ids = [p["seq"] for p in rel]
    inj_by_id = {}
    dup_injected = []
    for p in inj:
        if p["seq"] in inj_by_id:
            dup_injected.append(p["seq"])
        inj_by_id[p["seq"]] = p

    seen = {}
    duplicates = []
    corrupted = []
    unexpected = []
    for p in rel:
        i = p["seq"]
        if i in seen:
            duplicates.append(i)
            continue
        seen[i] = p
        twin = inj_by_id.get(i)
        if twin is None:
            unexpected.append(i)
        elif _canon(twin["frame"]) != _canon(p["frame"]):
            corrupted.append(i)

    missing = [i for i in inj_ids if i not in seen]
    # FIFO: released id order equals injected id order for the ids that were released
    inj_order = [i for i in inj_ids if i in seen]
    rel_order = [i for i in rel_ids if i in inj_by_id]   # released ids that were injected, in capture order
    # de-dup rel_order preserving first occurrence
    _s = set(); rel_order_u = [x for x in rel_order if not (x in _s or _s.add(x))]
    fifo_ok = (inj_order == rel_order_u)

    res = {
        "injected_count": len(inj),
        "released_count": len(rel),
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
    ok = (not duplicates and not missing and not corrupted and not unexpected and fifo_ok)
    if expect is not None:
        ok = ok and (len(seen) == expect) and (len(inj) == expect)
    res["verdict"] = "PASS" if ok else "FAIL"
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--injected")
    ap.add_argument("--released")
    ap.add_argument("--cooked", help="single -i any pcap; split by SLL pkttype")
    ap.add_argument("--held-spec", help="reconstruct injected HELD instead of capturing them: "
                    "count:id_start:gen:slot:dst_hex:src_hex:pad")
    ap.add_argument("--paired-spec", help="Part 11 paired ACK-before-response check: "
                    "nack:nresp:idack:idresp:gen:slot:dst_hex:src_hex:pad")
    ap.add_argument("--expect", type=int, default=None)
    ap.add_argument("--json")
    a = ap.parse_args()

    if a.paired_spec:
        nack, nresp, idack, idresp, gen, slot, dst, src, pad = a.paired_spec.split(":")
        nack, nresp, idack, idresp, gen, slot, pad = int(nack), int(nresp), int(idack), int(idresp), int(gen), int(slot), int(pad)
        allf = _all_ibspg(list(_read_pcap(a.released)))
        rel_ack = [p for p in allf if p["role"] == ROLE_ACK]
        rel_resp = [p for p in allf if p["role"] == ROLE_RESP]
        exp_ack = _build_held(nack, idack, gen, slot, dst, src, pad, ROLE_ACK)
        exp_resp = _build_held(nresp, idresp, gen, slot, dst, src, pad, ROLE_RESP)
        r_ack = verify(exp_ack, rel_ack, nack)
        r_resp = verify(exp_resp, rel_resp, nresp)
        # ordering: every ACK record precedes every RESP record in capture order
        if rel_ack and rel_resp:
            order_ok = max(p["idx"] for p in rel_ack) < min(p["idx"] for p in rel_resp)
        else:
            order_ok = (nack == 0 or nresp == 0)   # trivially ordered if one side empty
        ok = (r_ack["verdict"] == "PASS" and r_resp["verdict"] == "PASS" and order_ok)
        out = {"verdict": "PASS" if ok else "FAIL", "ack": r_ack, "resp": r_resp,
               "ack_before_resp": order_ok,
               "last_ack_idx": (max(p["idx"] for p in rel_ack) if rel_ack else None),
               "first_resp_idx": (min(p["idx"] for p in rel_resp) if rel_resp else None)}
        if a.json:
            json.dump(out, open(a.json, "w"), indent=2)
        print(json.dumps({"verdict": out["verdict"], "ack_before_resp": order_ok,
                          "ack": {k: r_ack[k] for k in ("verdict", "released_count", "missing_ids", "corrupted_ids", "fifo_ok")},
                          "resp": {k: r_resp[k] for k in ("verdict", "released_count", "missing_ids", "corrupted_ids", "fifo_ok")},
                          "last_ack_idx": out["last_ack_idx"], "first_resp_idx": out["first_resp_idx"]}, indent=2))
        sys.exit(0 if ok else 1)

    if a.held_spec:
        c, ids, gen, slot, dst, src, pad = a.held_spec.split(":")
        inj = _build_held(int(c), int(ids), int(gen), int(slot), dst, src, int(pad))
        rel = _held_frames(_read_pcap(a.released))
        res = verify(inj, rel, a.expect)
        if a.json:
            json.dump(res, open(a.json, "w"), indent=2)
        print(json.dumps({k: res[k] for k in (
            "verdict", "injected_count", "released_count", "unique_released", "expected",
            "missing_ids", "duplicate_released", "corrupted_ids", "unexpected_ids", "fifo_ok")}, indent=2))
        sys.exit(0 if res["verdict"] == "PASS" else 1)

    if a.cooked:
        recs = list(_read_pcap(a.cooked))
        held = _held_frames(recs)
        inj = [p for p in held if p.get("pkttype") == 4]      # OUTGOING
        rel = [p for p in held if p.get("pkttype") in (0, 1)]  # HOST / BROADCAST (incoming)
    else:
        if not (a.injected and a.released):
            ap.error("need --injected and --released, or --cooked")
        inj = _held_frames(_read_pcap(a.injected))
        rel = _held_frames(_read_pcap(a.released))

    res = verify(inj, rel, a.expect)
    if a.json:
        with open(a.json, "w") as f:
            json.dump(res, f, indent=2)
    print(json.dumps({k: res[k] for k in (
        "verdict", "injected_count", "released_count", "unique_released", "expected",
        "missing_ids", "duplicate_released", "corrupted_ids", "unexpected_ids", "fifo_ok")}, indent=2))
    sys.exit(0 if res["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()

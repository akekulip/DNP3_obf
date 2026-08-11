#!/usr/bin/env python3
"""Size Probe 1 — offline DNP3 READ-range normalization transformer + oracle.

Mechanism: rewrite a supported fixed-width DNP3 READ object range to a public superset by
expanding ONLY the stop/count field (same byte width), keeping the request's TCP + DNP3 frame
length unchanged, so the outstation naturally emits a larger response. Every originally requested
real point stays included; the added indices are reserved inert decoys. Recompute the affected
DNP3 block CRC and the TCP checksum. Byte-identical fail-open on unsupported layouts, qualifier
0x06 (all-points, no range), malformed CRC, fragmentation, or an unsafe range.

This proves the SPECIFICATION (parse/rewrite/CRC/length/fail-open). It is not evidence for the
captured Group-60 Class-1/2/3 all-points poll (qualifier 0x06), which must fail open byte-identical.

Run:  ~/.venvs/research/bin/python size_transform.py
"""
import sys
from scapy.all import Ether, IP, TCP, Raw

sys.path.insert(0, "/home/philip/Projects/DNP3/dnp3_split_harness")
import dnp3_crc  # dnp3_crc16 / append_crc / verify_crc  (CRC-16/DNP)

FUNC_READ = 0x01
# policy: (group, var, qualifier) -> public stop/count to expand to.
# qualifier 0x00 = 8-bit start/stop; 0x01 = 16-bit start/stop.
POLICY = {
    (30, 1, 0x00): {"public_stop": 15},   # analog input, 8-bit range
    (1, 2, 0x00):  {"public_stop": 31},   # binary input, 8-bit range
    (30, 1, 0x01): {"public_stop": 255},  # analog input, 16-bit range
}


# ---------- DNP3 framing (link header + CRC-blocked user data) ----------
def split_user_data(frame):
    """Return (link_header8, link_crc_ok, user_data) or (None,None,None) if malformed."""
    if len(frame) < 10 or frame[0] != 0x05 or frame[1] != 0x64:
        return None, None, None
    lh = frame[0:8]
    link_crc_ok = dnp3_crc.verify_crc(lh, frame[8:10])
    body = frame[10:]
    ud = bytearray()
    i = 0
    while i < len(body):
        chunk = body[i:i + 16]
        if len(chunk) < 2:
            return None, None, None
        data, crc = chunk[:-2], chunk[-2:]
        # last block may be short: data is everything but the trailing 2 CRC bytes
        if len(chunk) <= 16 and i + len(chunk) >= len(body):
            data, crc = chunk[:-2], chunk[-2:]
        if not dnp3_crc.verify_crc(bytes(data), bytes(crc)):
            return lh, link_crc_ok, None      # CRC bad -> caller fails open
        ud += data
        i += len(chunk)
    return lh, link_crc_ok, bytes(ud)


def rebuild_frame(link_header8, user_data):
    """Reassemble a DNP3 frame: link hdr + link CRC + 16-byte CRC-blocked user data."""
    out = bytearray(link_header8)
    out += dnp3_crc.dnp3_crc16(link_header8).to_bytes(2, "little")
    for i in range(0, len(user_data), 16):
        blk = user_data[i:i + 16]
        out += blk + dnp3_crc.dnp3_crc16(blk).to_bytes(2, "little")
    return bytes(out)


def parse_first_object(ud):
    """After transport(1)+app_ctrl(1)+func(1): return (func, obj_off, group, var, qual)."""
    if len(ud) < 4:
        return None
    func = ud[2]
    off = 3
    if off + 3 > len(ud):
        return None
    return func, off, ud[off], ud[off + 1], ud[off + 2]


# ---------- transform ----------
def transform(pkt):
    """Return (out_pkt, outcome). Length-preserving; fail-open byte-identical otherwise."""
    p = Ether(bytes(pkt))
    if TCP not in p or Raw not in p:
        return p, "fwd_non_dnp3"
    frame = bytes(p[Raw].load)
    lh, link_ok, ud = split_user_data(frame)
    if lh is None:
        return p, "fwd_not_dnp3_frame"
    if not link_ok or ud is None:
        return p, "failopen_bad_crc"           # malformed CRC -> byte-identical
    parsed = parse_first_object(ud)
    if parsed is None:
        return p, "failopen_short"
    func, off, group, var, qual = parsed
    if func != FUNC_READ:
        return p, "failopen_not_read"
    key = (group, var, qual)
    if key not in POLICY:
        return p, "failopen_unsupported_obj"   # covers qualifier 0x06 all-points
    # supported range qualifier: 0x00 (8-bit) or 0x01 (16-bit)
    ud2 = bytearray(ud)
    if qual == 0x00:
        if off + 5 > len(ud):
            return p, "failopen_short_range"
        start, stop = ud[off + 3], ud[off + 4]
        new_stop = POLICY[key]["public_stop"]
        if new_stop < stop or new_stop > 0xFF:
            return p, "failopen_unsafe_range"   # must not shrink; keep all real points
        ud2[off + 4] = new_stop
    elif qual == 0x01:
        if off + 7 > len(ud):
            return p, "failopen_short_range"
        start = int.from_bytes(ud[off + 3:off + 5], "little")
        stop = int.from_bytes(ud[off + 5:off + 7], "little")
        new_stop = POLICY[key]["public_stop"]
        if new_stop < stop or new_stop > 0xFFFF:
            return p, "failopen_unsafe_range"
        ud2[off + 5:off + 7] = new_stop.to_bytes(2, "little")
    else:
        return p, "failopen_unsupported_qual"
    # rebuild frame (same length), recompute DNP3 block CRCs + TCP checksum
    new_frame = rebuild_frame(lh, bytes(ud2))
    assert len(new_frame) == len(frame), "length must be preserved"
    q = Ether(bytes(p))
    q[Raw].load = new_frame
    del q[IP].chksum
    del q[TCP].chksum
    return Ether(bytes(q)), "range_expanded"


# ---------- fixtures ----------
def wrap(frame, sport=52000, dport=20000, seq=1000):
    return (Ether() / IP(src="10.0.0.9", dst="10.0.0.2", ttl=64, flags="DF") /
            TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=7, window=8192) /
            Raw(frame))


def mk_read(objs, dst=10, src=1):
    """Build a DNP3 READ request frame from object-header byte lists."""
    ud = bytes([0xC0, 0xC0, FUNC_READ]) + b"".join(bytes(o) for o in objs)
    ln = 5 + len(ud)                              # ctrl+dst+src+userdata
    lh = bytes([0x05, 0x64, ln, 0xC4,
                dst & 0xFF, dst >> 8, src & 0xFF, src >> 8])
    return rebuild_frame(lh, ud)


def points_of(qual, start, stop):
    return set(range(start, stop + 1))


def run():
    results = []

    def check(name, pkt, expect_outcome, real_pts=None, expect_identical=None):
        out, outcome = transform(pkt)
        ok, notes = True, []
        if outcome != expect_outcome:
            ok = False; notes.append(f"outcome {outcome}!={expect_outcome}")
        src = Ether(bytes(pkt))
        # length preserved always
        if len(bytes(out[Raw].load)) != len(bytes(src[Raw].load)):
            ok = False; notes.append("DNP3 length changed")
        # DNP3 CRCs valid on output — required only when we actually transformed;
        # a byte-identical fail-open of an already-corrupt frame keeps its (bad) CRC by design
        if outcome == "range_expanded":
            lh, lok, ud = split_user_data(bytes(out[Raw].load))
            if not lok or ud is None:
                ok = False; notes.append("output DNP3 CRC invalid")
        # TCP/IP checksums valid
        rp = Ether(bytes(out)); rec = Ether(bytes(rp))
        if rp[IP].chksum != rec[IP].chksum or rp[TCP].chksum != rec[TCP].chksum:
            ok = False; notes.append("L3/L4 checksum invalid")
        # seq/ack preserved
        if src[TCP].seq != rp[TCP].seq or src[TCP].ack != rp[TCP].ack:
            ok = False; notes.append("seq/ack changed")
        # fail-open must be byte-identical (whole packet payload)
        if expect_identical and bytes(src[Raw].load) != bytes(rp[Raw].load):
            ok = False; notes.append("fail-open NOT byte-identical")
        # real points still included after expansion
        if real_pts is not None and outcome == "range_expanded":
            _, _, ud2 = split_user_data(bytes(out[Raw].load))
            f2 = parse_first_object(ud2); q = f2[4]; o = f2[1]
            if q == 0x00:
                s, e = ud2[o + 3], ud2[o + 4]
            else:
                s = int.from_bytes(ud2[o + 3:o + 5], "little"); e = int.from_bytes(ud2[o + 5:o + 7], "little")
            got = points_of(q, s, e)
            if not real_pts.issubset(got):
                ok = False; notes.append("real points dropped")
            note = f"pts {min(got)}..{max(got)} (n={len(got)}, was n={len(real_pts)})"
            notes.append(note)
        results.append((name, "PASS" if ok else "FAIL", outcome, ";".join(notes)))

    # 1. real corpus Class 1/2/3 all-points poll (qualifier 0x06) -> FAIL OPEN byte-identical
    from scapy.all import rdpcap
    pk = rdpcap("/home/philip/Projects/DNP3/dnp3_split_harness/captures/baseline/read_request.pcap")
    corpus = None
    for p in pk:
        if TCP in p and Raw in p and bytes(p[Raw].load)[:2] == b"\x05\x64":
            corpus = p; break
    if corpus is not None:
        # NB: the real corpus frame is a DISABLE_UNSOLICITED request (func 0x15=21) for
        # Class 1/2/3 (Group 60 Var 2/3/4, qualifier 0x06) — NOT a READ. It must fail open.
        check("01 real corpus (DISABLE_UNSOLICITED func0x15)", corpus, "failopen_not_read",
              expect_identical=True)

    # 2. synthesized Group 30 Var 1 qualifier 0x00 range READ 0..5 -> expand stop to 15
    f = mk_read([[30, 1, 0x00, 0, 5]])
    check("02 G30V1 qual0x00 range 0..5 -> 0..15", wrap(f), "range_expanded", real_pts=points_of(0, 0, 5))

    # 3. synthesized Group 1 Var 2 qualifier 0x00 range 4..9 -> expand stop to 31
    f = mk_read([[1, 2, 0x00, 4, 9]])
    check("03 G1V2 qual0x00 range 4..9 -> 4..31", wrap(f), "range_expanded", real_pts=points_of(0, 4, 9))

    # 4. synthesized Group 30 Var 1 qualifier 0x01 (16-bit) range 0..10 -> expand to 255
    f = mk_read([[30, 1, 0x01, 0, 0, 10, 0]])
    check("04 G30V1 qual0x01 range 0..10 -> 0..255", wrap(f), "range_expanded", real_pts=points_of(1, 0, 10))

    # 5. unsupported object (Group 30 Var 2) -> FAIL OPEN
    f = mk_read([[30, 2, 0x00, 0, 5]])
    check("05 unsupported G30V2 -> fail open", wrap(f), "failopen_unsupported_obj", expect_identical=True)

    # 6. malformed CRC -> FAIL OPEN byte-identical
    f = bytearray(mk_read([[30, 1, 0x00, 0, 5]])); f[-1] ^= 0xFF
    check("06 corrupted DNP3 CRC -> fail open", wrap(bytes(f)), "failopen_bad_crc", expect_identical=True)

    # 7. already-public stop equal to target -> no shrink, expand is a no-op superset (still valid)
    f = mk_read([[30, 1, 0x00, 0, 15]])
    check("07 already at public stop 0..15", wrap(f), "range_expanded", real_pts=points_of(0, 0, 15))

    # ---- report + size projection ----
    npass = sum(1 for r in results if r[1] == "PASS")
    print(f"{'CASE':44s} {'RES':4s} {'OUTCOME':26s} NOTES")
    print("-" * 108)
    for n, r, o, nt in results:
        print(f"{n:44s} {r:4s} {o:26s} {nt}")
    print("-" * 108)
    print(f"SIZE-ORACLE: {npass}/{len(results)} cases pass")
    # response-size projection (analog input Var 1 = 5 bytes/point incl. flag+16-bit value... uses 3B var5/2B)
    print("\nResponse-size projection (illustrative, Group 30 Var 1 = ~3 B/point in the response):")
    for (name, base_stop, pub_stop) in [("G30V1 0..5->0..15", 5, 15), ("G1V2 4..9->4..31", 5, 27)]:
        print(f"  {name}: real {base_stop+1} pts -> public {pub_stop+1} pts "
              f"(request length UNCHANGED; response grows ~{(pub_stop-base_stop)*3} B)")
    return 0 if npass == len(results) else 1


if __name__ == "__main__":
    sys.exit(run())

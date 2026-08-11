#!/usr/bin/env python3
"""Canonical-response oracle — the reference model for the SIZE axis of the joint defense.

Given any device's DNP3 poll response, produce the single PUBLIC CANONICAL response whose wire
STRUCTURE (length + object variation + object header) is device-independent, so a passive observer
cannot tell the device MODEL apart from the response shape. This is the ground truth the egress P4
rewrite and the silicon wire-gate are checked against (JOINT_DEFENSE_SPEC.md, step 2).

Mechanism (matches the approved plan):
  * canonicalise the static analog block to public variation **G30 V3** (32-bit, NO per-point flag);
    a V1 source (32-bit WITH flag) has its flag octet stripped, value preserved;
  * fix the range to a public [start, PUB_STOP] and pad any short response with DNP3-legal decoy
    points (value 0) so the point count -- hence the length -- is a public constant;
  * recompute every DNP3 block CRC and the link-header CRC; the frame stays a well-formed DNP3
    message (a parser/observer sees a valid frame, not trailing junk).

Honest boundary (documented residuals, NOT normalised -- they carry live state/data or are
deployment-constant, so normalising them would corrupt the master's view or is unnecessary):
  * measurement VALUES (data, not a model tell);
  * IIN status bytes (device status: restart / need-time / local);
  * application/transport SEQUENCE bytes (per-transaction, not a model tell);
  * link SOURCE address (one outstation per deployment -> constant, not a cross-model tell).

Run:  python3 canonical_response.py   # self-test against the real per-device corpora
"""
import os
import sys

# reuse the lab-validated CRC-16/DNP (frozen split harness); fall back to an inline copy.
_HARNESS = "/home/philip/Projects/DNP3/dnp3_split_harness"
sys.path.insert(0, _HARNESS)
try:
    from dnp3_crc import dnp3_crc16, append_crc, verify_crc  # noqa: E402
except Exception:  # pragma: no cover - self-contained fallback
    import struct
    _RP = 0xA6BC
    def dnp3_crc16(data):
        crc = 0
        for byte in data:
            crc ^= byte
            for _ in range(8):
                crc = (crc >> 1) ^ _RP if crc & 1 else crc >> 1
        return (~crc) & 0xFFFF
    def append_crc(data):
        return data + struct.pack('<H', dnp3_crc16(data))
    def verify_crc(data, crc_bytes):
        return len(crc_bytes) == 2 and struct.unpack('<H', bytes(crc_bytes))[0] == dnp3_crc16(data)

PUB_STOP = 7          # public canonical stop index (start is preserved; 1..7 in this corpus)
G30, VAR3, QUAL00 = 0x1E, 0x03, 0x00


class DNP3ParseError(Exception):
    pass


def _strip_blocks(frame):
    """Return (ctrl, dest, src, user_data) from a wire DNP3 frame, verifying every block CRC.
    user_data = transport byte + application bytes (block CRCs removed)."""
    if frame[:2] != b'\x05\x64':
        raise DNP3ParseError("not a DNP3 link frame")
    length = frame[2]
    ctrl = frame[3]
    dest = frame[4:6]
    src = frame[6:8]
    if not verify_crc(frame[0:8], frame[8:10]):
        raise DNP3ParseError("bad link-header CRC")
    ud_len = length - 5                       # LEN counts CTRL+DEST(2)+SRC(2)+user_data
    pos, remaining, ud = 10, ud_len, b""
    while remaining > 0:
        n = min(16, remaining)
        block, crc = frame[pos:pos + n], frame[pos + n:pos + n + 2]
        if not verify_crc(block, crc):
            raise DNP3ParseError("bad block CRC at %d" % pos)
        ud += block
        pos += n + 2
        remaining -= n
    return ctrl, dest, src, ud


def parse_response(frame):
    """Parse a DNP3 poll response into its fields + the first analog object header/points."""
    ctrl, dest, src, ud = _strip_blocks(frame)
    transport = ud[0]
    appctrl, func, iin = ud[1], ud[2], ud[3:5]
    if func != 0x81:
        raise DNP3ParseError("not a response (func=0x%02x)" % func)
    objs = ud[5:]
    group, var, qual = objs[0], objs[1], objs[2]
    if group != G30 or qual != QUAL00:
        raise DNP3ParseError("unsupported object (group=0x%02x qual=0x%02x)" % (group, qual))
    start, stop = objs[3], objs[4]
    npts = stop - start + 1
    body = objs[5:]
    bpp = len(body) // npts                    # 4 (V3) or 5 (V1)
    vals = []                                   # the 4-byte 32-bit value of each point
    for i in range(npts):
        pt = body[i * bpp:(i + 1) * bpp]
        vals.append(pt[1:5] if bpp == 5 else pt[0:4])   # V1: flag+value -> value; V3: value
    return dict(ctrl=ctrl, dest=dest, src=src, transport=transport, appctrl=appctrl,
                iin=iin, group=group, var=var, qual=qual, start=start, stop=stop,
                bpp=bpp, values=vals, wire_len=len(frame))


def _reframe(ctrl, dest, src, ud):
    """Assemble a wire DNP3 frame: link header + CRC, then 16-byte user-data blocks each + CRC."""
    out = append_crc(bytes([0x05, 0x64, 5 + len(ud), ctrl]) + dest + src)
    for pos in range(0, len(ud), 16):
        out += append_crc(ud[pos:pos + 16])
    return out


def canonicalize(frame, pub_stop=PUB_STOP):
    """Rewrite a device response to the public canonical form (G30 V3, fixed range, CRCs valid)."""
    p = parse_response(frame)
    vals = list(p["values"])
    n_pub = pub_stop - p["start"] + 1
    if len(vals) > n_pub:
        raise DNP3ParseError("response has more points than the public range")
    vals += [b"\x00\x00\x00\x00"] * (n_pub - len(vals))   # DNP3-legal decoy points (value 0)
    obj = bytes([G30, VAR3, QUAL00, p["start"], pub_stop]) + b"".join(vals)
    app = bytes([p["appctrl"], 0x81]) + p["iin"] + obj    # IIN + seq preserved (documented residuals)
    return _reframe(p["ctrl"], p["dest"], p["src"], bytes([p["transport"]]) + app)


# The exact object classes the transform carves: G30 V1 (shrink) / V3 (passthrough), qual 0x00, [1,7].
SUPPORTED = {(G30, 0x01, QUAL00), (G30, VAR3, QUAL00)}


def is_eligible(frame, pub_stop=PUB_STOP):
    """True only for the EXACT canonical-eligible object the P4 rewrites; everything else fails open."""
    try:
        p = parse_response(frame)
    except DNP3ParseError:
        return False
    return ((p["group"], p["var"], p["qual"]) in SUPPORTED
            and p["start"] == 1 and p["stop"] == pub_stop)


def transform_or_passthrough(frame, pub_stop=PUB_STOP):
    """The fail-open CONTRACT the tightened P4 must match: canonicalise an eligible response,
    otherwise return the frame BYTE-IDENTICAL (a same-length non-eligible packet is NOT rewritten)."""
    if not is_eligible(frame, pub_stop):
        return bytes(frame)
    try:
        return canonicalize(frame, pub_stop)
    except DNP3ParseError:
        return bytes(frame)


def structural_signature(frame):
    """The device-MODEL fingerprint: what an observer reads from the response SHAPE.
    Two responses with the same signature are indistinguishable by model."""
    p = parse_response(frame)
    return (p["wire_len"], p["group"], p["var"], p["qual"],
            p["start"], p["stop"], p["bpp"])


# --------------------------------------------------------------------------- self-test
def _load_corpus():
    """First G30 poll response per device from the frozen split-harness corpora."""
    base = os.path.join(_HARNESS, "payloads")
    out = {}
    for dev in ("sel751", "ion7550", "ab1400"):
        d = os.path.join(base, dev)
        for fn in sorted(os.listdir(d)):
            if not fn.startswith("resp_"):
                continue
            b = open(os.path.join(d, fn), "rb").read()
            if b[:2] == b'\x05\x64' and b'\x1e' in b:
                try:
                    parse_response(b)
                except DNP3ParseError:
                    continue
                out[dev] = (fn, b)
                break
    return out


def main():
    corpus = _load_corpus()
    checks, sigs = [], {}

    print("%-9s %-11s %-22s %-10s %-22s" % ("device", "native", "native sig", "canon", "canon sig"))
    print("-" * 82)
    canon = {}
    for dev, (fn, frame) in corpus.items():
        nsig = structural_signature(frame)
        c = canonicalize(frame)
        csig = structural_signature(c)
        canon[dev] = c
        sigs[dev] = csig
        # every canonical frame must still be a well-formed DNP3 response
        checks.append((f"{dev}: canonical frame re-parses + all CRCs valid",
                       structural_signature(c) is not None and _crc_ok(c)))
        # canonical must preserve every real value (no data loss)
        checks.append((f"{dev}: real measurement values preserved",
                       parse_response(c)["values"][:len(parse_response(frame)["values"])]
                       == parse_response(frame)["values"]))
        print("%-9s %-11s %-22s %-10s %-22s"
              % (dev, "%dB" % len(frame), str(nsig[:1] + nsig[2:4] + (nsig[6],)),
                 "%dB" % len(c), str(csig[:1] + csig[2:4] + (csig[6],))))

    # ---- adversarial: the oracle must REJECT malformed / unsupported input (fail-closed) ----
    sample = next(iter(corpus.values()))[1]
    ctrl, dest, src, ud = _strip_blocks(sample)

    def _raises(fn):
        try:
            fn()
            return False
        except DNP3ParseError:
            return True

    corrupt = bytearray(sample)
    corrupt[20] ^= 0xFF                                            # flip a value byte -> block CRC fails
    g32 = _reframe(ctrl, dest, src, ud[:5] + b'\x20' + ud[6:])      # group 30->32, valid CRC, unsupported
    over = _reframe(ctrl, dest, src, ud[:5] + bytes([G30, VAR3, QUAL00, 0x01, 0x09]) + b'\x00' * 36)
    checks.append(("REJECTS corrupted block CRC", _raises(lambda: parse_response(bytes(corrupt)))))
    checks.append(("REJECTS unsupported object (G32, valid CRC) -> fail open",
                   _raises(lambda: parse_response(g32))))
    checks.append(("REJECTS over-range response (9 pts > public 7)", _raises(lambda: canonicalize(over))))
    checks.append(("REJECTS non-DNP3 bytes", _raises(lambda: parse_response(b'\x00' * 20))))

    # ---- fail-open PARITY (the tightening): same-LENGTH non-eligible packets pass through UNCHANGED ----
    ion = corpus["ion7550"][1]
    ic, idst, isrc, iud = _strip_blocks(ion)
    g32_61 = _reframe(ic, idst, isrc, iud[:5] + b'\x20' + iud[6:])     # 61B, G30->G32 (valid CRC)
    v2_61 = _reframe(ic, idst, isrc, iud[:6] + b'\x02' + iud[7:])      # 61B, G30 V1->V2 (valid CRC)
    nondnp61 = b'\xaa' * len(ion)                                      # 61B non-DNP3 blob
    checks.append(("fail-open: 61B non-G30 (G32) -> passthrough byte-identical",
                   transform_or_passthrough(g32_61) == g32_61))
    checks.append(("fail-open: 61B G30-but-V2 -> passthrough byte-identical",
                   transform_or_passthrough(v2_61) == v2_61))
    checks.append(("fail-open: 61B non-DNP3 -> passthrough byte-identical",
                   transform_or_passthrough(nondnp61) == nondnp61))
    for dev, (fn, frame) in corpus.items():
        checks.append((f"parity: {dev} transform_or_passthrough == canonicalize (eligible)",
                       transform_or_passthrough(frame) == canonicalize(frame)))

    uniq = set(sigs.values())
    checks.append(("all devices share ONE canonical structural signature", len(uniq) == 1))
    # what still differs (documented residuals) -- prove it's ONLY the allowed windows
    checks.append(("canonical device-model fingerprint is identical (len,var,bpp,range)",
                   len({(s[0], s[2], s[6], s[4], s[5]) for s in sigs.values()}) == 1))

    print("\nresidual (NOT normalised, by design): measurement values, IIN status, seq bytes, link addr")
    print("-" * 82)
    npass = sum(1 for _, ok in checks if ok)
    for name, ok in checks:
        print("  [%s] %s" % ("PASS" if ok else "FAIL", name))
    print("-" * 82)
    print("CANONICAL-RESPONSE ORACLE: %d/%d checks pass" % (npass, len(checks)))
    print("\nHeadline: native structures {54B/V3, 61B/V1} -> ONE canonical %dB/V3 structure for every"
          % (len(next(iter(canon.values())))))
    print("device -> the response SHAPE no longer identifies the model. Values/IIN preserved.")
    sys.exit(0 if npass == len(checks) else 1)


def _crc_ok(frame):
    try:
        _strip_blocks(frame)
        return True
    except DNP3ParseError:
        return False


if __name__ == "__main__":
    main()

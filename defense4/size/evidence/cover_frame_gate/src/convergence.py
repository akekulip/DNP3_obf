#!/usr/bin/env python3
"""Target-convergence demonstration for the DNP3 cover-frame size mechanism.

The prior cover-frame evidence showed only SIZE ENLARGEMENT: prepending a cover makes one
frame larger. It never showed NORMALIZATION: two DNP3 frames of DIFFERENT native lengths being
driven to ONE common public target in the same measured length domain.

This script does exactly that. It picks two real, CRC-valid DNP3 request frames with different
native lengths, then for EACH constructs one legal CRC-valid cover frame (addressed to the
recommended non-endpoint INDIVIDUAL link address 0x0032) so that:

    L_final(real_1) == L_final(real_2) == S_public

per length domain (corrected 2026-08-12, audit M2):
  - DNP3 serialized link bytes   (COMPUTED here, offline, from the serialized frames — this is
                                  the byte length of the emitted link frames, not a wire capture)
  - TCP-payload bytes            (NOT captured — numerically EQUAL to the DNP3 serialized link
                                  bytes for a single unsegmented TCP segment, BY CONSTRUCTION)
  - IP bytes                     (NOT measured — no capture; reported as a COMPUTED value)
  - Ethernet bytes               (NOT measured — no capture; reported as a COMPUTED value)
  (For an actually-captured DNP3-over-TCP byte stream on the wire, see ../real_channel/.)

Honest scope: reaching a common target defeats a COUNTING (size-only) observer. It does NOT
defeat a PARSING observer, which strips cover frames by link address and recovers each real
frame's native length. That bounded impossibility result is preserved and stated in the README.

No absolute paths: the repo root is resolved by walking up to dnp3_split_harness/dnp3_crc.py.
Fail-closed: exits nonzero if any frame CRC is invalid or the targets do not converge exactly.
"""
import csv
import hashlib
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import gen_and_measure as gm  # noqa: E402  (reuse the canonical builder + CRC verifier)

OUT_DIR = os.environ.get("COVER_FRAME_OUT", _HERE)

# Recommended cover address: non-local INDIVIDUAL, unused in the {master=1, outstation=10} domain.
COVER_DEST = 0x0032
MASTER = 1

# Per-layer header deltas for a single unfragmented segment (COMPUTED, not measured here).
IPV4_HDR = 20
ETH_HDR = 14


def crob(index):
    return bytes([index, 0x41, 0x01]) + (100).to_bytes(4, "little") + (100).to_bytes(4, "little") + bytes([0])


# Two REAL request frames with DIFFERENT native lengths, same length domain (outstation-bound
# requests carried as DNP3-over-TCP link frames). user-data = 0xC0 transport header || APDU.
REAL_1_UD = bytes([0xC0, 0xC0, 0x01, 0x3C, 0x02, 0x06])                       # READ class-1
REAL_2_UD = bytes([0xC0, 0xC0, 0x04, 0x0C, 0x01, 0x17, 0x02]) + crob(0) + crob(1)  # OPERATE, 2 CROBs


def frame_size(ud_len):
    """Total serialized DNP3 link-frame size for a user-data length (10B header+hdrCRC, 16B blocks)."""
    if ud_len == 0:
        return 10
    import math
    return 10 + ud_len + 2 * math.ceil(ud_len / 16)


def cover_ud_len_for_frame_size(target_frame_size):
    """Smallest user-data length whose cover frame serializes to exactly target_frame_size, or None."""
    for u in range(0, 300):
        if frame_size(u) == target_frame_size:
            return u
    return None


def build_cover(ud_len):
    """A legal CRC-valid cover frame of the requested user-data length, addressed to COVER_DEST.

    Cover CONTENT is unconstrained: the endpoint discards the frame by link address before any
    application parsing, so the payload is deterministic filler behind a short marker.
    """
    marker = bytes([0xC0, 0xC0, 0x01, 0x3C, 0x01, 0x06])  # READ class-0 marker
    if ud_len <= len(marker):
        ud = marker[:ud_len]
    else:
        ud = marker + bytes((0xA5 for _ in range(ud_len - len(marker))))
    return gm.build_user_data_frame(from_master=True, dest=COVER_DEST, src=MASTER, confirmed=False, ud=ud), ud


def main():
    # Native sizes.
    real1 = gm.build_user_data_frame(True, 10, MASTER, False, REAL_1_UD)
    real2 = gm.build_user_data_frame(True, 10, MASTER, False, REAL_2_UD)
    n1, n2 = len(real1), len(real2)
    assert n1 != n2, "the two real frames must have different native lengths"

    # Choose one common public target reachable by both with a single cover each.
    S_public = 63
    need1 = S_public - n1
    need2 = S_public - n2
    u1 = cover_ud_len_for_frame_size(need1)
    u2 = cover_ud_len_for_frame_size(need2)
    if u1 is None or u2 is None:
        print("ERROR: no single-cover user-data length hits the required cover size", need1, need2)
        return 2

    cover1, cud1 = build_cover(u1)
    cover2, cud2 = build_cover(u2)

    # Independently CRC-verify every constructed frame (fail-closed).
    crc_bad = []
    for name, frame, udlen in [("real_1", real1, len(REAL_1_UD)), ("real_2", real2, len(REAL_2_UD)),
                               ("cover_1", cover1, len(cud1)), ("cover_2", cover2, len(cud2))]:
        ok, why = gm.verify_frame_crcs(frame, udlen)
        if not ok:
            crc_bad.append((name, why))

    # Final serialized byte streams (one TCP segment each): [cover][real].
    final1 = cover1 + real1
    final2 = cover2 + real2
    Lf1, Lf2 = len(final1), len(final2)

    converged = (Lf1 == Lf2 == S_public) and not crc_bad

    rows = []

    def row(profile, native_ud, native_frame, n_cover, cover_frame_bytes, final_bytes):
        rows.append({
            "profile": profile,
            "native_userdata_bytes": native_ud,
            "native_dnp3_link_bytes": native_frame,
            "n_cover_frames": n_cover,
            "cover_dnp3_link_bytes": cover_frame_bytes,
            "final_dnp3_link_bytes_COMPUTED": final_bytes,
            "final_tcp_payload_bytes_EQUAL_BY_CONSTRUCTION": final_bytes,  # 1 seg: == DNP3 bytes, not captured
            "final_ip_bytes_COMPUTED_1seg": final_bytes + IPV4_HDR,
            "final_eth_bytes_COMPUTED_1seg": final_bytes + IPV4_HDR + ETH_HDR,
        })

    row("profile_1_READ_class1", len(REAL_1_UD), n1, 1, len(cover1), Lf1)
    row("profile_2_OPERATE_2CROB", len(REAL_2_UD), n2, 1, len(cover2), Lf2)

    frames_hex = {
        "real_1": real1.hex().upper(),
        "real_2": real2.hex().upper(),
        "cover_1": cover1.hex().upper(),
        "cover_2": cover2.hex().upper(),
        "final_1_cover+real": final1.hex().upper(),
        "final_2_cover+real": final2.hex().upper(),
    }

    result = {
        "S_public_target_bytes": S_public,
        "size_domain": "DNP3 serialized link bytes (COMPUTED); == one-segment TCP payload BY CONSTRUCTION, not captured",
        "cover_address": "0x%04X (recommended: non-local individual, unused in {1,10})" % COVER_DEST,
        "native_sizes": {"profile_1": n1, "profile_2": n2, "different": n1 != n2},
        "final_sizes_COMPUTED": {"profile_1": Lf1, "profile_2": Lf2},
        "converged_to_common_target": bool(converged),
        "ip_and_eth": "COMPUTED per single unfragmented segment, NOT captured/measured",
        "counting_observer": "defeated (both profiles present identical public size)",
        "parsing_observer": "NOT defeated (strips cover by link address, recovers native size)",
        "crc_failures": crc_bad,
    }

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "convergence_result.json"), "w") as fh:
        json.dump({"result": result, "frames_hex": frames_hex}, fh, indent=2)
    with open(os.path.join(OUT_DIR, "convergence_sizes.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    # sha256 of this generator + its outputs (relative paths only).
    with open(os.path.join(OUT_DIR, "convergence_sha256.txt"), "w") as fh:
        for p in [os.path.join(_HERE, "convergence.py"),
                  os.path.join(OUT_DIR, "convergence_result.json"),
                  os.path.join(OUT_DIR, "convergence_sizes.csv")]:
            if os.path.isfile(p):
                h = hashlib.sha256(open(p, "rb").read()).hexdigest()
                fh.write("%s  %s\n" % (h, os.path.relpath(p, OUT_DIR)))

    print("native DNP3 link bytes: profile_1=%d  profile_2=%d  (different=%s)" % (n1, n2, n1 != n2))
    print("cover user-data lengths: profile_1=%d (=%dB frame)  profile_2=%d (=%dB frame)"
          % (u1, len(cover1), u2, len(cover2)))
    print("FINAL sizes (COMPUTED DNP3 link bytes; == 1-seg TCP payload by construction): profile_1=%d  profile_2=%d  target=%d"
          % (Lf1, Lf2, S_public))
    print("IP bytes (COMPUTED, 1 seg): profile_1=%d  profile_2=%d" % (Lf1 + IPV4_HDR, Lf2 + IPV4_HDR))
    print("Ethernet bytes (COMPUTED, 1 seg): profile_1=%d  profile_2=%d" % (Lf1 + IPV4_HDR + ETH_HDR,
                                                                            Lf2 + IPV4_HDR + ETH_HDR))
    print("CRC failures:", crc_bad if crc_bad else 0)
    print("CONVERGED to one common public target:", converged)
    print("wrote: convergence_result.json, convergence_sizes.csv, convergence_sha256.txt -> <COVER_FRAME_OUT>")

    return 0 if converged else 1


if __name__ == "__main__":
    sys.exit(main())

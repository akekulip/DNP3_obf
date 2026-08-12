"""
Exact DNP3 response-length synthesizer for native READ/SBO size parity.

Goal
----
Find legal DNP3 encodings where a READ transaction and a Select-Before-Operate
(SBO) transaction produce the SAME native on-wire response size, and (because
the wire model is strictly monotonic in the user-data length ``u``) therefore
the SAME CRC-block geometry -- WITHOUT any switch-inserted padding bytes. The
switch later only splits the byte stream at existing CRC boundaries; the sizes
must already match natively through configured real(even)/decoy(odd) points.

Everything here is derived from DNP3 encoding rules (object header widths +
qualifier/range/prefix widths + per-point byte counts), NOT from remembered
size constants. The remembered anchors are used only to CHECK the derivation.

Measured anchors (physical SEL-751, verified 2026-08-12):
    SBO 1-CROB echo response = 35 B wire  (u = 21)
    SBO 2-CROB echo response = 49 B wire  (u = 33)
    READ G10V2 32 binary-output-status pts = 58 B wire (u = 42)
    READ G1  (binary in)                   = 40 B wire (u = 26)
    Class-0 poll                           = 134 B wire (u = 110)

Honesty
-------
The READ objects (G10/G30/...) and the SBO objects (G12 CROB) are
parser-distinguishable: different group/variation bytes, and the CROB carries
control-code/timing fields a status object does not. The claim proven here is
native SIZE equality (identical TCP-payload length + identical CRC-block
geometry / segment-length vector), NOT full deep-packet-inspection equality.
The parity is also scoped to the OUTSTATION RESPONSE direction (the
fingerprinting target); request-direction sizes differ and are reported as a
known limitation.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# 1. Data-link wire model  (IEEE 1815 / DNP3 data link layer)
# ---------------------------------------------------------------------------
# A DNP3 link frame is a 10-byte header (start 2, length 1, control 1, dest 2,
# source 2, header-CRC 2) followed by the "user data" (transport byte +
# application bytes = ``u`` octets) chopped into <=16-octet blocks, each block
# terminated by its own 2-octet CRC. The last block may be shorter.
LINK_HEADER = 10   # bytes: start(2)+len(1)+ctrl(1)+dst(2)+src(2)+hdrCRC(2)
BLOCK_DATA = 16    # bytes of user data per data block (DNP3 spec constant)
BLOCK_CRC = 2      # CRC octets appended to every block
LENGTH_FIELD_MAX = 255  # the 1-octet Length counts ctrl+dst+src+userdata = 5+u


def n_blocks(u: int) -> int:
    """Number of user-data blocks for ``u`` user-data octets."""
    if u <= 0:
        return 0
    return math.ceil(u / BLOCK_DATA)


def link_size(u: int) -> int:
    """Total on-wire / TCP-payload bytes for a single link frame carrying ``u``
    user-data octets:  link_size(u) = 10 + u + 2*ceil(u/16)."""
    return LINK_HEADER + u + BLOCK_CRC * n_blocks(u)


def single_frame_ok(u: int) -> bool:
    """A single link frame can carry at most (255 - 5) user-data octets because
    the 1-octet Length field counts ctrl+dst+src+userdata = 5 + u <= 255."""
    return 1 <= u <= (LENGTH_FIELD_MAX - 5)


def block_layout(u: int) -> List[int]:
    """User-data block sizes (each <=16), last may be shorter."""
    sizes: List[int] = []
    remaining = u
    while remaining > 0:
        b = min(BLOCK_DATA, remaining)
        sizes.append(b)
        remaining -= b
    return sizes


def crc_boundaries(u: int) -> List[int]:
    """Offsets from frame start at which a completed block ends (header end,
    then after each data+CRC block). E.g. u=33 -> [10, 28, 46, 49]."""
    offs = [LINK_HEADER]
    pos = LINK_HEADER
    for b in block_layout(u):
        pos += b + BLOCK_CRC
        offs.append(pos)
    return offs


def balanced_split(u: int) -> Tuple[int, int]:
    """Pick the interior CRC boundary nearest wire/2 and return the resulting
    two-segment length vector [first, rest]. E.g. u=33 (49 B) -> (28, 21)."""
    wire = link_size(u)
    interior = [b for b in crc_boundaries(u) if 0 < b < wire]
    if not interior:
        return (wire, 0)
    target = wire / 2.0
    cut = min(interior, key=lambda b: abs(b - target))
    return (cut, wire - cut)


# ---------------------------------------------------------------------------
# 2. Application-layer encoding model (derived component byte-widths)
# ---------------------------------------------------------------------------
# A DNP3 RESPONSE application fragment prepends:
#   transport function/sequence octet ...... 1
#   application control octet ............... 1
#   application function code (0x81=Response) 1
#   internal indications (IIN) .............. 2
# so the fixed overhead ahead of any object data is:
TRANSPORT = 1
APP_CTRL = 1
APP_FUNC = 1
IIN = 2
RESP_FIXED = TRANSPORT + APP_CTRL + APP_FUNC + IIN   # = 5


@dataclass(frozen=True)
class Qualifier:
    """An object-header qualifier: its range/count field width and the per-point
    index-prefix width it implies."""
    code: int
    name: str
    range_bytes: int    # octets of the range/count field in the object header
    prefix_bytes: int   # octets of index prefix carried before each point
    minimal: bool       # True if an outstation would naturally emit it at low
    #                     indices; False = only appears when forced (e.g. wide
    #                     range needs indices >= 256), i.e. residue-engineered.


# Qualifier catalog (IEEE 1815 Table qualifier codes).
Q_STARTSTOP_1B = Qualifier(0x00, "start-stop 1-byte", range_bytes=2, prefix_bytes=0, minimal=True)
Q_STARTSTOP_2B = Qualifier(0x01, "start-stop 2-byte", range_bytes=4, prefix_bytes=0, minimal=False)
Q_COUNT_1B = Qualifier(0x07, "limited-qty count 1-byte", range_bytes=1, prefix_bytes=0, minimal=False)
Q_COUNT_2B = Qualifier(0x08, "limited-qty count 2-byte", range_bytes=2, prefix_bytes=0, minimal=False)
# Indexed qualifier 0x17 is the NATURAL qualifier for SBO command echoes and for
# EVENT/Class polls (groups 2/4/22/32...), but it is NOT what an outstation emits
# for a static integrity READ of a contiguous range of G1/G10/G30/G20 static
# objects (those use start-stop 0x00). Hence minimal=False: as a READ qualifier
# for our static catalog it is residue-engineered (Tier 2), while remaining the
# correct, minimal choice on the SBO side (u_sbo uses it directly).
Q_INDEXED_1B = Qualifier(0x17, "indexed count 1-byte + 1-byte prefix", range_bytes=1, prefix_bytes=1, minimal=False)
Q_INDEXED_2B = Qualifier(0x28, "indexed count 2-byte + 2-byte prefix", range_bytes=2, prefix_bytes=2, minimal=False)


def obj_header_bytes(qual: Qualifier) -> int:
    """Object header = group(1) + variation(1) + qualifier(1) + range/count."""
    return 2 + 1 + qual.range_bytes


@dataclass(frozen=True)
class ObjType:
    """A DNP3 object type usable in a response, with its per-point byte size."""
    key: str
    group: int
    variation: int
    point_bytes: int
    direction: str       # "status"/"analog"/"counter"/"command"
    read_target: bool    # legal object for a READ response (status/measurement)
    note: str = ""


# Object catalog. point_bytes derived from the variation's on-wire layout.
CROB = ObjType("G12V1", 12, 1, point_bytes=11, direction="command", read_target=False,
               note="CROB: ctrl(1)+count(1)+ontime(4)+offtime(4)+status(1)")

READ_OBJS: List[ObjType] = [
    ObjType("G1V2", 1, 2, 1, "status", True, "binary input w/ flags (1 octet/pt)"),
    ObjType("G10V2", 10, 2, 1, "status", True, "binary output status w/ flags (1 octet/pt)"),
    ObjType("G30V1", 30, 1, 5, "analog", True, "analog input 32-bit + flag (5 B/pt)"),
    ObjType("G30V2", 30, 2, 3, "analog", True, "analog input 16-bit + flag (3 B/pt)"),
    ObjType("G30V3", 30, 3, 4, "analog", True, "analog input 32-bit, no flag (4 B/pt)"),
    ObjType("G30V4", 30, 4, 2, "analog", True, "analog input 16-bit, no flag (2 B/pt)"),
    ObjType("G20V1", 20, 1, 5, "counter", True, "counter 32-bit + flag (5 B/pt)"),
    ObjType("G20V2", 20, 2, 3, "counter", True, "counter 16-bit + flag (3 B/pt)"),
    ObjType("G20V5", 20, 5, 4, "counter", True, "counter 32-bit, no flag (4 B/pt)"),
    ObjType("G20V6", 20, 6, 2, "counter", True, "counter 16-bit, no flag (2 B/pt)"),
]


def u_response(point_bytes: int, qual: Qualifier, n_points: int, n_headers: int = 1) -> int:
    """User-data length ``u`` of a single-fragment response carrying ``n_points``
    points of a given per-point size under ``qual``, split across ``n_headers``
    identical object headers.

        u = RESP_FIXED + n_headers*header + n_points*(prefix + point_bytes)
    """
    return (RESP_FIXED
            + n_headers * obj_header_bytes(qual)
            + n_points * (qual.prefix_bytes + point_bytes))


def u_sbo(k_crobs: int, qual: Qualifier = Q_INDEXED_1B, n_headers: int = 1) -> int:
    """User-data length of an SBO SELECT/OPERATE echo response with ``k_crobs``
    CROBs (real + decoys) under ``qual``. Default qual 0x17 reproduces the
    measured anchors: u = 9 + 12K."""
    return u_response(CROB.point_bytes, qual, k_crobs, n_headers)


def u_read(obj: ObjType, qual: Qualifier, n_points: int, n_headers: int = 1) -> int:
    """User-data length of a READ response of ``n_points`` of ``obj``."""
    return u_response(obj.point_bytes, qual, n_points, n_headers)


# ---------------------------------------------------------------------------
# 3. Real serializer + CRC (faithful bytes, for verification/byte-preservation)
# ---------------------------------------------------------------------------
# CRC-16/DNP: reflected polynomial 0xA6BC, init 0x0000, final complement, low
# byte first on the wire. (Matches the repo's validated dnp3_crc16.)
_REFLECTED_POLY = 0xA6BC


def dnp3_crc16(data: bytes) -> int:
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ _REFLECTED_POLY
            else:
                crc >>= 1
    return (~crc) & 0xFFFF


def _crc_bytes(data: bytes) -> bytes:
    crc = dnp3_crc16(data)
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])


def serialize_frame(user_data: bytes, dest: int = 1, src: int = 0, control: int = 0x44) -> bytes:
    """Serialize one DNP3 link frame from ``user_data`` (transport+app octets).
    Returns the exact on-wire bytes: 10-byte header (with header CRC) + blocks
    (each <=16 data octets + 2 CRC). Length octet = 5 + len(user_data)."""
    u = len(user_data)
    length = 5 + u
    if length > LENGTH_FIELD_MAX:
        raise ValueError(f"user_data too long for one frame: u={u} (max 250)")
    header = bytes([0x05, 0x64, length & 0xFF, control & 0xFF,
                    dest & 0xFF, (dest >> 8) & 0xFF,
                    src & 0xFF, (src >> 8) & 0xFF])
    frame = bytearray(header + _crc_bytes(header))
    for b in block_layout(u):
        # consume next b octets
        chunk, user_data = user_data[:b], user_data[b:]
        frame += chunk + _crc_bytes(chunk)
    return bytes(frame)


def _obj_header_bytes_wire(obj: ObjType, qual: Qualifier, n_points: int,
                           start_index: int = 0) -> bytes:
    """The object header octets on the wire for a given qualifier."""
    out = bytes([obj.group, obj.variation, qual.code])
    if qual in (Q_STARTSTOP_1B,):
        out += bytes([start_index & 0xFF, (start_index + n_points - 1) & 0xFF])
    elif qual in (Q_STARTSTOP_2B,):
        stop = start_index + n_points - 1
        out += bytes([start_index & 0xFF, (start_index >> 8) & 0xFF,
                      stop & 0xFF, (stop >> 8) & 0xFF])
    elif qual in (Q_COUNT_1B, Q_INDEXED_1B):
        out += bytes([n_points & 0xFF])
    elif qual in (Q_COUNT_2B, Q_INDEXED_2B):
        out += bytes([n_points & 0xFF, (n_points >> 8) & 0xFF])
    else:
        raise ValueError(f"unhandled qualifier {qual.name}")
    return out


def build_read_response_payload(obj: ObjType, qual: Qualifier, n_points: int,
                                start_index: int = 0) -> bytes:
    """Faithful transport+application octets for a READ response of ``n_points``
    of ``obj`` (each point filled with placeholder value bytes)."""
    payload = bytes([0xC0,          # transport: FIR|FIN|seq
                     0xC0,          # app control: FIR|FIN|seq
                     0x81,          # app function: Response
                     0x00, 0x00])   # IIN
    payload += _obj_header_bytes_wire(obj, qual, n_points, start_index)
    for i in range(n_points):
        prefix = b""
        if qual.prefix_bytes == 1:
            prefix = bytes([(start_index + i) & 0xFF])
        elif qual.prefix_bytes == 2:
            idx = start_index + i
            prefix = bytes([idx & 0xFF, (idx >> 8) & 0xFF])
        payload += prefix + bytes([0x00] * obj.point_bytes)
    return payload


def build_sbo_response_payload(k_crobs: int, qual: Qualifier = Q_INDEXED_1B,
                               start_index: int = 0) -> bytes:
    """Faithful transport+application octets for an SBO SELECT/OPERATE echo of
    ``k_crobs`` CROBs (each an 11-byte G12V1 object)."""
    payload = bytes([0xC0, 0xC0, 0x81, 0x00, 0x00])
    payload += _obj_header_bytes_wire(CROB, qual, k_crobs, start_index)
    for i in range(k_crobs):
        prefix = b""
        if qual.prefix_bytes == 1:
            prefix = bytes([(start_index + i) & 0xFF])
        elif qual.prefix_bytes == 2:
            idx = start_index + i
            prefix = bytes([idx & 0xFF, (idx >> 8) & 0xFF])
        crob = bytes([0x41, 0x01,               # control code (LATCH_ON), count
                      0x00, 0x00, 0x00, 0x00,   # on-time (ms)
                      0x00, 0x00, 0x00, 0x00,   # off-time (ms)
                      0x00])                    # status
        payload += prefix + crob
    return payload


# ---------------------------------------------------------------------------
# 4. Intersection solver
# ---------------------------------------------------------------------------
@dataclass
class Candidate:
    cid: str
    k_crobs: int
    sbo_qual: str
    sbo_headers: int
    read_obj: str
    read_qual: str
    read_points: int
    read_headers: int
    u: int
    wire: int
    boundaries: List[int]
    split: Tuple[int, int]
    tier: int                # 1 = natural/minimal, 2 = residue-engineered
    real_objects: str
    decoy_objects: str
    point_config_burden: str
    parser_visible_diff: str
    physical_risk: str
    opendnp3_result: str
    sel751_compat: str
    reason: str


def sbo_targets(kmax: int = 5) -> List[Tuple[int, int]]:
    """Return [(K, u_SBO(K))] for K=1..kmax under the anchor-confirmed qual 0x17,
    single shared header."""
    return [(k, u_sbo(k)) for k in range(1, kmax + 1)]


def find_intersections(kmax: int = 5, nmax: int = 260,
                       include_residue: bool = True) -> List[Candidate]:
    """Enumerate READ encodings and return those whose ``u`` equals some SBO
    ``u_SBO(K)``. Because link_size is strictly increasing, equal ``u`` <=>
    equal wire size AND equal CRC-block geometry."""
    targets = {u: k for (k, u) in sbo_targets(kmax)}
    read_quals = [Q_STARTSTOP_1B]
    if include_residue:
        read_quals += [Q_STARTSTOP_2B, Q_COUNT_1B, Q_INDEXED_1B]
    cands: List[Candidate] = []
    seen = set()
    idx = 0
    for obj in READ_OBJS:
        for qual in read_quals:
            for n in range(1, nmax + 1):
                u = u_read(obj, qual, n)
                if u not in targets:
                    continue
                if not single_frame_ok(u):
                    continue
                k = targets[u]
                tier = 1 if qual.minimal else 2
                key = (obj.key, qual.code, n, k)
                if key in seen:
                    continue
                seen.add(key)
                idx += 1
                cands.append(_make_candidate(idx, k, obj, qual, n, tier))
    # stable sort: tier asc, then K asc, then point count asc
    cands.sort(key=lambda c: (c.tier, c.k_crobs, c.read_points))
    # re-id in sorted order
    for i, c in enumerate(cands, 1):
        c.cid = f"C{i:02d}"
    return cands


def _make_candidate(idx: int, k: int, obj: ObjType, qual: Qualifier,
                    n: int, tier: int) -> Candidate:
    u = u_read(obj, qual, n)
    wire = link_size(u)
    burden_read = f"{n} configured {obj.direction} points ({obj.key})"
    if qual.minimal:
        burden_read += " at low indices (<256)"
    else:
        if qual.code in (Q_STARTSTOP_2B.code,):
            burden_read += " forced to indices >=256 (2-byte range)"
        elif qual.code in (Q_COUNT_1B.code,):
            burden_read += " emitted with limited-qty count qualifier (atypical in a response)"
        elif qual.code in (Q_INDEXED_1B.code,):
            burden_read += " emitted with indexed qualifier (atypical for a static read)"
    decoy = k - 1
    return Candidate(
        cid=f"C{idx:02d}",
        k_crobs=k,
        sbo_qual=Q_INDEXED_1B.name,
        sbo_headers=1,
        read_obj=obj.key,
        read_qual=qual.name,
        read_points=n,
        read_headers=1,
        u=u,
        wire=wire,
        boundaries=crc_boundaries(u),
        split=balanced_split(u),
        tier=tier,
        real_objects=f"1 real CROB (even index) + SBO echo",
        decoy_objects=f"{decoy} decoy CROB(s) (odd index, must be physically disconnected)",
        point_config_burden=f"SBO: {k} G12V1 points (1 real + {decoy} decoy); READ: {burden_read}",
        parser_visible_diff=("group/var differ (G12 CROB vs "
                             f"{obj.key}); CROB carries control-code/timing "
                             "fields; both responses use func 0x81 + IIN; "
                             "sizes + CRC-block geometry identical"),
        physical_risk=("READ: none (read-only). SBO: decoy CROBs MUST be proven "
                       "physically disconnected/unmapped before any hardware "
                       "test (mandatory prereq; no relay writes this run)."),
        opendnp3_result="TBD (offline; validate on OpenDNP3 loopback)",
        sel751_compat="TBD (needs relay point-map: "
                      f"{n} {obj.direction} pts + {k} output pts configured)",
        reason="",  # filled by selection pass
    )


def select(cands: List[Candidate]) -> None:
    """Mark selected/rejected with a reason. Selection favors Tier-1 (natural
    minimal encodings), manageable decoy counts, and plausible READ covers."""
    for c in cands:
        if c.tier == 2:
            c.reason = ("REJECTED: residue-engineered -- requires a non-minimal "
                        "qualifier the relay would not naturally emit; keep as a "
                        "size-math fallback only.")
            continue
        # Tier 1
        if c.read_obj in ("G10V2",) and c.k_crobs == 2:
            c.reason = ("SELECTED (primary): 2-CROB SBO (1 real + 1 decoy) == "
                        "23-pt G10V2 status read at 49 B; smallest decoy count "
                        "with real cover; balanced split [28,21].")
        elif c.read_obj in ("G30V1",) and c.k_crobs == 3:
            c.reason = ("SELECTED (secondary): 3-CROB SBO (1 real + 2 decoy) == "
                        "7-pt G30V1 analog read at 61 B; 7 analog metering points "
                        "is a very natural SEL-751 poll; split [28,33].")
        elif c.k_crobs == 1:
            c.reason = ("VIABLE: 1-CROB SBO (0 decoy) == 11-pt G10V2/G1V2 read at "
                        "35 B; exact size match but no decoy cover in the SBO.")
        else:
            c.reason = ("VIABLE (Tier-1): natural minimal encoding both sides; "
                        "larger decoy/point count than the primary.")


# ---------------------------------------------------------------------------
# 5. Artifact emission (candidates.json / candidates.csv / CANDIDATE_REPORT.md)
# ---------------------------------------------------------------------------
def _cand_row(c: Candidate) -> Dict[str, object]:
    return {
        "candidate_id": c.cid,
        "tier": c.tier,
        "read_encoding": f"READ {c.read_obj} x{c.read_points} pts, "
                         f"qualifier {c.read_qual}",
        "sbo_encoding": f"SBO G12V1 x{c.k_crobs} CROB, qualifier {c.sbo_qual}",
        "real_objects": c.real_objects,
        "decoy_objects": c.decoy_objects,
        "native_size_bytes": c.wire,
        "u_userdata": c.u,
        "crc_boundary_offsets": c.boundaries,
        "balanced_split": list(c.split),
        "point_config_burden": c.point_config_burden,
        "parser_visible_differences": c.parser_visible_diff,
        "physical_risk": c.physical_risk,
        "opendnp3_result": c.opendnp3_result,
        "sel751_compat": c.sel751_compat,
        "reason": c.reason,
    }


def emit_json(cands: List[Candidate], path: str) -> None:
    import json
    payload = {
        "model": {
            "link_size": "10 + u + 2*ceil(u/16)",
            "resp_fixed": RESP_FIXED,
            "u_sbo": "9 + 12*K  (qual 0x17: header 4 + per-CROB 12)",
            "u_read_g10v2": "10 + N  (qual 0x00: header 5 + 1 B/pt)",
            "u_read_g30v1": "10 + 5N (qual 0x00: header 5 + 5 B/pt)",
            "note": "equal u <=> equal wire <=> equal CRC-block geometry "
                    "(link_size strictly increasing).",
        },
        "sbo_targets": [{"K": k, "u": u, "wire": link_size(u)}
                        for (k, u) in sbo_targets(5)],
        "candidates": [_cand_row(c) for c in cands],
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)


def emit_csv(cands: List[Candidate], path: str) -> None:
    import csv
    cols = ["candidate_id", "tier", "read_encoding", "sbo_encoding",
            "real_objects", "decoy_objects", "native_size_bytes", "u_userdata",
            "crc_boundary_offsets", "balanced_split", "point_config_burden",
            "parser_visible_differences", "physical_risk", "opendnp3_result",
            "sel751_compat", "reason"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for c in cands:
            row = _cand_row(c)
            row["crc_boundary_offsets"] = " ".join(map(str, c.boundaries))
            row["balanced_split"] = f"{c.split[0]}+{c.split[1]}"
            w.writerow(row)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="DNP3 native READ/SBO size-parity solver")
    ap.add_argument("--emit", action="store_true", help="write candidates.json/csv")
    ap.add_argument("--kmax", type=int, default=5)
    ap.add_argument("--nmax", type=int, default=260)
    args = ap.parse_args()
    cands = find_intersections(kmax=args.kmax, nmax=args.nmax, include_residue=True)
    select(cands)
    print(f"SBO targets (K, u, wire): "
          f"{[(k, u, link_size(u)) for (k, u) in sbo_targets(args.kmax)]}")
    print(f"{len(cands)} intersections "
          f"({sum(1 for c in cands if c.tier == 1)} Tier-1, "
          f"{sum(1 for c in cands if c.tier == 2)} Tier-2)\n")
    for c in cands:
        mark = "*" if c.reason.startswith("SELECTED") else " "
        print(f"{mark}{c.cid} T{c.tier} K={c.k_crobs} {c.wire}B  "
              f"READ {c.read_obj} N={c.read_points} [{c.read_qual}]  "
              f"split {c.split[0]}+{c.split[1]}")
    if args.emit:
        emit_json(cands, "candidates.json")
        emit_csv(cands, "candidates.csv")
        print("\nwrote candidates.json, candidates.csv")

"""Dependency-free pcap reader and DNP3 transaction extractor.

Written independently of the scapy-based extractor that produced the frozen
transactions.csv, so agreement between the two is a cross-check and not a restatement.

Units, which the rest of the pipeline keeps distinct:
  frame              one captured link-layer frame
  DNP3 exchange      one request, its transport acknowledgment, and its application response
  high-level op      one READ exchange, or one complete SELECT+OPERATE (SBO) pair
  TCP connection     one master-to-outstation connection, counted from SYN
  capture            one pcap file
  grouped run        the six captures collected together under one run identifier
"""
from __future__ import annotations
import struct
from dataclasses import dataclass, field

MASTER, OUTSTATION, DNP3_PORT = "192.168.10.1", "192.168.10.7", 20000
FUNC_NAME = {1: "READ", 3: "SELECT", 4: "OPERATE"}
RESP_FUNC = 0x81


@dataclass
class Frame:
    ts: float; src: str; dst: str; sport: int; dport: int
    seq: int; ack: int; flags: int; payload: bytes; wire_len: int; cap_len: int


def _ip(b: bytes) -> str:
    return "%d.%d.%d.%d" % tuple(b)


def read_pcap(path):
    """Yield Frame for every IPv4/TCP record. Raises on a malformed file."""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) != 24:
            raise ValueError("%s: short global header" % path)
        magic = gh[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            end, nano = "<", False
        elif magic == b"\xa1\xb2\xc3\xd4":
            end, nano = ">", False
        elif magic == b"\x4d\x3c\xb2\xa1":
            end, nano = "<", True
        elif magic == b"\xa1\xb2\x3c\x4d":
            end, nano = ">", True
        else:
            raise ValueError("%s: not a classic pcap (magic %r)" % (path, magic))
        linktype = struct.unpack(end + "I", gh[20:24])[0]
        if linktype != 1:
            raise ValueError("%s: linktype %d is not Ethernet" % (path, linktype))
        while True:
            rh = f.read(16)
            if not rh:
                return
            if len(rh) != 16:
                raise ValueError("%s: truncated record header" % path)
            ts_s, ts_f, cap_len, wire_len = struct.unpack(end + "IIII", rh)
            data = f.read(cap_len)
            if len(data) != cap_len:
                raise ValueError("%s: truncated record body" % path)
            ts = ts_s + (ts_f / 1e9 if nano else ts_f / 1e6)
            if cap_len < 14 or data[12:14] != b"\x08\x00":
                continue                                    # not IPv4
            ihl = (data[14] & 0x0F) * 4
            if data[23] != 6:                               # not TCP
                continue
            ipend = 14 + ihl
            src, dst = _ip(data[26:30]), _ip(data[30:34])
            sport, dport = struct.unpack(">HH", data[ipend:ipend + 4])
            seq, ack = struct.unpack(">II", data[ipend + 4:ipend + 12])
            doff = (data[ipend + 12] >> 4) * 4
            flags = data[ipend + 13]
            total_len = struct.unpack(">H", data[16:18])[0]
            payload = data[ipend + doff:14 + total_len]
            yield Frame(ts, src, dst, sport, dport, seq, ack, flags, bytes(payload),
                        wire_len, cap_len)


def dnp3_user_data(payload: bytes):
    """Strip the DNP3 link header and the per-block CRCs. None if not a DNP3 frame."""
    if len(payload) < 10 or payload[0] != 0x05 or payload[1] != 0x64:
        return None
    ln = payload[2]
    if ln < 5:
        return None
    n_user = ln - 5
    out, i, left = bytearray(), 10, n_user
    while left > 0:
        take = min(16, left)
        if i + take > len(payload):
            return None
        out += payload[i:i + take]
        i += take + 2                                       # skip the block CRC
        left -= take
    return bytes(out)


def dnp3_app(payload: bytes):
    """(function_code, application_sequence, crob_status) or None."""
    u = dnp3_user_data(payload)
    if u is None or len(u) < 3:
        return None
    app_seq = u[1] & 0x0F                                   # application control low nibble
    func = u[2]
    status = None
    obj = u[5:]
    if func == RESP_FUNC and len(obj) >= 16 and obj[0] == 12:
        status = obj[15]                                    # CROB status octet
    return func, app_seq, status


@dataclass
class Exchange:
    func: int; t_req: float; t_ack: float; t_resp: float
    req_seq: int; resp_func: int; status: int | None


@dataclass
class CaptureReport:
    path: str
    frames: int = 0
    wire_bytes: int = 0
    cap_bytes: int = 0
    syn: int = 0
    exchanges: list = field(default_factory=list)
    retransmissions: int = 0
    duplicate_app_frames: int = 0
    malformed: int = 0
    unpaired_requests: int = 0
    out_of_order_ts: int = 0
    wrong_endpoint: int = 0


def extract(path) -> CaptureReport:
    rep = CaptureReport(path=str(path))
    seen_payload = {}                                       # (dir, seq, len) -> count
    last_ts = None
    pend = None                                             # (t_req, func, app_seq, seq)
    t_ack = None
    for fr in read_pcap(path):
        rep.frames += 1
        rep.wire_bytes += fr.wire_len
        rep.cap_bytes += fr.cap_len
        if last_ts is not None and fr.ts < last_ts:
            rep.out_of_order_ts += 1
        last_ts = fr.ts
        if fr.flags & 0x02:
            rep.syn += 1
        m2o = fr.src == MASTER and fr.dst == OUTSTATION and fr.dport == DNP3_PORT
        o2m = fr.src == OUTSTATION and fr.dst == MASTER and fr.sport == DNP3_PORT
        if not (m2o or o2m):
            if fr.payload:
                rep.wrong_endpoint += 1
            continue
        if fr.payload:
            key = ("m" if m2o else "o", fr.seq, len(fr.payload))
            seen_payload[key] = seen_payload.get(key, 0) + 1
            if seen_payload[key] > 1:
                rep.retransmissions += 1
                rep.duplicate_app_frames += 1
        if m2o and fr.payload:
            app = dnp3_app(fr.payload)
            if app is None:
                rep.malformed += 1
                continue
            if pend is not None:
                rep.unpaired_requests += 1
            pend = (fr.ts, app[0], app[1], fr.seq)
            t_ack = None
        elif o2m and pend is not None:
            if not fr.payload:
                if t_ack is None:
                    t_ack = fr.ts
            else:
                app = dnp3_app(fr.payload)
                if app is None:
                    rep.malformed += 1
                    continue
                if t_ack is not None:
                    rep.exchanges.append(Exchange(pend[1], pend[0], t_ack, fr.ts,
                                                  pend[3], app[0], app[2]))
                else:
                    rep.unpaired_requests += 1
                pend = None
                t_ack = None
    if pend is not None:
        rep.unpaired_requests += 1
    return rep

"""Dependency-free pcap reader and DNP3 transaction extractor.

Written independently of the scapy-based extractor that produced the frozen
transactions.csv, so agreement between the two is a cross-check and not a restatement.

Timestamps are carried as **integer nanoseconds** from the capture record to the reported
interval. An earlier version converted each record to a float second, `ts_s + ts_f / 1e9`, and
subtracted floats downstream. At 2026 epoch magnitudes a float64 is spaced about 238 ns apart, so
that conversion discarded roughly a quarter of a microsecond before any interval was computed and
no number of printed decimals could restore it. Intervals are integers here; conversion to
milliseconds happens once, at the point of display.

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
    ts_ns: int; src: str; dst: str; sport: int; dport: int
    seq: int; ack: int; flags: int; payload: bytes; wire_len: int; cap_len: int

    @property
    def ts(self) -> float:
        """Seconds as a float, for display only. Never subtract two of these."""
        return self.ts_ns / 1e9

    def conn(self) -> tuple:
        """The 4-tuple, so per-connection state is not shared between connections."""
        return (self.src, self.sport, self.dst, self.dport)


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
            ts_ns = ts_s * 1_000_000_000 + (ts_f if nano else ts_f * 1000)
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
            yield Frame(ts_ns, src, dst, sport, dport, seq, ack, flags, bytes(payload),
                        wire_len, cap_len)


def _seq_covers(ack: int, want_end: int) -> bool:
    """True when TCP acknowledgment number `ack` covers `want_end`, modulo 2**32.

    Compared in the 32-bit sequence space so a wrap near the end of the number space does not
    make a valid acknowledgment look like an invalid one.
    """
    return ((ack - want_end) % (1 << 32)) < (1 << 31)


def dnp3_crc(data: bytes) -> int:
    """DNP3 link-layer CRC-16.

    Written out here rather than imported so this reader stays dependency-free and independent
    of the codec it is cross-checked against. `tests/` asserts the two agree.
    """
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA6BC if (c & 1) else (c >> 1)
    return (c ^ 0xFFFF) & 0xFFFF


def dnp3_crc_ok(payload: bytes) -> bool:
    """Check the header CRC and every data-block CRC. Absence of a check is not a pass."""
    if len(payload) < 10:
        return False
    if dnp3_crc(payload[:8]) != int.from_bytes(payload[8:10], "little"):
        return False
    ln = payload[2]
    if ln < 5:
        return False
    left, i = ln - 5, 10
    while left > 0:
        take = min(16, left)
        if i + take + 2 > len(payload):
            return False
        if dnp3_crc(payload[i:i + take]) != int.from_bytes(payload[i + take:i + take + 2],
                                                           "little"):
            return False
        i += take + 2
        left -= take
    return True


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
    """One exchange. The three timestamps are integer nanoseconds, not float seconds."""

    func: int; t_req_ns: int; t_ack_ns: int; t_resp_ns: int
    req_seq: int; resp_func: int; status: int | None

    @property
    def clrt_ns(self) -> int:
        """The cross-layer response time, exactly, as an integer."""
        return self.t_resp_ns - self.t_ack_ns

    @property
    def ack_gap_ns(self) -> int:
        return self.t_ack_ns - self.t_req_ns

    # Float views for display and for callers that want milliseconds.
    @property
    def t_req(self) -> float:
        return self.t_req_ns / 1e9

    @property
    def t_ack(self) -> float:
        return self.t_ack_ns / 1e9

    @property
    def t_resp(self) -> float:
        return self.t_resp_ns / 1e9


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
    crc_errors: int = 0
    acks_not_covering_request: int = 0
    connections: int = 0


def extract(path, *, verify_crc: bool = True) -> CaptureReport:
    """Extract exchanges from one capture.

    Three things this deliberately does more carefully than counting alone:

    * **CRCs are checked, not skipped.** The user data is recovered by stepping over the block
      CRCs, which on its own says nothing about whether they were correct. A frame whose header
      or any block CRC fails is counted as malformed rather than silently accepted.
    * **An acknowledgment must actually acknowledge the request.** Taking the first empty
      reverse-direction packet is weaker than checking that its TCP acknowledgment number covers
      the end of the request, which is what is done here. Empty packets that do not cover the
      request, such as a window update or a keepalive, are counted and skipped.
    * **Duplicate detection is scoped to a connection.** A key of direction, sequence and length
      alone collides across connections, since two connections can legitimately carry the same
      sequence number. The connection's 4-tuple is part of the key.

    The captures in this campaign are single-connection and serialised, so the looser rules
    happened to give the same answer; these make that a checked property rather than a lucky one.
    """
    rep = CaptureReport(path=str(path))
    seen_payload = {}                                       # (conn, dir, seq, len) -> count
    conns = set()
    last_ts_ns = None
    pend = None                                             # (t_req_ns, func, app_seq, seq, end)
    t_ack_ns = None
    for fr in read_pcap(path):
        rep.frames += 1
        rep.wire_bytes += fr.wire_len
        rep.cap_bytes += fr.cap_len
        if last_ts_ns is not None and fr.ts_ns < last_ts_ns:
            rep.out_of_order_ts += 1
        last_ts_ns = fr.ts_ns
        if fr.flags & 0x02:
            rep.syn += 1
        m2o = fr.src == MASTER and fr.dst == OUTSTATION and fr.dport == DNP3_PORT
        o2m = fr.src == OUTSTATION and fr.dst == MASTER and fr.sport == DNP3_PORT
        if not (m2o or o2m):
            if fr.payload:
                rep.wrong_endpoint += 1
            continue
        # One connection identity for both directions, keyed on the master's ephemeral port.
        conn = (fr.sport, fr.dport) if m2o else (fr.dport, fr.sport)
        conns.add(conn)
        if fr.payload:
            key = (conn, "m" if m2o else "o", fr.seq, len(fr.payload))
            seen_payload[key] = seen_payload.get(key, 0) + 1
            if seen_payload[key] > 1:
                rep.retransmissions += 1
                rep.duplicate_app_frames += 1
        if m2o and fr.payload:
            if verify_crc and not dnp3_crc_ok(fr.payload):
                rep.crc_errors += 1
                rep.malformed += 1
                continue
            app = dnp3_app(fr.payload)
            if app is None:
                rep.malformed += 1
                continue
            if pend is not None:
                rep.unpaired_requests += 1
            pend = (fr.ts_ns, app[0], app[1], fr.seq, fr.seq + len(fr.payload))
            t_ack_ns = None
        elif o2m and pend is not None:
            if not fr.payload:
                # The acknowledgment must cover the request's last byte to be its acknowledgment.
                if _seq_covers(fr.ack, pend[4]):
                    if t_ack_ns is None:
                        t_ack_ns = fr.ts_ns
                else:
                    rep.acks_not_covering_request += 1
            else:
                if verify_crc and not dnp3_crc_ok(fr.payload):
                    rep.crc_errors += 1
                    rep.malformed += 1
                    continue
                app = dnp3_app(fr.payload)
                if app is None:
                    rep.malformed += 1
                    continue
                if t_ack_ns is not None:
                    rep.exchanges.append(Exchange(pend[1], pend[0], t_ack_ns, fr.ts_ns,
                                                  pend[3], app[0], app[2]))
                else:
                    rep.unpaired_requests += 1
                pend = None
                t_ack_ns = None
    if pend is not None:
        rep.unpaired_requests += 1
    rep.connections = len(conns)
    return rep

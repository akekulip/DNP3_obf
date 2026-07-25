"""
Offline, read-only pcap -> TCP -> DNP3 parsing primitives for the Part 13 corpus audit.

Stdlib only. Python 3.8 compatible. Nothing in this module opens a socket, touches
hardware, or writes to a capture file; every function is a pure read of bytes that
were already on disk.

Layering, in the order the audit descends:
  1. ``read_pcap``          classic libpcap file -> per-packet Ethernet/IPv4/TCP records
  2. ``StreamReassembler``  per-direction TCP byte stream + offset -> packet-index map
  3. ``parse_dnp3_frames``  IEEE 1815 link frames -> transport -> application header

The application layer is entered ONLY when the link magic is valid AND the link
length field says the bytes are present (see ``parse_dnp3_frames``); a well formed
link frame carrying no user data is LINK_OTHER, not malformed.
"""

import struct
from collections import namedtuple

# ---------------------------------------------------------------------------
# CRC-16/DNP (IEEE 1815): poly 0x3D65, reflected, init 0x0000, final XOR 0xFFFF.
# Reflected poly used by the table generator below is 0xA6BC.
# ---------------------------------------------------------------------------
_REFLECTED_POLY = 0xA6BC


def _build_crc_table():
    table = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ _REFLECTED_POLY
            else:
                crc >>= 1
        table.append(crc)
    return tuple(table)


_CRC_TABLE = _build_crc_table()


def dnp3_crc16(data):
    """CRC-16/DNP of one DNP3 block (8-byte link header or <=16-byte data block)."""
    crc = 0x0000
    for byte in bytearray(data):
        crc = (crc >> 8) ^ _CRC_TABLE[(crc ^ byte) & 0xFF]
    return (~crc) & 0xFFFF


# ---------------------------------------------------------------------------
# pcap file reader
# ---------------------------------------------------------------------------
Packet = namedtuple('Packet', [
    'index',        # 1-based frame number, matches Wireshark/tshark frame.number
    'ts',           # absolute epoch seconds (float)
    'src', 'dst',   # dotted-quad IPv4 strings
    'sport', 'dport',
    'seq', 'ack',   # raw 32-bit TCP sequence / acknowledgement numbers
    'flags',        # TCP flag byte (FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10)
    'payload',      # bytes actually captured for the TCP payload
    'payload_len',  # payload length ON THE WIRE (from the IP total length field)
    'truncated',    # True when the capture snaplen cut the payload short
])

_PCAP_MAGICS = {
    b'\xd4\xc3\xb2\xa1': ('<', 1000000),      # little endian, microseconds
    b'\xa1\xb2\xc3\xd4': ('>', 1000000),      # big endian, microseconds
    b'\x4d\x3c\xb2\xa1': ('<', 1000000000),   # little endian, nanoseconds
    b'\xa1\xb2\x3c\x4d': ('>', 1000000000),   # big endian, nanoseconds
}


class PcapError(Exception):
    """Raised when a capture file cannot be parsed at all."""


def _ipv4(raw):
    return '%d.%d.%d.%d' % tuple(bytearray(raw))


def read_pcap(path):
    """
    Parse a classic libpcap file and return (packets, stats).

    ``packets`` holds one Packet per IPv4/TCP frame. ``stats`` counts every frame in
    the file, including the non-TCP ones that produce no Packet, so the audit can
    reconcile "total packets" against capinfos.
    """
    stats = {
        'total_packets': 0, 'ethernet': 0, 'vlan': 0, 'ipv4': 0, 'ipv6': 0,
        'arp': 0, 'other_l3': 0, 'tcp': 0, 'udp': 0, 'other_l4': 0,
        'ip_fragments_skipped': 0, 'truncated_payloads': 0, 'short_frames': 0,
    }
    packets = []
    with open(path, 'rb') as handle:
        magic = handle.read(4)
        if magic not in _PCAP_MAGICS:
            raise PcapError('unsupported pcap magic %r (pcapng is not handled)' % magic)
        endian, ts_divisor = _PCAP_MAGICS[magic]
        rest = handle.read(20)
        if len(rest) != 20:
            raise PcapError('truncated pcap global header')
        _vmaj, _vmin, _tz, _sig, snaplen, linktype = struct.unpack(endian + 'HHiIII', rest)
        if linktype != 1:
            raise PcapError('link type %d is not Ethernet' % linktype)
        stats['snaplen'] = snaplen
        rec_fmt = endian + 'IIII'
        index = 0
        while True:
            hdr = handle.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(rec_fmt, hdr)
            data = handle.read(incl_len)
            if len(data) < incl_len:
                break
            index += 1
            stats['total_packets'] += 1
            ts = ts_sec + float(ts_frac) / ts_divisor
            pkt = _parse_ethernet(index, ts, data, orig_len, stats)
            if pkt is not None:
                packets.append(pkt)
    return packets, stats


def _parse_ethernet(index, ts, data, orig_len, stats):
    if len(data) < 14:
        stats['short_frames'] += 1
        return None
    stats['ethernet'] += 1
    off = 12
    ethertype = struct.unpack('>H', data[off:off + 2])[0]
    off += 2
    while ethertype in (0x8100, 0x88A8) and len(data) >= off + 4:
        stats['vlan'] += 1
        ethertype = struct.unpack('>H', data[off + 2:off + 4])[0]
        off += 4
    if ethertype == 0x0806:
        stats['arp'] += 1
        return None
    if ethertype == 0x86DD:
        stats['ipv6'] += 1
        return None
    if ethertype != 0x0800:
        stats['other_l3'] += 1
        return None
    stats['ipv4'] += 1
    return _parse_ipv4(index, ts, data, off, orig_len, stats)


def _parse_ipv4(index, ts, data, off, orig_len, stats):
    if len(data) < off + 20:
        stats['short_frames'] += 1
        return None
    ihl = (data[off] & 0x0F) * 4
    total_len = struct.unpack('>H', data[off + 2:off + 4])[0]
    frag = struct.unpack('>H', data[off + 6:off + 8])[0]
    proto = data[off + 9]
    src = _ipv4(data[off + 12:off + 16])
    dst = _ipv4(data[off + 16:off + 20])
    if (frag & 0x1FFF) != 0:
        stats['ip_fragments_skipped'] += 1
        return None
    if proto == 17:
        stats['udp'] += 1
        return None
    if proto != 6:
        stats['other_l4'] += 1
        return None
    stats['tcp'] += 1
    tcp_off = off + ihl
    if len(data) < tcp_off + 20:
        stats['short_frames'] += 1
        return None
    sport, dport, seq, ack = struct.unpack('>HHII', data[tcp_off:tcp_off + 12])
    data_off = (data[tcp_off + 12] >> 4) * 4
    flags = data[tcp_off + 13]
    wire_payload_len = total_len - ihl - data_off
    if wire_payload_len < 0:
        wire_payload_len = 0
    payload_start = tcp_off + data_off
    payload = data[payload_start:payload_start + wire_payload_len]
    truncated = len(payload) < wire_payload_len
    if truncated:
        stats['truncated_payloads'] += 1
    return Packet(index, ts, src, dst, sport, dport, seq, ack, flags,
                  payload, wire_payload_len, truncated)


def is_pure_ack(pkt):
    """
    Pure TCP ACK per the hardened rule: zero payload, ACK set, SYN/FIN/RST clear.
    A zero-payload segment is never a DNP3 frame.
    """
    return (pkt.payload_len == 0
            and (pkt.flags & 0x10) != 0
            and (pkt.flags & 0x07) == 0)


# ---------------------------------------------------------------------------
# Per-direction TCP reassembly
# ---------------------------------------------------------------------------
SEQ_MOD = 1 << 32


def seq_add(a, b):
    return (a + b) % SEQ_MOD


def seq_diff(a, b):
    """Signed distance a - b under 32-bit sequence arithmetic."""
    d = (a - b) % SEQ_MOD
    if d >= SEQ_MOD // 2:
        d -= SEQ_MOD
    return d


class StreamReassembler:
    """
    Rebuild one direction of a TCP byte stream in sequence order.

    Retransmitted bytes are recorded but not re-appended, so a DNP3 frame that was
    retransmitted is parsed once. A frame split across TCP segments is stitched here
    and is therefore NOT reported as malformed downstream.
    """

    def __init__(self):
        self.buf = bytearray()
        self.next_seq = None
        self.base_offset = 0          # stream offset of buf[0] after consumption
        self.consumed = 0             # bytes already handed to the frame parser
        self.segments = []            # (stream_offset, length, pkt_index, seq, ts)
        self.retransmissions = []     # (pkt_index, seq, length, ts)
        self.gaps = []                # (pkt_index, expected_seq, got_seq, missing)

    def add(self, pkt):
        if pkt.payload_len == 0:
            return
        payload = pkt.payload
        if self.next_seq is None:
            self.next_seq = pkt.seq
        delta = seq_diff(pkt.seq, self.next_seq)
        if delta < 0:
            overlap = -delta
            if overlap >= len(payload):
                self.retransmissions.append((pkt.index, pkt.seq, pkt.payload_len, pkt.ts))
                return
            self.retransmissions.append((pkt.index, pkt.seq, overlap, pkt.ts))
            payload = payload[overlap:]
            delta = 0
        if delta > 0:
            self.gaps.append((pkt.index, self.next_seq, pkt.seq, delta))
            self.next_seq = pkt.seq
        offset = self.consumed + len(self.buf)
        self.segments.append((offset, len(payload), pkt.index, pkt.seq, pkt.ts))
        self.buf.extend(payload)
        self.next_seq = seq_add(pkt.seq, len(payload))

    def offset_for_seq(self, seq):
        """Stream offset of TCP sequence number ``seq``, or None if never delivered."""
        for start, length, _idx, sseq, _ts in self.segments:
            delta = seq_diff(seq, sseq)
            if 0 <= delta < length:
                return start + delta
        return None

    def packet_for_offset(self, offset):
        """Return (pkt_index, ts, seq) of the segment that carries stream byte ``offset``."""
        lo, hi = 0, len(self.segments) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            start, length, idx, seq, ts = self.segments[mid]
            if offset < start:
                hi = mid - 1
            elif offset >= start + length:
                lo = mid + 1
            else:
                return idx, ts, seq
        return None, None, None


# ---------------------------------------------------------------------------
# DNP3 framing
# ---------------------------------------------------------------------------
START_MAGIC = b'\x05\x64'
LINK_HEADER_LEN = 10          # 0x05 0x64 LEN CTRL DEST(2) SRC(2) CRC(2)
MIN_LEN_FIELD = 5             # LEN counts CTRL+DEST+SRC, i.e. 5 bytes with no user data

APP_FUNC_NAMES = {
    0: 'CONFIRM', 1: 'READ', 2: 'WRITE', 3: 'SELECT', 4: 'OPERATE',
    5: 'DIRECT_OPERATE', 6: 'DIRECT_OPERATE_NR', 7: 'IMMED_FREEZE',
    8: 'IMMED_FREEZE_NR', 9: 'FREEZE_CLEAR', 10: 'FREEZE_CLEAR_NR',
    11: 'FREEZE_AT_TIME', 12: 'FREEZE_AT_TIME_NR', 13: 'COLD_RESTART',
    14: 'WARM_RESTART', 15: 'INITIALIZE_DATA', 16: 'INITIALIZE_APPL',
    17: 'START_APPL', 18: 'STOP_APPL', 19: 'SAVE_CONFIG', 20: 'ENABLE_UNSOLICITED',
    21: 'DISABLE_UNSOLICITED', 22: 'ASSIGN_CLASS', 23: 'DELAY_MEASURE',
    24: 'RECORD_CURRENT_TIME', 25: 'OPEN_FILE', 26: 'CLOSE_FILE',
    27: 'DELETE_FILE', 28: 'GET_FILE_INFO', 29: 'AUTHENTICATE_FILE',
    30: 'ABORT_FILE', 31: 'ACTIVATE_CONFIG', 32: 'AUTHENTICATE_REQ',
    33: 'AUTH_REQ_NO_ACK', 129: 'RESPONSE', 130: 'UNSOLICITED_RESPONSE',
    131: 'AUTHENTICATE_RESP',
}

LINK_FUNC_PRI = {0: 'RESET_LINK_STATES', 1: 'RESET_USER_PROCESS',
                 2: 'TEST_LINK_STATES', 3: 'CONFIRMED_USER_DATA',
                 4: 'UNCONFIRMED_USER_DATA', 9: 'REQUEST_LINK_STATUS'}
LINK_FUNC_SEC = {0: 'ACK', 1: 'NACK', 11: 'LINK_STATUS',
                 14: 'NOT_SUPPORTED', 15: 'NOT_USED'}


def frame_wire_length(len_field):
    """Total on-wire length of a DNP3 link frame given its LEN field."""
    user = len_field - MIN_LEN_FIELD
    blocks = (user + 15) // 16
    return LINK_HEADER_LEN + user + 2 * blocks


def _strip_block_crcs(body, user_len):
    """Split the post-header bytes into user data and per-block CRC validity."""
    user = bytearray()
    crc_ok = True
    pos = 0
    remaining = user_len
    while remaining > 0:
        take = 16 if remaining >= 16 else remaining
        block = body[pos:pos + take]
        crc_bytes = body[pos + take:pos + take + 2]
        if len(block) < take or len(crc_bytes) < 2:
            return bytes(user), False
        if struct.unpack('<H', bytes(crc_bytes))[0] != dnp3_crc16(bytes(block)):
            crc_ok = False
        user.extend(block)
        pos += take + 2
        remaining -= take
    return bytes(user), crc_ok


def parse_dnp3_frames(stream):
    """
    Extract DNP3 link frames from a reassembled ``StreamReassembler``.

    Returns (frames, anomalies). Classification follows the hardened rule:
      * transport/application parsing is entered only when the magic is valid AND
        the LEN field says the payload bytes are present;
      * LEN == 5 (no user data) is a valid link-only frame -> class LINK_OTHER;
      * bytes still missing at the end of the buffer are 'incomplete', which is TCP
        segmentation, not corruption;
      * only a bad magic resync, LEN < 5, or a failed CRC is malformed.
    """
    frames = []
    anomalies = []
    buf = stream.buf
    pos = 0
    end = len(buf)
    while pos < end:
        if buf[pos:pos + 2] != START_MAGIC:
            nxt = buf.find(START_MAGIC, pos + 1)
            if nxt == -1:
                anomalies.append({'kind': 'MALFORMED_TRAILING_BYTES',
                                  'stream_offset': pos, 'skipped': end - pos,
                                  'packet': stream.packet_for_offset(pos)[0],
                                  'hex': bytes(buf[pos:pos + 16]).hex()})
                break
            anomalies.append({'kind': 'MALFORMED_RESYNC', 'stream_offset': pos,
                              'skipped': nxt - pos,
                              'packet': stream.packet_for_offset(pos)[0],
                              'hex': bytes(buf[pos:min(nxt, pos + 16)]).hex()})
            pos = nxt
            continue
        if pos + LINK_HEADER_LEN > end:
            anomalies.append({'kind': 'INCOMPLETE_HEADER_AT_EOF', 'stream_offset': pos,
                              'available': end - pos,
                              'packet': stream.packet_for_offset(pos)[0]})
            break
        len_field = buf[pos + 2]
        if len_field < MIN_LEN_FIELD:
            anomalies.append({'kind': 'MALFORMED_LEN_FIELD', 'stream_offset': pos,
                              'len_field': len_field,
                              'packet': stream.packet_for_offset(pos)[0],
                              'hex': bytes(buf[pos:pos + 10]).hex()})
            pos += 2
            continue
        total = frame_wire_length(len_field)
        if pos + total > end:
            anomalies.append({'kind': 'INCOMPLETE_FRAME_AT_EOF', 'stream_offset': pos,
                              'need': total, 'available': end - pos,
                              'packet': stream.packet_for_offset(pos)[0]})
            break
        frames.append(_decode_frame(stream, buf, pos, total, len_field))
        pos += total
    return frames, anomalies


def _decode_frame(stream, buf, pos, total, len_field):
    header = bytes(buf[pos:pos + 8])
    hdr_crc = struct.unpack('<H', bytes(buf[pos + 8:pos + 10]))[0]
    hdr_crc_ok = hdr_crc == dnp3_crc16(header)
    ctrl = header[3]
    dest = struct.unpack('<H', header[4:6])[0]
    src = struct.unpack('<H', header[6:8])[0]
    user_len = len_field - MIN_LEN_FIELD
    body = bytes(buf[pos + LINK_HEADER_LEN:pos + total])
    user, body_crc_ok = _strip_block_crcs(body, user_len)

    first_pkt, first_ts, first_seq = stream.packet_for_offset(pos)
    last_pkt, last_ts, _ = stream.packet_for_offset(pos + total - 1)

    prm = bool(ctrl & 0x40)
    link_fc = ctrl & 0x0F
    frame = {
        'stream_offset': pos, 'wire_len': total, 'len_field': len_field,
        'link_dir': bool(ctrl & 0x80), 'link_prm': prm, 'link_fc': link_fc,
        'link_fc_name': (LINK_FUNC_PRI if prm else LINK_FUNC_SEC).get(link_fc, 'UNKNOWN_%d' % link_fc),
        'link_src': src, 'link_dst': dest,
        'hdr_crc_ok': hdr_crc_ok, 'body_crc_ok': body_crc_ok,
        'first_packet': first_pkt, 'last_packet': last_pkt,
        'first_ts': first_ts, 'last_ts': last_ts, 'first_seq': first_seq,
        'spans_segments': first_pkt != last_pkt,
        'user_len': user_len,
        'transport': None, 'app_seq': None, 'app_fc': None, 'app_fc_name': None,
        'app_fir': None, 'app_fin': None, 'app_con': None, 'iin': None,
    }
    if not hdr_crc_ok or not body_crc_ok:
        frame['klass'] = 'MALFORMED_CRC'
        return frame
    # Hardened rule: descend past the link layer only when user data is present.
    if user_len == 0:
        frame['klass'] = 'LINK_OTHER'
        return frame
    tr = user[0]
    frame['transport'] = {'fir': bool(tr & 0x40), 'fin': bool(tr & 0x80), 'seq': tr & 0x3F}
    if len(user) < 3:
        frame['klass'] = 'TRANSPORT_ONLY'
        return frame
    if not frame['transport']['fir']:
        frame['klass'] = 'TRANSPORT_CONTINUATION'
        return frame
    ac = user[1]
    fc = user[2]
    frame['app_seq'] = ac & 0x0F
    frame['app_fir'] = bool(ac & 0x80)
    frame['app_fin'] = bool(ac & 0x40)
    frame['app_con'] = bool(ac & 0x20)
    frame['app_fc'] = fc
    frame['app_fc_name'] = APP_FUNC_NAMES.get(fc, 'UNKNOWN_%d' % fc)
    if fc >= 129:
        if len(user) >= 5:
            frame['iin'] = (user[3] << 8) | user[4]
        frame['klass'] = 'APP_RESPONSE'
    else:
        frame['klass'] = 'APP_REQUEST'
    return frame

"""The real stack's TCP profile, as bytes: Vision's kernel against the SEL-751, captured on Vision
(protocol/evidence/hw_range_read_01/native_ip_retest_20261010.pcap: handshake, one 20-byte READ request, its
49-byte response, orderly close; timestamps, SACK-permitted, window scale).

Two things a replay has to respect:
  * The capture was taken on the SENDER. The five master segments the kernel handed to the NIC for checksum
    offload (frames 0, 2, 3, 6, 7) carry only the pseudo-header sum in the TCP checksum field, not the
    checksum the NIC put on the wire. wire() fills in the checksum the NIC transmits. The outstation's six
    frames and the master's last ACK already verify and are used byte for byte.
  * One capture holds one READ. session(reads=n) continues it in the same profile: each further exchange is the
    capture's own request / ACK / response / ACK with sequence numbers, timestamps, IP ids and the DNP3
    application sequence advanced and every checksum and CRC recomputed.
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE4 = HERE.parent.parent.parent
sys.path.insert(0, str(CASE4.parent / 'framework' / 'size'))
import case4_padding as codec  # noqa: E402

PCAP = CASE4 / 'protocol' / 'evidence' / 'hw_range_read_01' / 'native_ip_retest_20261010.pcap'
MASTER_IP, RELAY_IP, MASTER_TCP, RELAY_TCP = '192.168.10.1', '192.168.10.7', 54330, 20000
REQUEST_LEN, RESPONSE_LEN = 20, 49
SYN, SYNACK, ACK3, REQUEST, REQ_ACK, RESPONSE, RSP_ACK, M_FIN, R_FIN_ACK, R_FIN, M_LAST_ACK = range(11)


def read_pcap(path=PCAP):
    data = Path(path).read_bytes()
    assert struct.unpack('<I', data[:4])[0] == 0xa1b2c3d4, 'classic little-endian pcap expected'
    off, out = 24, []
    while off < len(data):
        _sec, _usec, incl, orig = struct.unpack('<IIII', data[off:off + 16])
        assert incl == orig, 'truncated capture'
        out.append(data[off + 16:off + 16 + incl])
        off += 16 + incl
    return out


def _sum16(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def tcp_checksum(frame):
    """The correct TCP checksum of an Ethernet/IPv4(ihl 5)/TCP frame."""
    segment = bytearray(frame[34:14 + struct.unpack('!H', frame[16:18])[0]])
    segment[16:18] = b'\0\0'
    return _sum16(frame[26:34] + struct.pack('!BBH', 0, 6, len(segment)) + bytes(segment))


def from_master(frame):
    return frame[26:30] == bytes(int(x) for x in MASTER_IP.split('.'))


def checksummed(frame):
    """frame with its IP header checksum and TCP checksum recomputed."""
    frame = bytearray(frame)
    frame[24:26] = b'\0\0'
    frame[24:26] = struct.pack('!H', _sum16(bytes(frame[14:34])))
    frame[50:52] = struct.pack('!H', tcp_checksum(bytes(frame)))
    return bytes(frame)


def wire(frames=None):
    """The capture as it was on the wire: master segments with the checksum the NIC transmitted."""
    out = []
    for frame in frames or read_pcap():
        have = struct.unpack('!H', frame[50:52])[0]
        if have != tcp_checksum(frame):
            pseudo = _sum16(frame[26:34] + struct.pack('!BBH', 0, 6, struct.unpack('!H', frame[16:18])[0] - 20)) ^ 0xffff
            assert from_master(frame) and have == pseudo, 'only an offloaded master segment may fail its checksum'
            frame = frame[:50] + struct.pack('!H', tcp_checksum(frame)) + frame[52:]
        out.append(frame)
    return out


def edit(frame, seq=None, ack=None, ip_id=None, ts=None, sport=None, payload=None):
    """An offset-8 segment of the capture with fields replaced and checksums recomputed. ts = (tsval, tsecr)."""
    frame = bytearray(frame)
    assert frame[46] >> 4 == 8 and frame[54:58] == b'\x01\x01\x08\x0a', 'an offset-8 timestamped segment expected'
    if seq is not None:
        frame[38:42] = struct.pack('!I', seq & 0xffffffff)
    if ack is not None:
        frame[42:46] = struct.pack('!I', ack & 0xffffffff)
    if ip_id is not None:
        frame[18:20] = struct.pack('!H', ip_id & 0xffff)
    if ts is not None:
        frame[58:66] = struct.pack('!II', ts[0] & 0xffffffff, ts[1] & 0xffffffff)
    if sport is not None:
        frame[34:36] = struct.pack('!H', sport)
    if payload is not None:
        assert len(payload) == len(frame) - 66, 'same-length payload only'
        frame[66:] = payload
    return checksummed(bytes(frame))


def with_app_sequence(dnp3, sequence):
    """A DNP3 link frame with the application sequence (low 4 bits of the application control octet) replaced
    and its CRCs recomputed."""
    head, user = codec.decode_frame(dnp3)
    user = bytearray(user)
    user[1] = (user[1] & 0xf0) | (sequence & 0x0f)
    return codec.build_frame(head, bytes(user))


def session(reads=1, close=True):
    """[(name, from_master, frame)] in wire order: the capture's handshake, `reads` READ exchanges in its
    profile (the first is the capture's own, byte for byte), and its close."""
    cap = wire()
    out = [('SYN', True, cap[SYN]), ('SYNACK', False, cap[SYNACK]), ('ACK', True, cap[ACK3])]
    cseq, sseq = struct.unpack('!I', cap[REQUEST][38:42])[0], struct.unpack('!I', cap[RESPONSE][38:42])[0]
    m_id, r_id = struct.unpack('!H', cap[REQUEST][18:20])[0], struct.unpack('!H', cap[REQ_ACK][18:20])[0]
    m_ts, r_ts = struct.unpack('!I', cap[REQUEST][58:62])[0], struct.unpack('!I', cap[REQ_ACK][58:62])[0]
    for n in range(reads):
        if n == 0:
            four = [cap[REQUEST], cap[REQ_ACK], cap[RESPONSE], cap[RSP_ACK]]
        else:
            step = 1000 * n     # one second between polls, in both hosts' millisecond timestamp clocks
            req = with_app_sequence(cap[REQUEST][66:], n)
            rsp = with_app_sequence(cap[RESPONSE][66:], n)
            four = [edit(cap[REQUEST], seq=cseq, ack=sseq, ip_id=m_id + 2 * n, ts=(m_ts + step, r_ts + step - 1000 + 25), payload=req),
                    edit(cap[REQ_ACK], seq=sseq, ack=cseq + REQUEST_LEN, ip_id=r_id + 2 * n, ts=(r_ts + step, m_ts + step)),
                    edit(cap[RESPONSE], seq=sseq, ack=cseq + REQUEST_LEN, ip_id=r_id + 2 * n + 1, ts=(r_ts + step + 25, m_ts + step), payload=rsp),
                    edit(cap[RSP_ACK], seq=cseq + REQUEST_LEN, ack=sseq + RESPONSE_LEN, ip_id=m_id + 2 * n + 1, ts=(m_ts + step + 25, r_ts + step + 25))]
        out += [('READ%d_request' % (n + 1), True, four[0]), ('READ%d_relay_ack' % (n + 1), False, four[1]),
                ('READ%d_response' % (n + 1), False, four[2]), ('READ%d_master_ack' % (n + 1), True, four[3])]
        cseq, sseq = cseq + REQUEST_LEN, sseq + RESPONSE_LEN
    if close:
        extra = reads - 1
        out += [('master_FIN', True, edit(cap[M_FIN], seq=cseq, ack=sseq) if extra else cap[M_FIN]),
                ('relay_ACK_of_FIN', False, edit(cap[R_FIN_ACK], seq=sseq, ack=cseq + 1) if extra else cap[R_FIN_ACK]),
                ('relay_FIN', False, edit(cap[R_FIN], seq=sseq, ack=cseq + 1) if extra else cap[R_FIN]),
                ('master_last_ACK', True, edit(cap[M_LAST_ACK], seq=cseq + 1, ack=sseq + 1) if extra else cap[M_LAST_ACK])]
    return out

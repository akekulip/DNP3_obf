"""Synthetic pcap toolkit for the hw_vepa analyzer tests: build Ethernet/IPv4/TCP frames (with correct
or deliberately offloaded checksums) and valid DNP3 link frames, and write a microsecond classic pcap.
No scapy; mirrors the on-disk format the analyzers read."""
import struct

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
_MAC_A = bytes.fromhex('020000000001')
_MAC_B = bytes.fromhex('020000000002')


def dnp3_crc(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA6BC if c & 1 else c >> 1
    return (~c) & 0xFFFF


def dnp3_frame(user, ctrl=0x44, dest=0, src=1):
    """A valid DNP3 link frame around `user` (transport octet, app-control octet, function, objects...)."""
    header = bytes([0x05, 0x64, 5 + len(user), ctrl]) + struct.pack('<HH', dest, src)
    out = header + struct.pack('<H', dnp3_crc(header))
    for i in range(0, len(user), 16):
        blk = user[i:i + 16]
        out += blk + struct.pack('<H', dnp3_crc(blk))
    return out


def read_request(app_seq=0, func=1):
    """A G10V2 ScanRange-shaped READ request payload (20 bytes), DNP3-CRC valid."""
    user = bytes([0xc0, 0xc0 | (app_seq & 0x0f), func, 0x0a, 0x02, 0x00, 0x00, 0x16])
    return dnp3_frame(user)


def read_response(app_seq=0, func=0x81, body_len=28):
    """A response payload (default 49 bytes) echoing the request's application sequence."""
    user = bytes([0xc0, 0xc0 | (app_seq & 0x0f), func, 0x81, 0x00]) + bytes(body_len)
    return dnp3_frame(user)


def _ck16(data):
    if len(data) % 2:
        data = data + b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def frame(src, dst, sport, dport, seq, ack, flags, payload=b'', ip_id=0, offload=False):
    """An Ethernet/IPv4/TCP frame. offload=True writes the pseudo-header placeholder the NIC overwrites."""
    tcp = bytearray(struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff,
                                0x50, flags, 64240, 0, 0)) + payload
    ip = bytearray(struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(tcp), ip_id, 0x4000, 64, 6, 0))
    ip += bytes(int(x) for x in src.split('.')) + bytes(int(x) for x in dst.split('.'))
    ip[10:12] = struct.pack('!H', _ck16(bytes(ip)))
    pseudo = bytes(ip[12:20]) + struct.pack('!BBH', 0, 6, len(tcp))
    if offload:
        tcp[16:18] = struct.pack('!H', _ck16(pseudo) ^ 0xffff)   # pseudo-header-only placeholder
    else:
        tcp[16:18] = struct.pack('!H', _ck16(pseudo + bytes(tcp)))
    eth = (_MAC_B if src.endswith('.61') else _MAC_A) + (_MAC_A if src.endswith('.61') else _MAC_B) + b'\x08\x00'
    return eth + bytes(ip) + bytes(tcp)


def write_pcap(path, records):
    """records: iterable of (t_us:int, frame:bytes)."""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for t_us, fr in records:
            f.write(struct.pack('<IIII', t_us // 1_000_000, t_us % 1_000_000, len(fr), len(fr)))
            f.write(fr)

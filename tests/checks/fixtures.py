"""Small generated SEL-751 conversations; no historical capture dependency."""
import json
import struct

from scripts.hardware.active_harness import dnp3_codec as codec
from scripts.checks import wire_check


def link(user, request=False):
    header = bytes([5, 100, len(user) + 5, 0xc4 if request else 0x44])
    header += struct.pack('<HH', *( (0, 1) if request else (1, 0)))
    raw = header + codec.crc_le(header)
    for offset in range(0, len(user), 16):
        block = user[offset:offset + 16]
        raw += block + codec.crc_le(block)
    return raw


def control(operation, seq=0, status=0, padded=False, points=(1, 3), on_ms=200):
    command = bytes([1, 1]) + struct.pack('<II', on_ms, 0) + bytes([status])
    objects = bytes([12, 1, 0x17, len(points)]) + b''.join(bytes([point]) + command for point in points)
    app = bytes([0xc0 | seq, {'SELECT': 3, 'OPERATE': 4}[operation]]) + objects
    response = bytes([app[0], 0x81, 0x80, 0]) + objects
    frames = [link(b'\xc0' + response)] if not padded else [
        link(b'\x40' + response[:15]), link(b'\x81' + response[15:])]
    return link(b'\xc0' + app, request=True), frames, app, response


def packet(outgoing, seq, ack, flags, payload=b''):
    src, dst, sport, dport = ('192.168.10.1', '192.168.10.7', 59410, 20000) if outgoing else (
        '192.168.10.7', '192.168.10.1', 20000, 59410)
    if flags == 2:
        options = bytes.fromhex('020405b40402080a000000010000000001030307')
    elif flags == 18:
        options = bytes.fromhex('020405b401030300010104020101080a0000000200000001')
    else:
        options = bytes.fromhex('0101080a0000000300000002')
    tcp = bytearray(struct.pack('!HHIIBBHHH', sport, dport, seq, ack,
                               ((20 + len(options)) // 4) << 4, flags, 64240, 0, 0) + options + payload)
    ip = bytearray(struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0))
    ip += bytes(map(int, src.split('.'))) + bytes(map(int, dst.split('.')))
    ip[10:12] = struct.pack('!H', wire_check._sum16(bytes(ip)))
    pseudo = bytes(ip[12:20]) + struct.pack('!BBH', 0, 6, len(tcp))
    tcp[16:18] = struct.pack('!H', wire_check._sum16(pseudo + bytes(tcp)))
    return bytes.fromhex('0200000000010200000000020800') + bytes(ip) + bytes(tcp)


def pcap(path, packets):
    with path.open('wb') as stream:
        stream.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for timestamp, raw in packets:
            stream.write(struct.pack('<IIII', 0, timestamp, len(raw), len(raw)))
            stream.write(raw)


def conversation(root, *, status=0, padded=True, forge_success=False, on_ms=200, split_tcp=False):
    """Two guarded controls, with independently selectable wire status and master claims."""
    root.mkdir(exist_ok=True)
    outgoing = [(1, packet(True, 100, 0, 2)), (3, packet(True, 101, 201, 16))]
    incoming = [(2, packet(False, 200, 101, 18))]
    records, tx, rx = [], 101, 201
    for seq, operation in enumerate(('SELECT', 'OPERATE')):
        observed_status = status if operation == 'OPERATE' else 0
        request, frames, request_app, response_app = control(
            operation, seq, observed_status, padded, on_ms=on_ms if operation == 'OPERATE' else 200)
        response = b''.join(frames)
        claimed = 0 if forge_success else observed_status
        record = dict(operation=operation, outcome='OK' if claimed == 0 else 'INVALID',
                      local_address=['192.168.10.1', 59410], peer_address=['192.168.10.7', 20000],
                      request_wire_hex=request.hex(), request_frames_hex=[request.hex()],
                      request_app_hex=request_app.hex(), response_wire_hex=response.hex(),
                      response_frames_hex=[frame.hex() for frame in frames], response_app_hex=response_app.hex(),
                      points=[[point, codec.STATUS_NAMES[claimed]] for point in (1, 3)])
        records.append(record)
        timestamp = 10 + seq * 20
        outgoing.append((timestamp, packet(True, tx, rx, 24, request)))
        tx += len(request)
        incoming.append((timestamp + 1, packet(False, rx, tx, 16)))
        if split_tcp:
            incoming.extend([(timestamp + 2, packet(False, rx, tx, 24, response[:20])),
                             (timestamp + 3, packet(False, rx + 20, tx, 24, response[20:]))])
        else:
            incoming.append((timestamp + 2, packet(False, rx, tx, 24, response)))
        rx += len(response)
    counts = dict(READ=0, SELECT=1, OPERATE=int(not status or forge_success))
    planned = dict(READ=0, SELECT=1, OPERATE=1)
    master = dict(ok=counts == planned, counts=counts, planned=planned, records=records)
    for name, value in [('master.json', master), ('result.json', {'tcpdump': {
            'out': {'dropped_kernel': 0}, 'in': {'dropped_kernel': 0}}}),
                        ('capture_offloads.json', {'restore_ok': True}), ('relay_wire.json', {})]:
        (root / name).write_text(json.dumps(value))
    pcap(root / 'out.pcap', outgoing)
    pcap(root / 'in.pcap', incoming)
    return {key: {'path': str(root / filename)} for key, filename in {
        'out': 'out.pcap', 'in': 'in.pcap', 'master': 'master.json', 'run_result': 'result.json',
        'capture_offloads': 'capture_offloads.json', 'relay_wire': 'relay_wire.json'}.items()}

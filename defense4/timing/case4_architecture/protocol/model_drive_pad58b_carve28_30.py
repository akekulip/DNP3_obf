"""Local Tofino-1 model run of case4_pad58b_carve28_30.p4: Option B' 58-byte pad, then an RRC carve [28,30].

Functional model execution only: not hardware, not timing, not a combined pipe-0 fit.

  integration/core/launch_model.sh -p protocol/evidence/pad58b_carve28_30_01/out \
     -o protocol/evidence/pad58b_carve28_30_01/model_NN -P "1 2" -d protocol/model_drive_pad58b_carve28_30.py

Expected bytes come from two independent software sources, never hand-copied:
  - the padded 58-byte image from framework/size/case4_pad58b.py (the same oracle pad58b_wire_02 used);
  - the two segments from framework/size/rrc.py's own segment builder (rrc._build: prefix flags lose
    PSH|FIN, suffix seq + 28, fresh IPv4 length/checksum and TCP checksum).
Independently of both, every received segment is re-checked from its own bytes: IPv4 header checksum,
TCP checksum, IP total length, seq, flags, and every DNP3 CRC block it carries; and prefix||suffix is
compared with the padded image byte for byte. Each captured frame is recorded (hex, arrival index) in
cases.json so reassemble_kernel_pad58b_carve28_30.py can feed the exact received bytes to a real
Linux TCP receiver.
"""
import os
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE4 = HERE.parent
sys.path[:0] = [str(CASE4 / 'integration' / 'core'), str(CASE4.parent / 'framework' / 'size')]
from model_driver import Model, Report, gc  # noqa: E402
import case4_pad58b as b  # noqa: E402
import case4_padding as pad  # noqa: E402
import rrc  # noqa: E402

IN, OUT, MGID = 1, 2, 7
SRC, DST, SPORT, DPORT = 0x0a000001, 0x0a000002, 20000, 40000
ETH = bytes.fromhex('0a0000000002' '0a0000000001') + b'\x08\x00'
LINK_HEAD = bytes.fromhex('056419c40a000100')
READ_USER = bytes([0xc7, 0xc5, 0x81, 0x80, 0x00]) + b.HEADER_READ23 + bytes(range(1, 24))
CTL_USER = bytes([0xc3, 0xc2, 0x81, 0x00, 0x00]) + b.HEADER_CROB28 + bytes(
    [0x05, 0x00, 0x03, 0x01, 0x64, 0, 0, 0, 0x64, 0, 0, 0, 0x00])
CTL_POINTS = [b.AnalogFloatPoint(301, 10.0, 0), b.AnalogFloatPoint(302, 20.0, 0)]
CUT = 28
ORDER_TRIALS = 20


def csum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def packet(dnp3, seq=0x11111111, flags=0x18, dport=DPORT):
    src, dst = struct.pack('!I', SRC), struct.pack('!I', DST)
    tcp = struct.pack('!HHIIBBHHH', SPORT, dport, seq, 0x22222222, 0x50, flags, 8192, 0, 0)
    pseudo = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(dnp3))
    tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp + dnp3)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(dnp3), 0x1234, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ETH + ip + tcp + dnp3


def expected_segments(padded_packet):
    """rrc's own segment builder applied to the padded image at cut 28 (rrc.carve itself only accepts
    its fixed 49/57-byte profiles, so its builder is called directly with the same flag rule)."""
    p = rrc.parse(padded_packet)
    first = rrc._build(p, p.payload[:CUT], p.seq, p.flags & ~(rrc.PSH | rrc.FIN))
    second = rrc._build(p, p.payload[CUT:], (p.seq + CUT) & 0xffffffff, p.flags)
    return first, second


def crc_blocks(data, starts):
    """True iff every (offset, length) block in `data` is followed by its correct little-endian DNP3 CRC."""
    return all(rrc.dnp3_crc(data[o:o + n]) == int.from_bytes(data[o + n:o + n + 2], 'little') for o, n in starts)


def wire_facts(frame):
    p = rrc.parse(frame)
    if p is None:
        return None
    return dict(ip_total_len=struct.unpack('>H', frame[16:18])[0], ip_csum_ok=rrc.ip_ok(p),
                tcp_csum_ok=rrc.tcp_ok(p), seq=p.seq, ack=p.ack, flags=p.flags, payload_len=len(p.payload),
                ip_id=struct.unpack('>H', frame[18:20])[0], frame_len=len(frame), payload=p.payload.hex())


m = Model(ports=[IN, OUT])
rep = Report(os.environ['PROG'], ingress_port=IN, egress_port=OUT, mgid=MGID, cut=CUT)
rep.add('ports_enabled', {}, m.port_errors, ok=not m.port_errors)

# PRE: one group, two level-1 nodes: node 1 (rid 1, prefix) and node 2 (rid 2, suffix), listed [1, 2] by default.
tgt = gc.Target(device_id=0, pipe_id=0xffff)
node, mg = m.info.table_get('$pre.node'), m.info.table_get('$pre.mgid')
for nid, rid in ((1, 1), (2, 2)):
    node.entry_add(tgt, [node.make_key([gc.KeyTuple('$MULTICAST_NODE_ID', nid)])],
                   [node.make_data([gc.DataTuple('$MULTICAST_RID', rid), gc.DataTuple('$MULTICAST_LAG_ID', int_arr_val=[]),
                                    gc.DataTuple('$DEV_PORT', int_arr_val=[OUT])])])
# NODE_ORDER=2,1 lists the suffix node first in the group (an order probe; correctness checks are unchanged).
NODE_ORDER = [int(x) for x in os.environ.get('NODE_ORDER', '1,2').split(',')]
rep.add('pre_group_node_order', 'recorded', 'recorded', ok=True, node_order=NODE_ORDER)
mg.entry_add(tgt, [mg.make_key([gc.KeyTuple('$MGID', MGID)])],
             [mg.make_data([gc.DataTuple('$MULTICAST_NODE_ID', int_arr_val=NODE_ORDER),
                            gc.DataTuple('$MULTICAST_NODE_L1_XID_VALID', bool_arr_val=[False, False]),
                            gc.DataTuple('$MULTICAST_NODE_L1_XID', int_arr_val=[0, 0])])])
m.add('Ingress.forwarding', {'ig.ingress_port': IN}, 'Ingress.route', {'port': OUT})
for ip_len in (89, 77):                       # native READ / CONTROL
    for flags in (0x10, 0x18):                # ACK, PSH|ACK
        m.add('Ingress.connection', {'hdr.ip.src': SRC, 'hdr.ip.dst': DST, 'hdr.tcp.sport': SPORT,
                                     'hdr.tcp.dport': DPORT, 'hdr.ip.len': ip_len, 'hdr.tcp.flags': flags},
              'Ingress.split', {'mgid': MGID})

read_native = pad.build_frame(LINK_HEAD, READ_USER)
ctl_native = pad.build_frame(LINK_HEAD, CTL_USER)
read_img, read_grow = b.pad_read_response(read_native)
ctl_img, ctl_grow = b.pad_control_response(ctl_native, CTL_POINTS)
rep.add('oracle_read_native_49', 49, len(read_native))
rep.add('oracle_ctl_native_37', 37, len(ctl_native))
rep.add('oracle_read_padded_58', 58, len(read_img))
rep.add('oracle_ctl_padded_58', 58, len(ctl_img))
# The cut lands on a DNP3 block boundary in both padded images: header(8)+crc | block 0 (16)+crc | ...
LAYOUT_PREFIX = [(0, 8), (10, 16)]            # offsets within the 28-byte prefix payload
LAYOUT_SUFFIX = [(0, 16), (18, 10)]           # offsets within the 30-byte suffix payload
for role, img in (('read', read_img), ('ctl', ctl_img)):
    rep.add('oracle_%s_padded_frame_ok' % role, True, rrc.dnp3_frame_ok(img))
    rep.add('oracle_%s_cut28_on_crc_boundary' % role, True,
            crc_blocks(img[:CUT], LAYOUT_PREFIX) and crc_blocks(img[CUT:], LAYOUT_SUFFIX))


def split_case(name, native, img, seq=0x11111111, flags=0x18):
    sent = packet(native, seq, flags)
    padded = packet(img, seq, flags)
    e1, e2 = expected_segments(padded)
    got = m.exchange(IN, sent, [OUT], timeout=2.0, quiet=0.5)[OUT]
    facts = [wire_facts(g) for g in got]
    order = ['prefix' if g == e1 else 'suffix' if g == e2 else 'other' for g in got]
    rep.add(name + '_two_frames', 2, len(got), sent=sent, padded=padded, expected_prefix=e1, expected_suffix=e2,
            received=[g.hex() for g in got], arrival=order, facts=facts)
    rep.add(name + '_prefix_byte_identical', 1, order.count('prefix'))
    rep.add(name + '_suffix_byte_identical', 1, order.count('suffix'))
    rep.add(name + '_no_other_frame', 0, order.count('other'))
    if len(got) != 2 or None in facts:
        return order
    pre = next((f for f in facts if f['seq'] == seq), None)
    suf = next((f for f in facts if f['seq'] == (seq + CUT) & 0xffffffff), None)
    rep.add(name + '_seq_numbers', [seq, (seq + CUT) & 0xffffffff],
            [pre and pre['seq'], suf and suf['seq']])
    if not (pre and suf):
        return order
    p_pay, s_pay = bytes.fromhex(pre['payload']), bytes.fromhex(suf['payload'])
    rep.add(name + '_payload_sizes', [28, 30], [len(p_pay), len(s_pay)])
    rep.add(name + '_prefix_cat_suffix_eq_padded', img.hex(), (p_pay + s_pay).hex())
    rep.add(name + '_ip_total_lengths', [68, 70], [pre['ip_total_len'], suf['ip_total_len']])
    rep.add(name + '_ip_checksums_valid', [True, True], [pre['ip_csum_ok'], suf['ip_csum_ok']])
    rep.add(name + '_tcp_checksums_valid', [True, True], [pre['tcp_csum_ok'], suf['tcp_csum_ok']])
    rep.add(name + '_flags', [flags & ~(rrc.PSH | rrc.FIN), flags], [pre['flags'], suf['flags']])
    rep.add(name + '_ack_and_ip_id_kept', [[0x22222222, 0x1234]] * 2,
            [[pre['ack'], pre['ip_id']], [suf['ack'], suf['ip_id']]])
    rep.add(name + '_prefix_crcs_intact', True, crc_blocks(p_pay, LAYOUT_PREFIX))
    rep.add(name + '_suffix_crcs_intact', True, crc_blocks(s_pay, LAYOUT_SUFFIX))
    rep.add(name + '_reassembled_dnp3_frame_ok', True, rrc.dnp3_frame_ok(p_pay + s_pay))
    return order


arrivals = {}
for role, native, img in (('read', read_native, read_img), ('ctl', ctl_native, ctl_img)):
    arrivals[role] = [split_case('%s_split' % role, native, img)]
    split_case('%s_split_ack_only' % role, native, img, flags=0x10)
    split_case('%s_split_seq_wrap' % role, native, img, seq=0xfffffff0)
    for i in range(ORDER_TRIALS):
        arrivals[role].append(split_case('%s_split_order_trial%02d' % (role, i), native, img,
                                         seq=0x30000000 + 0x1000 * i))
for role, seen in arrivals.items():
    tally = {}
    for o in seen:
        tally[','.join(o)] = tally.get(','.join(o), 0) + 1
    rep.add('%s_arrival_order_tally' % role, 'recorded', 'recorded', ok=True, tally=tally)


def single_case(name, sent, want):
    got = m.exchange(IN, sent, [OUT], timeout=2.0, quiet=0.5)[OUT]
    rep.add(name, 1, len(got), sent=sent, want=want, received=[g.hex() for g in got])
    rep.add(name + '_byte_identical', True, bool(got) and got[0] == want)


# A frame on the selected connection whose flags are not installed (FIN|PSH|ACK) is NOT split; it takes the
# unicast route and gets the whole [58] pad (the response-only, no-split baseline behaviour).
single_case('read_fin_not_split_padded58', packet(read_native, flags=0x19), packet(read_img, flags=0x19))
# A connection with no split entry: unicast, whole [58] pad.
single_case('read_unselected_connection_padded58', packet(read_native, dport=40001), packet(read_img, dport=40001))
single_case('ctl_unselected_connection_padded58', packet(ctl_native, dport=40001), packet(ctl_img, dport=40001))


def flip(frame, i):
    f = bytearray(frame)
    f[i] ^= 0x01
    return bytes(f)


# Refused by the native-CRC gate after replication: rid 1 must carry the original once, rid 2 must be dropped.
corrupt = [('read', read_native, 'head_crc', 8), ('read', read_native, 'blk0_data', 20),
           ('read', read_native, 'blk1_crc', 44), ('read', read_native, 'tail_data', 46),
           ('ctl', ctl_native, 'head_byte_src', 6), ('ctl', ctl_native, 'blk0_crc', 26),
           ('ctl', ctl_native, 'tail_crc', 36)]
for role, native, site, i in corrupt:
    bad = flip(native, i)
    o, g = (b.pad_read_response(bad) if role == 'read' else b.pad_control_response(bad, CTL_POINTS))
    rep.add('oracle_%s_%s_unchanged' % (role, site), (True, 0), (o == bad, g))
    single_case('%s_corrupt_%s_once_unchanged' % (role, site), packet(bad), packet(bad))

sys.exit(0 if rep.finish(os.path.join(os.environ['OUT'], 'cases.json')) else 1)

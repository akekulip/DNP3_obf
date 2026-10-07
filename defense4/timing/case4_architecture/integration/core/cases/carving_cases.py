#!/usr/bin/env python3
"""Carving role of egress_selected_wire (port 64, IP length 97): 57-byte response split into 28+29 by
multicast replication + egress rid render. Expected frames are built by the independent TCP/IP builder."""
import os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__)); CORE = os.path.dirname(HERE); ARCH = os.path.abspath(os.path.join(CORE, '..', '..'))
sys.path[:0] = [HERE, CORE, os.path.join(ARCH, 'protocol/egress/tests'), os.path.join(ARCH, 'protocol/egress'), os.path.join(ARCH, 'protocol/tests'), os.path.join(ARCH, 'tests')]
import frames as F
from model_driver import Model, Report, same_frame, gc
import test_carving as TC
m = Model(ports=[1, 64])
rep = Report(os.environ['PROG'], ports=m.ports)
OUTP, MGID = 1, 7
TUP = {'hdr.ip.src': 0x0a000001, 'hdr.ip.dst': 0x0a000002, 'hdr.tcp.sport': 42000, 'hdr.tcp.dport': 20000}
A, B = (0x0a000001, 42000), (0x0a000002, 20000)
tgt = gc.Target(device_id=0, pipe_id=0xffff)
node, mg = m.info.table_get('$pre.node'), m.info.table_get('$pre.mgid')
for nid, rid in ((1, 1), (2, 2)):
    node.entry_add(tgt, [node.make_key([gc.KeyTuple('$MULTICAST_NODE_ID', nid)])],
                   [node.make_data([gc.DataTuple('$MULTICAST_RID', rid), gc.DataTuple('$MULTICAST_LAG_ID', int_arr_val=[]),
                                    gc.DataTuple('$DEV_PORT', int_arr_val=[OUTP])])])
mg.entry_add(tgt, [mg.make_key([gc.KeyTuple('$MGID', MGID)])],
             [mg.make_data([gc.DataTuple('$MULTICAST_NODE_ID', int_arr_val=[1, 2]),
                            gc.DataTuple('$MULTICAST_NODE_L1_XID_VALID', bool_arr_val=[False, False]),
                            gc.DataTuple('$MULTICAST_NODE_L1_XID', int_arr_val=[0, 0])])])
m.add('Ingress.carving.forwarding', {'ig.ingress_port': 64}, 'Ingress.carving.route', {'port': OUTP})
m.add('Ingress.carving.connection', TUP, 'Ingress.carving.split', {'mgid': MGID})

def selected_key(p):
    dl_dst, dl_src = struct.unpack('>HH', p[4:8])
    first, second, tail = p[10:28], p[28:46], p[46:]
    w = lambda blk, i: int.from_bytes(blk[4 * i:4 * i + 4], 'big')
    return {'hdr.dl.dst': dl_dst, 'hdr.dl.src': dl_src, 'hdr.first.w0[31:24]': first[0], 'hdr.first.w0[23:16]': first[1],
            'hdr.first.w2[15:0]': w(first, 2) & 0xffff, 'hdr.first.w3': w(first, 3), 'hdr.second.w0': w(second, 0),
            'hdr.second.w1[31:16]': w(second, 1) >> 16, 'hdr.second.w3': w(second, 3),
            'hdr.tail.w0': int.from_bytes(tail[0:4], 'big'), 'hdr.tail.w1': int.from_bytes(tail[4:8], 'big')}

payload = TC.response()
assert len(payload) == 57
m.add('Ingress.carving.selected_objects', selected_key(payload), 'Ingress.carving.selected', {})
def run(name, pay, expect_split, base=1000, flags=0x18, bad_ip=False, bad_tcp=False, port=64):
    fr = F.tcp_frame(A, B, flags, base, 777, pay, ip_id=1, bad_ip=bad_ip, bad_tcp=bad_tcp)
    out = m.exchange(port, fr, [OUTP], timeout=1.0, quiet=0.3)[OUTP]
    if expect_split:
        e1 = F.tcp_frame(A, B, flags & ~8, base, 777, pay[:28], ip_id=1)
        e2 = F.tcp_frame(A, B, flags, (base + 28) & 0xffffffff, 777, pay[28:], ip_id=1)
        got = {'first': [x for x in out if same_frame(x, e1, fr)], 'second': [x for x in out if same_frame(x, e2, fr)]}
        pair = len(got['first']) == 1 and len(got['second']) == 1
        stray = [x for x in out if not same_frame(x, e1, fr) and not same_frame(x, e2, fr)]
        obs = 'split-28+29' if pair and not stray else ('pair-exact+%d-stray-frame' % len(stray) if pair else '%d-frames' % len(out))
        rep.add(name, 'split-28+29', obs, input=fr, expected_first=e1, expected_second=e2, pair_exact=pair, stray_frames=stray, out=out)
    else:
        one_original = len(out) == 1 and same_frame(out[0], fr)
        rep.add(name, 'original-only', 'original-only' if one_original else '%d-frames' % len(out), input=fr, out=out)
for base in (1000, 0xfffffff0):
    run('split_base%d' % base, payload, True, base)
bad = bytearray(payload); bad[8] ^= 1
for nm, off in (('crc_head', 8), ('crc_first', 26), ('crc_second', 44), ('crc_tail', 55)):
    b = bytearray(payload); b[off] ^= 1; run('refused_' + nm, bytes(b), False)
run('refused_bad_ip_csum', payload, False, bad_ip=True); run('refused_bad_tcp_csum', payload, False, bad_tcp=True)
# a status change CRC-correct but not the selected object statuses must not split
alt = bytearray(payload); alt[10 + 2] ^= 0x00
head, user = TC.padding.decode_frame(payload); user = bytearray(user); user[20] ^= 1
run('refused_unselected_status', TC.padding.build_frame(head, bytes(user)), False)
ok = rep.finish(os.path.join(os.environ['OUT'], 'cases.json'))
sys.exit(0 if ok else 1)

"""Offline checks of packet and runtime-row identities; no model or network."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parents[1]
STAGE = HERE.parent


def run_profile(build, code):
    env = dict(os.environ, PORT_MAP=str(STAGE / 'ctl_timing_01/evidence' / build / 'response_only.inputs.json'))
    script = 'import sys; sys.path.insert(0, %r)\n' % str(HERE) + code
    result = subprocess.run([sys.executable, '-c', script], env=env, text=True, capture_output=True)
    if result.returncode:
        raise AssertionError(result.stderr)
    return json.loads(result.stdout)


class EndpointProfileTests(unittest.TestCase):
    def test_failed_relay_controls_preserve_bytes_without_success_authority(self):
        result = run_profile('m12p_c37_sdk9132', r'''
import json
import model_packets as m
items=[]
for statuses,iin in [((1,0),b'\x00\x00'),((0,1),b'\x00\x00'),((1,2),b'\x00\x00'),((0,0),b'\x00\x01')]:
    native=m.rp.relay_control_frame(response=True,statuses=statuses,iin=iin)
    image=m.encode61.ctl61(native)
    assert image is not None, 'failed response must still be faithfully delivered'
    info=m.validate_control_image(m.control_request(),native,image,require_success=False)
    items.append([info['native_len'],info['image_len'],info['authorizes_or_succeeds']])
native=m.rp.relay_control_frame(response=True)
bad_crc=bytearray(native);bad_crc[-1]^=1
head,user=m.std.deframe(native);user=user[:9]+b'\x02'+user[10:]
bad_point=m.std.frame(head,user)
print(json.dumps(dict(items=items,read_growth=m.READ_GROWTH,
    crc_rejected=m.encode61.ctl61(bytes(bad_crc)) is None,
    point_rejected=m.encode61.ctl61(bad_point) is None)))
''')
        self.assertEqual(result['items'], [[49, 60, False]] * 4)
        self.assertEqual(result['read_growth'], 50)
        self.assertTrue(result['crc_rejected'])
        self.assertTrue(result['point_rejected'])

    def test_timestamp_profile_has_native_options_and_dynamic_payload_offsets(self):
        result = run_profile('m12p_c37_sdk9132', '''
import json
import model_repeat as r
import model_packets as m
v=r.vectors; ts=(0x12345678, 0x23456789)
q=r.rp.read_frames()[0]; native=r.rp.read_frames()[1]
frames=[v.packet(2,100,mss=1460,timestamps=(ts[0],0)),
        v.packet(18,900,101,reverse=True,mss=1460,timestamps=ts),
        v.packet(24,101,901,payload=q,timestamps=ts),
        v.packet(24,901,126,reverse=True,payload=native,timestamps=ts),
        v.packet(24,901,126,reverse=True,payload=r.encode61.read61(native),timestamps=ts),
        v.packet(16,126,1042,timestamps=ts)]
for f in frames:m.assert_ip_tcp(f)
changed=m.mutate_payload(frames[3], native[:-1]+bytes([native[-1]^1]))
m.assert_ip_tcp(changed)
bad_tcp=bytearray(frames[3]); bad_tcp[50]^=1
qctl=r.rp.relay_control_frame(); nctl=r.rp.relay_control_frame(response=True)
ctl=[v.packet(24,101,payload=qctl,timestamps=ts),v.packet(24,901,reverse=True,payload=nctl,timestamps=ts),
     v.packet(24,901,reverse=True,payload=r.encode61.ctl61(nctl),timestamps=ts)]
full=r.rp.read_frames(cls='integrity')[1]
full_packets=[v.packet(24,901,reverse=True,payload=x,timestamps=ts) for x in (full,r.encode61.read61(full))]
other=v.packet(16,1,timestamps=(99,88))
mapped=r.rp.preserve_options(frames[3],v.packet(24,9999,777,reverse=True,payload=r.encode61.read61(native),timestamps=(55,44)))
m.assert_ip_tcp(mapped)
print(json.dumps(dict(headers=[(f[46]>>4)*4 for f in frames],
    ip_lengths=[int.from_bytes(f[16:18],'big') for f in frames],
    options=[f[54:14+20+(f[46]>>4)*4].hex() for f in frames],
    payload=m.tcp_payload(changed).hex(), expected=(native[:-1]+bytes([native[-1]^1])).hex(),
    mutated_options=changed[54:66].hex(),
    mutated_identity=changed[:12].hex()+changed[26:34].hex(),
    invalid_dnp=not m.wire_check.dnp3_ok(m.tcp_payload(changed))[0],
    invalid_tcp=not m.wire_check.ip_tcp_checksum({'frame':bytes(bad_tcp)})[1],
    ctl_lengths=[int.from_bytes(f[16:18],'big') for f in ctl],
    full_lengths=[int.from_bytes(f[16:18],'big') for f in full_packets],
    preserved_timestamp=r.rp.timestamp_values(mapped),
    abort_references=[r.rp.abort_reference_len('READ'),r.rp.abort_reference_len('SELECT')],
    order_good=r.rp.timestamp_order_ok([v.packet(16,1,timestamps=(1,0)),v.packet(16,1,timestamps=(2,0))]),
    order_bad=r.rp.timestamp_order_ok([v.packet(16,1,timestamps=(2,0)),v.packet(16,1,timestamps=(1,0))]),
    scaled=r.rp.reverse_window(2,141,91))))
''')
        self.assertEqual(result['headers'], [40, 44, 32, 32, 32, 32])
        self.assertEqual(result['ip_lengths'], [60, 64, 77, 143, 193, 52])
        self.assertEqual(result['options'][0], '020405b40402080a123456780000000001030307')
        self.assertEqual(result['options'][1], '020405b401030300010104020101080a1234567823456789')
        self.assertEqual(result['options'][2:], ['0101080a1234567823456789'] * 4)
        self.assertEqual(result['payload'], result['expected'])
        self.assertEqual(result['mutated_options'], result['options'][3])
        self.assertEqual(result['mutated_identity'], '3cfdfecc5dc00030a7024ca2c0a80a07c0a80a01')
        self.assertTrue(result['invalid_dnp'])
        self.assertTrue(result['invalid_tcp'])
        self.assertEqual(result['ctl_lengths'], [97, 101, 112])
        self.assertEqual(result['full_lengths'], [186, 210])
        self.assertEqual(result['preserved_timestamp'], [0x12345678, 0x23456789])
        self.assertEqual(result['abort_references'], [91, 49])
        self.assertTrue(result['order_good'])
        self.assertFalse(result['order_bad'])
        self.assertEqual(result['scaled'], 1)

    def test_sel751_packets_and_runtime_rows_use_physical_identities(self):
        result = run_profile('m12p_c32_sdk9132', '''
import json
import model_repeat as r
v = r.vectors
r.rp.configure_helpers(r.helpers)  # Repeat configuration must not nest packet wrappers.
frames = [v.packet(16, 101, 901), v.packet(16, 901, 101, reverse=True)]
rows = r.cp.n_read_rows(r.RELAY, r.MASTER)
report = r.Report('offline')
r.rp.report_endpoint(report)
import model_packets as mp
for packet in frames: mp.assert_ip_tcp(packet)
print(json.dumps(dict(packets=[x.hex() for x in frames],
    endpoints=[[e.ip, e.port, e.dev_port] for e in (r.MASTER, r.RELAY)],
    rows=[dict(key=dict(x[1]), data=dict(x[3])) for x in rows],
    links=[r.rp.read_frames()[0][4:8].hex(), r.rp.read_frames()[1][4:8].hex()],
    meta=report.record['meta'])))
''')
        forward, reverse = map(bytes.fromhex, result['packets'])
        self.assertEqual(forward[:12].hex(), '0030a7024ca23cfdfecc5dc0')
        self.assertEqual(reverse[:12].hex(), '3cfdfecc5dc00030a7024ca2')
        self.assertEqual(forward[26:34], bytes((192, 168, 10, 1, 192, 168, 10, 7)))
        self.assertEqual(reverse[26:34], bytes((192, 168, 10, 7, 192, 168, 10, 1)))
        self.assertEqual(int.from_bytes(forward[34:36], 'big'), 59410)
        self.assertEqual(forward[46] >> 4, 5)  # Historical sel751 clean replay remains TCP20.
        self.assertEqual(result['endpoints'], [['192.168.10.1', 59410, 9], ['192.168.10.7', 20000, 64]])
        self.assertEqual(result['rows'][0]['key']['hdr.ip.src'], int.from_bytes(forward[26:30], 'big'))
        self.assertEqual(result['rows'][0]['key']['hdr.tcp.sport'], 59410)
        self.assertEqual(result['rows'][0]['data'], {'dst': 0, 'src': 256})
        self.assertEqual(result['rows'][1]['data'], {'dst': 256, 'src': 0})
        self.assertEqual(result['links'], ['00000100', '01000000'])
        self.assertEqual(result['meta']['endpoint_profile']['master_tcp_port'], 59410)

    def test_legacy_packet_fixture_stays_unchanged(self):
        result = run_profile('m12p_c30_sdk9132', '''
import json
import model_repeat as r
print(json.dumps(dict(packet=r.vectors.packet(16, 101, 901).hex())))
''')
        packet = bytes.fromhex(result['packet'])
        self.assertEqual(packet[:12].hex(), '001122334455aabbccddeeff')
        self.assertEqual(packet[26:34], bytes((10, 0, 0, 1, 10, 0, 0, 2)))
        self.assertEqual(int.from_bytes(packet[34:36], 'big'), 30001)

    def test_boundary_schedule_uses_selected_templates_for_c30_and_sel751(self):
        # c30 has relay READ91/134 but legacy SBO37/61: READ shape selection
        # must be independent of the endpoint's control admission profile.
        for build, control in [('m12p_c30_sdk9132', 61), ('m12p_c32_sdk9132', 60)]:
            with self.subTest(build=build):
                result = run_profile(build, '''
import json
import model_policy as p
class FakeGate:
    def __init__(self): self.bounds=[]; self.commits=[]; self.c5=[]
    def handshake(self, c, n, tag): return c+1, n+1, n+1
    def close(self, *args): pass
    def _bound(self, label, c, w, size): self.bounds.append([label, size])
    def _retire(self, *args): pass
    def _commit_two(self, c, n, w, tag, cls, seq=0):
        item=p.TWO_TEMPLATES['v0']['classes'][cls]
        q, native=bytes.fromhex(item['request']), bytes.fromhex(item['native'])
        size=p.mp.rp.SHAPES[len(native)]['target']; self.commits.append(cls)
        return c+len(q), n+len(native), w+size, w, size
    def _commit_sbo(self, c, n, w, tag):
        size=p.mp.IMAGE_LEN
        return c+p.mp.CONTROL_REQUEST, n+p.mp.CONTROL_NATIVE, w+size, w, size
    def c5_two(self, cls, seq, isn): self.c5.append(cls)
g=FakeGate(); p.PolicyBoundaryGate.run_two(g)
print(json.dumps(dict(bounds=g.bounds, commits=g.commits, c5=g.c5)))
''')
                self.assertEqual(result['bounds'][:3], [['READ141', 141], ['READ158', 158], ['SBO%d' % control, control]])
                self.assertEqual(len(result['bounds']), 12)
                self.assertEqual(result['c5'], ['mixed', 'integrity'])
                self.assertIn('mixed', result['commits'])
                self.assertIn('integrity', result['commits'])


if __name__ == '__main__':
    unittest.main()

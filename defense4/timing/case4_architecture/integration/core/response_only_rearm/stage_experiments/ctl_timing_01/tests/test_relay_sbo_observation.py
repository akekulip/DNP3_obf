"""Adversarial offline checks for observed SBO bytes and accounting, without a model."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parents[1]


def probe(code):
    env = dict(os.environ, PORT_MAP=str(HERE / 'evidence/m12p_c37_sdk9132/response_only.inputs.json'))
    setup = 'import sys;sys.path.insert(0,%r)\nimport model_relay_sbo as d\nimport model_repeat as r\n' % str(HERE)
    result = subprocess.run([sys.executable, '-c', setup + code], env=env, text=True, capture_output=True)
    if result.returncode:
        raise AssertionError(result.stderr)
    return json.loads(result.stdout)


class RelayObservationTests(unittest.TestCase):
    def test_observed_control_bytes_must_match_native_even_with_valid_reframing(self):
        result = probe('''
import json
native=d.control_frame(63,15,response=True)
image=d.control_image(native)
packet=r.vectors.packet(24,100,200,reverse=True,payload=image)
info=d.verify_control_delivery(native,packet)
frames=d.mp.rp.split_frames(image)
head,user=d.mp.std.deframe(frames[1]);user=user[:-1]+bytes([user[-1]^1])
altered=frames[0]+d.mp.std.frame(head,user)
bad=r.vectors.packet(24,100,200,reverse=True,payload=altered)
rejected=False
try:d.verify_control_delivery(native,bad)
except AssertionError:rejected=True
bad_checksum=bytearray(packet);bad_checksum[50]^=1
checksum_rejected=False
try:d.verify_control_delivery(native,bytes(bad_checksum))
except AssertionError:checksum_rejected=True
print(json.dumps(dict(info=info,rejected=rejected,checksum_rejected=checksum_rejected)))
''')
        self.assertEqual(result['info']['application_octets'], 32)
        self.assertEqual(result['info']['frames'], [28, 32])
        self.assertTrue(result['rejected'])
        self.assertTrue(result['checksum_rejected'])

    def test_double_growth_and_commit_cannot_pass_a_logical_response(self):
        result = probe('''
import json
before=dict(commit=7,replay=3,growth=50)
d.verify_encoding_effect(before,dict(commit=8,replay=3,growth=61))
d.verify_encoding_effect(dict(commit=8,replay=3,growth=61),dict(commit=8,replay=4,growth=61),commits=0,replays=1,growth=0)
bad=[]
for after in [dict(commit=9,replay=3,growth=72),dict(commit=8,replay=3,growth=72),dict(commit=7,replay=3,growth=61)]:
    try:d.verify_encoding_effect(before,after)
    except AssertionError:bad.append(after)
print(json.dumps(dict(rejected=len(bad))))
''')
        self.assertEqual(result['rejected'], 3)

    def test_partial_ack_cannot_advance_native_frontier_or_change_timestamp(self):
        result = probe('''
import json
passed=0;rejected=0
for offset in (28,29,59):
    sent=r.vectors.packet(16,100,900+offset,timestamps=(123,456))
    correct=bytearray(sent);correct[42:46]=(800).to_bytes(4,'big')
    correct[48:50]=((4096*128+49-(60-offset))//128).to_bytes(2,'big')
    correct=d.mp.fix_checksums(bytes(correct))
    d.verify_partial_ack(sent,correct,800,900);passed+=1
    wrong=bytearray(correct);wrong[42:46]=(800+offset).to_bytes(4,'big')
    try:d.verify_partial_ack(sent,d.mp.fix_checksums(bytes(wrong)),800,900)
    except AssertionError:rejected+=1
print(json.dumps(dict(passed=passed,rejected=rejected)))
''')
        self.assertEqual(result, {'passed': 3, 'rejected': 3})


if __name__ == '__main__':
    unittest.main()

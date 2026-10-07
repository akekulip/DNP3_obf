"""Packet-driven source checks for the new N candidate, not target execution."""
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
ARCH = HERE.parents[3]
sys.path.insert(0, str(ARCH / 'integration/core/harness'))
from driver import Pipeline
import vectors


class NativeHandoff(unittest.TestCase):
    def pipeline(self):
        return Pipeline.from_path(HERE.parent / 'n.p4', vectors.topology())

    def establish(self, pipe, client=100):
        for port, frame in (
            (1, vectors.packet(2, client, mss=1500)),
            (2, vectors.packet(18, 900, client + 1, reverse=True, mss=1500)),
            (1, vectors.packet(16, client + 1, 901)),
        ):
            out = pipe.inject(port, frame)
            self.assertFalse(out.dropped, out.drop_reason)
            self.assertEqual(out.emitted, [(3-port, frame)])
        return (client + 1) & 0xffffffff

    def test_actual_handshake_select_hands_to_m_with_pin_and_no_endpoint_copy(self):
        for initial in (100, 0xffffffff, 0xfffffff0):
            with self.subTest(initial=initial):
                pipe = self.pipeline()
                start = self.establish(pipe, initial)
                raw = vectors.packet(24, start, 901, payload=vectors.native_select())
                out = pipe.inject(1, raw)
                self.assertFalse(out.dropped, out.drop_reason)
                self.assertEqual(len(out.emitted), 1)
                port, handoff = out.emitted[0]
                self.assertEqual(port, 196)
                self.assertEqual(handoff[12:16], bytes.fromhex('03050000'))
                self.assertEqual(handoff[28:], raw)
                state = pipe.state()
                self.assertEqual(state['work']['phase'], 5)
                self.assertEqual(int.from_bytes(handoff[0:4], 'big'), state['epoch'])
                self.assertEqual(int.from_bytes(handoff[4:8], 'big'), state['work']['generation'])
                self.assertEqual(int.from_bytes(handoff[8:12], 'big'), state['owner'])
                index,code,repeat,on,off = vectors.decoy_config()
                expected = index.to_bytes(2,'big')+bytes((code,repeat))+on.to_bytes(4,'big')+off.to_bytes(4,'big')
                self.assertEqual(handoff[16:28], expected)
                before = pipe.state()
                duplicate = pipe.inject(68, handoff)
                self.assertTrue(duplicate.dropped)
                self.assertEqual(duplicate.emitted, [])
                self.assertEqual(pipe.state(), before)

    def test_decoy_snapshot_survives_configuration_change_during_n_returns(self):
        pipe = self.pipeline()
        start = self.establish(pipe)
        raw = vectors.packet(24, start, 901, payload=vectors.native_select())
        original = vectors.decoy_config()
        _, result, reason = pipe.run_pass(1, 1, raw)
        self.assertIsNone(reason)
        self.assertEqual(result[0], 68)
        pipe.src.controls['Ingress'].tables['data_connection']['runtime'].clear()
        for *tuple4, _direction, _port in vectors.topology().flows:
            pipe.src.install('data_connection',tuple4,'configure',(202,2,2,77,88))
        out = pipe.inject(68,result[1])
        self.assertFalse(out.dropped,out.drop_reason)
        self.assertEqual(out.emitted[0][0],196)
        index,code,repeat,on,off = original
        expected=index.to_bytes(2,'big')+bytes((code,repeat))+on.to_bytes(4,'big')+off.to_bytes(4,'big')
        self.assertEqual(out.emitted[0][1][16:28],expected)


if __name__ == '__main__': unittest.main()

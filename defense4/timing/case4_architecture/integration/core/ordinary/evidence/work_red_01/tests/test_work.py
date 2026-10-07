"""Execute actual candidate Work SALU source; no Python state-machine oracle."""
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / 'integration/core/harness'))
from interp_ext import ExtSource


WRAPPER = '''
struct headers_t{} struct meta_t{bit<8> op;bit<32> gen;bit<32> phase;bit<32> result;}
parser IgParser(packet_in pkt,out headers_t hdr,inout meta_t m){state start{transition accept;}}
control IgDeparser(packet_out pkt,inout headers_t hdr){apply{}}
control Ingress(inout headers_t hdr,inout meta_t m){ExpectedWorkRecord() work;
 apply{work.apply(m.op,m.gen,m.phase,m.result);}}
'''


class WorkLifetime(unittest.TestCase):
    def setUp(self):
        self.src = ExtSource((HERE.parent / 'work_record.p4').read_text() + WRAPPER)

    def step(self, op, generation, phase=0):
        self.src.begin_pass(1)
        self.src.env.update({'m.op': op, 'm.gen': generation, 'm.phase': phase})
        self.src.apply_control('Ingress')
        return self.src.env['m.result']

    def state(self):
        return dict(self.src.cells[('work', 'work')][0])

    def pending(self):
        self.assertEqual(self.step(1, 9), 4)
        self.assertEqual(self.step(2, 9, 1), 1)
        self.assertEqual(self.step(2, 9, 2), 2)
        self.assertEqual(self.step(3, 9, 3), 3)
        self.assertEqual(self.state(), {'generation': 9, 'phase': 5})

    def test_handoff_pins_until_genuine_ready_and_completion(self):
        self.pending()
        self.assertEqual(self.step(1, 10), 5)
        self.assertEqual(self.step(3, 9, 5), 5)
        self.assertEqual(self.state()['phase'], 6)
        self.assertEqual(self.step(1, 10), 6)
        self.assertEqual(self.step(3, 9, 6), 6)
        self.assertEqual(self.state()['phase'], 4)
        self.assertEqual(self.step(1, 10), 4)

    def test_duplicate_handoff_ready_and_foreign_completion_do_not_advance(self):
        self.pending()
        before = self.state()
        for op, generation, phase in ((3, 9, 3), (3, 8, 5), (3, 9, 6)):
            self.assertEqual(self.step(op, generation, phase), 0)
            self.assertEqual(self.state(), before)
        self.assertEqual(self.step(3, 9, 5), 5)
        before = self.state()
        for generation, phase in ((9, 5), (8, 6), (10, 6)):
            self.assertEqual(self.step(3, generation, phase), 0)
            self.assertEqual(self.state(), before)

    def test_normal_handshake_terminal_remains_phase_three_to_free(self):
        self.step(1, 9)
        self.step(2, 9, 1)
        self.step(2, 9, 2)
        self.assertEqual(self.step(2, 9, 3), 3)
        self.assertEqual(self.state()['phase'], 4)


if __name__ == '__main__':
    unittest.main()

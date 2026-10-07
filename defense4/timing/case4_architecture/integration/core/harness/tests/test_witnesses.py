"""The four retained step-1 witnesses, run whole-program through the source interpreter.

History: on source 35bf9aa3... (step-1 commit 78a0b50da) the network table had no row for private
kind 8, so each witness was forwarded on pass 1, recirculated as event 0x01_08 and DENIED on pass 2
at the network miss. The restructured generator adds kind-8 rows (flags 2, 18, 16), and the
acceptance test below now passes for real on the repository source.
"""
import unittest

import support
from driver import Pipeline
import vectors
import reference

# label, flags, seq, ack, reverse, mss, owner, client register, server register
WITNESSES = (
    ('lost_SYN_native_retry', 2, 100, 0, False, 1500, 0x20001, 101, 0),
    ('lost_SYNACK_native_retry', 18, 900, 101, True, 1500, 0x40001, 101, 901),
    ('lost_final_ACK_native_retry', 16, 101, 901, False, None, 0x50001, 101, 901),
    ('established_client_ACK', 16, 136, 958, False, None, 0x90001, 136, 958),
)


def run(witness, text=None):
    label, flags, seq, ack, reverse, mss, owner, client, server = witness
    raw = vectors.frame(flags, seq, ack, reverse, mss)
    pipe = Pipeline(text or vectors.source_text(), vectors.topology(), include_dir=vectors.SOURCE_PATH.parent)
    pipe.preset(owner=owner, client=client, server=server, epoch=17)
    before = pipe.state()
    return raw, before, pipe, pipe.inject(2 if reverse else 1, raw)


class Witnesses(unittest.TestCase):
    def check_forwarded(self, text=None):
        for witness in WITNESSES:
            with self.subTest(witness[0]):
                raw, before, pipe, out = run(witness, text)
                self.assertFalse(out.dropped, out.drop_reason)
                self.assertEqual(out.passes, 4)
                self.assertEqual(out.emitted, [(1 if witness[4] else 2, raw)])
                self.assertEqual(pipe.state()['owner'], witness[6])
                self.assertEqual(pipe.state()['owner'], before['owner'])

    def test_acceptance_repository_source_forwards_each_witness_unchanged(self):
        self.check_forwarded()

    def test_witness_frames_are_valid_by_the_independent_oracle(self):
        for label, flags, seq, ack, reverse, mss, *_ in WITNESSES:
            packet = reference.parse_packet(vectors.frame(flags, seq, ack, reverse, mss))
            self.assertEqual((packet.flags, packet.seq, packet.ack), (flags, seq, ack))


if __name__ == '__main__':
    unittest.main()

"""The four retained step-1 witnesses, run whole-program through the source interpreter.

Finding (2026-10-06, source sha256 35bf9aa3...): on the repository source the network table has
no row for private kind 8 (the nonmutating forward event added by 78a0b50da), so each witness is
forwarded on pass 1, recirculated as event 0x01_08, and DENIED on pass 2 at the network miss
(`else if(m.stage!=8w0){deny();}`). The source-fragment tests that accompanied that change never
apply `network`, so they cannot see it. Three tests below record this:
  * the acceptance criterion as specified (forward unchanged in 4 passes) is expectedFailure on
    the repository source and will flip to an unexpected success when the source is repaired;
  * the observed drop is pinned so a change in behaviour is noticed either way;
  * an in-memory copy with ONE added network row for kind 8 meets the acceptance criterion,
    which shows that missing row is the only blocker. That copy is hypothetical, not the repo.
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
KIND8_ROW = '(8w1,8w8,_,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();'


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

    @unittest.expectedFailure
    def test_acceptance_repository_source_forwards_each_witness_unchanged(self):
        self.check_forwarded()

    def test_repository_source_currently_denies_each_witness_at_pass_2_network_miss(self):
        for witness in WITNESSES:
            with self.subTest(witness[0]):
                raw, before, pipe, out = run(witness)
                self.assertTrue(out.dropped)
                self.assertEqual(out.emitted, [])
                self.assertEqual(out.passes, 2)
                self.assertIn('pass 2: drop_ctl set by deny()', out.drop_reason)
                self.assertIn('stage=1', out.drop_reason)
                self.assertTrue(any('table network -> NoAction (default)' in e and ', 8, ' in e
                                    for e in out.trace[1]))
                self.assertEqual(pipe.state()['owner'], before['owner'])

    def test_one_added_kind8_network_row_would_forward_all_four_unchanged(self):
        text = vectors.source_text()
        marker = '(8w1,8w255,_,false'
        self.assertEqual(text.count(marker), 1)
        self.check_forwarded(text.replace(marker, KIND8_ROW + marker))

    def test_witness_frames_are_valid_by_the_independent_oracle(self):
        for label, flags, seq, ack, reverse, mss, *_ in WITNESSES:
            packet = reference.parse_packet(vectors.frame(flags, seq, ack, reverse, mss))
            self.assertEqual((packet.flags, packet.seq, packet.ack), (flags, seq, ack))


if __name__ == '__main__':
    unittest.main()

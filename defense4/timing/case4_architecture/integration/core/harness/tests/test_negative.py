"""Negative cases. Documents the ACTUAL behaviour of the repository source at the source level."""
import unittest

import support
from driver import Pipeline
import vectors


def pipeline(owner, client, server, **kwargs):
    pipe = Pipeline.from_path(vectors.SOURCE_PATH, vectors.topology(), **kwargs)
    pipe.preset(owner=owner, client=client, server=server, epoch=17)
    return pipe


class Passthrough(unittest.TestCase):
    """Frames the stage-0 network/connection/data guards reject are NOT dropped: ports.route
    still forwards them to the routed port, byte-identical, in one pass, with no state change."""

    def check(self, port, raw, owner, client, server, expected_port=None):
        pipe = pipeline(owner, client, server)
        before = pipe.state()
        out = pipe.inject(port, raw)
        self.assertFalse(out.dropped, out.drop_reason)
        self.assertEqual(out.passes, 1)
        self.assertEqual(out.emitted, [(expected_port or vectors.IN_SERVER, raw)])
        self.assertEqual(pipe.state(), before)
        return out

    def test_bad_ip_checksum(self):
        raw = bytearray(vectors.packet(16, 136, 958))
        raw[24] ^= 1
        out = self.check(1, bytes(raw), 0x90001, 136, 958)
        self.assertIn('table network -> NoAction (default)', '\n'.join(out.trace[0]))

    def test_bad_tcp_checksum(self):
        raw = bytearray(vectors.packet(16, 136, 958))
        raw[50] ^= 1
        out = self.check(1, bytes(raw), 0x90001, 136, 958)
        self.assertIn('table network -> NoAction (default)', '\n'.join(out.trace[0]))

    def test_bad_dnp3_crc_in_select(self):
        select = bytearray(vectors.native_select())
        select[26] ^= 1
        raw = vectors.packet(24, 101, 901, payload=bytes(select))
        out = self.check(1, raw, 0x40001, 101, 901)
        self.assertIn('table guard -> NoAction (default)', '\n'.join(out.trace[0]))

    def test_wrong_tuple_passes_untouched_at_stage_0(self):
        raw = vectors.packet(16, 136, 958, tuple4=(vectors.CLIENT, vectors.SERVER, 30002, 20000))
        out = self.check(1, raw, 0x90001, 136, 958)
        self.assertIn('table connection -> NoAction (default)', '\n'.join(out.trace[0]))

    def test_unparsed_ethertype_passes_untouched_at_stage_0(self):
        raw = bytearray(vectors.packet(16, 136, 958))
        raw[12:14] = b'\x08\x06'
        out = self.check(1, bytes(raw), 0x90001, 136, 958)
        self.assertIn('m.parsed=0', '\n'.join(out.trace[0]))

    def test_unrouted_ingress_port_is_denied(self):
        pipe = pipeline(0x90001, 136, 958)
        out = pipe.inject(9, vectors.packet(16, 136, 958))
        self.assertTrue(out.dropped)
        self.assertEqual(out.emitted, [])
        self.assertIn('deny()', out.drop_reason)


class Duplicate(unittest.TestCase):
    def test_out_of_sequence_duplicate_is_dropped_and_owner_is_unchanged(self):
        pipe = pipeline(0x90001, 136, 958)
        before = pipe.state()
        out = pipe.inject(1, vectors.packet(16, 101, 901))     # old ACK, client expects 136
        self.assertTrue(out.dropped)
        self.assertEqual(out.emitted, [])
        self.assertIn('deny()', out.drop_reason)
        after = pipe.state()
        for key in ('owner', 'client', 'server', 'epoch'):
            self.assertEqual(after[key], before[key], key)
        # A work generation was minted and returned; the free phase is restored.
        self.assertEqual(after['work']['phase'], 4)
        self.assertEqual(after['counter'], before['counter'] + 1)
        self.assertEqual(out.passes, 4)
        self.assertTrue(any('m.kind=255' in e for e in out.trace[1]))


class Truncated(unittest.TestCase):
    def test_truncated_tcp_header_is_a_parser_error_drop(self):
        pipe = pipeline(0x90001, 136, 958)
        before = pipe.state()
        out = pipe.inject(1, vectors.packet(16, 136, 958)[:40])
        self.assertTrue(out.dropped)
        self.assertIn('parser error: truncated extract of hdr.tcp', out.drop_reason)
        self.assertEqual(out.passes, 1)
        self.assertEqual(pipe.state(), before)

    def test_truncated_select_payload_is_a_parser_error_drop(self):
        raw = vectors.packet(24, 101, 901, payload=vectors.native_select())[:70]
        pipe = pipeline(0x40001, 101, 901)
        before = pipe.state()
        out = pipe.inject(1, raw)
        self.assertTrue(out.dropped)
        self.assertIn('truncated extract of hdr.first', out.drop_reason)
        self.assertEqual(pipe.state(), before)

    def test_continue_policy_forwards_the_truncated_bytes_untouched(self):
        # If the target continued after a parser error (unverified), the program itself
        # treats an unparsed packet as stage-0 passthrough.
        raw = vectors.packet(16, 136, 958)[:40]
        pipe = pipeline(0x90001, 136, 958, on_parser_error='continue')
        out = pipe.inject(1, raw)
        self.assertEqual(out.emitted, [(vectors.IN_SERVER, raw)])


class Recirculation(unittest.TestCase):
    def test_epoch_zero_register_no_longer_produces_an_endless_loop(self):
        # Was: "epoch-zero envelope never terminates" (the snapshot copied the power-on epoch 0 into the
        # envelope, the parser accepted early, and the packet looped on port 68 for ever). The epoch
        # register now reads as a nonzero sentinel while it is 0, so the packet
        # is bounded: here a valid established ACK is forwarded unchanged and WorkRecord is released.
        pipe = pipeline(0x90001, 136, 958)
        pipe.preset(epoch=0)
        raw = vectors.packet(16, 136, 958)
        out = pipe.inject(1, raw)
        self.assertNotIn('recirculation limit', out.drop_reason or '')
        self.assertLessEqual(out.passes, 4)
        # An established ACK is a valid transparent forward (kind 8 takes no epoch): forwarded unchanged.
        self.assertEqual(out.emitted, [(vectors.IN_SERVER, raw)])
        self.assertEqual(pipe.state()['work']['phase'], 4)


if __name__ == '__main__':
    unittest.main()

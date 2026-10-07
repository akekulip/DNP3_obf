"""Native 35-byte SELECT coalesced after the final handshake ACK."""
import unittest

import support
from driver import Pipeline
import vectors
import reference
import case4_padding


def pipeline(owner, client, server, epoch=17):
    pipe = Pipeline.from_path(vectors.SOURCE_PATH, vectors.topology())
    pipe.preset(owner=owner, client=client, server=server, epoch=epoch)
    return pipe


class NativeSelect(unittest.TestCase):
    def setUp(self):
        self.select = vectors.native_select()
        self.raw = vectors.packet(24, 101, 901, payload=self.select)

    def test_vector_is_the_independent_oracle_35_byte_select(self):
        self.assertEqual(len(self.select), 35)
        packet = reference.parse_packet(self.raw)
        self.assertEqual((packet.flags, packet.seq, packet.ack, packet.payload), (24, 101, 901, self.select))
        self.assertEqual(reference._select(packet.payload)[3:8], bytes.fromhex('0c01280100'))
        self.assertEqual(len(case4_padding.decode_frame(self.select)[1]), 21)

    def test_forwarded_unchanged_and_owner_advances_phase4_to_phase9(self):
        pipe = pipeline(0x40001, 101, 901)
        out = pipe.inject(vectors.IN_CLIENT, self.raw)
        self.assertFalse(out.dropped, out.drop_reason)
        self.assertEqual(out.passes, 4)
        self.assertEqual(out.emitted, [(vectors.IN_SERVER, self.raw)])
        state = pipe.state()
        # Source: claim_select -> phase 8, publish_select -> phase 9, generation 1 kept.
        self.assertEqual(state['owner'], 0x90001)
        # Oracle: client_next advances by the 35 native bytes; server position and epoch unchanged.
        oracle = reference.Connection(
            (vectors.CLIENT, vectors.SERVER, vectors.CLIENT_PORT, vectors.SERVER_PORT), allowed_ports={1})
        oracle.client_next, oracle.server_next, oracle.cell, oracle.generation = 101, 901, 4 << 16 | 1, 1
        envelope = oracle.begin(self.raw, 1)
        for _ in range(3):
            envelope = oracle.advance(envelope)
        self.assertEqual(envelope.outcome, 'forward')
        self.assertEqual(state['client'], oracle.client_next)
        self.assertEqual(state['client'], 101 + 35)
        self.assertEqual(state['server'], 901)
        self.assertEqual(state['epoch'], 17)

    def test_work_record_returns_to_free_phase_and_a_generation_was_minted(self):
        pipe = pipeline(0x40001, 101, 901)
        pipe.inject(vectors.IN_CLIENT, self.raw)
        self.assertEqual(pipe.state()['work'], {'generation': 1, 'phase': 4})
        self.assertEqual(pipe.state()['counter'], 1)

    def test_select_is_also_admitted_at_final_ack_owner_phase_5(self):
        pipe = pipeline(0x50001, 101, 901)
        out = pipe.inject(vectors.IN_CLIENT, self.raw)
        self.assertEqual(out.emitted, [(vectors.IN_SERVER, self.raw)])
        self.assertEqual(pipe.state()['owner'], 0x90001)

    def test_select_trace_shows_the_data_path_tables(self):
        out = pipeline(0x40001, 101, 901).inject(vectors.IN_CLIENT, self.raw)
        pass1 = '\n'.join(out.trace[0])
        for text in ('table data_connection -> configure (runtime)', 'table profile -> eligible',
                     'table guard -> go_new', 'table first_event -> first_select'):
            self.assertIn(text, pass1)


if __name__ == '__main__':
    unittest.main()

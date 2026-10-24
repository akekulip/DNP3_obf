"""Retain E's exact77/89 guards while consuming IP matches before timestamps."""
import hashlib
import re
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import ExitStack

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from m12gen import relay_ts, relay_sbo
from m12gen.build import build
import test_n_read_shapes as shared
import test_relay_ts as ts


class EgressLengthOrder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with ExitStack() as patches:
            patches.enter_context(patch.object(relay_sbo, 'retry_fin_phase', side_effect=lambda src: src))
            patches.enter_context(patch.object(relay_sbo, 'half_closed_rst', side_effect=lambda src: src))
            patches.enter_context(patch.object(relay_sbo, 'canonical_profile_keys', side_effect=lambda src: src))
            patches.enter_context(patch.object(relay_sbo, 'relay_departure_provenance', side_effect=lambda src: src))
            for name in ('stream_handshake_options', 'padder_crc_placement'):
                patches.enter_context(patch.object(relay_ts, name, side_effect=lambda src: src))
            with patch.object(relay_ts, 'early_egress_lengths', side_effect=lambda src: src):
                cls.original, _ = build(**ts.FLAGS, relay_ts=True)
            cls.selected, _ = build(**ts.FLAGS, relay_ts=True)

    def test_scope_and_no_parser_ip_length_use_after_any_timestamp_branch(self):
        self.assertEqual(hashlib.sha256(self.original.encode()).hexdigest(),
                         '19c54773901e5cc21162e198173df5694a232f57030b288c1486be49f633acd0')
        for role in ('N', 'T'):
            self.assertEqual(shared.role(self.original, role), shared.role(self.selected, role))
        old, new = shared.role(self.original, 'E'), shared.role(self.selected, 'E')
        self.assertEqual(old[:old.index('parser EgParser(')], new[:new.index('parser EgParser(')])
        self.assertEqual(old[old.index('control Egress('):], new[new.index('control Egress('):])
        before, after = shared.interp.ESource(old), shared.interp.ESource(new)
        changed = {'tcp', 'ts12', 'dl_len', 'dl'}
        self.assertEqual(set(after.pstates) - set(before.pstates), {'ctl_len', 'ts12_short', 'ts12_mid', 'dl_mid'})
        for state in before.pstates.keys() - changed:
            self.assertEqual(before.pstates[state], after.pstates[state], state)
        def successors(state):
            tr = after.pstates[state][1]
            return [tr[1]] if tr[0] == 'goto' else [target for _, target in tr[2]]
        for root, destination in (('ts12', 'dl'), ('ts12_mid', 'dl_mid'), ('ts12_short', 'accept')):
            statements, transition = after.pstates[root]
            self.assertEqual(statements, before.pstates['ts12'][0])
            self.assertEqual(transition[1], before.pstates['ts12'][1][1])
            self.assertEqual(transition[2][-1][1], 'tcp_odd')
            self.assertEqual(transition[2][0][1], destination)
            pending, visited = [root], set()
            while pending:
                state = pending.pop()
                if state in ('accept', 'reject') or state in visited:
                    continue
                visited.add(state)
                self.assertNotIn("('name', 'hdr.ip.len')", repr(after.pstates[state]), state)
                pending.extend(successors(state))

    @staticmethod
    def route(parser, ip_length, dl_length, prefix=0x0101080a):
        parser.env.update({'hdr.ip.len': ip_length, 'hdr.dl.len': dl_length,
                           'hdr.tcp.offset': 8, 'hdr.tso.a': prefix})
        parser.valid.update({name: True for name in ('ip', 'dl', 'tcp', 'tso')})
        state = 'tcp'
        for _ in range(12):
            if state in ('accept', 'tcp_odd', 'ctl_b0', 'read_pp', 'read_b0'):
                return state
            tr = parser.pstates[state][1]
            if tr[0] == 'goto':
                state = tr[1]
            else:
                values = [parser.ev(key)[0] for key in tr[1]]
                state = next(target for terms, target in tr[2]
                             if terms is None or all(parser.match(term, value) for term, value in zip(terms, values)))
        raise AssertionError('unbounded parser classification')

    def test_every16bit_ip_length_and_every_dl_class_at_boundaries_match(self):
        old = shared.interp.ESource(shared.role(self.original, 'E'))
        new = shared.interp.ESource(shared.role(self.selected, 'E'))
        for length in range(65536):
            a, b = self.route(old, length, 0x26), self.route(new, length, 0x26)
            self.assertEqual(a, b, length)
            self.assertEqual(b, 'ctl_b0' if length >= 89 else 'accept', length)
        for length in (0, 52, 76, 77, 78, 79, 80, 87, 88, 89, 90, 65535):
            for dl_length in range(256):
                self.assertEqual(self.route(old, length, dl_length), self.route(new, length, dl_length), (length, dl_length))
            for bit in range(32):
                prefix = 0x0101080a ^ (1 << bit)
                self.assertEqual(self.route(old, length, 0x26, prefix), 'tcp_odd')
                self.assertEqual(self.route(new, length, 0x26, prefix), 'tcp_odd')

    def test_full_packets_preserve_options_cursor_residual_fields_and_wire(self):
        old = shared.interp.ESource(shared.role(self.original, 'E'))
        new = shared.interp.ESource(shared.role(self.selected, 'E'))
        native = bytes.fromhex('05642644010000002f77d2cb8180000c011702010101c8000000e2170000000000030101c8000000000000008bf700ffff')
        cases = []
        boundaries = (0, 40, 51, 52, 53, 76, 77, 78, 79, 80, 87, 88, 89, 90, 100, 101, 143, 186, 65535)
        for length in boundaries:
            for dl_length in (0x26, 0x27, 0x11, 0x4c, 0x73, 0):
                payload = bytearray((native + bytes(max(0, length - 52)))[:max(0, length - 52)])
                if len(payload) >= 3:
                    payload[2] = dl_length
                raw = bytearray(ts.packet(bytes(payload), reverse=True))
                raw[16:18] = struct.pack('!H', length)
                raw[24:26] = bytes(2)
                raw[24:26] = struct.pack('!H', shared._sum(raw[14:34]))
                cases.append(bytes(raw))
                if length in (52, 76, 77, 88, 89, 101):
                    for bit in range(32):
                        corrupt = bytearray(raw); corrupt[54 + bit // 8] ^= 1 << (bit % 8)
                        cases.append(bytes(corrupt))
        for value, echo in ((0, 0), (1, 0xffffffff), (0x7fffffff, 0x80000000), (0xffffffff, 1)):
            options = bytes.fromhex('0101080a') + struct.pack('!II', value, echo)
            cases.append(ts.packet(native, reverse=True, options=options))
        for options, flags in ((ts.SYN_OPTIONS, 2), (ts.SYNACK_OPTIONS, 18)):
            cases.append(ts.packet(b'', flags=flags, options=options, reverse=flags == 18))
            corrupt = bytearray(options); corrupt[0] ^= 1
            cases.append(ts.packet(b'', flags=flags, options=bytes(corrupt), reverse=flags == 18))
        for raw in cases:
            results = []
            for parser in (old, new):
                parser.begin_pass(0); parser.env['eg.egress_port'] = 9
                accepted, cursor = parser.packet_parser(bytes(16) + raw)
                results.append((accepted, cursor, dict(parser.env), dict(parser.valid),
                                parser.deparse() + (bytes(16) + raw)[cursor:]))
            self.assertEqual(results[0], results[1], (int.from_bytes(raw[16:18], 'big'), raw[54:58].hex()))
        self.assertEqual(len(cases), 1274)


if __name__ == '__main__':
    unittest.main()

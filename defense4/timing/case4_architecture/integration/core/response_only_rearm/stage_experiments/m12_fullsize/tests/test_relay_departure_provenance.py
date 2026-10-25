"""Physical relay departures must consume internal provenance before wire output."""
import hashlib
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from m12gen import relay_sbo
from m12gen.build import build
import test_n_read_shapes as shared
import test_relay_ts as ts


class RelayDepartureProvenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Preserve this historical c47-to-c48 parser-only regression; the
        # independent c49 static-key repair has its own equivalence tests.
        with patch.object(relay_sbo, 'retry_fin_phase', side_effect=lambda src: src), patch.object(relay_sbo, 'half_closed_rst', side_effect=lambda src: src), patch.object(relay_sbo, 'relay_fin_psh', side_effect=lambda src: src), \
                patch.object(relay_sbo, 'canonical_profile_keys', side_effect=lambda src: src):
            with patch.object(relay_sbo, 'relay_departure_provenance', side_effect=lambda src: src):
                cls.original, _ = build(**ts.FLAGS, relay_ts=True)
            cls.selected, _ = build(**ts.FLAGS, relay_ts=True)

    def test_only_physical_relay_port_is_added_to_provenance_parser(self):
        self.assertEqual(hashlib.sha256(self.original.encode()).hexdigest(),
                         '2191c15b94f4f83fcd78650b0bdc8f66f3029eda66253d8df85abfb48e1711fe')
        before = 'transition select(eg.egress_port) { 9w9: provenance; 9w48: provenance;  default: accept; }'
        after = 'transition select(eg.egress_port) { 9w9: provenance; 9w64: provenance; 9w48: provenance;  default: accept; }'
        self.assertEqual(self.selected, self.original.replace(before, after))
        # The legacy declaration is dead, so no active raw close departure
        # bypasses the internal header contract in this selected profile.
        n = shared.n_source(self.selected)
        for table in n.controls['Ingress'].tables.values():
            self.assertTrue(all(action != 'close_forward' for _, action, _ in table['entries']))
        source_n = shared.role(self.selected, 'N')
        self.assertEqual(source_n.count('close_forward'), 2)  # definition + unused action list

    def test_c47_syn_leak_reproduces_and_new_relay_entry_removes_exact_prefix(self):
        wire = bytes.fromhex('0030a7024ca23cfdfecc5dc008004500003c000140004006a562c0a80a01c0a80a07e8124e200000006400000000a002100029c10000020405b40402080a000f42400000000001030307')
        prefix = bytes.fromhex('0000000100000000000000000e000000')
        old = shared.interp.ESource(shared.role(self.original, 'E'))
        new = shared.interp.ESource(shared.role(self.selected, 'E'))
        self.assertEqual(old.inject(64, prefix + wire), prefix + wire)
        self.assertEqual(new.inject(64, prefix + wire), wire)
        self.assertEqual(len(wire), 74)

    def test_all_relay_event_roles_strip_and_open_initializes_lifecycle(self):
        e = shared.interp.ESource(shared.role(self.selected, 'E'))
        syn = ts.packet(b'', flags=2, options=ts.SYN_OPTIONS)
        e.install('conn', [0xc0a80a01, 0xc0a80a07, 56857, 20000, 64], 'rev_conn', [0])
        opened = e.inject(64, struct.pack('!IIIBBH', 1, 0, 0, 14, 0, 0) + syn)
        self.assertEqual(opened, syn)
        self.assertEqual(e.cells[('', 'epoch')][0], 1)
        self.assertEqual(e.cells[('', 'master_isn')][0], 900)
        request = bytes.fromhex('056424c4000001004a59cbcb030c011702010101c800000000008136000000030101c8000000000000000015ee')
        header, user = relay_sbo.deframe(request)
        user = bytearray(user); user[2] = 4
        operate = relay_sbo.frame(header, bytes(user))
        for kind, flags, payload in ((14, 2, b''), (13, 4, b''), (9, 24, request), (12, 24, operate),
                                     (0xe3, 17, b''), (0xe4, 16, b'')):
            wire = ts.packet(payload, flags=flags, options=ts.SYN_OPTIONS if flags == 2 else ts.DATA_OPTIONS)
            # The unconfigured tuple branch must also strip internal framing.
            parser = shared.interp.ESource(shared.role(self.selected, 'E'))
            self.assertEqual(parser.inject(64, struct.pack('!IIIBBH', 1, 0, 0, kind, 0, 0) + wire), wire, kind)

    def test_existing_master_normalization_and_token_ports_are_unchanged(self):
        wire = ts.packet(b'', flags=2, options=ts.SYN_OPTIONS)
        tagged = struct.pack('!IIIBBH', 1, 0, 0, 14, 0, 0) + wire
        for port in (9, 48, 0, 8, 128, 180, 196, 197):
            old = shared.interp.ESource(shared.role(self.original, 'E'))
            new = shared.interp.ESource(shared.role(self.selected, 'E'))
            self.assertEqual(old.inject(port, tagged), new.inject(port, tagged), port)
        # No terminal/token action changed: only the E parser port row differs.
        self.assertEqual(shared.role(self.original, 'T'), shared.role(self.selected, 'T'))


if __name__ == '__main__':
    unittest.main()

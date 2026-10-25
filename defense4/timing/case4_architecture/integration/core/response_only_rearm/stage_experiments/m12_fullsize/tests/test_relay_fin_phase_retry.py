"""Retry a FIN whose same-epoch owner snapshot loses to a pure ACK."""
import hashlib
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from m12gen import relay_sbo
from m12gen.build import build
import test_n_read_shapes as shared
import test_relay_ts as ts


def boundary(n, direction=2, difference=0x80000, epoch_difference=0, count=1,
             flags=17, owner_op=0, stage=1):
    n.begin_pass(68)
    n.env.update({'m.stage': stage, 'm.owner_op': owner_op, 'm.owner_diff': difference,
                  'm.epoch_diff': epoch_difference, 'hdr.event.reserved': count,
                  'm.direction': direction, 'hdr.tcp.flags': flags,
                  'hdr.envelope.epoch': 1, 'hdr.expected_cell.expected_cell': 0x1010001})
    n.table('reset_boundary')


class RelayFINPhaseRetry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = (shared.STAGE / 'ctl_timing_01/evidence/m12p_c49_sdk9132/response_only.p4').read_text()
        cls.selected, _ = build(**ts.FLAGS, relay_ts=True)
        # Source isolation of this layer excludes the later c51 half-closed RST rows.
        with patch.object(relay_sbo, 'half_closed_rst', side_effect=lambda src: src), patch.object(relay_sbo, 'relay_fin_psh', side_effect=lambda src: src):
            cls.layer, _ = build(**ts.FLAGS, relay_ts=True)

    def test_exact_c49_fin_snapshot_loses_to_ack_then_recomputes_without_losing_flags(self):
        self.assertEqual(hashlib.sha256(self.original.encode()).hexdigest(),
                         '995386583fc373e9a770b22e50194b49c246afc0e1c5789ccd099d9ae0b31bc2')
        old, new = shared.n_source(self.original), shared.n_source(self.selected)
        boundary(old)
        self.assertEqual(old.env.get('md.drop_ctl'), 1)  # c49 :0xbc
        n = new
        n.cells[('', 'owner')][0] = 0x1010001
        n.begin_pass(68)
        n.env.update({'hdr.tcp.flags': 17, 'm.direction': 2, 'm.observed': 0x1010001,
                      'm.server_diff': 1})
        n.table('close_phase_t')
        self.assertEqual(n.env['m.desired'], 0x10b)  # :0xb8 FIN snapshot
        # The pure ACK publishes 0109 before the FIN's work-free CAS slot.
        n.env.update({'hdr.expected_cell.expected_cell': 0x1010001,
                      'hdr.origin.normalized_epoch': 0x109})
        n.action('close_owner'); n.action('owner_cas')
        self.assertEqual(n.cells[('', 'owner')][0], 0x1090001)  # :0xbb
        boundary(n)
        self.assertNotEqual(n.env.get('md.drop_ctl'), 1)
        self.assertEqual(n.env['hdr.event.event'], 0x0800)
        self.assertEqual(n.env['hdr.event.reserved'], 2)
        # Recovery adds a retry lap: reload current owner, qualify the same
        # FIN again, then CAS against the fresh ACK-bearing owner snapshot.
        n.env.update({'m.observed': n.cells[('', 'owner')][0], 'hdr.tcp.flags': 17,
                      'm.direction': 2, 'm.server_diff': 1, 'm.epoch': 1,
                      'm.generation': 1, 'm.wire_ack': 0, 'm.normalized_epoch': 0})
        n.table('close_phase_t')
        self.assertEqual(n.env['m.desired'], 0x10b)
        n.action('snapshot_retry'); n.action('first_close')
        self.assertEqual(n.env['hdr.event.reserved'], 2)
        n.action('close_owner'); n.action('owner_cas')
        self.assertEqual(n.env['m.owner_diff'], 0)
        self.assertEqual(n.cells[('', 'owner')][0], 0x10b0001)
        # The final master's ACK joins the remaining bit rather than losing
        # either prior FIN or the relay's earlier ACK of the master FIN.
        n.env.update({'m.observed': 0x10b0001, 'hdr.tcp.flags': 16,
                      'm.direction': 1, 'm.server_diff': 1})
        n.table('close_phase_t')
        self.assertEqual(n.env['m.desired'], 0x10f)

    def test_both_directions_restart_only_current_epoch_same_generation_before_bound(self):
        n = shared.n_source(self.selected)
        for direction in (1, 2):
            for count in range(32):
                boundary(n, direction=direction, count=count)
                self.assertNotEqual(n.env.get('md.drop_ctl'), 1)
                self.assertEqual(n.env['hdr.event.event'], 0x0800)
                self.assertEqual(n.env['hdr.event.reserved'], count + 1)
                self.assertEqual(n.env['hdr.origin.normalized_epoch'], 1 if direction == 1 else 0)
            for kw in ({'count': 32}, {'difference': 0x80001}, {'difference': 0x7ffff},
                       {'epoch_difference': 1}, {'epoch_difference': 0xffffffff},
                       {'stage': 2}, {'flags': 16}, {'flags': 18}):
                boundary(n, direction=direction, **kw)
                self.assertEqual(n.env.get('md.drop_ctl'), 1, (direction, kw))

    def test_retry_snapshot_preserves_bound_and_every_valid_close_phase_keeps_existing_bits(self):
        n = shared.n_source(self.selected)
        checked = 0
        for direction in (1, 2):
            for phase in range(0x100, 0x110):
                for acknowledged in (0, 1):
                    n.begin_pass(68)
                    n.env.update({'m.direction': direction, 'm.observed': phase << 16 | 1,
                                  'hdr.tcp.flags': 17, 'm.server_diff': acknowledged, 'm.desired': 0})
                    n.table('close_phase_t')
                    desired = n.env['m.desired']
                    if desired:
                        self.assertEqual(desired & phase, phase)
                        self.assertTrue(desired & (1 if direction == 1 else 2))
                        checked += 1
            for action in ('snapshot_retry', 'snapshot_lap_retry'):
                for count in range(33):
                    n.begin_pass(68); n.env['hdr.event.reserved'] = count; n.action(action)
                    self.assertEqual(n.env['hdr.event.reserved'], count)
        self.assertGreater(checked, 40)

    def test_existing_owner_success_wait_and_reset_behavior_are_unchanged(self):
        old, new = shared.n_source(self.original), shared.n_source(self.selected)
        for direction in (1, 2):
            for owner_op in (0, 1):
                for flags in (4, 20, 17):
                    for count in (0, 1, 31, 32):
                        for n in (old, new):
                            boundary(n, direction=direction, difference=0, owner_op=owner_op,
                                     flags=flags, count=count)
                        fields = ('hdr.event.event', 'hdr.event.reserved', 'md.drop_ctl',
                                  'hdr.expected_cell.expected_cell')
                        self.assertEqual([old.env.get(k) for k in fields], [new.env.get(k) for k in fields])

    def test_only_existing_boundary_table_gains_three_bounded_fin_rows(self):
        def erase(text):
            return re.sub(r'table reset_boundary\{[^\n]+', '<reset_boundary>', text)
        self.assertEqual(erase(self.layer), erase(self.original))
        n = shared.n_source(self.layer)
        rows = n.controls['Ingress'].tables['reset_boundary']['entries']
        self.assertEqual(len(rows), 10)


if __name__ == '__main__':
    unittest.main()

"""Admit a sequence-valid RST/RSTACK while the owner is half-closed (c51).

c50 fin_busy02 trace: after master FIN and relay ACK the owner is 0109; a valid
RSTACK (SEQ c+1) yields seq_fin5 and close_phase_t desired0x200, but first_event
misses, the reset is ignored and later SYNs stay blocked.

Source-interpreter tier (harness/driver.Pipeline: N parser, Ingress, deparser,
recirculation on 68). N only: master packets are injected on their device port
with a plain route instead of the normalize_ack lap through egress, so a full
SYN completion (epoch store after that lap) is checked by the runtime model
driver (seg61_02/model_packets.py half_closed_rst) on the compiled image, not here.
"""
import difflib
import hashlib
import re
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from unittest.mock import patch

from m12gen import relay_sbo
from m12gen.build import build
from m12gen.relay_sbo import HALF_CLOSED_BANDS, HALF_CLOSED_ROWS
import test_n_read_shapes as shared
import test_relay_ts as ts

sys.path.insert(0, str(shared.INTEG / 'core/harness'))
from driver import Config, MAX_PASSES, Pipeline  # noqa: E402

C50 = shared.STAGE / 'ctl_timing_01/evidence/m12p_c50_sdk9132/response_only.p4'
C50_SHA = '1c4138ede50aaea8a662f0fba4db6b6dac2916cad46679b5d16599d34f67f43b'
MASTER, RELAY = 0xc0a80a01, 0xc0a80a07
MPORT, RPORT = 59410, 20000
DEV_MASTER, DEV_RELAY, READ_HANDOFF = 9, 64, 180
# c49_02 coordinates: master FIN SEQ70233, wire ACK90540.
CLIENT, SERVER = 70233, 90540
OWNER_0109 = 0x01090001
# c49_02 c0_last_ACK as sent by the master; seq/ack/flags are rewritten per case.
TEMPLATE_M = ('0030a7024ca23cfdfecc5dc0080045000034000140004006a56ac0a80a01c0a80a07e8124e20'
              '0001125a000161ad801010007b3900000101080a000f4260000f6970')
SYN = ('0030a7024ca23cfdfecc5dc008004500003c000140004006a562c0a80a01c0a80a07e8124e2000011170'
       '00000000a002100018b40000020405b40402080a000f42400000000001030307')
NEW_ROWS = HALF_CLOSED_ROWS


def tcp(base_hex, seq, ack, flags, reverse=False):
    """Rewrite seq/ack/flags (and, for the relay, swap MAC/IP/port) with a valid TCP checksum."""
    f = bytearray(bytes.fromhex(base_hex))
    if reverse:
        f[0:6], f[6:12] = f[6:12], f[0:6]
        f[26:30], f[30:34] = f[30:34], f[26:30]
        f[34:36], f[36:38] = f[36:38], f[34:36]
    seg = f[34:]
    struct.pack_into('!II', seg, 4, seq, ack)
    seg[13] = flags
    seg[16:18] = b'\0\0'
    pseudo = bytes(f[26:34]) + struct.pack('!BBH', 0, 6, len(seg))
    struct.pack_into('!H', seg, 16, shared._sum(pseudo + bytes(seg)))
    return bytes(f[:34] + seg)


def pipeline(text):
    n = shared.interp.source_text(shared.role(text, 'N')).replace('p.global_tstamp', 'ig.global_tstamp')
    cfg = Config(ports={DEV_MASTER: DEV_RELAY, DEV_RELAY: DEV_MASTER, 68: 68},
                 flows=[(MASTER, RELAY, MPORT, RPORT, 'forward', DEV_RELAY),
                        (RELAY, MASTER, RPORT, MPORT, 'reverse', DEV_MASTER)])
    return Pipeline(n, cfg, include_dir=shared.INTEG)


def preset(p, owner=OWNER_0109, epoch=1):
    p.preset(owner=owner, client=CLIENT, server=SERVER, epoch=epoch, work=(32, 4))
    p.src.cells[('', 'retry_epoch')][0] = 1


def inject(p, port, frame, between=None):
    """Driver.inject with an optional hook run after pass 1 (a concurrent register change).

    p.at_first_event collects (m.kind, m.desired) as each first_event lookup executes."""
    trace, raw, ingress, emitted, dropped = [], bytes(frame), port, [], None
    src, apply_table = p.src, type(p.src).apply_table
    p.at_first_event = []

    def observed(self, name):
        if name == 'first_event':
            p.at_first_event.append((self.env.get('m.kind'), self.env.get('m.desired')))
        return apply_table(self, name)
    src.apply_table = observed.__get__(src)
    for number in range(1, MAX_PASSES + 1):
        events, result, reason = p.run_pass(number, ingress, raw)
        trace.append(events)
        if number == 1 and between:
            between(p)
        if result is None:
            dropped = reason
            break
        egress, raw = result
        if egress == 68:
            ingress = 68
            continue
        emitted.append((egress, raw))
        break
    del src.apply_table
    return trace, emitted, dropped


def hits(trace, table):
    return [e.split(' -> ')[1].split(' ')[0] for t in trace for e in t if e.startswith('table %s ->' % table)]


def rst(direction, flags, seq_delta=1):
    if direction == 1:
        return DEV_MASTER, tcp(TEMPLATE_M, (CLIENT + seq_delta) & 0xffffffff, SERVER, flags)
    return DEV_RELAY, tcp(TEMPLATE_M, (SERVER + seq_delta) & 0xffffffff, CLIENT + 1, flags, reverse=True)


# ---- static row algebra -------------------------------------------------------------------
def _term(text):
    if text == '_':
        return 0, 0
    parts = text.split('&&&')
    value = int(parts[0].split('w', 1)[1], 0)
    mask = int(parts[1].split('w', 1)[1], 0) if len(parts) == 2 else (1 << int(parts[0].split('w')[0])) - 1
    return value & mask, mask


def first_event_rows(text):
    start = text.index('table first_event{')
    body = text[start:text.index('}}', start)]
    entries = body[body.index('const entries={') + len('const entries={'):]
    return [([_term(t) for t in keys.split(',')], action)
            for keys, action in re.findall(r'\(([^()]*)\):([A-Za-z_]+)\(\);', entries)]


def intersects(a, b):
    return all((va ^ vb) & ma & mb == 0 for (va, ma), (vb, mb) in zip(a, b))


class HalfClosedRST(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c50 = C50.read_text()
        # this layer only: the later c52 relay FIN+PSH layer is patched out (test_relay_fin_psh covers it)
        with patch.object(relay_sbo, 'relay_fin_psh', side_effect=lambda src: src):
            cls.selected, _ = build(**ts.FLAGS, relay_ts=True)

    def test_c50_reproduces_ignored_reset_and_blocked_syn(self):
        self.assertEqual(hashlib.sha256(self.c50.encode()).hexdigest(), C50_SHA)
        p = pipeline(self.c50)
        preset(p)
        trace, emitted, dropped = inject(p, *rst(1, 0x14))
        self.assertEqual(hits(trace, 'sequence_guard')[0], 'seq_fin')
        self.assertEqual(hits(trace, 'close_phase_t'), ['qualify_close'])
        self.assertEqual(hits(trace, 'first_event'), ['NoAction'])
        self.assertEqual((emitted, p.cell('', 'owner')), ([], OWNER_0109))
        self.assertIsNotNone(dropped)
        trace, emitted, _ = inject(p, DEV_MASTER, tcp(SYN, 0x20000, 0, 2))
        self.assertEqual(hits(trace, 'first_event')[0], 'NoAction')  # SYN blocked at 0109

    def test_selected_resets_retires_and_readmits_syn(self):
        p = pipeline(self.selected)
        preset(p)
        trace, emitted, dropped = inject(p, *rst(1, 0x14))
        self.assertIsNone(dropped)
        self.assertEqual(hits(trace, 'first_event'), ['first_close'])
        self.assertEqual(p.at_first_event, [(4, 0x200)])
        self.assertEqual(hits(trace, 'owner_command'), ['NoAction', 'close_owner', 'NoAction'])
        self.assertIn('owner_cas', hits(trace, 'owner_t'))
        self.assertEqual(hits(trace, 'reset_boundary'), ['reset_continue', 'emit_reset'])
        self.assertEqual(hits(trace, 'retry_epoch_t')[-1], 'retry_epoch_clear')
        self.assertEqual(p.cell('', 'owner'), 0x02000001)  # retired 0x200, generation kept
        self.assertEqual([port for port, _ in emitted], [READ_HANDOFF])
        trace, _, _ = inject(p, DEV_MASTER, tcp(SYN, 0x20000, 0, 2))
        self.assertEqual(hits(trace, 'first_event')[0], 'first_syn')

    def test_close_phase_qualifies_200_before_first_event(self):
        body = shared.role(self.selected, 'N')
        self.assertEqual(re.findall(r'bit<(\d+)> sequence_valid;', body), ['3'])  # 3w1&&&3w3 is exactly {1,5}
        branch = re.search(r'if\(m\.work_phase==32w4&&[^\n]*\n([^\n]*)', body).group(1)
        self.assertLess(branch.index('close_phase_t.apply();'), branch.index('first_event.apply();'))
        for table in ('snapshot_t', 'retry_dup_t'):
            start = body.index('table %s{' % table)
            actions = re.search(r'actions=\{([^}]*)\}', body[start:]).group(1).split(';')
            for action in filter(None, actions):
                m = re.search(r'action %s\([^)]*\)\{([^}]*)\}' % re.escape(action), body)
                if m:
                    self.assertNotIn('m.desired=', m.group(1), action)

    def test_both_directions_all_phases_both_flags(self):
        p = pipeline(self.selected)
        for direction in (1, 2):
            for phase in range(0x101, 0x110):
                for flags in (0x04, 0x14):
                    with self.subTest(direction=direction, phase=hex(phase), flags=flags):
                        owner = phase << 16 | 1
                        preset(p, owner=owner)
                        trace, emitted, dropped = inject(p, *rst(direction, flags))
                        events = [e for t in trace[:1] for e in t]
                        q = next(i for i, e in enumerate(events) if e.startswith('table close_phase_t'))
                        f = next(i for i, e in enumerate(events) if e.startswith('table first_event'))
                        self.assertLess(q, f)
                        self.assertIn('qualify_close', events[q])
                        self.assertIn(hits(trace, 'sequence_guard')[0], ('seq_ok', 'seq_fin'))
                        self.assertEqual(hits(trace, 'first_event'), ['first_close'])
                        self.assertEqual(p.at_first_event, [(4, 0x200)])
                        self.assertEqual(hits(trace, 'reset_boundary'), ['reset_continue', 'emit_reset'])
                        self.assertEqual(p.cell('', 'owner'), 0x02000001)
                        self.assertEqual(([port for port, _ in emitted], dropped), ([READ_HANDOFF], None))

    def test_both_sequence_valid_values_reset(self):
        p = pipeline(self.selected)
        # (direction, flags, delta): the relay's natural RSTACK is seq=server (0,1) -> seq_fin,
        # its bare RST (0,0) -> seq_ok; the master's RST after its FIN is seq=c+1 -> seq_fin.
        for direction, flags, delta, expected in ((1, 0x04, 0, 'seq_ok'), (1, 0x04, 1, 'seq_fin'),
                                                  (2, 0x14, 0, 'seq_fin'), (2, 0x04, 0, 'seq_ok')):
            with self.subTest(direction=direction, flags=flags, delta=delta):
                preset(p)
                trace, _, dropped = inject(p, *rst(direction, flags, seq_delta=delta))
                self.assertEqual(hits(trace, 'sequence_guard')[0], expected)
                self.assertEqual((hits(trace, 'first_event'), dropped), (['first_close'], None))

    def test_invalid_sequence_coordinates_do_not_reset(self):
        p = pipeline(self.selected)
        for direction in (1, 2):
          for delta in (2, 0x1000, -1, -0x2d):
            with self.subTest(direction=direction, delta=delta):
                preset(p)
                trace, emitted, _ = inject(p, *rst(direction, 0x14, seq_delta=delta))
                self.assertNotIn(hits(trace, 'sequence_guard')[0], ('seq_ok', 'seq_fin'))
                self.assertNotEqual(hits(trace, 'first_event'), ['first_close'])
                self.assertEqual((emitted, p.cell('', 'owner')), ([], OWNER_0109))

    def test_other_flags_and_unknown_tuple_do_not_reset(self):
        p = pipeline(self.selected)
        for direction in (1, 2):
          for flags in (0x05, 0x0c, 0x24, 0x84, 0x15):
            with self.subTest(direction=direction, flags=flags):
                preset(p)
                trace, emitted, _ = inject(p, *rst(direction, flags))
                self.assertNotIn('first_close', hits(trace, 'first_event'))
                self.assertNotIn(READ_HANDOFF, [port for port, _ in emitted])
                self.assertEqual(p.cell('', 'owner'), OWNER_0109)
        preset(p)
        frame = bytearray(rst(1, 0x14)[1])
        frame[36:38] = struct.pack('!H', MPORT + 1)  # tuple not installed: direction 0
        frame[50:52] = b'\0\0'
        trace, emitted, _ = inject(p, DEV_MASTER, tcp(frame.hex(), CLIENT + 1, SERVER, 0x14))
        self.assertEqual(hits(trace, 'first_event'), [])
        self.assertEqual((p.cell('', 'owner'), [port for port, _ in emitted]), (OWNER_0109, [DEV_RELAY]))

    def test_non_half_closed_phases_unchanged(self):
        """0x100/0x200/normal phases keep c50's first_event outcome for the same RST."""
        old, new = pipeline(self.c50), pipeline(self.selected)
        for phase in (0x2, 0x5, 0xa, 0x100, 0x110, 0x200, 0x1ff):
            for direction in (1, 2):
                with self.subTest(phase=hex(phase), direction=direction):
                    results = []
                    for p in (old, new):
                        preset(p, owner=phase << 16 | 1)
                        trace, emitted, dropped = inject(p, *rst(direction, 0x14))
                        results.append((hits(trace, 'first_event'), p.cell('', 'owner'),
                                        [port for port, _ in emitted], dropped))
                    self.assertEqual(results[0], results[1])

    def test_stale_epoch_aborts(self):
        p = pipeline(self.selected)
        for direction in (1, 2):
            with self.subTest(direction=direction):
                preset(p)
                trace, emitted, dropped = inject(p, *rst(direction, 0x14),
                                                 between=lambda q: q.src.cells[('', 'epoch')].__setitem__(0, 2))
                self.assertEqual(hits(trace, 'first_event'), ['first_close'])
                self.assertEqual(hits(trace, 'reset_boundary'), ['terminal_abort'])
                self.assertEqual((emitted, p.cell('', 'owner')), ([], OWNER_0109))
                self.assertIsNotNone(dropped)

    def test_stale_generation_aborts(self):
        p = pipeline(self.selected)
        for direction in (1, 2):
            with self.subTest(direction=direction):
                preset(p)
                trace, emitted, dropped = inject(p, *rst(direction, 0x14),
                                                 between=lambda q: q.preset(owner=0x01090002))
                self.assertEqual(hits(trace, 'reset_boundary'), ['terminal_abort'])
                self.assertEqual((emitted, p.cell('', 'owner')), ([], 0x01090002))
                self.assertIsNotNone(dropped)

    def test_failed_cas_same_generation_takes_bounded_restart(self):
        p = pipeline(self.selected)
        restart = {1: 'reset_restart_master', 2: 'reset_restart_out'}
        for direction in (1, 2):
            with self.subTest(direction=direction):
                preset(p)
                trace, emitted, dropped = inject(p, *rst(direction, 0x14),
                                                 between=lambda q: q.preset(owner=0x010b0001))
                # The concurrent owner change fails the CAS against snapshot 0109. c50's bounded
                # restart reloads the fresh owner 010b and requalifies; only that second, fresh
                # CAS retires the connection. The stale snapshot never writes the owner.
                self.assertEqual(hits(trace, 'reset_boundary'), [restart[direction], 'reset_continue', 'emit_reset'])
                self.assertEqual(hits(trace, 'first_event'), ['first_close', 'first_close'])
                self.assertEqual(p.at_first_event, [(4, 0x200), (4, 0x200)])
                self.assertEqual(hits(trace, 'owner_t').count('owner_cas'), 2)
                self.assertEqual((p.cell('', 'owner'), [port for port, _ in emitted], dropped),
                                 (0x02000001, [READ_HANDOFF], None))

    def test_row_algebra_is_exact(self):
        phases = set()
        for phase in range(1 << 16):
            if any((phase << 16) & mask == value for value, mask in HALF_CLOSED_BANDS):
                phases.add(phase)
        self.assertEqual(phases, set(range(0x101, 0x110)))
        self.assertEqual({v for v in range(8) if v & 3 == 1}, {1, 5})
        self.assertEqual({f for f in range(256) if f & 0xef == 4}, {4, 20})
        rows = first_event_rows(self.selected)
        self.assertEqual(len(rows), 176 + NEW_ROWS)
        self.assertEqual(first_event_rows(self.c50), rows[:-NEW_ROWS])
        for keys, action in rows[-NEW_ROWS:]:
            self.assertEqual(action, 'first_close')
            self.assertEqual(keys[0], (4, 0xff))
            self.assertEqual(keys[1], (1, 3))
            self.assertEqual(keys[7], (4, 0xef))
            self.assertIn(keys[6], ((1, 3), (2, 3)))
            self.assertEqual(keys[3][1] & 0xffff, 0)
        # Appended last: they decide only packets that previously reached the default NoAction,
        # and no earlier row of the complete table can match any packet they match.
        for new_keys, _ in rows[-NEW_ROWS:]:
            for index, (old_keys, action) in enumerate(rows[:-NEW_ROWS]):
                self.assertFalse(intersects(new_keys, old_keys), (index, action))

    def test_emitted_diff_is_only_rows_and_size(self):
        a, b = self.c50.replace(';', ';\n').splitlines(), self.selected.replace(';', ';\n').splitlines()
        changed = [l for l in difflib.unified_diff(a, b, lineterm='', n=0)
                   if l[:1] in '+-' and not l.startswith(('+++', '---'))]
        self.assertEqual(changed[:2], ['-}size=176;', '+}size=184;'])
        self.assertEqual(len(changed), 2 + NEW_ROWS)
        self.assertTrue(all(l.startswith('+(8w4,3w1&&&3w3,') and l.endswith(':first_close();')
                            for l in changed[2:]))


if __name__ == '__main__':
    unittest.main()

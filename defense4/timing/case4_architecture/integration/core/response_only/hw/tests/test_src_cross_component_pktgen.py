"""Cross-component regression: the installer's generator app-IDs (hw/t_config.PKTGEN_APPS) must be the ones
T's compiled parser/control (read/read_queue_timing.p4) actually admits and routes to a blocker.

This is the test that was missing: the installer test asserts its own app numbers and the T tests build their
own tokens, so each passed alone while the contract between them was broken (defect B: READ configured on
app 2, which parse_timer drops as a foreign frame, so no READ blocker is ever seeded). Here the token is built
from the INSTALLER's app-IDs and run through T's real parser + Ingress in the source interpreter; a wrong
app-ID shows up as a missing seed, which a schema check on the installer alone cannot see.

  python3 -m unittest discover -s tests -p 'test_src_*.py'     (from integration/core/response_only/hw)
"""
import struct
import sys
import unittest
from pathlib import Path

HW = Path(__file__).resolve().parent.parent
READ_TESTS = HW.parents[2] / 'read' / 'tests'
sys.path.insert(0, str(HW))
sys.path.insert(0, str(READ_TESTS))
import t_config as tc  # noqa: E402  (the installer config under test)
import queue_sim as qs  # noqa: E402  (T's source interpreter + ports)

PKTGEN_PIPE = qs.PKTGEN_PIPE
PKTGEN_RETURN = qs.PORTS['PKTGEN_RETURN']
HELD_RETURN, HB_RETURN = qs.PORTS['HELD_RETURN'], qs.PORTS['HB_RETURN']
# read_queue_timing.p4: ladder roles and the ladder each blocker is seeded onto.
ROLE_ACK_BLK, ROLE_RESP_BLK, ROLE_OP_BLK = 11, 12, 13
SEED = {'OPERATE': (ROLE_OP_BLK, HB_RETURN, 3), 'READ_ACK': (ROLE_ACK_BLK, HELD_RETURN, 7),
        'READ_RESP': (ROLE_RESP_BLK, HELD_RETURN, 5)}


def timer_token(pipe, app, batch_id, packet_id):
    """The 6-byte Tofino-1 pktgen timer header as read_queue_timing.p4's parse_timer reads it
    (pad(3)=0 | pipe_id(2) | app_id(3), pad(8), batch_id(16), packet_id(16)) plus filler. Exactly what the
    generator delivers; the pipe and app are what the installed app_cfg stamps."""
    return bytes([(pipe & 3) << 3 | (app & 7)]) + bytes([app & 7]) + struct.pack('!HH', batch_id, packet_id) + bytes(10)


def run_token(raw, port=PKTGEN_RETURN, read_gen=0, op_gen=0):
    """One pass of T's real parser + Ingress on `raw`. Returns (result, before, after) where result reports
    the seed / drop and before/after are snapshots of every register and counter."""
    sim = qs.QueueSim()                                   # fresh switch: all registers at their P4 init
    sim.cell_set = None
    sim.src.cells[('', 'gen_alloc_reg')][0] = read_gen    # the live READ generation a token must match
    sim.src.cells[('', 'op_gen_alloc_reg')][0] = op_gen   # the live OPERATE generation
    snap = lambda: ({name: list(cells) for (path, name), cells in sim.src.cells.items() if path == ''})
    before = snap()
    sim.src.begin_pass(port)
    accepted, _cursor = sim.src.packet_parser(raw)
    if accepted:
        sim.src.apply_control('Ingress')
    env = sim.src.env
    # token_ok is read from the parser trace (parse_timer -> token_format_ok set md.token_ok=1); the interpreter
    # does not keep md.token_ok in env past apply. hdr.ladder validity is tracked under the header's short name.
    result = dict(accepted=accepted, token_ok=1 if 'token_format_ok' in sim.src.parser_states else 0,
                  drop=(env.get('md.drop_ctl') or 0) & 1, role=env.get('hdr.ladder.role'), qid=env.get('tm.qid'),
                  egress=env.get('tm.ucast_egress_port'), ladder_valid=sim.src.valid.get('ladder', False))
    return result, before, snap()


def changed(before, after):
    return {name: (before[name], after[name]) for name in after if before.get(name) != after[name]}


class InstallerAppIdsSeedBlockers(unittest.TestCase):
    """The heart of the regression: each installer app-ID, fed through T, seeds the blocker it should."""

    def app(self, name):
        return next(app_id for n, app_id, _p in tc.PKTGEN_APPS if n == name)

    def test_operate_app_seeds_the_operate_blocker(self):
        gen = 0x0007
        r, _b, _a = run_token(timer_token(PKTGEN_PIPE, self.app('OPERATE'), batch_id=gen, packet_id=0), op_gen=gen)
        role, egress, qid = SEED['OPERATE']
        self.assertTrue(r['ladder_valid'] and not r['drop'], 'OPERATE token was not seeded: %s' % r)
        self.assertEqual((r['role'], r['egress'], r['qid']), (role, egress, qid))

    def test_read_app_even_packet_seeds_the_ack_blocker(self):
        gen = 0x0005
        r, _b, _a = run_token(timer_token(PKTGEN_PIPE, self.app('READ'), batch_id=gen, packet_id=0), read_gen=gen)
        role, egress, qid = SEED['READ_ACK']
        self.assertTrue(r['ladder_valid'] and not r['drop'], 'READ (even) token was not seeded: %s' % r)
        self.assertEqual((r['role'], r['egress'], r['qid']), (role, egress, qid))

    def test_read_app_odd_packet_seeds_the_response_blocker(self):
        gen = 0x0005
        r, _b, _a = run_token(timer_token(PKTGEN_PIPE, self.app('READ'), batch_id=gen, packet_id=1), read_gen=gen)
        role, egress, qid = SEED['READ_RESP']
        self.assertTrue(r['ladder_valid'] and not r['drop'], 'READ (odd) token was not seeded: %s' % r)
        self.assertEqual((r['role'], r['egress'], r['qid']), (role, egress, qid))

    def test_both_apps_use_the_ids_the_P4_admits(self):
        # parse_timer admits only (PKTGEN_PIPE, 0) and (PKTGEN_PIPE, 1). The installer must use exactly those.
        self.assertEqual({app_id for _n, app_id, _p in tc.PKTGEN_APPS}, {0, 1})
        self.assertEqual(self.app('OPERATE'), 1)   # token_verdict routes app 1 -> OPERATE
        self.assertEqual(self.app('READ'), 0)      # and the other admitted app -> READ

    def test_a_read_token_on_a_wrong_app_id_would_not_seed(self):
        # Pins the defect: app 2 (the old READ id) is not admitted, so nothing is seeded. Guards against a
        # future edit that moves READ off an admitted id while every other test still passes.
        gen = 0x0005
        r, before, after = run_token(timer_token(PKTGEN_PIPE, 2, batch_id=gen, packet_id=0), read_gen=gen)
        self.assertFalse(r['ladder_valid'], 'app 2 must not seed a blocker (it is not admitted)')
        self.assertEqual(r['token_ok'], 0)
        self.assertEqual(changed(before, after), {}, 'a foreign app mutated state: %s' % changed(before, after))


class ForeignOrStaleTokensDoNotCorruptState(unittest.TestCase):
    """A token that is not a valid, current one of the installed apps must not seed and must not change state."""

    def test_wrong_pipe_is_foreign_and_changes_nothing(self):
        gen = 0x0005
        wrong = 0 if PKTGEN_PIPE != 0 else 2
        r, before, after = run_token(timer_token(wrong, tc.PKTGEN_APPS[1][1], batch_id=gen, packet_id=0), read_gen=gen)
        self.assertEqual(r['token_ok'], 0)
        self.assertFalse(r['ladder_valid'])
        self.assertTrue(r['drop'])
        self.assertEqual(changed(before, after), {}, 'wrong-pipe token changed state')

    def test_an_unadmitted_app_is_foreign_and_changes_nothing(self):
        gen = 0x0005
        for app in (2, 3, 7):
            with self.subTest(app=app):
                r, before, after = run_token(timer_token(PKTGEN_PIPE, app, batch_id=gen, packet_id=0), read_gen=gen)
                self.assertEqual(r['token_ok'], 0)
                self.assertFalse(r['ladder_valid'])
                self.assertEqual(changed(before, after), {}, 'app %d changed state' % app)

    def test_a_wrong_generation_token_is_stale_counted_but_seeds_nothing_and_changes_no_other_state(self):
        # A valid-format READ token whose generation is not the live one is stale: the P4 counts it
        # (OUT_TOKEN_STALE, the telemetry the silicon readback uses) and seeds nothing. Only that one counter
        # moves; no state register and no other counter does.
        consts = qs.QueueSim().consts()
        stale_idx = consts['OUT_TOKEN_STALE']
        r, before, after = run_token(timer_token(PKTGEN_PIPE, 0, batch_id=0x00AA, packet_id=0), read_gen=0x0005)
        self.assertEqual(r['token_ok'], 1, 'format is valid; it is stale, not foreign')
        self.assertFalse(r['ladder_valid'], 'a stale token must not seed a blocker')
        self.assertTrue(r['drop'])
        diff = changed(before, after)
        self.assertEqual(set(diff), {'outcomes'}, 'only the outcomes counter may move: %s' % diff)
        b_out, a_out = diff['outcomes']
        self.assertEqual([i for i in range(len(a_out)) if a_out[i] != b_out[i]], [stale_idx])
        self.assertEqual(a_out[stale_idx] - b_out[stale_idx], 1)

    def test_an_operate_token_in_a_wrong_generation_is_stale_and_seeds_nothing(self):
        r, before, after = run_token(timer_token(PKTGEN_PIPE, 1, batch_id=0x00AA, packet_id=0), op_gen=0x0007)
        self.assertEqual(r['token_ok'], 1)
        self.assertFalse(r['ladder_valid'])
        self.assertTrue(r['drop'])
        self.assertEqual(set(changed(before, after)), {'outcomes'})


if __name__ == '__main__':
    unittest.main()

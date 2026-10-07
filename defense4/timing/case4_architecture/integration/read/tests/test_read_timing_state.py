"""Cookie-tagged timing state, lazy re-arm, no heartbeat pin (ticket T7).

T2-REARM: a second READ association never sees the first one's anchor, observations, release,
          response deadline or ready bit, and a stale (lower) cookie cannot arm, record, OR,
          commit or set ready on the newer association.
T2-HB-LOSS: the heartbeat service path holds no pinned work record; a lost service pass cannot
          wedge later ticks.
Fragment-level source tests: they execute the actual RegisterActions and tables of
read_timing.p4 one pass at a time. They are not target, queue or recirculation evidence.
"""
import re
import unittest

from read_fragment import TEXT, fragment_text, source

CELLS = ('admission_anchor', 'observations', 'releases', 'committed_response_deadline', 'ready_response')
T1, T2 = 0x01000100, 0x05000200


def fresh(active=1):
    registers = {(name, 0): {'cookie': 0, 'word': 0} for name in CELLS}
    registers[('association_cookie', 0)] = active
    s = source({'m.eligible_mask': 0, 'm.seen_mask': 0, 'm.anchor_operation': 0, 'm.seen_operation': 0,
                'm.timing_authorized': 0, 'm.service_phase': 0, 'm.ingress_port': 71, 'm.service_role': 0,
                'm.response_eligible': 0}, registers=registers)
    return s


def set_active(s, cookie):
    """Pktgen snapshot pass: no packet cookie, so the active association cookie is read."""
    s.registers[('association_cookie', 0)] = cookie
    s.run('m.timing_cookie=current_cookie.execute(0);')
    assert s.env['m.timing_cookie'] == cookie


def arm(s, cookie, now):
    s.env.update({'m.timing_cookie': cookie, 'm.now': now, 'm.anchor_operation': 1})
    s.table('anchor_event')
    return s.env['m.anchor']


def observe(s, cookie, mask):
    s.env.update({'m.timing_cookie': cookie, 'm.seen_mask': mask, 'm.seen_operation': 1})
    s.table('observation_event')
    return s.env['m.seen']


def service_release(s, cookie, mask):
    s.env.update({'m.timing_cookie': cookie, 'm.eligible_mask': mask, 'm.ingress_port': 10,
                  'm.service_phase': 1, 'm.timing_authorized': 1})
    s.table('release_event')


def service_ready(s, cookie, eligible=1):
    s.env.update({'m.timing_cookie': cookie, 'm.response_eligible': eligible, 'm.ready_set': eligible, 'm.ingress_port': 10,
                  'm.service_phase': 1, 'm.timing_authorized': 1})
    s.table('ready_event')


def commit(s, cookie, anchor):
    s.env.update({'m.timing_cookie': cookie, 'm.response_anchor': anchor, 'm.role': 5, 'm.kind': 1,
                  'm.release_reason': 2, 'm.credit_op': 2, 'm.result': 1, 'm.service_role': 0})
    s.table('response_clock')


def read_all(s):
    """What the active association sees on a snapshot pass: qualified reads only."""
    s.env['m.timing_cookie'] = s.registers[('association_cookie', 0)]
    s.env.update({'m.anchor_operation': 0, 'm.seen_operation': 0, 'm.ingress_port': 71,
                  'm.service_phase': 0, 'm.timing_authorized': 0, 'm.service_role': 1,
                  'm.role': 0, 'm.kind': 0, 'm.release_reason': 0, 'm.credit_op': 0, 'm.result': 0})
    s.table('anchor_event'); s.table('observation_event'); s.table('release_event')
    s.table('ready_event'); s.table('response_clock')
    return dict(anchor=s.env['m.anchor'], seen=s.env['m.seen'], release=s.env['m.current_release'],
                ready=s.env['m.response_ready'], deadline=s.env['hdr.service.response_deadline'])


class Rearm(unittest.TestCase):
    def finish_read_one(self, s):
        set_active(s, 1)
        self.assertEqual(arm(s, 1, T1), T1 | 1)
        self.assertEqual(observe(s, 1, 1), 1)
        self.assertEqual(observe(s, 1, 2), 3)
        service_release(s, 1, 3)
        commit(s, 1, T1 + 1_000_000)
        service_ready(s, 1)
        got = read_all(s)
        self.assertEqual(got, dict(anchor=T1 | 1, seen=3, release=3, ready=1,
                                   deadline=(T1 + 1_000_000) | 1))

    def test_second_read_starts_from_zero_state(self):
        s = fresh()
        self.finish_read_one(s)
        set_active(s, 2)
        self.assertEqual(read_all(s), dict(anchor=0, seen=0, release=0, ready=0, deadline=0))

    def test_second_read_arms_and_accumulates_independently(self):
        s = fresh()
        self.finish_read_one(s)
        set_active(s, 2)
        self.assertEqual(arm(s, 2, T2), T2 | 1)
        self.assertEqual(arm(s, 2, T2 + 5000), T2 | 1, 'one arm per cookie')
        self.assertEqual(observe(s, 2, 2), 2)           # response first: no leftover ACK bit
        service_release(s, 2, 0)
        service_ready(s, 2, eligible=0)
        self.assertEqual(read_all(s), dict(anchor=T2 | 1, seen=2, release=0, ready=0, deadline=0))
        self.assertEqual(observe(s, 2, 1), 3)

    def test_stale_cookie_cannot_arm_record_release_commit_or_ready(self):
        s = fresh()
        self.finish_read_one(s)
        set_active(s, 2)
        arm(s, 2, T2)
        observe(s, 2, 1)
        service_release(s, 2, 0)
        commit(s, 2, T2 + 1_000_000)
        service_ready(s, 2, eligible=0)
        before = read_all(s)
        arm(s, 1, T2 + 12800)
        observe(s, 1, 2)
        service_release(s, 1, 3)
        commit(s, 1, T2 + 99_000)
        service_ready(s, 1)
        self.assertEqual(read_all(s), before)
        for name in CELLS:
            self.assertEqual(s.registers[(name, 0)]['cookie'], 2, name)

    def test_stale_cookie_reads_see_nothing_of_a_newer_association(self):
        s = fresh()
        set_active(s, 2)
        arm(s, 2, T2)
        observe(s, 2, 3)
        set_active(s, 1)
        self.assertEqual(read_all(s), dict(anchor=0, seen=0, release=0, ready=0, deadline=0))

    def test_cookie_zero_state_never_matches_a_minted_cookie(self):
        s = fresh()
        set_active(s, 1)
        self.assertEqual(read_all(s), dict(anchor=0, seen=0, release=0, ready=0, deadline=0))


class HeartbeatLoss(unittest.TestCase):
    code = re.sub(r'/\*.*?\*/|//[^\n]*', '', TEXT, flags=re.S)

    def test_no_pinned_service_record_remains(self):
        self.assertNotIn('heartbeat_work', self.code)
        self.assertEqual(self.code.count('ExpectedWorkRecord()'), 1)   # only the original-producer pin
        self.assertNotIn('service_expected', self.code)

    def test_service_passes_are_derived_from_the_packet_alone(self):
        s = fresh()
        for _ in range(5):          # five ticks whose service passes are all lost
            s.env.update({'m.service_operation': 1, 'm.service_phase': 0, 'm.service_role': 0})
            s.run(self.service_role_block())
            self.assertEqual(s.env['m.service_role'], 1)
        for phase, role in ((1, 2), (2, 2), (3, 3), (0, 0), (4, 0)):
            s.env.update({'m.service_operation': 2, 'm.service_phase': phase, 'm.service_role': 0})
            s.run(self.service_role_block())
            self.assertEqual(s.env['m.service_role'], role, phase)

    @classmethod
    def service_role_block(cls):
        text = fragment_text(TEXT)
        start = text.index('if(m.service_operation==1)')
        end = text.index('work.apply', start)
        return text[start:end]

    def test_next_tick_commits_release_after_an_earlier_tick_was_lost(self):
        s = fresh()
        set_active(s, 1)
        arm(s, 1, T1)
        observe(s, 1, 3)
        read_all(s)                  # tick 1 snapshot taken, its service passes never return
        read_all(s)                  # tick 2 snapshot
        service_release(s, 1, 3)     # tick 2 return pass
        self.assertEqual(read_all(s)['release'], 3)

    def test_heartbeat_return_parser_derives_phase_from_the_stage_field(self):
        state = self.code[self.code.index('state heartbeat_return'):]
        state = state[:state.index('state heartbeat_timer')]
        self.assertIn('md.service_phase = (bit<32>)hdr.service.stage', state)
        self.assertRegex(state, r'\(0, 1\)')
        self.assertRegex(state, r'\(0, 3\)')


if __name__ == '__main__':
    unittest.main()

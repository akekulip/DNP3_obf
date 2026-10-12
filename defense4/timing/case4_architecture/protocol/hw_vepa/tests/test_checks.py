"""Per-trial feature/outcome checks (checks.evaluate): computed only from the trial's own evidence, enforced by the
gate. Synthetic evidence for each violation, plus the real production evidence tree when it is present."""
import copy
import json
import sys
import unittest
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import checks  # noqa: E402
import campaign as cp  # noqa: E402

CONFIG = HERE.parent / 'campaign.json'
EXP = json.load(open(CONFIG))['expectations']
ROLES = ('n_ack_return', 't_in', 'hb_return', 'held_return')


def loop(extra=0):
    return {r: {'dev_port': 48, '$OctetsReceived': 1000 + extra, '$OctetsReceivedinGoodFrames': 1000}
            for r in ROLES}


def snap(outcomes, lp):
    return {'outcomes': dict(outcomes), 'loop_ports': lp}


def kind(n, lens, piggy=0):
    return {'logical_requests': n, 'complete': n, 'incomplete': 0, 'piggyback': piggy, 'req_crc_bad': 0,
            'resp_crc_bad': 0, 'resp_len': lens}


def evidence(padding=1, T=1, fixture='separate_ack', reads=10):   # noqa: C901
    """The evidence an ideal trial of this arm/fixture produces."""
    plen = [58] if padding else None
    read_len, sbo_len = (plen or [49]), (plen or [37])
    piggy = reads if fixture == 'piggyback' else 0
    ex = [{'kind': 'READ', 'resp_len': read_len[0], 'complete': True} for _ in range(reads)]
    ex += [{'kind': 'SELECT', 'resp_len': sbo_len[0], 'complete': True},
           {'kind': 'OPERATE', 'resp_len': sbo_len[0], 'complete': True}]
    out0 = {'OUT_ACK_COMMIT': 7, 'OUT_RESP_RELEASE': 7, 'OUT_OP_RELEASE': 1, 'OUT_ACK_FALLBACK': 0,
            'OUT_RESP_FALLBACK': 0}
    d = {'OUT_ACK_COMMIT': reads, 'OUT_RESP_RELEASE': reads, 'OUT_OP_RELEASE': 1} if T else \
        {'OUT_ACK_COMMIT': 0, 'OUT_RESP_RELEASE': 0, 'OUT_OP_RELEASE': 0}
    out1 = {k: out0.get(k, 0) + d.get(k, 0) for k in out0}
    return {
        'before': snap(out0, loop()), 'after': snap(out1, loop()),
        'master': {'success': True, 'reads_requested': reads, 'reads_completed': reads, 'all_reads_match_seed': True,
                   'reads': [{'completed': True, 'points_received': 23, 'matches_seed': True}] * reads},
        'outstation': {'select_real': 1, 'select_decoy': 0, 'operate_real': 1, 'operate_decoy': 0},
        'wire': {'returned_integrity': {'dnp3_crc_bad': [], 'tcp_checksum_bad': [], 'tcp_checksum_offloaded': []}},
        'timing': {'summary': {'READ': kind(reads, read_len, piggy), 'SELECT': kind(1, sbo_len),
                               'OPERATE': kind(1, sbo_len)}, 'exchanges': ex}}


def run(ev, padding=1, T=1, fixture='separate_ack', reads=10, allowed=None, exp=None):
    return checks.evaluate(exp or EXP, {'T': T, 'padding': padding}, fixture, reads, ev, allowed)


class IdealTrials(unittest.TestCase):
    def test_every_arm_and_fixture_of_ideal_evidence_passes(self):
        for pad in (0, 1):
            for T in (0, 1):
                for fx in ('separate_ack', 'piggyback'):
                    fails, obs = run(evidence(pad, T, fx), pad, T, fx)
                    self.assertEqual(fails, [], (pad, T, fx))

    def test_observed_values_are_recorded(self):
        fails, obs = run(evidence(1, 1), 1, 1)
        self.assertGreater(obs['growth_bytes'], 0)
        self.assertEqual(obs['outcomes']['OUT_ACK_COMMIT'], 10)
        self.assertEqual(obs['piggyback_fraction'], 0.0)
        self.assertEqual(obs['loop_octet_gap'], {r: 0 for r in ROLES})

    def test_padding_off_has_zero_growth(self):
        self.assertEqual(run(evidence(0, 1), 0, 1)[1]['growth_bytes'], 0)


class Violations(unittest.TestCase):
    def one(self, ev, needle, **kw):
        fails, _ = run(ev, **kw)
        self.assertTrue(any(needle in f for f in fails), (needle, fails))

    def test_padding_on_but_read_response_native(self):
        ev = evidence(1, 1)
        ev['timing']['summary']['READ']['resp_len'] = [49]
        self.one(ev, 'READ response length')

    def test_padding_on_but_sbo_response_native(self):
        ev = evidence(1, 1)
        ev['timing']['summary']['OPERATE']['resp_len'] = [37]
        self.one(ev, 'OPERATE response length')

    def test_padding_on_with_zero_growth(self):
        ev = evidence(1, 1)
        for e in ev['timing']['exchanges']:
            e['resp_len'] = {'READ': 49}.get(e['kind'], 37)
        self.one(ev, 'growth')

    def test_padding_off_but_responses_padded(self):
        ev = evidence(1, 1)
        self.one(ev, 'READ response length', padding=0)
        self.one(ev, 'growth', padding=0)

    def test_T_on_commit_release_count_mismatch(self):
        ev = evidence(1, 1)
        ev['after']['outcomes']['OUT_RESP_RELEASE'] -= 1
        self.one(ev, 'OUT_RESP_RELEASE')

    def test_T_on_missing_operate_release_when_sbo_ran(self):
        ev = evidence(1, 1)
        ev['after']['outcomes']['OUT_OP_RELEASE'] -= 1
        self.one(ev, 'OUT_OP_RELEASE')

    def test_T_on_fallback_on_the_on_time_fixture(self):
        ev = evidence(1, 1)
        ev['after']['outcomes']['OUT_ACK_FALLBACK'] += 1
        self.one(ev, 'OUT_ACK_FALLBACK')
        fails, _ = run(ev, fixture='piggyback')      # the fallback bound applies to separate_ack only
        self.assertFalse(any('FALLBACK' in f for f in fails))

    def test_T_off_with_release_outcomes(self):
        ev = evidence(1, 0)
        ev['after']['outcomes']['OUT_ACK_COMMIT'] += 3
        self.one(ev, 'OUT_ACK_COMMIT', T=0)

    def test_master_failure(self):
        ev = evidence()
        ev['master']['success'] = False
        self.one(ev, 'master')

    def test_missing_seed_values(self):
        ev = evidence()
        ev['master']['reads'][3] = {'completed': True, 'points_received': 22, 'matches_seed': True}
        self.one(ev, '23')

    def test_seed_mismatch(self):
        ev = evidence()
        ev['master']['all_reads_match_seed'] = False
        self.one(ev, 'seed')

    def test_decoy_and_missing_real_sbo(self):
        ev = evidence()
        ev['outstation']['operate_decoy'] = 1
        self.one(ev, 'decoy')
        ev = evidence()
        ev['outstation']['select_real'] = 0
        self.one(ev, 'select_real')

    def test_returned_checksum_or_crc_errors(self):
        ev = evidence()
        ev['wire']['returned_integrity']['tcp_checksum_bad'] = [4]
        self.one(ev, 'checksum')
        ev = evidence()
        ev['wire']['returned_integrity']['dnp3_crc_bad'] = [4]
        self.one(ev, 'CRC')

    def test_fixture_piggyback_fraction(self):
        ev = evidence(fixture='separate_ack')
        ev['timing']['summary']['READ']['piggyback'] = 5
        self.one(ev, 'piggyback fraction')
        ev = evidence(fixture='piggyback')
        ev['timing']['summary']['READ']['piggyback'] = 0
        self.one(ev, 'piggyback fraction', fixture='piggyback')

    def test_loop_octet_gap_fails_with_the_byte_count(self):
        ev = evidence()
        ev['after']['loop_ports']['t_in']['$OctetsReceived'] += 80
        fails, obs = run(ev)
        self.assertTrue(any('t_in' in f and '80' in f for f in fails), fails)
        self.assertEqual(obs['loop_octet_gap']['t_in'], 80)

    def test_loop_gap_is_a_delta_not_the_absolute_counter(self):
        ev = evidence()
        for s in ('before', 'after'):
            ev[s]['loop_ports']['t_in']['$OctetsReceived'] += 80       # a gap that predates the trial
        self.assertEqual(run(ev)[0], [])

    def test_per_build_allowed_gap(self):
        ev = evidence()
        ev['after']['loop_ports']['t_in']['$OctetsReceived'] += 80
        self.assertEqual(run(ev, allowed={'t_in': 80})[0], [])
        ev['after']['loop_ports']['t_in']['$OctetsReceived'] += 1
        self.assertTrue(run(ev, allowed={'t_in': 80})[0])

    def test_unreadable_loop_counters_fail(self):
        ev = evidence()
        ev['after']['loop_ports']['held_return'] = {'dev_port': 182, '$OctetsReceived': None,
                                                    '$OctetsReceivedinGoodFrames': None}
        self.one(ev, 'held_return')

    def test_missing_evidence_is_a_failure_not_a_crash(self):
        ev = evidence()
        del ev['after']
        self.one(ev, 'after snapshot')
        ev = evidence()
        ev['timing'] = None
        self.one(ev, 'timing')


class ConfigTable(unittest.TestCase):
    def test_table_lives_in_campaign_json_and_is_complete(self):
        for k in ('common', 'padding', 'T', 'fixture', 'native_len'):
            self.assertIn(k, EXP)
        self.assertEqual(EXP['padding']['1']['read_resp_len'], [58])
        self.assertEqual(EXP['padding']['0']['sbo_resp_len'], [37])

    def test_allowed_loop_gap_defaults_to_zero_per_build(self):
        cfg = cp.load_config(str(CONFIG))
        self.assertEqual(checks.allowed_gap(cfg['builds'][cfg['arms'][0]['build']]), {})

    def test_bad_allowed_gap_is_rejected(self):
        cfg = copy.deepcopy(cp.load_config(str(CONFIG)))
        cfg['builds'][cfg['arms'][0]['build']]['allowed_loop_octet_gap'] = {'t_in': -1}
        with self.assertRaises(ValueError):
            cp.validate_profile(cfg)
        cfg['builds'][cfg['arms'][0]['build']]['allowed_loop_octet_gap'] = {'nope': 1}
        with self.assertRaises(ValueError):
            cp.validate_profile(cfg)


REAL = HERE.parents[2] / 'integration' / 'evidence' / 'p2_production_01' / 'p_unshaped'


@pytest.mark.evidence_tree
class RealEvidence(unittest.TestCase):
    """The production unshaped run (padding on, T on, separate ACK, 50 READs): analyzers run for real."""
    def ev(self):
        import clrt_check, wire_check
        ev = checks.load_evidence_files(
            before=REAL / 'snb_p_unshaped.json', after=REAL / 'sna_p_unshaped.json', master=REAL / 'master.json',
            outstation=REAL / 'outstation.json')
        ev['timing'] = clrt_check.analyze(str(REAL / 'out.pcap'), str(REAL / 'in.pcap'))
        ev['wire'] = wire_check.analyze(str(REAL / 'out.pcap'), str(REAL / 'in.pcap'))
        return ev

    def test_known_t_in_gap_is_reported_with_its_byte_count_then_accepted_by_config(self):
        ev = self.ev()
        fails, obs = run(ev, reads=50)
        self.assertEqual([f for f in fails if 't_in' not in f], [], fails)
        self.assertTrue(any('t_in' in f and '80' in f for f in fails), fails)
        self.assertEqual(run(ev, reads=50, allowed={'t_in': 80})[0], [])


if __name__ == '__main__':
    unittest.main()

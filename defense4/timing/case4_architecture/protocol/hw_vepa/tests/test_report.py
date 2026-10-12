"""`campaign.py report RUN_DIR` / report.py: one table per fixture/arm/preset from a campaign run directory, with the
delta conventions of evidence/mirror_fix_silicon_01 (snapshot after minus before), plus A-B per paired condition."""
import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import campaign as cp  # noqa: E402
import clrt_check as cc  # noqa: E402
import report  # noqa: E402

ROLES = ('n_ack_return', 't_in', 'hb_return', 'held_return')
PORTS = {'n_ack_return': 48, 't_in': 180, 'hb_return': 181, 'held_return': 182}


def loop_block(frames, octets, bad=0):
    return {r: {'dev_port': PORTS[r], '$FramesTransmittedAll': frames[i], '$OctetsTransmittedTotal': octets[i],
                '$OctetsReceived': octets[i], '$OctetsReceivedinGoodFrames': octets[i] - bad}
            for i, r in enumerate(ROLES)}


def timing(clrt, ack, rt, retx=0, resp_lens=(58,)):
    n = len(clrt)
    kind = {'logical_requests': n, 'attempts': n + retx, 'retransmitted': retx, 'complete': n, 'incomplete': 0,
            'piggyback': 0, 'req_crc_bad': 0, 'resp_crc_bad': 0, 'resp_len': sorted(set(resp_lens)),
            'eligible_for_latency': n, 'clrt_us': cc.stats(clrt), 'rt_us': cc.stats(rt), 'ack_lat_us': cc.stats(ack)}
    ex = [{'kind': 'READ', 'resp_len': l, 'complete': True} for l in resp_lens for _ in range(n // len(resp_lens))]
    return {'summary': {'READ': kind}, 'exchanges': ex}


def make_trial(root, fixture, arm, label, preset, frames, octets, clrt, ack=(5500, 5510), rt=(6300, 6320), rewait=100,
               blk=None, stale=0, triggers=None, bad=0, retx=0, resp_lens=(58,)):
    d = Path(root) / fixture / arm / label
    (d / 'snapshots').mkdir(parents=True)
    zero = loop_block([0] * 4, [0] * 4)
    b = {'outcomes': {'OUT_HELD_REWAIT': 0, 'OUT_TOKEN_STALE': 0}, 'loop_ports': zero,
         'pktgen': {'READ': {'trigger_counter': 0, 'pkt_counter': 0}, 'OPERATE': {'trigger_counter': 0, 'pkt_counter': 0}},
         'diag': {'present': blk is not None, 'blocker_laps': {'ACK': 0, 'RESP': 0, 'OP': 0}, 'rewait': {}}}
    a = json.loads(json.dumps(b))
    a['outcomes'] = {'OUT_HELD_REWAIT': rewait, 'OUT_TOKEN_STALE': stale}
    a['loop_ports'] = loop_block(frames, octets, bad)
    rd = triggers or (len(clrt), 4 * len(clrt))
    a['pktgen'] = {'READ': {'trigger_counter': rd[0], 'pkt_counter': rd[1]},
                   'OPERATE': {'trigger_counter': 1, 'pkt_counter': 4}}
    if blk is not None:
        a['diag']['blocker_laps'] = {'ACK': blk[0], 'RESP': blk[1], 'OP': blk[2]}
    (d / 'snapshots' / ('%s_before.json' % label)).write_text(json.dumps(b))
    (d / 'snapshots' / ('%s_after.json' % label)).write_text(json.dumps(a))
    t = timing(list(clrt), list(ack), list(rt), retx, resp_lens)
    (d / 'timing.json').write_text(json.dumps(t))
    (d / 'wire.json').write_text(json.dumps({'unmatched_returned': [], 'duplicate_returned': [1],
                                             'returned_integrity': {'dnp3_crc_bad': [], 'tcp_checksum_bad': []}}))
    growth = sum(9 for _ in clrt) if 58 in resp_lens else 0
    return {'fixture': fixture, 'label': label, 'preset': preset, 'ok': True, 'reads': len(clrt),
            'observed': {'growth_bytes': growth}}


def make_run(root, trials_by_arm, pairs=None, gap_ns=800000):
    arms = {}
    for (fixture, arm), trials in trials_by_arm.items():
        arms[(fixture, arm)] = {'fixture': fixture, 'arm': arm, 'trials': trials}
    rec = {'run_id': 'c1', 'ok': True, 'arms': list(arms.values()),
           'effective': {'timing_params_ns': {'gap': gap_ns}, 'k': 2}}
    if pairs:
        rec['pairs'] = pairs
    (Path(root) / 'campaign_run.json').write_text(json.dumps(rec))


class Metrics(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = td.name
        self.clrt = [800, 805, 810, 815, 820, 900]
        t = make_trial(self.root, 'separate_ack', 'combined', 'c1_separate_ack_combined_t0', 'shape_3723',
                       frames=[10, 20, 30, 40], octets=[100, 200, 300, 400], clrt=self.clrt, rewait=77,
                       blk=(5, 6, 7), stale=2, bad=80, retx=1, triggers=(6, 24))
        make_run(self.root, {('separate_ack', 'combined'): [t]})
        self.m = report.load(self.root)[0]

    def test_loop_packets_and_bytes_are_summed_over_the_four_ports_with_per_port_values(self):
        self.assertEqual(self.m['loop_pkts'], 100)
        self.assertEqual(self.m['loop_bytes'], 1000)
        self.assertEqual(self.m['per_port']['t_in'], {'pkts': 20, 'bytes': 200})
        self.assertEqual(self.m['per_port']['held_return']['bytes'], 400)

    def test_rewaits_and_blocker_laps(self):
        self.assertEqual(self.m['rewaits'], 77)
        self.assertEqual(self.m['blocker_laps'], 18)

    def test_blocker_laps_absent_without_diag_counters(self):
        d = Path(self.root) / 'separate_ack' / 'combined' / 'c1_separate_ack_combined_t0' / 'snapshots'
        for n in ('before', 'after'):
            f = d / ('c1_separate_ack_combined_t0_%s.json' % n)
            s = json.loads(f.read_text())
            s['diag']['present'] = False
            f.write_text(json.dumps(s))
        self.assertIsNone(report.load(self.root)[0]['blocker_laps'])

    def test_clrt_distribution_and_both_sds(self):
        want = cc.stats(self.clrt)
        c = self.m['clrt']
        for k in ('median', 'iqr', 'p95', 'p99', 'sd_population', 'sd_sample'):
            self.assertEqual(c[k], want[k], k)

    def test_ack_and_response_latency_medians_and_p95(self):
        self.assertEqual(self.m['ack']['median'], cc.stats([5500, 5510])['median'])
        self.assertEqual(self.m['rt']['p95'], cc.stats([6300, 6320])['p95'])

    def test_intended_gap_error_uses_t_gap_from_the_run_record(self):
        self.assertEqual(self.m['gap_us'], 800)
        self.assertEqual(self.m['gap_error_median_us'], cc.stats(self.clrt)['median'] - 800)
        self.assertEqual(self.m['gap_error_p95_us'], cc.stats(self.clrt)['p95'] - 800)

    def test_completion_and_retransmissions(self):
        self.assertEqual((self.m['logical'], self.m['complete'], self.m['incomplete'], self.m['retransmitted']),
                         (6, 6, 0, 1))
        self.assertEqual(self.m['duplicate_returned'], 1)
        self.assertEqual(self.m['unmatched_returned'], 0)

    def test_padding_coverage_and_growth(self):
        self.assertEqual(self.m['padding_coverage'], 1.0)
        self.assertEqual(self.m['growth_bytes'], 54)

    def test_trigger_stale_and_bad_octet_counts(self):
        self.assertEqual(self.m['read_triggers'], 6)
        self.assertEqual(self.m['read_pkts'], 24)
        self.assertEqual(self.m['stale'], 2)
        self.assertEqual(self.m['bad_octets'], 80 * 4)             # the bad count is set on every port in the fixture

    def test_missing_files_become_none_not_a_crash(self):
        d = Path(self.root) / 'separate_ack' / 'combined' / 'c1_separate_ack_combined_t0'
        (d / 'timing.json').unlink()
        (d / 'snapshots' / 'c1_separate_ack_combined_t0_after.json').unlink()
        m = report.load(self.root)[0]
        self.assertIsNone(m['clrt'])
        self.assertIsNone(m['loop_pkts'])


class Tables(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = td.name
        a, b = 'shape_14892', 'shape_3723'
        mk = lambda fx, arm, lab, preset, pk, by, clrt, rw: make_trial(
            self.root, fx, arm, lab, preset, [pk] * 4, [by] * 4, clrt, rewait=rw)
        self.t0 = mk('separate_ack', 'combined', 'c1_separate_ack_combined_t0', a, 1000, 80000, [800, 810], 11)
        self.t1 = mk('separate_ack', 'combined', 'c1_separate_ack_combined_t1', b, 400, 30000, [820, 830], 5)
        self.t2 = mk('separate_ack', 'combined', 'c1_separate_ack_combined_t2', b, 410, 31000, [790, 800], 6)
        self.t3 = mk('separate_ack', 'combined', 'c1_separate_ack_combined_t3', a, 1100, 82000, [805, 815], 12)
        self.t4 = mk('piggyback', 'off', 'c1_piggyback_off_t4', None, 50, 4000, [5, 6], 0)
        pairs = [{'pair': 0, 'condition': {'delay_ms': 5, 'gap_ms': 0, 'start_delay_ms': 20, 'seed': 1},
                  'order': [a, b], 'labels': [self.t0['label'], self.t1['label']], 'ok': True},
                 {'pair': 1, 'condition': {'delay_ms': 5, 'gap_ms': 20, 'start_delay_ms': 40, 'seed': 2},
                  'order': [b, a], 'labels': [self.t2['label'], self.t3['label']], 'ok': True}]
        make_run(self.root, {('separate_ack', 'combined'): [self.t0, self.t1, self.t2, self.t3],
                             ('piggyback', 'off'): [self.t4]}, pairs)
        self.text = report.render(self.root)

    def test_one_table_per_fixture_arm_preset(self):
        heads = [l for l in self.text.splitlines() if l.startswith('== fixture')]
        self.assertEqual(heads, ['== fixture separate_ack | arm combined | preset shape_14892 ==',
                                 '== fixture separate_ack | arm combined | preset shape_3723 ==',
                                 '== fixture piggyback | arm off | preset (config default) =='])

    def test_tables_carry_the_requested_rows(self):
        for row in ('loop packets', 'loop bytes', 'port 48', 'port 182', 'orig re-waits', 'blocker laps',
                    'CLRT median', 'CLRT IQR', 'CLRT p95', 'CLRT p99', 'CLRT SD (population)', 'CLRT SD (sample)',
                    'req->ACK median', 'req->ACK p95', 'req->resp median', 'req->resp p95',
                    'gap error median', 'READs complete', 'retransmitted', 'padding coverage', 'growth bytes',
                    'READ triggers', 'READ gen pkts', 'stale tokens', 'bad octets'):
            self.assertIn(row, self.text, row)

    def test_a_minus_b_per_condition(self):
        diffs = [l for l in self.text.splitlines() if l.startswith('pair ')]
        self.assertEqual(len(diffs), 2)
        self.assertIn('A=shape_14892', self.text)
        p0 = [l for l in self.text.splitlines() if l.startswith('  A-B loop packets')][0]
        self.assertIn('2,400', p0)                                    # (1000-400)*4 ports
        p1 = [l for l in self.text.splitlines() if l.startswith('  A-B loop packets')][1]
        self.assertIn('2,760', p1)                                    # (1100-410)*4: A is the t3 run even though it ran second
        clrt0 = [l for l in self.text.splitlines() if l.startswith('  A-B CLRT median')][0]
        self.assertIn('-20', clrt0)                                  # 805 - 825

    def test_cli_subcommand_prints_the_same_report(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cp.main(['report', '--run-dir', self.root])
        self.assertEqual(rc, 0)
        self.assertEqual(buf.getvalue().strip(), self.text.strip())

    def test_missing_run_record_is_a_clean_error(self):
        with tempfile.TemporaryDirectory() as empty:
            with self.assertRaises(SystemExit):
                cp.main(['report', '--run-dir', empty])


REAL = HERE.parents[2] / 'integration' / 'evidence' / 'mirror_fix_silicon_01' / 's_r20'


@pytest.mark.evidence_tree
class RealSiliconRun(unittest.TestCase):
    """mirror_fix_silicon_01/s_r20 laid out as a campaign run dir; the report must reproduce its STATUS.md row."""
    def test_report_reproduces_the_status_table_row(self):
        import wire_check
        with tempfile.TemporaryDirectory() as td:
            label = 'c1_separate_ack_combined_t0'
            d = Path(td) / 'separate_ack' / 'combined' / label
            (d / 'snapshots').mkdir(parents=True)
            shutil.copy(REAL / 'snb_s_r20.json', d / 'snapshots' / ('%s_before.json' % label))
            shutil.copy(REAL / 'sna_s_r20.json', d / 'snapshots' / ('%s_after.json' % label))
            for f in ('master.json', 'outstation.json', 'out.pcap', 'in.pcap'):
                shutil.copy(REAL / f, d / f)
            (d / 'timing.json').write_text(json.dumps(cc.analyze(str(d / 'out.pcap'), str(d / 'in.pcap'))))
            (d / 'wire.json').write_text(json.dumps(wire_check.analyze(str(d / 'out.pcap'), str(d / 'in.pcap')), default=str))
            make_run(td, {('separate_ack', 'combined'): [{'fixture': 'separate_ack', 'label': label,
                                                          'preset': 'shape_14892', 'ok': True, 'reads': 20}]})
            m = report.load(td)[0]
            self.assertEqual(m['loop_pkts'], 8375)
            self.assertEqual(m['rewaits'], 1926)
            self.assertEqual((m['read_triggers'], m['read_pkts'], m['stale']), (20, 80, 0))
            self.assertEqual(m['clrt']['median'], 810)
            self.assertEqual(m['ack']['median'], 5505)
            self.assertEqual(m['rt']['median'], 6317)
            self.assertAlmostEqual(m['clrt']['sd_population'], 11.7, places=1)
            self.assertGreater(m['loop_bytes'], 0)
            self.assertEqual(m['bad_octets'], 0)
            self.assertIn('loop bytes', report.render(td))


if __name__ == '__main__':
    unittest.main()

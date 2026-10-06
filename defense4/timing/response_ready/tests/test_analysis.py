import unittest
from defense4.timing.response_ready import analyze

def row(i=1, **kw):
    r = dict(transaction_id=str(i), da_ms='5', requested_gap_ms='1', realized_gap_ms='0.999936', request_ns='10000000', ack_ns='15000000', response_ns='15999936', arrival_group='early', outcome='normal', body_equal='true')
    r.update(kw)
    return r

class AnalysisTests(unittest.TestCase):
    def test_loss_retained_and_coverage(self):
        a = analyze.analyze_rows([row(), row(2, outcome='failure', response_ns='', body_equal='false')])
        self.assertEqual(a['counts']['total'], 2)
        self.assertEqual(a['counts']['missing_response'], 1)
        self.assertFalse(a['accepted'])
        self.assertEqual(a['by_da']['5']['late']['coverage'], 'insufficient')

    def test_separate_groups_and_sample_variance(self):
        a = analyze.analyze_rows([row(), row(2, response_ns='16001936'), row(3, arrival_group='late')], 1, 1, 'custom')
        self.assertTrue(a['accepted'])
        self.assertAlmostEqual(a['by_da']['5']['early']['clrt_us']['sample_variance'], 2.0)
        self.assertEqual(a['by_da']['5']['late']['clrt_us']['sample_variance'], None)
        self.assertFalse(analyze.analyze_rows([row(), row(2, arrival_group='late')], 2)['accepted'])

    def test_corruption_outlier_not_dropped(self):
        for change in ({'body_equal':'false'}, {'response_ns':'16199936'}):
            a = analyze.analyze_rows([row(), row(2, arrival_group='late', **change)])
            self.assertFalse(a['accepted'])
            self.assertEqual(a['counts']['total'], 2)

    def test_missing_normal_is_retained(self):
        a = analyze.analyze_rows([row(response_ns='')], 1, 1, 'custom')
        self.assertEqual(a['counts']['total'], 1)
        self.assertEqual(a['counts']['missing_response'], 1)
        self.assertFalse(a['delivery_integrity_pass'])
        self.assertFalse(a['accepted'])

    def test_full_requires_four_das_and_unknown_outliers_count(self):
        rows = [row(), row(2, arrival_group='late')]
        self.assertFalse(analyze.analyze_rows(rows, 1, 1)['accepted'])
        rows.append(row(3, arrival_group='unknown', response_ns='16999936'))
        self.assertFalse(analyze.analyze_rows(rows, 1, 1, 'custom')['timing_pass'])
        self.assertEqual(analyze.analyze_rows(rows)['counts']['retransmit_unknown'], 3)

    def test_observed_latency_stats_keep_available_timestamps(self):
        rows = [row(), row(2, outcome='watchdog', ack_ns='17000000', response_ns='18000000'), row(3, outcome='failure', response_ns='')]
        report = analyze.analyze_rows(rows, 1, 1, 'custom')
        da = report['by_da']['5']
        self.assertEqual(da['all']['request_to_ack_us']['mean'], 5000)
        self.assertAlmostEqual(da['all']['request_to_response_us']['mean'], 5999.936)
        observed = da['all_observed_latency']
        self.assertEqual(observed['request_to_ack_us']['n'], 3)
        self.assertEqual(observed['request_to_response_us']['n'], 2)
        self.assertEqual(observed['request_to_ack_us']['max'], 7000)
        self.assertEqual(observed['request_to_response_us']['max'], 8000)

    def test_profile_floors_cannot_be_lowered(self):
        rows = [row(i, da_ms=str(da), arrival_group=group, retransmit_count='0') for i,(da,group) in enumerate(((d,g) for d in (5,10,15,20) for g in ('early','late')),1)]
        ids = [r['transaction_id'] for r in rows]
        full = analyze.analyze_rows(rows, 1, 1, 'full', ids)
        self.assertFalse(full['full_acceptance'])
        self.assertEqual(full['min_normal_samples'], 6000)
        self.assertEqual(full['min_group_samples'], 200)
        smoke = analyze.analyze_rows(rows, 1, 1, 'smoke', ids)
        self.assertFalse(smoke['accepted'])
        self.assertEqual(smoke['min_normal_samples'], 100)
        custom = analyze.analyze_rows(rows, 1, 1, 'custom', ids)
        self.assertTrue(custom['accepted'])
        self.assertFalse(custom['full_acceptance'])

    def test_reject_invalid(self):
        for rows in ([row(),row()], [row(ack_ns='9000000')], [row(response_ns='bad')], [row(requested_gap_ms='nan')], [row(arrival_group='inferred')]):
            with self.assertRaises(ValueError): analyze.analyze_rows(rows)

class CampaignEvidenceTests(unittest.TestCase):
    def test_full_manifest_and_retransmit_gates(self):
        rows = [row(i, da_ms=str(da), arrival_group=group, retransmit_count='0') for i,(da,group) in enumerate(((d, 'early' if i < 3000 else 'late') for d in (5,10,15,20) for i in range(6000)),1)]
        ids = [r['transaction_id'] for r in rows]
        self.assertTrue(analyze.analyze_rows(rows, 1, 2, 'full', ids)['full_acceptance'])
        self.assertFalse(analyze.analyze_rows(rows, 1, 2, 'full')['accepted'])
        missing = analyze.analyze_rows(rows[:-1], 1, 1, 'full', ids)
        self.assertEqual(missing['missing_transaction_ids'], [ids[-1]])
        self.assertFalse(missing['accepted'])
        rows[0]['retransmit_count'] = ''
        self.assertFalse(analyze.analyze_rows(rows, 1, 2, 'full', ids)['accepted'])

    def test_smoke_separate_and_order_failure_retained(self):
        rows = [row(i, retransmit_count='0') for i in range(100)]
        ids = [r['transaction_id'] for r in rows]
        report = analyze.analyze_rows(rows, 200, 100, 'smoke', ids)
        self.assertTrue(report['accepted'])
        self.assertFalse(report['full_acceptance'])
        self.assertEqual(report['subgroup_coverage'], 'insufficient')
        rows[0]['response_ns'] = '14999999'
        rows[0]['outcome'] = 'failure'
        report = analyze.analyze_rows(rows, 200, 100, 'smoke', ids)
        self.assertEqual(report['counts']['total'], 100)
        self.assertEqual(report['counts']['ordering_violations'], 1)
        self.assertFalse(report['accepted'])

if __name__ == '__main__': unittest.main()

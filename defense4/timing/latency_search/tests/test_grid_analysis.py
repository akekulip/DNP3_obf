from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import grid_analysis as a
import grid_report as report
import grid_watch as watch


def test_pairs_use_only_their_distinct_off_blocks():
    pairs = [dict(round=0, policy=n, protected=n+'p', native=n+'off') for n in ('a', 'b')]
    rows = [dict(block=p[k], replicate=0, arm=arm,
                 policy_name=p['policy'] if arm=='obfuscated' else 'OFF')
            for p in pairs for k, arm in (('protected', 'obfuscated'), ('native', 'native'))]
    assert [r['block'] for r in a.select_rows(rows, pairs, 'b')] == ['bp', 'boff']
    for field, value in (('replicate', 1), ('arm', 'native'), ('policy_name', 'a')):
        broken = deepcopy(rows)
        broken[2][field] = value
        with pytest.raises(ValueError):
            a.select_rows(broken, pairs, 'b')


def attacks():
    protocol = a.campaign.protocol()
    protocol['bootstrap_resamples'] = 100
    results = {}
    for name in protocol['policy_names']:
        tasks = {}
        for task, classes in protocol['tasks'].items():
            chance = 1/len(classes)
            records = [dict(scenario=scenario, feature=feature, model='logistic', pool=1,
                            groups=protocol['test_rounds'], fold_scores=[accuracy]*60)
                       for scenario, feature, accuracy in (
                           ('fixed_on_native', 'ack_clrt', 1.),
                           ('adaptive_on_obfuscated', 'ack_clrt', chance),
                           ('adaptive_on_offset_residuals', 'clrt', chance+.01),
                           ('adaptive_on_obfuscated', 'request_gap', .99))]
            tasks[task] = dict(records=records)
        results[name] = dict(tasks=tasks)
    return protocol, results


def test_joint_bounds_include_levels_and_all_policies_but_separate_cadence():
    p, results = attacks()
    b = a.joint_bounds(results, p)
    for task, value in b.items():
        assert value['n_policy_attack_comparisons'] == 8
        assert value['shared_margin'] == pytest.approx(0.)
        for r in value['per_policy'].values():
            assert r['passes']
            assert r['strongest_attack']['scenario'] == 'adaptive_on_offset_residuals'
            assert r['max_accuracy'] == pytest.approx(value['chance']+.01)
    assert not any(r['passes'] for t in a.joint_bounds(results, p, 'all_timing').values()
                   for r in t['per_policy'].values())
    missing = deepcopy(results)
    del missing[p['policy_names'][0]]
    with pytest.raises(ValueError):
        a.joint_bounds(missing, p)
    results[p['policy_names'][0]]['tasks']['three_class']['records'][1]['groups'] = list(reversed(p['test_rounds']))
    with pytest.raises(ValueError):
        a.joint_bounds(results, p)


def test_shared_bootstrap_reproducible_and_nonzero():
    p, results = attacks()
    for idx, name in enumerate(p['policy_names']):
        results[name]['tasks']['three_class']['records'][2]['fold_scores'] = [.2, .6]*30
    bounds = a.joint_bounds(results, p)
    assert bounds == a.joint_bounds(results, p)
    assert bounds['three_class']['shared_margin'] > 0
    assert len({round(r['upper_bound']-r['max_accuracy'], 12)
                for r in bounds['three_class']['per_policy'].values()}) == 1


def test_selection_requires_both_tasks_then_latency_tiebreaks():
    p, results = attacks()
    bounds = a.joint_bounds(results, p)
    names = p['policy_names']
    latencies = {n: dict(worst_added_median_ms=1., worst_p99_ms=20-i, center_da_ms=d)
                 for i, (n,d) in enumerate(zip(names, p['delays_ms']))}
    assert a.rank_policies(bounds, latencies)['selected_policy'] == names[-1]
    bounds['read_select']['per_policy'][names[-1]]['passes'] = False
    assert a.rank_policies(bounds, latencies)['selected_policy'] == names[-2]
    for r in bounds['three_class']['per_policy'].values():
        r['passes'] = False
    assert a.rank_policies(bounds, latencies)['selected_policy'] is None


def test_coverage_weights_joint_deadlines_and_ignores_protected_rows():
    plan = dict(center_da_ms=5, entries=[
        dict(low=0, high=63, d_ticks=4000000, da_dr_ticks=5000000),
        dict(low=64, high=255, d_ticks=6000000, da_dr_ticks=7000000)])
    rows = [dict(arm='native', txn_class=op, replicate=0, ack_ms=ack, rt_ms=rt)
            for op in report.OPS for ack, rt in ((4.,5.), (5.,6.), (7.,7.))]
    rows += [dict(arm='obfuscated', txn_class=op, replicate=0, ack_ms=0., rt_ms=0.) for op in report.OPS]
    for r in report.coverage(rows, plan).values():
        assert r['native_n'] == 3
        assert r['beyond_da_center_count'] == 2
        assert r['estimated_response_availability'] == pytest.approx(2.5/3)
        assert r['estimated_joint_ack_response_availability'] == pytest.approx(1.75/3)
        assert r['by_round_joint_availability'] == {'0': pytest.approx(1.75/3)}
    plan['entries'].pop()
    with pytest.raises(ValueError):
        report.coverage(rows, plan)


def test_training_snapshot_requires_exact_completed_training_labels(tmp_path):
    import json
    p = a.campaign.protocol()
    schedule = a.campaign.rc.build_schedule(random_plan_paths=[Path(n+'.json') for n in a.campaign.names()],
        repeats=100, seed=a.campaign.SEED, off_every=1, count=100)
    (tmp_path/'protocol.json').write_text(json.dumps(p))
    (tmp_path/'pairing.json').write_text(json.dumps(a.campaign.pairing(schedule)))
    progress = [dict(label=b.label) for b in schedule]
    labels = watch.training_labels(tmp_path, progress)
    assert len(labels) == 320
    assert set(labels) == {b.label for b in schedule[:320]}
    with pytest.raises(ValueError):
        watch.training_labels(tmp_path, progress[1:])
    with pytest.raises(ValueError):
        watch.training_labels(tmp_path, progress+[progress[0]])


def test_final_requires_all_blocks_and_restoration():
    good = dict(completed_blocks=800, configuration_restored=True, error=None)
    watch.verify_final(good, 800)
    for key, value in (('completed_blocks', 799), ('configuration_restored', False), ('error', 'failed')):
        with pytest.raises(RuntimeError):
            watch.verify_final(dict(good, **{key:value}), 800)


def test_report_integration_preserves_primary_criterion_and_variance(tmp_path, monkeypatch):
    """Exercise report assembly using explicit synthetic fixtures, never hardware evidence."""
    import json
    p, records = attacks()
    run = tmp_path/'synthetic_run'
    out = tmp_path/'synthetic_results'
    (run/'plans').mkdir(parents=True)
    (out/'final').mkdir(parents=True)
    subsets = {}
    for n, d in zip(p['policy_names'], p['delays_ms']):
        rows = []
        for rep in (40, 41):
            for op in report.OPS:
                for arm in ('native', 'obfuscated'):
                    for i in range(2):
                        rows.append(dict(replicate=rep, txn_class=op, arm=arm,
                            rt_ms=3+i if arm=='native' else d+1+i,
                            ack_ms=1 if arm=='native' else d, clrt_ms=1+i,
                            ack_minus_selected_ms=.1, response_minus_selected_ms=.1,
                            selected_da_ms=d, selected_gap_ms=1, selected_r_ms=d+1))
        subsets[n] = (rows, a.policy_protocol(n, p), {})
        plan = dict(center_da_ms=d, entries=[dict(low=0, high=255,
                    d_ticks=d*1000000, da_dr_ticks=(d+1)*1000000)])
        (run/'plans'/(n+'.json')).write_text(json.dumps(plan))
        (out/n/'final').mkdir(parents=True)
        (out/n/'final/attacks_heldout.json').write_text(json.dumps(records[n]))
    measurement = out/'final/measurements.json'
    transactions = out/'final/primarytransactions.csv'
    measurement.write_text(json.dumps(dict(row_count=96, blocks={'synthetic':dict(capture=dict(dropped_packets=0))})))
    transactions.write_text('synthetic fixture; load explicitly mocked\n')
    (run/'protocol.json').write_text(json.dumps(p))
    attack_doc = dict(protocol=p, complete_attack_coverage=True,
        measurements_sha256=a.core.sha(measurement), transactions_sha256=a.core.sha(transactions),
        policy_results_sha256={n:a.core.sha(out/n/'final/attacks_heldout.json') for n in subsets},
        primary_ack_clrt=a.joint_bounds(records,p), all_timing_diagnostic=a.joint_bounds(records,p,'all_timing'))
    (out/'grid_attacks.json').write_text(json.dumps(attack_doc))
    (out/'final/tcp_audit.json').write_text(json.dumps(dict(measurements_sha256=a.core.sha(measurement),flagged_frame_count=2)))
    monkeypatch.setattr(a, 'load', lambda *args: (p, subsets))
    # Plot rendering is checked separately; inspect the arguments the report actually sends.
    plotted = []
    monkeypatch.setattr(report, 'plot_mechanism', lambda *args: None)
    monkeypatch.setattr(report, 'plot_attacks', lambda doc,bounds,path,stem: plotted.append((stem,bounds)))
    monkeypatch.setattr(report.figures_random, 'generate', lambda *args: None)
    result = report.generate(run,out)
    assert result['selection']['selected_policy'] == p['policy_names'][0]
    assert not any(r['passes'] for task in attack_doc['all_timing_diagnostic'].values() for r in task['per_policy'].values())
    assert result['retransmission_flagged_frames'] == 2
    assert result['policies'][p['policy_names'][0]]['timing']['READ']['clrt_variance_ratio'] == pytest.approx(1.)
    assert result['latencies'][p['policy_names'][0]]['worst_added_median_ms'] == 3.
    assert 'not measured switch arrival' in result['coverage_interpretation']
    assert [stem for stem,_ in plotted] == ['grid_ack_clrt_tradeoff','grid_all_timing_diagnostic']
    assert json.loads((out/'grid_report.json').read_text()) == result
    # Changed capture/model evidence must invalidate reporting.
    transactions.write_text('changed')
    with pytest.raises(ValueError, match='differ from measurement'):
        report.generate(run,out)

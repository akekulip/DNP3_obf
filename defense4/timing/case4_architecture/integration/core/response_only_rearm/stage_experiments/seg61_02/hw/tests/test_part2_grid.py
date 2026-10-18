"""part2_grid.py and the Part 2 configs it governs (2026-10-18; prepared only, never run)."""
import glob
import importlib.util
import json
from pathlib import Path

HW = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('part2_grid', HW / 'part2_grid.py')
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
MS = g.MS


def test_the_grid_is_the_reconciled_one():
    by = {c[0]: c[1:] for c in g.CONDITIONS}
    assert by['ref_r30'] == (2 * MS, 950_000, 30 * MS)                    # the qualified setting, unchanged
    assert [by['da%02d_g100' % d][0] for d in (5, 10, 15, 20)] == [d * MS for d in (5, 10, 15, 20)]   # historical DA
    assert {by['da%02d_g100' % d][1] for d in (5, 10, 15, 20)} == {1 * MS}                            # D = 1 ms
    assert [by[c][1] for c in ('da10_g095', 'da10_g200', 'da10_g400', 'da10_g800')] == [950_000, 2 * MS, 4 * MS, 8 * MS]
    assert all(r == g.READINESS_NS for name, _d, _g, r in g.CONDITIONS if name != 'ref_r30')


def test_every_condition_passes_validator_and_implementation_rules():
    for name, da, gap, readiness in g.CONDITIONS:
        assert g.check(g.params(da, gap, readiness)) == [], name


def test_the_implementation_rule_catches_a_readiness_that_preempts_d():
    """readiness below max(da, L) + gap + slack would release the response by fallback before a_commit + gap."""
    p = g.params(20 * MS, 8 * MS, 30 * MS)
    assert any(x.startswith('implementation:') for x in g.check(p))
    assert g.check(g.params(2 * MS, 950_000, 30 * MS)) == []               # the qualified setting is clear of it


def test_validator_rules_are_enforced():
    p = g.params(10 * MS, 1 * MS, g.READINESS_NS)
    assert any('op_j < pb' in x for x in g.check(dict(p, pb=1 * MS)))
    assert any('readiness <= cap' in x for x in g.check(dict(p, cap=30 * MS)))
    assert g.check({'da': 1})[0].startswith('missing')


def test_generated_configs_match_the_grid_and_the_rotation():
    files = sorted(glob.glob(str(HW / 'config' / 'part2_m10_*.json')))
    assert len(files) == 5 * len(g.CONDITIONS)
    ports = []
    for f in files:
        d = json.load(open(f))
        cond = d['part2']['condition']
        _n, da, gap, readiness = next(c for c in g.CONDITIONS if c[0] == cond)
        t = d['timing_params_ns']
        assert {k: t[k] for k in ('da', 'gap', 'readiness', 'pb', 'op_j')} == {
            k: g.params(da, gap, readiness)[k] for k in ('da', 'gap', 'readiness', 'pb', 'op_j')}
        assert g.check_config(d) == []
        assert d['fixture']['delay_ms'] == 5                         # one L for every block (code review C1)
        assert not any('3 ms' in n or '8 ms' in n or '500 READ' in n for n in d['_notes']), f  # no stale block notes
        assert d['ctl_timing_identity']['source_sha256'].startswith('d9b84fcc')           # the frozen m10_03 source
        r = d['traffic']['master_port_range']
        ports.append((cond, d['part2']['role'], r['first'], r['last']))
        if d['part2']['role'] == 'campaign':
            assert sorted(a['name'] for a in d['arms']) == ['combined', 'off', 'size_only', 'timing_only']
        else:
            assert [a['name'] for a in d['arms']] == ['combined']
    # the three campaign blocks of a condition share one range and run one after another (as every b1-b3 family
    # does); across conditions and roles no port is shared, and all are clear of every earlier range
    spans = {(c, role): (a, b) for c, role, a, b in ports}
    assert len({(c, role) for c, role, _a, _b in ports}) == len(spans) == 3 * len(g.CONDITIONS)
    flat = [p for a, b in spans.values() for p in range(a, b + 1)]
    assert len(flat) == len(set(flat)) and min(flat) >= 60000


def test_operate_request_to_ack_includes_j_and_the_rule_covers_it():
    """Code review H1: OPERATE's ACK commits only after its command was held for J and answered, so request->ACK is
    max(da, L + J); the readiness rule includes J, and normalization is stated per kind."""
    assert g.normalizes(2 * MS) == {'READ': False, 'SELECT': False, 'OPERATE': False}
    assert g.normalizes(5 * MS) == {'READ': False, 'SELECT': False, 'OPERATE': False}   # equality is not enough
    assert g.normalizes(10 * MS) == {'READ': True, 'SELECT': True, 'OPERATE': True}
    tight = dict(g.params(2 * MS, 950_000, 30 * MS), readiness=12 * MS, cap=40 * MS)
    assert any(x.startswith('implementation:') for x in g.check(tight))   # 5 + 2.4 + 0.95 + 5 = 13.35 ms > 12 ms


def test_a_config_with_another_fixture_delay_fails(tmp_path):
    cfg = json.load(open(sorted(glob.glob(str(HW / 'config' / 'part2_m10_*.json')))[0]))
    cfg['fixture']['delay_ms'] = 8
    assert any('not the grid L' in x for x in g.check_config(cfg))

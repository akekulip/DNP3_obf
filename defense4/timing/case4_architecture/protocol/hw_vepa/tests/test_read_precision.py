"""Absolute READ CLRT error is gated against the configured gap, with a declared denominator."""
import pytest

from test_checks import EXP, evidence
import checks


def rows(values):
    return {'exchanges': [{'kind': 'READ', 'complete': True, 'piggyback': False,
                           'attempts': 1, 'clrt_us': value, 't_req': i} for i, value in enumerate(values)]}


def test_non_aligned_gap_uses_absolute_errors_in_both_tails():
    obs = checks.read_precision(rows([950] * 18 + [850, 1050]), 950000)
    assert obs['eligible'] == 20
    assert obs['absolute_error_us']['p99'] == 100
    assert obs['signed_error_us']['min'] == -100
    assert obs['signed_error_us']['max'] == 100
    assert obs['pass']


def test_negative_tail_cannot_pass_using_signed_positive_percentile():
    obs = checks.read_precision(rows([800] * 19 + [650]), 800000)
    assert obs['absolute_error_us']['p99'] == 150
    assert not obs['pass']


def test_short_diagnostic_run_cannot_establish_precision():
    obs = checks.read_precision(rows([800]), 800000)
    assert obs['eligible'] == 1
    assert not obs['pass']


def test_denominator_and_mutually_exclusive_exclusions_are_retained():
    t = rows([800] * 20)
    t['exchanges'] += [dict(t['exchanges'][0], complete=False), dict(t['exchanges'][0], piggyback=True),
                       dict(t['exchanges'][0], attempts=2), dict(t['exchanges'][0], clrt_us=None),
                       {'kind': 'SELECT', 'complete': True}]
    obs = checks.read_precision(t, 800000)
    assert obs['read_rows'] == 24
    assert obs['eligible'] == 20
    assert obs['excluded'] == {'incomplete': 1, 'piggyback': 1, 'multiple_attempts': 1, 'missing_clrt': 1}
    assert obs['pass']


def test_clean_t1_separate_ack_block_enforces_precision():
    ev = evidence(reads=20)
    ev['timing'].update(rows([800] * 19 + [650]))
    fails, obs = checks.evaluate(EXP, {'T': 1, 'padding': 1}, 'separate_ack', 20, ev, gap_ns=800000)
    assert any('READ precision' in f for f in fails)
    assert not obs['read_precision']['pass']


@pytest.mark.parametrize('arm,fixture,precision', [({'T': 0, 'padding': 1}, 'separate_ack', True),
                                                ({'T': 1, 'padding': 1}, 'piggyback', True),
                                                ({'T': 1, 'padding': 1}, 'separate_ack', False)])
def test_feature_off_piggyback_and_explicit_diagnostic_profiles_are_not_precision_gated(arm, fixture, precision):
    ev = evidence(T=arm['T'], fixture=fixture)
    fails, obs = checks.evaluate(EXP, arm, fixture, 10, ev, gap_ns=800000, precision=precision)
    assert not any('READ precision' in f for f in fails)


def test_piggyback_uses_response_fallback_and_still_generates_each_read():
    ev = evidence(fixture='piggyback')
    before, after = ev['before']['outcomes'], ev['after']['outcomes']
    after['OUT_ACK_COMMIT'] = before['OUT_ACK_COMMIT']
    after['OUT_RESP_RELEASE'] = before['OUT_RESP_RELEASE']
    after['OUT_RESP_FALLBACK'] = before['OUT_RESP_FALLBACK'] + 10
    fails, observed = checks.evaluate(EXP, {'T': 1, 'padding': 1}, 'piggyback', 10, ev, mirror_k=2)
    assert not fails, fails
    assert observed['pktgen']['READ'] == {'triggers': 10, 'pkts': 40}


def test_piggyback_ack_fallback_is_never_allowed():
    ev = evidence(fixture='piggyback')
    ev['after']['outcomes']['OUT_ACK_FALLBACK'] += 1
    fails, _ = checks.evaluate(EXP, {'T': 1, 'padding': 1}, 'piggyback', 10, ev)
    assert any('OUT_ACK_FALLBACK' in f for f in fails)


def test_read_only_profile_requires_zero_operate_release():
    ev = evidence()
    ev['outstation'].update(select_real=0, operate_real=0)
    for kind in ('SELECT', 'OPERATE'):
        ev['timing']['summary'].pop(kind)
    ev['timing']['exchanges'] = [row for row in ev['timing']['exchanges'] if row['kind'] == 'READ']
    fails, _ = checks.evaluate(EXP, {'T': 1, 'padding': 1}, 'separate_ack', 10, ev, run_sbo=False)
    assert any('OUT_OP_RELEASE' in f for f in fails)

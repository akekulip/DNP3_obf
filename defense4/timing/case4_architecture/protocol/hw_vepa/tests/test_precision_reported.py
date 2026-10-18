"""Evaluation option 1 (Philip, 2026-10-18): host-observed CLRT precision is reported, not a block gate, only for
configs with evaluation.host_precision_gated == False; every other failure stays a hard failure."""
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('precision_campaign', HERE / 'campaign.py')
campaign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign)

FLAG = dict(purpose='timing_precision_characterization', host_precision_gated=False)


def record(*failures, allowed=True):
    soft = dict(ok=False, failures=list(failures), continuation=dict(allowed=allowed))
    return dict(arms=[dict(trials=[dict(ok=True)]), dict(trials=[soft])])


def test_a_precision_only_miss_is_reported_when_the_config_says_so():
    assert campaign.precision_only_soft(record('SELECT precision: p99 1076 us (maximum100)'), FLAG)
    assert campaign.precision_only_soft(record('OPERATE precision: x', 'READ precision: y'), FLAG)


def test_j_hold_piggyback_or_any_other_failure_stays_hard():
    for other in ('OPERATE hold: realized J below op_j', 'PIGGYBACK latency: x', 'master reads_completed 64 != 65'):
        assert not campaign.precision_only_soft(record('SELECT precision: x', other), FLAG)


def test_without_the_explicit_flag_or_continuation_nothing_changes():
    miss = 'SELECT precision: x'
    assert not campaign.precision_only_soft(record(miss), dict(purpose='timing_precision_characterization'))
    assert not campaign.precision_only_soft(record(miss), dict(purpose='qualification', host_precision_gated=False))
    assert not campaign.precision_only_soft(record(miss), dict(FLAG, host_precision_gated=True))
    assert not campaign.precision_only_soft(record(miss, allowed=False), FLAG)
    assert not campaign.precision_only_soft(dict(arms=[dict(trials=[dict(ok=True)])]), FLAG)   # nothing soft

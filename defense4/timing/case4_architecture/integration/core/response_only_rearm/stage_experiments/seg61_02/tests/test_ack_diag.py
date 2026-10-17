"""ack_diag.py localization rules on a retained trial with a synthetic m9d snapshot (round-2 review findings)."""
import importlib.util
import json
import shutil
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ack_diag', HERE.parent / 'analysis/ack_diag.py')
ad = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ad)
RUN = HERE.parent / 'evidence/hw_campaigns/ctl_m9_qual_repeat_sbo_950_b1'
TRIAL = 'separate_ack/timing_only/ctl_m9_qual_repeat_sbo_950_b1_separate_ack_timing_only_t0'


def test_signed32_keeps_a_response_before_its_ack_negative():
    assert ad.signed32(950_000) == 950_000
    assert ad.signed32(-26_000) == -26_000 and ad.signed32((1 << 32) - 26_000) == -26_000


def instrumented_copy(tmp_path, gap_ns_for_127=None, with_diag=True):
    run = tmp_path / RUN.name
    trial = run / TRIAL
    trial.mkdir(parents=True)
    for f in ('timing.json', 'in.pcap'):
        shutil.copy2(RUN / TRIAL / f, trial / f)
    (trial / 'snapshots').mkdir()
    record = json.loads((RUN / 'campaign_run.json').read_text())
    record['source_identity']['build_sources'] = {'ctl_timing_m9d_01': {'source_sha256': ad.M9D_SOURCE}}
    (run / 'campaign_run.json').write_text(json.dumps(record))
    rows = ad.trial_rows(trial, True)
    entries = {}
    for r in rows:
        gap = gap_ns_for_127 if (r['index'] == 127 and gap_ns_for_127 is not None) else 950_000
        entries[str(r['ack'] & 0x3fff)] = [1_000_000, (1_000_000 + gap) & 0xffffffff]
    snap = {'n_counters': {}}
    if with_diag:
        snap['egress_diag'] = dict(entries=entries)
    (trial / 'snapshots' / 'x_after.json').write_text(json.dumps(snap))
    return run


def tail_127(run):
    t = ad.analyse(run)['trials'][0]
    return next(x for x in t['tails'] if x['index'] == 127), t


def test_switch_on_time_means_the_delay_is_downstream_of_the_egress_parser(tmp_path):
    x, t = tail_127(instrumented_copy(tmp_path))
    assert t['matched'] == t['exchanges'] == 193 and x['localized'] == 'downstream of the egress parser'


def test_switch_late_ack_means_at_or_before_the_egress_parser(tmp_path):
    x, _t = tail_127(instrumented_copy(tmp_path, gap_ns_for_127=-26_000))
    assert x['switch_clrt_us'] == -26.0 and x['localized'] == 'at or before the egress parser'


def test_an_instrumented_block_without_its_snapshot_is_unmatched_not_control(tmp_path):
    x, _t = tail_127(instrumented_copy(tmp_path, with_diag=False))
    assert x['localized'].startswith('unmatched') and 'no egress_diag' in x['localized']


def test_the_retained_control_block_stays_control():
    assert ad.instrumented(RUN) is False
    t = ad.analyse(RUN)['trials']
    assert [x['localized'] for tr in t for x in tr['tails']] == ['no instrument (control)']

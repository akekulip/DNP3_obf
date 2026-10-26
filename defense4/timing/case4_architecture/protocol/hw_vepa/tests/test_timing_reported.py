"""Host-observed timing is reported, never gated (Philip, 2026-10-25).

Derived-evidence mutation tests: each starts from a COPY (tmp_path) of a retained passing ctl_timing m3 trial,
derives the evidence the campaign gate reads (timing.json rows; hold_check.analyze of the copied captures), shifts
one derived timing metric, and checks that checks.evaluate still passes and reports the CLRT, and that the standards
artifact carries no timing block. Correctness checks (OPERATE delivery, generation exhaustion) still fail the trial.
Retained evidence is read only.
"""
import copy
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import checks  # noqa: E402
import hold_check  # noqa: E402
import standards  # noqa: E402

# A private copy of campaign.py: test_campaign_run.py replaces Campaign._load_standards_checker and
# standards_observed with fakes at import time, and these tests need the real artifact path in the same process.
_spec = importlib.util.spec_from_file_location('campaign_timing_reported', HERE.parent / 'campaign.py')
cp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cp)

S = HERE.parents[2] / 'integration/core/response_only_rearm/stage_experiments/seg61_02'
RUNS = S / 'evidence/hw_campaigns'
CASES = {'separate_ack': ('ctl_timing_repeat_sbo_950_b1_02', 'ctl_timing_repeat_sbo_950_b1.json'),
         'piggyback': ('ctl_timing_piggyback_950_b1', 'ctl_timing_piggyback_950_b1.json')}


def retained_trial(run):
    hits = sorted(p.parent for p in (RUNS / run).rglob('trial.json') if '/combined/' in str(p))
    return hits[0] if hits else None


def _present():
    return all(retained_trial(run) is not None and (retained_trial(run) / 'in.pcap').is_file()
               and (S / 'hw/config' / cfg).is_file() for run, cfg in CASES.values())


pytestmark = pytest.mark.skipif(not _present(), reason='retained ctl_timing m3 trials or configs absent')


class Trial:
    """A copied trial with its config, arm, derived evidence and a campaign object for the artifact path."""

    def __init__(self, tmp_path, fixture):
        run, cfg_name = CASES[fixture]
        src = retained_trial(run)
        self.dir = tmp_path / src.name
        shutil.copytree(src, self.dir, ignore=shutil.ignore_patterns('*.log', 'standards*.json', 'profile_verdict.json'))
        self.fixture = fixture
        self.cfg = json.loads((S / 'hw/config' / cfg_name).read_text())
        self.arm = next(a for a in self.cfg['arms'] if a['name'] == 'combined')
        self.build = self.cfg['builds'][self.arm['build']]
        self.trial = json.loads((self.dir / 'trial.json').read_text())
        self.trial = {k: self.trial[k] for k in ('fixture', 'label', 'master_port', 'reads')}
        label = self.trial['label']
        self.ev = checks.load_evidence_files(
            before=str(self.dir / 'snapshots' / ('%s_before.json' % label)),
            after=str(self.dir / 'snapshots' / ('%s_after.json' % label)),
            master=str(self.dir / 'master.json'), outstation=str(self.dir / 'outstation.json'),
            wire=str(self.dir / 'wire.json'), timing=str(self.dir / 'timing.json'))
        self.ev['hold'] = hold_check.analyze(self.dir / 'out.pcap', self.dir / 'in.pcap', self.trial['master_port'])
        c = object.__new__(cp.Campaign)
        c.cfg, c.run_id, c.record = self.cfg, run, {'run_id': run}
        c.config_sha256 = standards.effective_config_hash(self.cfg)
        c.bound = {self.arm['build']: self.build['hashes']}
        self.campaign = c

    def evaluate(self, ev=None):
        t = self.cfg['timing_params_ns']
        return checks.evaluate(self.cfg['expectations'], self.arm, self.fixture, self.trial['reads'], ev or self.ev,
                               {}, self.cfg['service']['k'], 0,
                               run_sbo=checks.sbo_count(self.cfg['traffic']), repeated=True,
                               control_timed=True, piggyback_bound=True, op_j_ns=t['op_j'],
                               gen_exhausted_outcome=self.build.get('gen_exhausted_outcome'))

    def artifact(self, fails):
        """standards.json through the campaign's own observed path, written and reloaded from JSON."""
        c = self.campaign
        observed = c.standards_observed(
            self.ev, list(fails), transport_ok=True, select_ok=True, operate_ok=True, aggregate_ok=not fails,
            checker_result=c.run_standards_checker(str(self.dir), self.trial, self.arm))
        context = c.standards_context(self.trial, self.arm)
        context.update(master_port=self.trial['master_port'])
        captures = c.standards_captures(str(self.dir), {'out': {'path': str(self.dir / 'out.pcap')},
                                                        'in': {'path': str(self.dir / 'in.pcap')}})
        path = self.dir / 'standards.json'
        path.write_text(json.dumps(standards.build_standards_artifact(context, captures, observed), default=str))
        return json.loads(path.read_text()), context, captures

    def validate(self, artifact, context, captures):
        path = self.dir / 'standards_check.json'
        path.write_text(json.dumps(artifact))
        return standards.validate_standards(str(path), context, captures)


def shift_control_clrt(ev, us):
    mutated = copy.deepcopy(ev)
    n = 0
    for row in mutated['timing']['exchanges']:
        if row['kind'] in ('SELECT', 'OPERATE') and row.get('clrt_us') is not None:
            row['clrt_us'] += us
            n += 1
    assert n == 128
    return mutated


# ---- unmodified retained trials: pass, CLRT reported, no timing block in the standards artifact -------------------

def test_unmodified_separate_ack_trial_passes_and_reports_visible_clrt(tmp_path):
    t = Trial(tmp_path, 'separate_ack')
    fails, obs = t.evaluate()
    assert fails == []
    for key in ('read_precision', 'select_precision', 'operate_precision', 'piggyback_latency'):
        assert key not in obs
    for kind in ('READ', 'SELECT', 'OPERATE'):
        v = obs['visible_clrt'][kind]
        assert v['n'] == len(v['values_us']) > 0
        assert v['min_us'] == v['values_us'][0] <= v['median_us'] <= v['max_us'] == v['values_us'][-1]
    assert obs['operate_hold']['pass'] and obs['operate_hold']['sent'] == obs['operate_hold']['observed'] == 64
    assert obs['operate_hold']['observation'] == hold_check.OBSERVATION
    artifact, context, captures = t.artifact(fails)
    assert artifact['schema_version'] == standards.SCHEMA_VERSION_V4
    assert 'precision' not in artifact['observed'] and 'objectives' not in artifact['observed']
    result = t.validate(artifact, context, captures)
    assert result['ok'] is True, result['failures'][:4]
    assert not {'precision', 'objectives', 'qualification'} & set(result)


def test_unmodified_piggyback_trial_passes_and_counts_piggybacks_apart(tmp_path):
    t = Trial(tmp_path, 'piggyback')
    fails, obs = t.evaluate()
    assert fails == []
    assert sum(obs['visible_clrt'][k]['piggyback'] for k in ('READ', 'SELECT', 'OPERATE')) > 0
    assert 'piggyback_fraction' in obs
    artifact, context, captures = t.artifact(fails)
    result = t.validate(artifact, context, captures)
    assert result['ok'] is True, result['failures'][:4]


# ---- a timing shift is reported, never a failure -----------------------------------------------------------------

def test_control_clrt_shift_is_reported_not_failed(tmp_path):
    t = Trial(tmp_path, 'separate_ack')
    _, before = t.evaluate()
    fails, obs = t.evaluate(shift_control_clrt(t.ev, 2000))
    assert fails == []
    for kind in ('SELECT', 'OPERATE'):
        assert obs['visible_clrt'][kind]['min_us'] == before['visible_clrt'][kind]['min_us'] + 2000
    assert obs['visible_clrt']['READ'] == before['visible_clrt']['READ']


def test_piggyback_latency_shift_is_not_a_failure(tmp_path):
    t = Trial(tmp_path, 'piggyback')
    mutated = copy.deepcopy(t.ev)
    for row in mutated['timing']['exchanges']:
        if row.get('piggyback'):
            row['rt_us'] += 100000
    fails, _ = t.evaluate(mutated)
    assert fails == []


def test_operate_transit_below_op_j_is_reported_not_failed(tmp_path):
    t = Trial(tmp_path, 'separate_ack')
    mutated = copy.deepcopy(t.ev)
    mutated['hold']['operates'][10]['transit_us'] = t.cfg['timing_params_ns']['op_j'] / 1000.0 - 1
    fails, obs = t.evaluate(mutated)
    assert fails == []
    assert obs['operate_hold']['pass'] is True
    assert obs['operate_hold']['below_op_j'] == [{'seq': mutated['hold']['operates'][10]['seq'],
                                                  'app_seq': mutated['hold']['operates'][10]['app_seq'],
                                                  'transit_us': 2399.0}]
    assert obs['operate_hold']['min_transit_us'] == 2399.0


def test_unobserved_operate_or_missing_hold_evidence_still_fails(tmp_path):
    """Correctness, not timing: every OPERATE sent must reach the outstation-side capture."""
    t = Trial(tmp_path, 'separate_ack')
    unseen = copy.deepcopy(t.ev)
    unseen['hold']['operates'][3].update(observed=False, transit_us=None)
    fails, obs = t.evaluate(unseen)
    assert [f for f in fails if f.startswith('OPERATE hold:')] == fails and fails
    assert obs['operate_hold']['sufficient'] is False
    missing = dict(t.ev, hold=None)
    fails, obs = t.evaluate(missing)
    assert any('OPERATE hold: OPERATE hold evidence missing' in f for f in fails), fails


def test_old_timing_blocks_in_an_artifact_are_ignored(tmp_path):
    """An artifact that still carries the retired timing blocks (failed ones included) validates on conformance."""
    t = Trial(tmp_path, 'separate_ack')
    fails, _ = t.evaluate()
    artifact, context, captures = t.artifact(fails)
    artifact['observed']['precision'] = {'required': True, 'status': 'fail', 'reasons': ['legacy']}
    artifact['observed']['objectives'] = {'operate_hold': {'required': True, 'status': 'fail', 'reasons': ['x']}}
    result = t.validate(artifact, context, captures)
    assert result['ok'] is True, result['failures'][:4]


def test_retained_artifact_labels_are_rejected_under_the_current_checker(tmp_path):
    t = Trial(tmp_path, 'separate_ack')
    fails, _ = t.evaluate()
    artifact, context, captures = t.artifact(fails)
    for label in (standards.SCHEMA_VERSION, standards.SCHEMA_VERSION_V3):
        result = t.validate(dict(artifact, schema_version=label), context, captures)
        assert any('never written by the current checker' in f for f in result['failures']), result['failures']


def test_any_generation_exhaustion_drop_fails_the_trial(tmp_path):
    """T outcome 15 (snapshots: index_15) counts a request or OPERATE dropped on an exhausted allocator; a
    protected transaction is never silently untimed, and a trial with any such drop fails."""
    t = Trial(tmp_path, 'separate_ack')
    fails, obs = t.evaluate()
    assert obs['generation_exhausted'] == 0 and not any(f.startswith('generation exhausted') for f in fails)
    ev = copy.deepcopy(t.ev)
    ev['after']['outcomes']['index_15'] = ev['before']['outcomes']['index_15'] + 1
    fails, obs = t.evaluate(ev)
    assert obs['generation_exhausted'] == 1
    assert any(f.startswith('generation exhausted: 1') for f in fails)


def test_generation_exhaustion_is_gated_only_where_the_build_declares_it(tmp_path):
    """The ctl m3 build declares GEN_EXHAUSTED at outcome 15; an undeclared build records not_applicable (index 15
    is a diagnostic RESP re-wait counter on route_ab_01/stale_split_diag_01), and a declared but missing counter
    fails rather than passing silently."""
    t = Trial(tmp_path, 'separate_ack')
    assert t.build['gen_exhausted_outcome'] == 15
    ev = copy.deepcopy(t.ev)
    ev['after']['outcomes']['index_15'] = ev['before']['outcomes']['index_15'] + 3
    t.build.pop('gen_exhausted_outcome')
    fails, obs = t.evaluate(ev)
    assert obs['generation_exhausted'] == 'not_applicable'
    assert not any(f.startswith('generation exhausted') for f in fails)
    t.build['gen_exhausted_outcome'] = 15
    for snap in ('before', 'after'):
        del ev[snap]['outcomes']['index_15']
    fails, obs = t.evaluate(ev)
    assert any(f.startswith('generation exhausted: the build declares outcome 15') for f in fails), fails

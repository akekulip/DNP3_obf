"""Timing objectives beyond READ precision: SELECT/OPERATE CLRT, piggyback latency and the OPERATE hold J.

Derived-evidence mutation tests: each starts from a COPY (tmp_path) of a retained passing ctl_timing m3 trial,
derives the evidence the campaign gate reads (timing.json rows; hold_check.analyze of the copied captures), shifts
one derived metric, and checks that checks.evaluate fails exactly the matching objective gate and that the standards
artifact, serialized and reloaded from JSON, carries the failure into the qualification verdict. They are not an
end-to-end forged-capture demonstration: the captures are never rewritten. Retained evidence is read only.
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
_spec = importlib.util.spec_from_file_location('campaign_timing_objectives', HERE.parent / 'campaign.py')
cp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cp)

S = HERE.parents[2] / 'integration/core/response_only_rearm/stage_experiments/seg61_02'
RUNS = S / 'evidence/hw_campaigns'
CASES = {'separate_ack': ('ctl_timing_repeat_sbo_950_b1_02', 'ctl_timing_repeat_sbo_950_b1.json'),
         'piggyback': ('ctl_timing_piggyback_950_b1', 'ctl_timing_piggyback_950_b1.json')}
CHAR = 'timing_precision_characterization'


def retained_trial(run):
    hits = sorted(p.parent for p in (RUNS / run).rglob('trial.json') if '/combined/' in str(p))
    return hits[0] if hits else None


def _present():
    return all(retained_trial(run) is not None and (retained_trial(run) / 'in.pcap').is_file()
               and (S / 'hw/config' / cfg).is_file() for run, cfg in CASES.values())


pytestmark = pytest.mark.skipif(not _present(), reason='retained ctl_timing m3 trials or configs absent')


class Trial:
    """A copied trial with its config, arm, derived evidence and a campaign object for the artifact path."""

    def __init__(self, tmp_path, fixture, purpose=CHAR):
        run, cfg_name = CASES[fixture]
        src = retained_trial(run)
        self.dir = tmp_path / src.name
        shutil.copytree(src, self.dir, ignore=shutil.ignore_patterns('*.log', 'standards*.json', 'profile_verdict.json'))
        self.fixture = fixture
        self.cfg = json.loads((S / 'hw/config' / cfg_name).read_text())
        self.cfg['evaluation']['purpose'] = purpose
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
                               {}, self.cfg['service']['k'], 0, gap_ns=t['gap'], precision=True,
                               run_sbo=checks.sbo_count(self.cfg['traffic']), repeated=True,
                               control_timed=True, piggyback_bound=True, pb_ns=t['pb'], op_j_ns=t['op_j'],
                               gen_exhausted_outcome=self.build.get('gen_exhausted_outcome'))

    def artifact(self, fails, obs, exempt=None):
        """standards.json through the campaign's own observed/objective path, written and reloaded from JSON."""
        c = self.campaign
        observed = c.standards_observed(
            self.ev, list(fails), transport_ok=True, select_ok=True, operate_ok=True, aggregate_ok=not fails,
            precision_required=c.precision_required(self.arm, self.fixture), precision=obs.get('read_precision'),
            precision_reason='fixture %s: READ CLRT undefined or precision disabled' % self.fixture,
            checker_result=c.run_standards_checker(str(self.dir), self.trial, self.arm),
            objectives=c.objective_blocks(self.trial, self.arm, obs, exempt))
        context = c.standards_context(self.trial, self.arm)
        context.update(precision_exempt=None, objectives_exempt=exempt, master_port=self.trial['master_port'])
        captures = c.standards_captures(str(self.dir), {'out': {'path': str(self.dir / 'out.pcap')},
                                                        'in': {'path': str(self.dir / 'in.pcap')}})
        path = self.dir / 'standards.json'
        path.write_text(json.dumps(standards.build_standards_artifact(context, captures, observed), default=str))
        return json.loads(path.read_text()), context, captures

    def validate(self, artifact, context, captures):
        path = self.dir / 'standards_check.json'
        path.write_text(json.dumps(artifact))
        return standards.validate_standards(str(path), context, captures)


def objective_failures(fails):
    return sorted({p for f in fails for p in checks.OBJECTIVE_PREFIXES if f.startswith(p)})


def reload_qualification(artifact, purpose):
    observed = json.loads(json.dumps(artifact))['observed']
    return standards.qualification(True, observed['precision'], purpose, observed.get('objectives'))


# ---- unmodified retained trials pass every objective -----------------------------------------------------------

def test_unmodified_separate_ack_trial_passes_every_objective_and_qualifies(tmp_path):
    t = Trial(tmp_path, 'separate_ack', 'qualification')
    fails, obs = t.evaluate()
    assert fails == []
    for key in ('read_precision', 'select_precision', 'operate_precision', 'operate_hold'):
        assert obs[key]['gated'] and obs[key]['pass'], key
    assert obs['piggyback_latency']['gated'] is False
    assert obs['operate_hold']['sent'] == obs['operate_hold']['observed'] == 64
    assert obs['operate_hold']['min_transit_us'] >= t.cfg['timing_params_ns']['op_j'] / 1000.0
    assert obs['operate_hold']['observation'] == hold_check.OBSERVATION
    artifact, context, captures = t.artifact(fails, obs)
    statuses = {k: v['status'] for k, v in artifact['observed']['objectives'].items()}
    assert statuses == {'select_precision': 'pass', 'operate_precision': 'pass',
                        'piggyback_latency': 'not_applicable', 'operate_hold': 'pass'}
    result = t.validate(artifact, context, captures)
    assert result['ok'] is True, result['failures'][:4]
    assert result['qualification'] == 'qualified'
    assert result['objectives'] == statuses


def test_unmodified_piggyback_trial_passes_the_piggyback_objective(tmp_path):
    t = Trial(tmp_path, 'piggyback', 'qualification')
    fails, obs = t.evaluate()
    assert fails == []
    pb = obs['piggyback_latency']
    assert pb['gated'] and pb['pass'] and pb['n'] >= 20 and pb['p99'] <= pb['target_us'] == 4250.0
    assert 'not observed' in pb['note']
    assert not obs['select_precision']['gated'] and not obs['read_precision']['gated']
    artifact, context, captures = t.artifact(fails, obs)
    assert artifact['observed']['objectives']['piggyback_latency']['status'] == 'pass'
    result = t.validate(artifact, context, captures)
    assert result['ok'] is True, result['failures'][:4]
    assert result['qualification'] == 'qualified'


# ---- one derived metric shifted: exactly the matching gate fails --------------------------------------------------

def test_control_clrt_shift_fails_select_and_operate_precision_while_read_passes(tmp_path):
    t = Trial(tmp_path, 'separate_ack')
    mutated = copy.deepcopy(t.ev)
    n = 0
    for row in mutated['timing']['exchanges']:
        if row['kind'] in ('SELECT', 'OPERATE') and row.get('clrt_us') is not None:
            row['clrt_us'] += 2000
            n += 1
    assert n == 128
    fails, obs = t.evaluate(mutated)
    assert objective_failures(fails) == ['OPERATE precision:', 'SELECT precision:']
    assert all(f.startswith(checks.OBJECTIVE_PREFIXES) for f in fails), fails
    assert obs['read_precision']['pass'] and obs['read_precision']['gated']
    assert len(obs['select_precision']['over_bound']) == 64
    assert all('app_seq' in row for row in obs['operate_precision']['over_bound'])


def test_piggyback_latency_shift_fails_the_piggyback_gate(tmp_path):
    t = Trial(tmp_path, 'piggyback')
    mutated = copy.deepcopy(t.ev)
    for row in mutated['timing']['exchanges']:
        if row.get('piggyback'):
            row['rt_us'] += 100000
    fails, obs = t.evaluate(mutated)
    assert objective_failures(fails) == ['PIGGYBACK latency:']
    assert obs['piggyback_latency']['above_target'] and \
        {'kind', 'app_seq'} <= set(obs['piggyback_latency']['above_target'][0])


def test_too_few_piggyback_samples_fail_rather_than_pass(tmp_path):
    t = Trial(tmp_path, 'piggyback')
    mutated = copy.deepcopy(t.ev)
    kept = 0
    for row in mutated['timing']['exchanges']:
        if row.get('piggyback'):
            kept += 1
            row['piggyback'] = kept <= 5
    fails, obs = t.evaluate(mutated)
    assert any(f.startswith('PIGGYBACK latency: insufficient piggyback samples') for f in fails), fails
    assert obs['piggyback_latency']['sufficient'] is False


def test_operate_transit_below_op_j_fails_the_hold_gate(tmp_path):
    t = Trial(tmp_path, 'separate_ack')
    mutated = copy.deepcopy(t.ev)
    mutated['hold']['operates'][10]['transit_us'] = t.cfg['timing_params_ns']['op_j'] / 1000.0 - 1
    fails, obs = t.evaluate(mutated)
    assert objective_failures(fails) == ['OPERATE hold:']
    assert obs['operate_hold']['below_op_j'] == [{'seq': mutated['hold']['operates'][10]['seq'],
                                                  'app_seq': mutated['hold']['operates'][10]['app_seq'],
                                                  'transit_us': 2399.0}]
    assert obs['operate_hold']['sufficient'] is True


def test_unobserved_operate_or_missing_hold_evidence_fails_the_hold_gate(tmp_path):
    t = Trial(tmp_path, 'separate_ack')
    unseen = copy.deepcopy(t.ev)
    unseen['hold']['operates'][3].update(observed=False, transit_us=None)
    fails, obs = t.evaluate(unseen)
    assert objective_failures(fails) == ['OPERATE hold:'] and obs['operate_hold']['sufficient'] is False
    missing = dict(t.ev, hold=None)
    fails, obs = t.evaluate(missing)
    assert any('OPERATE hold: OPERATE hold evidence missing' in f for f in fails), fails


# ---- serialized, reloaded, and turned into the qualification verdict ----------------------------------------------

@pytest.mark.parametrize('purpose, want', [('qualification', 'rejected'), (CHAR, 'measurement_only')])
def test_mutated_objectives_serialize_into_the_qualification_verdict(tmp_path, purpose, want):
    t = Trial(tmp_path, 'separate_ack', purpose)
    mutated = copy.deepcopy(t.ev)
    for row in mutated['timing']['exchanges']:
        if row['kind'] in ('SELECT', 'OPERATE') and row.get('clrt_us') is not None:
            row['clrt_us'] += 2000
    fails, obs = t.evaluate(mutated)
    assert objective_failures(fails) == ['OPERATE precision:', 'SELECT precision:']
    t.ev = mutated
    artifact, context, captures = t.artifact(fails, obs)
    assert artifact['schema_version'] == standards.SCHEMA_VERSION_V3
    blocks = artifact['observed']['objectives']
    status = 'deferred' if purpose == CHAR else 'fail'
    assert {k: blocks[k]['status'] for k in blocks} == {
        'select_precision': status, 'operate_precision': status, 'piggyback_latency': 'not_applicable',
        'operate_hold': 'pass'}
    assert artifact['observed']['precision']['status'] == 'pass'            # READ untouched
    assert reload_qualification(artifact, purpose) == want
    result = t.validate(artifact, context, captures)
    assert result['ok'] is True, result['failures'][:4]                      # conformance stays separate
    assert result['qualification'] == want


@pytest.mark.parametrize('purpose', ['qualification', CHAR])
def test_hold_mutation_is_rejected_and_the_validator_recomputes_it_from_the_captures(tmp_path, purpose):
    """A shifted hold.json fails the gate; and because the validator re-derives the hold from the bound pcaps, the
    stated (mutated) numbers no longer match the captures, so even a characterization deferral is rejected."""
    t = Trial(tmp_path, 'separate_ack', purpose)
    mutated = copy.deepcopy(t.ev)
    for row in mutated['hold']['operates']:
        row['transit_us'] -= 1000
    fails, obs = t.evaluate(mutated)
    assert objective_failures(fails) == ['OPERATE hold:']
    t.ev = mutated
    artifact, context, captures = t.artifact(fails, obs)
    assert artifact['observed']['objectives']['operate_hold']['status'] == ('deferred' if purpose == CHAR else 'fail')
    result = t.validate(artifact, context, captures)
    assert result['qualification'] == 'rejected'
    if purpose == CHAR:
        assert any('differs from the bound captures' in f for f in result['failures']), result['failures']


def test_nearest_rank_p99_catches_the_single_worst_of_64(tmp_path):
    """63 control CLRT errors of 50 us and one of 500 us: the round(q(n-1)) index lands on 50 and would pass; the
    nearest-rank p99 (ceil(0.99*64) = 64th) is 500 and fails SELECT and OPERATE precision."""
    t = Trial(tmp_path, 'separate_ack')
    mutated = copy.deepcopy(t.ev)
    gap_us = t.cfg['timing_params_ns']['gap'] / 1000.0
    for kind in ('SELECT', 'OPERATE'):
        rows = [r for r in mutated['timing']['exchanges'] if r['kind'] == kind]
        assert len(rows) == 64
        for i, row in enumerate(rows):
            row['clrt_us'] = gap_us + (500 if i == 17 else 50)
    fails, obs = t.evaluate(mutated)
    assert objective_failures(fails) == ['OPERATE precision:', 'SELECT precision:']
    for key in ('select_precision', 'operate_precision'):
        assert obs[key]['p99'] == 500 and obs[key]['absolute_error_us']['p99'] == 50
        assert obs[key]['over_bound'] and obs[key]['over_bound'][0]['error_us'] == 500
    assert checks.nearest_rank([50] * 63 + [500], 0.99) == 500 and checks.nearest_rank([], 0.99) is None


def test_piggyback_mutation_serializes_into_rejection_for_qualification(tmp_path):
    t = Trial(tmp_path, 'piggyback', 'qualification')
    mutated = copy.deepcopy(t.ev)
    for row in mutated['timing']['exchanges']:
        if row.get('piggyback'):
            row['rt_us'] += 100000
    fails, obs = t.evaluate(mutated)
    t.ev = mutated
    artifact, context, captures = t.artifact(fails, obs)
    assert artifact['observed']['objectives']['piggyback_latency']['status'] == 'fail'
    assert reload_qualification(artifact, 'qualification') == 'rejected'
    assert t.validate(artifact, context, captures)['qualification'] == 'rejected'


def test_removed_objective_block_rejects_a_qualification_artifact(tmp_path):
    t = Trial(tmp_path, 'separate_ack', 'qualification')
    fails, obs = t.evaluate()
    artifact, context, captures = t.artifact(fails, obs)
    del artifact['observed']['objectives']['operate_hold']
    result = t.validate(artifact, context, captures)
    assert result['qualification'] == 'rejected'
    assert any('observed.objectives.operate_hold missing' in f for f in result['failures']), result['failures']
    assert reload_qualification(artifact, 'qualification') == 'rejected'


@pytest.mark.parametrize('name, status', [('operate_hold', 'not_applicable'), ('select_precision', 'deferred')])
def test_objective_status_must_agree_with_the_context(tmp_path, name, status):
    t = Trial(tmp_path, 'separate_ack', 'qualification')
    fails, obs = t.evaluate()
    artifact, context, captures = t.artifact(fails, obs)
    artifact['observed']['objectives'][name].update(status=status, reasons=['self-declared'])
    result = t.validate(artifact, context, captures)
    assert result['ok'] is False and result['qualification'] == 'rejected', result


def test_claimed_hold_pass_is_rechecked_against_op_j_from_the_config(tmp_path):
    t = Trial(tmp_path, 'separate_ack', 'qualification')
    fails, obs = t.evaluate()
    artifact, context, captures = t.artifact(fails, obs)
    artifact['observed']['objectives']['operate_hold']['evidence']['min_transit_us'] = 100.0
    result = t.validate(artifact, context, captures)
    assert result['ok'] is False and result['qualification'] == 'rejected'
    assert any('operate_hold.evidence does not support' in f for f in result['failures']), result['failures']


def test_v3_artifact_without_objectives_is_rejected(tmp_path):
    """Deleting observed.objectives from a written (v3) artifact must not fall back to the pre-objective path."""
    t = Trial(tmp_path, 'separate_ack', 'qualification')
    mutated = copy.deepcopy(t.ev)
    for row in mutated['timing']['exchanges']:
        if row['kind'] == 'OPERATE' and row.get('clrt_us') is not None:
            row['clrt_us'] += 2000
    fails, obs = t.evaluate(mutated)
    t.ev = mutated
    artifact, context, captures = t.artifact(fails, obs)
    assert t.validate(artifact, context, captures)['qualification'] == 'rejected'
    del artifact['observed']['objectives']
    result = t.validate(artifact, context, captures)
    assert result['ok'] is False and result['qualification'] == 'rejected'
    assert any('observed.objectives missing' in f for f in result['failures']), result['failures']


@pytest.mark.parametrize('drop_objectives', [True, False])
def test_v3_relabelled_as_v2_is_rejected_under_the_current_checker(tmp_path, drop_objectives):
    """Decision: the current checker never writes v2, so a v2 label on an artifact bound to the current checker
    closure (or a v2 artifact carrying objectives) is rejected."""
    t = Trial(tmp_path, 'separate_ack', 'qualification')
    fails, obs = t.evaluate()
    artifact, context, captures = t.artifact(fails, obs)
    artifact['schema_version'] = standards.SCHEMA_VERSION
    if drop_objectives:
        del artifact['observed']['objectives']
    result = t.validate(artifact, context, captures)
    assert result['ok'] is False and result['qualification'] == 'rejected'
    assert any('never written by the current checker' in f for f in result['failures']), result['failures']
    # and, whatever the checker, a v2 artifact may not carry objectives
    assert standards._validate_objectives({'objectives': {}}, {}, 'qualification', v3=False) == [
        'dnp3-standards-v2 artifact carries observed.objectives (relabelled v3?)']


def test_v2_artifact_without_objectives_keeps_its_verdict():
    """A retained v2 artifact (older checker closure, no objectives) validates through the old path: READ block
    rules only, and the qualification it always had."""
    observed = {'precision': standards.precision_block(True, {'eligible': 65, 'absolute_error_us': {'p99': 11.0}})}
    assert standards._validate_objectives(observed, {}, 'qualification', v3=False) == []
    assert standards._validate_precision(observed, {'arm': {'T': 1}}, 'qualification', nearest_rank=False) == []
    assert standards.qualification(True, observed['precision'], 'qualification') == 'qualified'
    assert standards.qualification(True, observed['precision'], CHAR) == 'measurement_only'


@pytest.mark.parametrize('exempt', ['loss/recovery trial: timing objectives are not evaluated',
                                    'reconnect c1: timing objectives beyond READ precision are not evaluated'])
def test_exempted_objectives_cap_a_qualification_run_at_measurement_only(tmp_path, exempt):
    """Loss and reconnect connections do not evaluate SELECT/OPERATE/hold; on a build/arm/fixture that would
    require them they are recorded exempted (with the reason) and the trial can never be qualified."""
    t = Trial(tmp_path, 'separate_ack', 'qualification')
    fails, obs = t.evaluate()
    artifact, context, captures = t.artifact(fails, obs, exempt=exempt)
    blocks = artifact['observed']['objectives']
    for name in ('select_precision', 'operate_precision', 'operate_hold'):
        assert blocks[name]['status'] == 'not_applicable' and blocks[name]['exempted'] is True
        assert exempt in blocks[name]['reasons'][0]
    assert blocks['piggyback_latency']['exempted'] is False          # not required by this fixture anyway
    result = t.validate(artifact, context, captures)
    assert result['ok'] is True, result['failures'][:4]
    assert result['qualification'] == 'measurement_only'
    for name in ('select_precision', 'operate_precision', 'operate_hold'):
        artifact['observed']['objectives'][name]['exempted'] = False      # hiding the exemption is caught
    result = t.validate(artifact, context, captures)
    assert result['ok'] is False and result['qualification'] == 'rejected'


def test_read_precision_serialization_is_unchanged_against_the_retained_verdict():
    """Gate 1's READ block: read_precision over the retained timing.json equals what the retained verdict holds."""
    d = retained_trial(CASES['separate_ack'][0])
    timing = json.loads((d / 'timing.json').read_text())
    retained = json.loads((d / 'standards_verdict.json').read_text())['precision']['evidence']
    now = checks.read_precision(timing, 950000)
    assert now == {k: v for k, v in retained.items() if k != 'gated'}


def test_every_retained_standards_artifact_keeps_its_recorded_qualification():
    """Pre-objective artifacts carry no observed.objectives; v3 artifacts carry them. Either way the qualification
    recomputed from the retained verdict fields equals the recorded one."""
    checked = 0
    for verdict_path in sorted(RUNS.glob('**/standards_verdict.json')):
        artifact = json.loads((verdict_path.parent / 'standards.json').read_text())
        verdict = json.loads(verdict_path.read_text())
        root = next((p for p in verdict_path.parents if (p / 'campaign_run.json').is_file()), None)
        if root is None:
            continue
        purpose = json.loads((root / 'campaign_run.json').read_text()).get('effective', {}).get(
            'evaluation', {}).get('purpose', 'qualification')
        if artifact['schema_version'] == 'dnp3-standards-v3':
            # artifacts written since the objectives gate (2026-10-15 silicon): they must carry every objective
            # block, and their recorded qualification is recomputed with them
            assert isinstance(artifact['observed'].get('objectives'), dict), verdict_path
            got = standards.qualification(verdict['ok'], verdict['precision'], purpose,
                                          artifact['observed']['objectives'])
        else:
            assert 'objectives' not in artifact['observed'], verdict_path
            assert artifact['schema_version'] in ('dnp3-standards-v1', standards.SCHEMA_VERSION), verdict_path
            assert standards._validate_objectives(artifact['observed'], {}, purpose, v3=False) == []
            if 'qualification' not in verdict:            # pre-v2 verdicts record no qualification to compare
                continue
            got = standards.qualification(verdict['ok'], verdict['precision'], purpose)
        want = verdict['qualification']
        if (verdict.get('profile') or {}).get('ok') is False:
            got = 'rejected'
        assert got == want, verdict_path
        checked += 1
    assert checked >= 58


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

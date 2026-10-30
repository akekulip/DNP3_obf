"""switch_process_repair: the narrow repair for a final restore whose bf_switchd stop did not finish, and its reconcile
acceptance (2026-10-30). Offline: no switch, no Vision, no systemd."""
import copy
import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HW = ROOT / 'scripts/hardware'
sys.path.insert(0, str(HW))
import evaluation_campaign as ec  # noqa: E402
import switch_process_repair as spr  # noqa: E402

RUN_ID = 'rc01_hw_c74diag_e2c_20261030_01_e2_combined_first_request_d20_c74'
BLOCK = ROOT / 'results/hardware/blocks' / RUN_ID
CAMPAIGN_CONFIG = ROOT / 'results/hardware/campaigns/rc01_hw_c74diag_e2c_20261030_01/configs/e2_combined_first_request_d20_c74.json'
REMOTE = '/home/decps/Philip_repo/dnp3-defense4/response_only_composite'
CANDIDATE = ('/home/decps/Downloads/bf-sde-9.13.2/install/bin/bf_switchd --install-dir /x --conf-file '
             '%s/response_only_hw_%s_physical_relay_combined_t31.conf --init-mode=cold' % (REMOTE, RUN_ID))
PRODUCTION = '/home/decps/Downloads/bf-sde-9.13.2/install/bin/bf_switchd --conf-file /p/case4_response_path.conf'
CONFIG = dict(hosts=dict(switch='u@switch', vision='u@vision', switch_remote_dir=REMOTE, vision_run_dir='/v'),
              production=dict(program='case4_response_path', launch_script='/p/launch.sh', relay_slot=True,
                              ping=dict(count=2, src='192.168.10.1', dst='192.168.10.7')),
              endpoint_profile='sel751')
needs_block = pytest.mark.skipif(not (BLOCK / 'campaign_run.json').is_file(), reason='c74 e2c block evidence absent')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def proc(pid, start, args):
    return dict(pid=pid, starttime=start, cmdline=args, status={}, wchan='')


def failure_out(detail='3735291', after='STILL_RUNNING'):
    return '\n'.join(['RESTORE STEP FAILED: %s (rc 1) %s' % (spr.STEPS[0], detail), after] +
                     ['RESTORE STEP FAILED: %s (rc %d) x' % (s, rc) for s, rc in zip(spr.STEPS[1:], (1, 1, 2))])


FAILED = [dict(step=s, rc=rc, ok=False) for s, rc in zip(spr.STEPS, (1, 1, 1, 2))]
VISION = dict(step=ec.VISION_RESTORE_STEP, rc=0, ok=True)


# --- the recorded failure ------------------------------------------------------------------------------------------

@needs_block
def test_the_c74_e2c_failure_is_exactly_the_switch_process_shape():
    record = json.loads((BLOCK / 'campaign_run.json').read_text())
    failure, problems = spr.bound_failure(record, (BLOCK / 'run_block_run.out').read_text(), relay_slot=True)
    assert problems == [] and [s['step'] for s in failure['steps']] == spr.STEPS
    assert failure['recorded_pid'] == 3735291


def test_other_failure_shapes_are_refused():
    run = dict(restore=FAILED[:1] + [VISION] + FAILED[1:])
    assert spr.bound_failure(run, failure_out(), relay_slot=True) == (
        dict(steps=FAILED, lines=failure_out().splitlines()[:1] + failure_out().splitlines()[2:], recorded_pid=3735291), [])
    assert spr.bound_failure(dict(restore=FAILED + [dict(VISION, ok=False, rc=255)]), failure_out(), True)[1]
    assert spr.bound_failure(dict(restore=FAILED[:3] + [VISION]), failure_out(), True)[1]
    assert spr.bound_failure(run, failure_out(after='device_add error'), True)[1]
    assert spr.bound_failure(run, failure_out(detail='no pid'), True)[1]
    assert spr.bound_failure(run, failure_out(), relay_slot=False)[1]
    assert spr.bound_failure(dict(restore=[dict(FAILED[0], rc=2)] + FAILED[1:] + [VISION]), failure_out(), True)[1]


# --- the commands are the runner's own ------------------------------------------------------------------------------

@needs_block
def test_commands_equal_the_runners_planned_restore_commands_but_for_the_log_name():
    planned = [l.strip()[2:] for l in (BLOCK / 'run_block_plan.out').read_text().splitlines()
               if l.strip().startswith('$ ')]
    tail = planned[planned.index(next(c for c in reversed(planned) if 'switch_swap.sh' in c)):]
    config = json.loads(CAMPAIGN_CONFIG.read_text())
    ours = [c for _, _, c in spr.commands(config, RUN_ID, 'STAMP')]
    assert ours[0] == tail[0].replace('%s.log' % RUN_ID, '%s_repair_STAMP.log' % RUN_ID)
    assert 'vision_run.py restore' in tail[3]                # the runner's Vision restore passed: not repeated
    assert ours[1:] == tail[1:3] + tail[4:]


# --- identifying the process ---------------------------------------------------------------------------------------

def test_candidate_is_this_blocks_composite_with_the_recorded_pid():
    assert spr.candidate([proc(7, 100, CANDIDATE)], REMOTE, RUN_ID, 7) == (proc(7, 100, CANDIDATE), [])
    assert spr.candidate([], REMOTE, RUN_ID, 7) == (None, [])
    assert spr.candidate([proc(7, 100, PRODUCTION)], REMOTE, RUN_ID, 7)[1]
    assert spr.candidate([proc(7, 100, CANDIDATE), proc(8, 101, CANDIDATE)], REMOTE, RUN_ID, 7)[1]
    assert spr.candidate([proc(7, 100, CANDIDATE), proc(8, 101, PRODUCTION)], REMOTE, RUN_ID, 7)[1]
    assert spr.candidate([proc(8, 100, CANDIDATE)], REMOTE, RUN_ID, 7)[1]                      # restarted since
    assert spr.candidate([dict(proc(7, None, CANDIDATE))], REMOTE, RUN_ID, 7)[1]                # unreadable
    for other in (RUN_ID.replace('e2c', 'e2o'), RUN_ID + '_x'):                               # other or longer run id
        assert spr.candidate([proc(7, 100, CANDIDATE.replace(RUN_ID, other))], REMOTE, RUN_ID, 7)[1]


def test_candidate_log_follows_the_conf_name():
    assert spr.candidate_log(proc(7, 1, CANDIDATE), REMOTE) == \
        '%s/switchd_%s_physical_relay_combined_t31.log' % (REMOTE, RUN_ID)


# --- termination ---------------------------------------------------------------------------------------------------

class FakeSwitch:
    """bf_switchd processes over time; kill_effect[sig] says whether that signal ends the candidate."""

    def __init__(self, procs, kill_effect, events=None):
        self.procs, self.kill_effect, self.sent = list(procs), kill_effect, []
        self.events = events if events is not None else []

    def list(self):
        return list(self.procs)

    def kill(self, target, sig):
        self.sent.append((target['pid'], sig))
        self.events.append('kill %s' % sig)
        if not any(p['pid'] == target['pid'] and p['starttime'] == target['starttime'] for p in self.procs):
            return 3
        if self.kill_effect.get(sig):
            self.procs = [p for p in self.procs if p['pid'] != target['pid']]
        return 0


def terminate(switch, target):
    clock = iter(range(0, 10000, 2))
    return spr.terminate(target, switch.list, switch.kill, now=lambda: next(clock), sleep=lambda s: None)


def test_sigterm_that_works_sends_no_sigkill():
    target = proc(7, 100, CANDIDATE)
    switch = FakeSwitch([target], {'TERM': True})
    out = terminate(switch, target)
    assert out['exited'] and out['signals'] == ['TERM'] and switch.sent == [(7, 'TERM')]


def test_sigterm_that_does_not_finish_in_60_s_is_followed_by_sigkill_on_that_process_only():
    target = proc(7, 100, CANDIDATE)
    switch = FakeSwitch([target, proc(9, 50, '/usr/bin/other')], {'KILL': True})
    out = terminate(switch, target)
    assert out['exited'] and out['signals'] == ['TERM', 'KILL'] and switch.sent == [(7, 'TERM'), (7, 'KILL')]
    assert out['term_wait_s'] >= 60


def test_a_reused_pid_with_another_start_time_counts_as_exited_and_is_never_signalled_again():
    target = proc(7, 100, CANDIDATE)
    switch = FakeSwitch([target], {})
    original = switch.kill
    switch.kill = lambda t, sig: (original(t, sig), setattr(switch, 'procs', [proc(7, 999, 'x')]))[0]
    out = terminate(switch, target)
    assert out['exited'] and switch.sent == [(7, 'TERM')]


def test_an_unreadable_listing_of_the_pid_counts_as_alive():
    target = proc(7, 100, CANDIDATE)
    switch = FakeSwitch([dict(target, starttime=None)], {})
    assert not terminate(switch, target)['exited']


def test_a_process_that_survives_sigkill_is_reported_not_exited():
    target = proc(7, 100, CANDIDATE)
    out = terminate(FakeSwitch([target], {}), target)
    assert not out['exited'] and out['signals'] == ['TERM', 'KILL']


# --- the repair sequence -------------------------------------------------------------------------------------------

class FakeHosts:
    def __init__(self, procs, kill_effect, rcs=None, state_rc=0):
        self.events, self.saved = [], {}
        self.switch = FakeSwitch(procs, kill_effect, self.events)
        self.rcs, self.state_rc, self.commands = rcs or {}, state_rc, []

    def run(self, host, command, timeout=600):
        self.commands.append((host, command))
        if '/proc/' in command:
            self.events.append('state')
            return type('R', (), dict(returncode=self.state_rc, stdout='threads', stderr=''))()
        rc = next((v for k, v in self.rcs.items() if k in command), 0)
        return type('R', (), dict(returncode=rc, stdout='ok', stderr=''))()

    def save(self, name, data):
        self.events.append('save %s' % name)
        self.saved[name] = data


def apply(hosts, inputs=True, listening=False, list_procs=None, config=CONFIG):
    clock = iter(range(0, 100000, 2))
    return spr.apply_repair(config, RUN_ID, 'STAMP', 7, run=hosts.run, list_procs=list_procs or hosts.switch.list,
                            kill=hosts.switch.kill, listening=lambda: listening, inputs_ok=lambda: (inputs, {}),
                            save=hosts.save, now=lambda: next(clock), sleep=lambda s: None)


def restore_commands(hosts):
    return [c for _, c in hosts.commands if '/proc/' not in c]


def test_repair_saves_the_state_before_any_signal_then_runs_the_runner_commands():
    hosts = FakeHosts([proc(7, 100, CANDIDATE)], {'KILL': True})
    out = apply(hosts)
    assert out['ok'] and out['termination']['signals'] == ['TERM', 'KILL']
    assert hosts.events[:3] == ['state', 'save pre_signal_state.json', 'kill TERM']
    assert hosts.saved['pre_signal_state.json']['process']['pid'] == 7
    assert restore_commands(hosts) == [c for _, _, c in spr.commands(CONFIG, RUN_ID, 'STAMP')]
    assert [s['name'] for s in out['steps']] == list(spr.STEP_NAMES)


def test_a_failed_state_capture_signals_nothing():
    hosts = FakeHosts([proc(7, 100, CANDIDATE)], {'TERM': True}, state_rc=1)
    out = apply(hosts)
    assert not out['ok'] and hosts.switch.sent == [] and out['steps'] == []
    assert 'pre_signal_state.json' in hosts.saved


def test_nothing_is_launched_when_the_candidate_cannot_be_ended():
    hosts = FakeHosts([proc(7, 100, CANDIDATE)], {})
    out = apply(hosts)
    assert not out['ok'] and out['steps'] == [] and not any('switch_swap' in c for c in restore_commands(hosts))
    assert out['errors'] == ['the candidate bf_switchd did not exit after SIGTERM and SIGKILL; nothing launched']


def test_nothing_is_launched_while_port_50052_still_listens_after_the_candidate_exited():
    hosts = FakeHosts([proc(7, 100, CANDIDATE)], {'TERM': True})
    out = apply(hosts, listening=True)
    assert not out['ok'] and out['steps'] == [] and out['absent_before_launch'] is False


def test_nothing_is_touched_when_the_running_process_is_not_this_blocks_candidate():
    hosts = FakeHosts([proc(7, 100, PRODUCTION)], {'TERM': True})
    out = apply(hosts)
    assert not out['ok'] and hosts.switch.sent == [] and out['steps'] == [] and hosts.saved == {}


def test_nothing_is_touched_when_the_deployed_inputs_differ():
    hosts = FakeHosts([proc(7, 100, CANDIDATE)], {'TERM': True})
    out = apply(hosts, inputs=False)
    assert not out['ok'] and hosts.switch.sent == [] and out['steps'] == [] and hosts.commands == []


def test_a_config_fault_stops_before_any_signal():
    hosts = FakeHosts([proc(7, 100, CANDIDATE)], {'TERM': True})
    broken = copy.deepcopy(CONFIG)
    del broken['production']['launch_script']
    out = apply(hosts, config=broken)
    assert not out['ok'] and hosts.switch.sent == [] and 'raised' in out['errors'][0]


def test_an_exception_after_a_signal_keeps_the_evidence_gathered_so_far():
    hosts = FakeHosts([proc(7, 100, CANDIDATE)], {})
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) > 2:
            raise RuntimeError('ssh dropped')
        return hosts.switch.list()
    out = apply(hosts, list_procs=flaky)
    assert not out['ok'] and out['processes_before'] and hosts.switch.sent == [(7, 'TERM')]
    assert 'pre_signal_state' in out and "RuntimeError('ssh dropped')" in out['errors'][0]


def test_the_sequence_stops_at_the_first_failed_step():
    hosts = FakeHosts([proc(7, 100, CANDIDATE)], {'TERM': True}, rcs={'restore_ports.py': 1})
    out = apply(hosts)
    assert not out['ok'] and [s['name'] for s in out['steps']] == ['launch_production', 'replay_ports']


# --- reconcile acceptance (pure) -----------------------------------------------------------------------------------

def fresh_ok(**over):
    checks = dict(program=dict(program='case4_response_path'), snapshot=dict(errors=[], tables_compared=12),
                  vision_state=dict(rc=0), ping=dict(rc=0))
    checks.update(over)
    return dict(ok=False, failures=[ec.SWITCH_PROCESS_REPAIRED_FAILURE], checks=checks)


def repair_record(**over):
    record = dict(ok=True, bound_sha256={'terminal': 'T', 'campaign_run.json': 'C'},
                  failed_restoration=dict(steps=[dict(step=s) for s in spr.STEPS]),
                  termination=dict(exited=True), absent_before_launch=True,
                  steps=[dict(name=n, rc=0) for n in spr.STEP_NAMES])
    record.update(over)
    return record


def partial_record(**over):
    """The first c74 e2c repair's shape: switch steps passed, then a failed step after relay_slot."""
    record = repair_record(ok=False, steps=[dict(name=n, rc=0) for n in spr.STEP_NAMES[:3]] +
                           [dict(name='vision_restore', rc=1)], errors=['vision_restore exited 1'])
    record.update(over)
    return record


def write_repair(records, record):
    out = records / 'switch_process_repair_20261030T160000Z'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'repair.json').write_text(json.dumps(record))


def accept(records, fresh=None, program='case4_response_path'):
    return ec.switch_process_acceptance(records, 'T', 'C', fresh or fresh_ok(), program)


@needs_block
def test_the_historical_failure_line_is_the_one_restore_verify_wrote():
    assert json.loads((BLOCK / 'restore_verify.json').read_text())['failures'][0] == ec.SWITCH_PROCESS_REPAIRED_FAILURE


def test_acceptance_needs_the_bound_repair_and_an_otherwise_complete_fresh_check(tmp_path):
    assert accept(tmp_path)[1] == ['no switch_process_repair record for this step']
    write_repair(tmp_path, repair_record())
    binding, problems = accept(tmp_path)
    assert problems == [] and binding['path'].endswith('repair.json')
    assert accept(tmp_path, program=None)[1]


@pytest.mark.parametrize('over', [dict(ok=False), dict(bound_sha256={'terminal': 'X', 'campaign_run.json': 'C'}),
                                  dict(termination=dict(exited=False)), dict(absent_before_launch=False),
                                  dict(steps=[dict(name=n, rc=1 if n == 'ping' else 0) for n in spr.STEP_NAMES]),
                                  dict(steps=[dict(name='launch_production', rc=0)]),
                                  dict(failed_restoration=dict(steps=[dict(step=spr.STEPS[0])]))])
def test_acceptance_refuses_a_repair_record_that_does_not_prove_the_repair(tmp_path, over):
    write_repair(tmp_path, repair_record(**over))
    assert accept(tmp_path)[1]


@pytest.mark.parametrize('fresh', [
    dict(fresh_ok(), failures=[ec.SWITCH_PROCESS_REPAIRED_FAILURE, 'ping through the restored path failed (rc 1)']),
    fresh_ok(program=dict(program='response_only')),
    fresh_ok(snapshot=dict(errors=['table differs'])),
    fresh_ok(snapshot=None),
    fresh_ok(ping=dict(rc=1)),
    fresh_ok(vision_state=dict(rc=1))])
def test_acceptance_refuses_a_fresh_check_with_any_other_failure(tmp_path, fresh):
    write_repair(tmp_path, repair_record())
    assert accept(tmp_path, fresh)[1]


# --- reconcile end to end and the tool's own preconditions (fixture campaign, fixture testbed) -----------------------

class Fixture:
    """A failed block with this shape in a campaign, its run root, its terminal record and a testbed with
    unsafe_restoration set (after the archived test_reconcile harness)."""

    def __init__(self, base, kind='supervision_fixture'):
        self.base = base
        self.run_root = base / 'run0'
        self.run_root.mkdir()
        self.config = base / 'config.json'
        self.config.write_text(json.dumps(CONFIG))
        argv = ['bash', str(HW / 'run_block_frozen.sh'), str(base / 'freeze.json'), 'campaign', str(self.config), 'block0']
        manifest = {'campaign_id': 'switch-repair-test', 'evidence_kind': kind,
                    'steps': [{'id': 'block0', 'kind': 'block', 'argv': argv, 'run_root': str(self.run_root)}]}
        (base / 'input.json').write_text(json.dumps(manifest))
        self.campaign = Path(ec.initialize(base / 'input.json'))
        (base / 'freeze.json').write_text(json.dumps({'files': {}}))
        (self.run_root / 'campaign_run.json').write_text(json.dumps(
            {'run_id': 'block0', 'restore': FAILED[:1] + [VISION] + FAILED[1:]}))
        (self.run_root / 'block0_prerun.json').write_text('{"tables": {}}')
        (self.run_root / 'run_block_run.out').write_text(failure_out())
        (self.run_root / 'freeze_check.json').write_text(json.dumps(
            {'freeze': str((base / 'freeze.json').relative_to(base)), 'config_sha256': sha(self.config)}))
        (self.run_root / 'restore_verify.json').write_text(json.dumps(
            {'ok': False, 'failures': [ec.SWITCH_PROCESS_REPAIRED_FAILURE, "switch runs 'response_only'"]}))
        self.steps = self.campaign / 'steps' / 'block0'
        self.steps.mkdir(parents=True, exist_ok=True)
        self.testbed = base / 'testbed'
        self.testbed.mkdir()
        self.ownership = self.testbed / 'ownership.json'
        self.bind()

    def bind(self, **terminal_over):
        files = {p.name: {'sha256': sha(p), 'size': p.stat().st_size} for p in self.run_root.iterdir()
                 if p.name != 'artifact_manifest.json'}
        (self.run_root / 'artifact_manifest.json').write_text(json.dumps({'files': files}))
        terminal = {'id': 'block0', 'status': 'failed', 'reason': 'unsafe_restoration', 'rc': 2,
                    'restoration': {'path': str(self.run_root / 'restore_verify.json'), 'ok': False,
                                    'sha256': sha(self.run_root / 'restore_verify.json')},
                    'artifact_manifest': {'path': str(self.run_root / 'artifact_manifest.json'),
                                          'sha256': sha(self.run_root / 'artifact_manifest.json')}}
        terminal.update(terminal_over)
        (self.steps / 'terminal.json').write_text(json.dumps(terminal))
        self.ownership.write_text(json.dumps({'active': False, 'unsafe_restoration': True,
                                              'campaign_dir': str(self.campaign), 'step_id': 'block0',
                                              'terminal_sha256': sha(self.steps / 'terminal.json')}))

    def write_repair(self, **over):
        write_repair(self.steps, repair_record(bound_sha256={'terminal': sha(self.steps / 'terminal.json'),
                                                             'campaign_run.json': sha(self.run_root / 'campaign_run.json')},
                                               **over))

    def reconcile(self, failures, program='case4_response_path', now=1000):
        checks = {'program': {'program': program}, 'snapshot': {'errors': []}, 'vision_state': {'rc': 0},
                  'ping': {'rc': 0}}
        code = ('import json,sys; from pathlib import Path; Path(%r).joinpath("restore_verify.json").write_text('
                'json.dumps({"ok": False, "failures": %r, "checks": %r})); sys.exit(1)')
        verifier = lambda config, out: [sys.executable, '-c', code % (str(out), list(failures), checks)]  # noqa: E731
        return ec.reconcile(self.campaign, 'block0', root=self.testbed, units=lambda: [], verifier=verifier, now=now)

    def flag(self):
        return json.loads(self.ownership.read_text())['unsafe_restoration']


ONLY = [ec.SWITCH_PROCESS_REPAIRED_FAILURE]


def test_reconcile_clears_the_flag_only_with_the_bound_repair(tmp_path):
    f = Fixture(tmp_path)
    original = {p: p.read_bytes() for p in f.run_root.iterdir()}
    with pytest.raises(ec.Refused):
        f.reconcile(ONLY)                                            # no repair record: refused
    assert f.flag() is True
    f.write_repair()
    record = json.loads(Path(f.reconcile(ONLY, now=1001)).read_text())
    assert f.flag() is False and record['switch_process_repair']['problems'] == []
    assert 'switch_process_repair' in record['result']
    assert {p: p.read_bytes() for p in f.run_root.iterdir()} == original           # original evidence untouched


@pytest.mark.parametrize('failures,program', [(ONLY + ['ping through the restored path failed (rc 1)'],
                                               'case4_response_path'), (ONLY, 'response_only')])
def test_reconcile_refuses_any_other_fresh_failure_even_with_the_repair(tmp_path, failures, program):
    f = Fixture(tmp_path)
    f.write_repair()
    with pytest.raises(ec.Refused):
        f.reconcile(failures, program=program)
    assert f.flag() is True


def test_a_switch_process_record_never_lets_a_nic_repair_record_decide(tmp_path):
    f = Fixture(tmp_path)
    f.write_repair(ok=False)
    nic = f.steps / 'nic_repair_20261030T000000Z'
    nic.mkdir()
    (nic / 'repair.json').write_text(json.dumps({'ok': True}))
    with pytest.raises(ec.Refused):
        f.reconcile(ONLY)
    refused = json.loads(sorted(tmp_path.glob('reconcile_block0_*/reconciliation_refused.json'))[-1].read_text())
    assert 'switch_process_repair' in refused and 'nic_repair' not in refused
    assert f.flag() is True


class Untouchable:
    """live inputs that fail the test if the tool ever reaches the switch."""

    def __call__(self, *args):
        raise AssertionError('the tool contacted the switch despite a failed precondition')


def hardware_fixture(tmp_path, monkeypatch):
    monkeypatch.setattr(ec, 'running_eval_units', lambda: [])
    monkeypatch.setattr(spr, 'REPO', tmp_path)
    return Fixture(tmp_path, kind='hardware')


def run_main(f, apply=False):
    argv = [str(f.campaign), 'block0'] + (['--apply'] if apply else [])
    return spr.main(argv, root=f.testbed, live_inputs=Untouchable(), run=Untouchable())


def test_main_reaches_the_switch_only_when_every_precondition_holds(tmp_path, monkeypatch):
    f = hardware_fixture(tmp_path, monkeypatch)
    with pytest.raises(AssertionError, match='contacted the switch'):
        run_main(f)                                                  # all preconditions hold: it would contact


@pytest.mark.parametrize('breakage', ['ownership_active', 'ownership_other_step', 'terminal_changed', 'units_busy',
                                      'artifact_changed', 'config_changed', 'run_id', 'restore_verify_changed',
                                      'failure_shape', 'profile'])
def test_main_refuses_untouched_when_a_precondition_fails(tmp_path, monkeypatch, breakage):
    f = hardware_fixture(tmp_path, monkeypatch)
    own = json.loads(f.ownership.read_text())
    if breakage == 'ownership_active':
        f.ownership.write_text(json.dumps(dict(own, active=True)))
    elif breakage == 'ownership_other_step':
        f.ownership.write_text(json.dumps(dict(own, step_id='other')))
    elif breakage == 'terminal_changed':
        (f.steps / 'terminal.json').write_text((f.steps / 'terminal.json').read_text() + ' ')
    elif breakage == 'units_busy':
        monkeypatch.setattr(ec, 'running_eval_units', lambda: ['dnp3-eval-x.service'])
    elif breakage == 'artifact_changed':
        (f.run_root / 'block0_prerun.json').write_text('{"tables": {"x": 1}}')
    elif breakage == 'config_changed':
        f.config.write_text(json.dumps(dict(CONFIG, extra=1)))
    elif breakage == 'run_id':
        (f.run_root / 'campaign_run.json').write_text(json.dumps({'run_id': 'other', 'restore': FAILED + [VISION]}))
        f.bind()
    elif breakage == 'restore_verify_changed':
        (f.run_root / 'restore_verify.json').write_text('{"ok": true}')
    elif breakage == 'failure_shape':
        (f.run_root / 'run_block_run.out').write_text(failure_out(after='device_add error'))
        f.bind()
    elif breakage == 'profile':
        f.config.write_text(json.dumps(dict(CONFIG, endpoint_profile='other')))
        (f.run_root / 'freeze_check.json').write_text(json.dumps({'freeze': 'freeze.json',
                                                                  'config_sha256': sha(f.config)}))
        f.bind()
    with pytest.raises(SystemExit, match='REFUSED'):
        run_main(f, apply=True)
    assert not list(f.steps.glob('switch_process_repair_*'))
    assert re.search('"unsafe_restoration": true', f.ownership.read_text())


# --- the ssh-bound functions (fake ssh) ----------------------------------------------------------------------------

class FakeSsh:
    def __init__(self, replies):
        self.replies, self.calls = replies, []

    def __call__(self, host, command, timeout=1800):
        self.calls.append(command)
        rc, out = next(v for k, v in self.replies.items() if k in command)
        return type('R', (), dict(returncode=rc, stdout=out, stderr=''))()


def bound_inputs():
    import campaign_base
    files = {str(Path(p).resolve().relative_to(ROOT)): {'sha256': sha(p)} for p, _ in campaign_base.switch_tools()}
    remote = {'%s/aux/%s' % (REMOTE, n): sha(p) for p, n in campaign_base.switch_tools()}
    remote['%s/snap/%s_prerun.json' % (REMOTE, RUN_ID)] = 'P' * 64
    return files, remote


def test_inputs_must_match_the_freeze_hashes_and_the_retained_prerun_including_response_path_cp(monkeypatch):
    files, remote = bound_inputs()
    assert any(k.endswith('model/response_path_cp.py') for k in files)
    listing = '\n'.join('%s  %s' % (h, p) for p, h in remote.items())
    monkeypatch.setattr(spr, 'ssh', FakeSsh({'sha256sum': (0, listing)}))
    assert spr.live(CONFIG, RUN_ID, files, 'P' * 64)[3]()[0] is True
    assert spr.live(CONFIG, RUN_ID, files, 'Q' * 64)[3]()[0] is False                      # pre-run differs
    missing = {k: v for k, v in files.items() if not k.endswith('response_path_cp.py')}
    assert spr.live(CONFIG, RUN_ID, missing, 'P' * 64)[3]()[0] is False                     # unbound tool
    monkeypatch.setattr(spr, 'ssh', FakeSsh({'sha256sum': (0, listing.replace(remote[next(iter(remote))], 'X' * 64))}))
    assert spr.live(CONFIG, RUN_ID, files, 'P' * 64)[3]()[0] is False                       # deployed tool differs


def test_listening_fails_closed_and_the_signal_command_rechecks_the_start_time(monkeypatch):
    for rc, want in ((0, True), (1, False), (255, True)):
        monkeypatch.setattr(spr, 'ssh', FakeSsh({'ss -lnt': (rc, '')}))
        assert spr.live(CONFIG, RUN_ID, {}, None)[2]() is want
    fake = FakeSsh({'kill': (0, ''), 'sudo -n python3': (0, '')})
    monkeypatch.setattr(spr, 'ssh', fake)
    spr.live(CONFIG, RUN_ID, {}, None)[1](proc(3735291, 241142860, CANDIDATE), 'KILL')
    assert fake.calls[-1].startswith('sudo -n python3 -c ') and fake.calls[-1].endswith(' 3735291 241142860 KILL')


def test_the_remote_scripts_run_and_the_signal_script_refuses_a_process_that_is_not_bf_switchd():
    import subprocess
    listed = subprocess.run([sys.executable, '-c', spr.LIST_PROCS], stdout=subprocess.PIPE, text=True, check=True)
    assert isinstance(json.loads(listed.stdout), list)
    sleeper = subprocess.Popen(['sleep', '30'])
    try:
        stat = Path('/proc/%d/stat' % sleeper.pid).read_text()
        start = int(stat[stat.rindex(')') + 2:].split()[19])
        rc = subprocess.run([sys.executable, '-c', spr.SIGNAL_IF_SAME, str(sleeper.pid), str(start), 'KILL']).returncode
        assert rc == 3 and sleeper.poll() is None                       # comm is sleep: refused, still running
    finally:
        sleeper.kill()
        sleeper.wait()


# --- completing a partial repair -----------------------------------------------------------------------------------

BOUND = {'terminal': 'T', 'campaign_run.json': 'C'}


@pytest.mark.parametrize('over,allowed', [({}, True), (dict(ok=True), False), (dict(bound_sha256={'terminal': 'X'}), False),
                                          (dict(termination=dict(exited=False)), False),
                                          (dict(absent_before_launch=False), False),
                                          (dict(steps=[dict(name='launch_production', rc=0),
                                                       dict(name='replay_ports', rc=1)]), False),
                                          (dict(steps=[]), False),
                                          (dict(continues=dict(path='x', sha256='y')), False)])
def test_only_a_partial_repair_that_passed_the_switch_steps_can_be_completed(over, allowed):
    assert (spr.continuable(partial_record(**over), BOUND) == []) is allowed


def test_completion_runs_only_the_ping_and_only_on_the_production_program():
    hosts = FakeHosts([], {})
    out = spr.complete_repair(CONFIG, partial_record(), hosts.run, lambda: {'program': 'case4_response_path'})
    assert out['ok'] and [s['name'] for s in out['steps']] == list(spr.STEP_NAMES)
    assert restore_commands(hosts) == ['ping -c 2 -I 192.168.10.1 192.168.10.7']
    assert out['continued_steps'][-1] == dict(name='vision_restore', rc=1)       # the failed attempt stays visible
    assert out['continued_errors'] == ['vision_restore exited 1']
    hosts = FakeHosts([], {})
    out = spr.complete_repair(CONFIG, partial_record(), hosts.run, lambda: {'program': 'response_only'})
    assert not out['ok'] and hosts.commands == []
    out = spr.complete_repair(CONFIG, partial_record(), hosts.run, lambda: (_ for _ in ()).throw(OSError('ssh')))
    assert not out['ok'] and 'raised' in out['errors'][0]


def test_reconcile_accepts_a_completion_bound_to_its_partial_repair(tmp_path):
    f = Fixture(tmp_path)
    bound = {'terminal': sha(f.steps / 'terminal.json'), 'campaign_run.json': sha(f.run_root / 'campaign_run.json')}
    first = f.steps / 'switch_process_repair_20261030T155946Z'
    first.mkdir()
    (first / 'repair.json').write_text(json.dumps(partial_record(bound_sha256=bound)))
    with pytest.raises(ec.Refused):
        f.reconcile(ONLY)                                            # the partial repair alone is refused
    completion = repair_record(bound_sha256=bound, continues=dict(path=str(first / 'repair.json'),
                                                                  sha256=sha(first / 'repair.json')))
    second = f.steps / 'switch_process_repair_20261030T161000Z'
    second.mkdir()
    (second / 'repair.json').write_text(json.dumps(completion))
    record = json.loads(Path(f.reconcile(ONLY, now=1001)).read_text())
    assert f.flag() is False and record['switch_process_repair']['problems'] == []


@pytest.mark.parametrize('tamper', ['sha', 'carried', 'elsewhere'])
def test_a_completion_that_does_not_bind_its_partial_repair_is_refused(tmp_path, tamper):
    first = tmp_path / 'switch_process_repair_20261030T155946Z'
    first.mkdir()
    (first / 'repair.json').write_text(json.dumps(partial_record()))
    path, digest = str(first / 'repair.json'), sha(first / 'repair.json')
    over = {}
    if tamper == 'sha':
        digest = '0' * 64
    elif tamper == 'carried':
        over = dict(termination=dict(exited=True, signals=['TERM']))
    elif tamper == 'elsewhere':
        other = tmp_path / 'other' / 'switch_process_repair_x'
        other.mkdir(parents=True)
        (other / 'repair.json').write_text(json.dumps(partial_record()))
        path, digest = str(other / 'repair.json'), sha(other / 'repair.json')
    write_repair(tmp_path, repair_record(continues=dict(path=path, sha256=digest), **over))
    assert accept(tmp_path)[1]


def test_main_complete_refuses_without_a_continuable_record_and_records_a_bound_completion(tmp_path, monkeypatch):
    f = hardware_fixture(tmp_path, monkeypatch)
    hosts = FakeHosts([], {})
    argv = [str(f.campaign), 'block0', '--complete']
    with pytest.raises(SystemExit, match='REFUSED'):
        spr.main(argv, root=f.testbed, live_inputs=Untouchable(), run=hosts.run, observe=lambda c: {'program': 'case4_response_path'})
    record, *_ = spr.preconditions(f.campaign, ec.load(f.campaign)[1]['steps'][0], f.steps, f.testbed)
    first = f.steps / 'switch_process_repair_20261030T155946Z'
    first.mkdir()
    (first / 'repair.json').write_text(json.dumps(partial_record(bound_sha256=record['bound_sha256'])))
    assert spr.main(argv, root=f.testbed, live_inputs=Untouchable(), run=hosts.run,
                    observe=lambda c: {'program': 'case4_response_path'}) == 0
    done = sorted(f.steps.glob('switch_process_repair_*/repair.json'))[-1]
    data = json.loads(done.read_text())
    assert data['ok'] and data['continues']['sha256'] == sha(first / 'repair.json')
    assert ec.switch_process_acceptance(f.steps, data['bound_sha256']['terminal'], data['bound_sha256']['campaign_run.json'],
                                        fresh_ok(), 'case4_response_path')[1] == []

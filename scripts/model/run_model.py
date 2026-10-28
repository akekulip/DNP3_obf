"""Run one of the 17 current model drivers in a private SDK namespace.

Usage: python3 scripts/model/run_model.py BUILD DRIVER ATTEMPT
Evidence: results/models/BUILD_NAME/model_DRIVER_BUILD_NAME_NN/"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

HERE = Path(__file__).resolve().parent
REQUIRED = ('abandon', 'abort', 'contention', 'control_timing', 'dup', 'fin_busy', 'packets', 'policy', 'policy_boundary', 'rearm', 'relay_sbo', 'repeat', 'response_ready', 'select_lifecycle', 'smoke', 'smoke_sizeoff', 'two_read_robust')
DRIVERS = {name: HERE / ('model_' + name + '.py') for name in REQUIRED}
WRAPPED = {'abort': {'model_contention.py': HERE / 'model_contention.py'}}
DEPENDENCIES = [HERE / 'model_repeat.py', HERE / 'model_drive_composite.py']


def gate_environment(inputs_path, inputs, driver, out, model_sde):
    """The qualifying gate has fixed coverage; inherited diagnostic knobs cannot narrow it."""
    env = dict(os.environ)
    for name in ('CONTENTION_SECTIONS', 'CONTENTION_TIMELINE', 'POLICY_CASE', 'CTL_PB',
                 'MODEL_EXTRA', 'MODEL_NO_PORTMAP', 'MODEL_INT_PORT_LOOP', 'MODEL_ENABLE_PORTS', 'PYTHONPATH'):
        env.pop(name, None)
    env.update(PORT_MAP=str(inputs_path), PAD_ENABLE='1', MILESTONE=inputs['milestone'],
               REPEAT_CYCLES='64', REPEAT_TIMED_CYCLES='3', ABANDON_T='0',
               MODEL_SDE=str(model_sde), CTL_CLOSURE_REPO=str(ROOT),
               CTL_CLOSURE_TARGET=str(driver), CTL_CLOSURE_OUT=str(out / 'dependency_closure.json'))
    return env

def model_ports(inputs, driver=None):
    """Ports are source-profile data, including distinct physical relay dev64."""
    profile = inputs.get('supported_profile') or {}
    ports = profile.get('ports') or {}
    values = {int(v) for k, v in ports.items() if k != 'stat_ports' and type(v) is int}
    pm = inputs.get('port_map') or {}
    values.update(int(v) for v in pm.values())
    if profile.get('timing_contract') == 'response_ready_ack_d_no_j_v3' and driver in ('response_ready','control_timing','dup'):
        # Private model namespace only: exercise rejection at the removed old HB ingress.
        values.add(181)
    values.add(9)
    values.add(68)
    values.add(((int(pm.get('t_in', 180)) >> 7) << 7) + 68)
    return ' '.join(map(str, sorted(values)))


def check_reset(out, inputs_path):
    """Run the reset checker through the existing recorder and bind its evidence into the run closure."""
    checker = HERE / 'reset_application_check.py'
    check_closure = out / 'reset_application.dependencies.json'
    env = dict(os.environ, CTL_CLOSURE_TARGET=str(checker), CTL_CLOSURE_OUT=str(check_closure))
    checked = subprocess.run([sys.executable, str(HERE / 'record_closure.py'), str(out)],
                             env=env, capture_output=True, text=True)
    report = out / 'reset_application.json'
    report.write_text(checked.stdout if checked.stdout.strip() else json.dumps(
        dict(error='reset checker produced no report', stderr=checked.stderr[-4000:])) + '\n')
    path = out / 'dependency_closure.json'
    try:
        closure = json.loads(path.read_text())
    except (OSError, ValueError):
        closure = dict(files={}, error='driver dependency closure missing or unreadable')
    dependency = json.loads(check_closure.read_text()) if check_closure.is_file() else {}
    files = closure.setdefault('files', {})
    for name, sha in dependency.get('files', {}).items():
        if name in files and files[name] != sha:
            raise ValueError('dependency changed between driver and reset checker: %s' % name)
        files[name] = sha
    inputs = list(out.glob('*_results.json')) + list(out.glob('model_*.log'))
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    hashes['response_only.inputs.json'] = hashlib.sha256(inputs_path.read_bytes()).hexdigest()
    closure.setdefault('postchecks', {})['reset_application'] = dict(
        checker=str(checker), exit_code=checked.returncode, input_sha256=hashes,
        report_sha256=hashlib.sha256(report.read_bytes()).hexdigest(),
        dependency_closure_sha256=(hashlib.sha256(check_closure.read_bytes()).hexdigest()
                                   if check_closure.is_file() else None))
    path.write_text(json.dumps(closure, indent=1) + '\n')
    return checked.returncode or (1 if closure.get('error') else 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('driver', choices=sorted(DRIVERS))
    parser.add_argument('attempt', type=int)
    args = parser.parse_args()
    if args.attempt < 1:
        parser.error('attempt must be a positive integer')
    build = args.build.resolve()
    inputs_path = build / 'response_only.inputs.json'
    inputs = json.loads(inputs_path.read_text())
    from model_profile import resolve, compiled_t_state_of_build
    profile = resolve(inputs, build / 'response_only.p4')
    sys.path.insert(0, str(HERE.parent))
    import build as compiler_evidence
    verified = compiler_evidence.verify_evidence(build / 'compile_local', source_root=build)
    if not verified['compiled_artifacts_verified']:
        raise SystemExit('model requires a verified compile of the selected source')
    sys.path.insert(0, str(HERE.parent / 'hardware'))
    import sealed_profile
    sealed_profile.describe(build / 'compile_local/out')
    compile_manifest_sha256 = hashlib.sha256((build / 'compile_local/manifest.json').read_bytes()).hexdigest()
    audit = compiled_t_state_of_build(build, profile['timing_contract'])
    if audit['problems']:
        raise SystemExit('compiled state/layout precondition failed: ' + '; '.join(audit['problems']))
    # A source change must not silently reuse the meaning of a log action.
    from telemetry_from_log import verified_observations
    verified_observations(build / 'response_only.p4')
    sha = hashlib.sha256((build / 'response_only.p4').read_bytes()).hexdigest()
    out = ROOT / 'results/models' / build.name / ('model_%s_%s_%02d' % (args.driver, build.name, args.attempt))
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        raise SystemExit('model evidence must not be overwritten: ' + str(out))
    driver = DRIVERS[args.driver]
    command = ['bash', str(HERE / 'launch_model.sh'), '-p', str(build / 'compile_local/out'),
               '-o', str(out), '-P', model_ports(inputs, driver=args.driver), '-d', str(HERE / 'record_closure.py')]
    env = gate_environment(inputs_path, inputs, driver, out, compiler_evidence.DEFAULT_COMPILER.parents[2])
    result = subprocess.run(command, env=env)
    exit_code = result.returncode
    if out.is_dir():
        if args.driver == 'contention':
            check_exit = check_reset(out, inputs_path)
            if exit_code == 0:
                exit_code = check_exit
        from retained_logs import archive_run, MANIFEST
        retention_error = None
        try:
            archive_run(out, preserve_startup_stdout=not (out / 'dependency_closure.json').is_file())
        except (OSError, ValueError) as error:
            retention_error = str(error)
            exit_code = exit_code or 1
        (out / 'driver_source.py').write_bytes(driver.read_bytes())
        for name, path in WRAPPED.get(args.driver, {}).items():
            (out / ('driver_dependency_%s' % name)).write_bytes(path.read_bytes())
        libraries = [HERE / 'model_driver.py', HERE.parent / 'hardware/t_config.py',
                     HERE / 'action_observations.json']
        (out / 'launch_command.json').write_text(json.dumps({
            'command': command, 'PORT_MAP': str(inputs_path), 'PAD_ENABLE': '1', 'MILESTONE': inputs['milestone'],
            'pb_injected': None, 'timeline': False, 'hardware': False, 'source_sha256': sha,
            'driver_sha256': hashlib.sha256(driver.read_bytes()).hexdigest(),
            'compile_manifest_sha256': compile_manifest_sha256,
            'library_sha256': {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in libraries},
            'dependency_sha256': {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in DEPENDENCIES + list(WRAPPED.get(args.driver, {}).values())},
            'closure_target': str(driver),
            'dependency_closure_sha256': (hashlib.sha256((out / 'dependency_closure.json').read_bytes()).hexdigest()
                                          if (out / 'dependency_closure.json').is_file() else None),
            'timing_contract': profile['timing_contract'], 'reset_restart_required': True,
            'supported_profile_sha256': hashlib.sha256(inputs_path.read_bytes()).hexdigest(),
            'observation_source': 'SDK model action log; not physical switch counters',
            'stimulus_environment': {name: env[name] for name in
                ('REPEAT_CYCLES', 'REPEAT_TIMED_CYCLES', 'ABANDON_T', 'MODEL_SDE')},
            'model_log_retention_sha256': (hashlib.sha256((out / MANIFEST).read_bytes()).hexdigest()
                                          if (out / MANIFEST).is_file() else None),
            'retention_error': retention_error,
            'exit_code': exit_code}, indent=2) + '\n')
        if args.driver == 'contention':
            (out / 'committed_precondition.json').write_text(json.dumps(dict(applicable=False,
                timing_contract=profile['timing_contract'],
                reason='D-only proofs use actual ACK hold, whole response, ACK commit and full-D model clock'), indent=1) + '\n')
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())

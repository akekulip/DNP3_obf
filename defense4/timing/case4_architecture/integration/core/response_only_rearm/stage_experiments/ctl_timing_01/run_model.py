"""Run a model driver against a ctl_timing_01 build in the private local model launcher (no hardware).

  python3 run_model.py BUILD_DIR DRIVER ATTEMPT [--milestone m1]
BUILD_DIR holds response_only.p4, response_only.inputs.json and compile_local/out; the source hash recorded in
inputs.json must match the file and the compile manifest. Evidence goes to evidence/model_<driver>_<build>_NN.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DRIVERS = {'fin_busy': HERE / 'model_fin_busy.py', 'relay_sbo': HERE / 'model_relay_sbo.py', 'control_timing': HERE / 'model_control_timing.py', 'select_lifecycle': HERE / 'model_select_lifecycle.py',
           'contention': HERE / 'model_contention.py', 'abort': HERE / 'model_abort.py', 'egress_diag': HERE / 'model_egress_diag.py', 'isolation_cleanup': HERE / 'model_isolation_cleanup.py'}
# wrapper drivers and the driver code they execute; local modules every driver imports
WRAPPED = {name: {'model_contention.py': HERE / 'model_contention.py'} for name in ('abort', 'egress_diag')}
DEPENDENCIES = [HERE.parent / 'seg61_02' / 'model_repeat.py', HERE.parents[2] / 'response_only' / 'model_drive_composite.py']
for name in ('smoke', 'packets', 'rearm', 'dup', 'repeat', 'abandon', 'prefix', 'mixed', 'fullread', 'mixedfull', 'fullread_corrupt', 'fullread_boundary', 'policy', 'policy_boundary', 'smoke_sizeoff', 'segmented', 'two_read_robust'):
    DRIVERS[name] = HERE.parent / 'seg61_02' / ('model_%s.py' % name)


def model_ports(inputs):
    """Ports are source-profile data, including distinct physical relay dev64."""
    profile = inputs.get('supported_profile') or {}
    ports = profile.get('ports') or {}
    values = {int(v) for k, v in ports.items() if k != 'stat_ports' and type(v) is int}
    pm = inputs.get('port_map') or {}
    values.update(int(v) for v in pm.values())
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
    parser.add_argument('build')
    parser.add_argument('driver', choices=sorted(DRIVERS))
    parser.add_argument('attempt', type=int)
    parser.add_argument('--milestone', default='m1')
    parser.add_argument('--timeline', action='store_true',
                        help='contention only: run under timeline_wrapper.py (diagnostic timeline, health monitor and the '
                             'packet-path stop rule; Philip, 2026-10-17); behaviour and acceptance unchanged')
    parser.add_argument('--pb', type=int, help='run a seg61_02 driver with this pb injected (model ns), via with_pb.py')
    args = parser.parse_args()
    build = (HERE / args.build).resolve() if not Path(args.build).is_absolute() else Path(args.build)
    inputs_path = build / 'response_only.inputs.json'
    inputs = json.loads(inputs_path.read_text())
    from model_profile import resolve
    profile = resolve(inputs, build / 'response_only.p4', args.milestone)
    sha = hashlib.sha256((build / 'response_only.p4').read_bytes()).hexdigest()
    manifest = json.loads((build / 'compile_local/manifest.json').read_text())
    assert sha == inputs['source_sha256'] == manifest['source_sha256'] and manifest['exit_code'] == 0
    if inputs.get('milestone') and args.milestone != inputs['milestone']:
        raise SystemExit('--milestone %s does not match the build (%s)' % (args.milestone, inputs['milestone']))
    out = HERE / ('evidence/model_%s_%s_%02d' % (args.driver, build.name, args.attempt))
    assert not out.exists(), 'evidence must not be overwritten'
    driver = DRIVERS[args.driver]
    launched = HERE / 'with_pb.py' if args.pb is not None else driver
    if args.timeline:
        if args.driver != 'contention' or args.pb is not None:
            raise SystemExit('--timeline instruments the contention driver only')
        launched = HERE / 'timeline_wrapper.py'
    # every run goes through record_closure.py, which records each repository file the driver executed (review
    # of af7bd434: a wrapper plus one inner driver is not the imported closure)
    command = ['bash', str(HERE.parents[2] / 'launch_model.sh'), '-p', str(build / 'compile_local/out'),
               '-o', str(out), '-P', model_ports(inputs), '-d', str(HERE / 'record_closure.py')]
    env = dict(os.environ, PORT_MAP=str(build / 'response_only.inputs.json'), PAD_ENABLE='1',
               MILESTONE=args.milestone, CTL_CLOSURE_TARGET=str(launched),
               CTL_CLOSURE_OUT=str(out / 'dependency_closure.json'))
    if args.pb is not None:
        env.update(CTL_PB=str(args.pb), CTL_TARGET_DRIVER=str(driver))
    if args.timeline:
        env.update(TIMELINE_TARGET=str(driver), CONTENTION_TIMELINE=str(out / 'timeline.jsonl'),
                   HEALTH_LOG=str(out / 'health.jsonl'))
    result = subprocess.run(command, env=env)
    exit_code = result.returncode
    if out.is_dir():
        if args.driver == 'contention' and profile['reset_restart_required']:
            check_exit = check_reset(out, inputs_path)
            if exit_code == 0:
                exit_code = check_exit
        (out / 'driver_source.py').write_bytes(driver.read_bytes())
        # the executed closure (review of 7637390c1): a wrapper's inner driver is retained beside it, and every
        # local module the drivers import is hashed
        for name, path in WRAPPED.get(args.driver, {}).items():
            (out / ('driver_dependency_%s' % name)).write_bytes(path.read_bytes())
        (out / 'launch_command.json').write_text(json.dumps({
            'command': command, 'PORT_MAP': env['PORT_MAP'], 'PAD_ENABLE': '1', 'MILESTONE': args.milestone,
            'pb_injected': args.pb, 'timeline': bool(args.timeline),
            'hardware': False, 'source_sha256': sha, 'driver_sha256': hashlib.sha256(driver.read_bytes()).hexdigest(),
            # the shared libraries that convert and install T parameters (review W5)
            'library_sha256': {name: hashlib.sha256((HERE.parents[2] / name).read_bytes()).hexdigest()
                               for name in ('model_driver.py', '../core/response_only/hw/t_config.py')},
            'dependency_sha256': {str(path.relative_to(HERE.parents[2])): hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in DEPENDENCIES + list(WRAPPED.get(args.driver, {}).values())},
            'closure_target': str(launched),
            'dependency_closure_sha256': (hashlib.sha256((out / 'dependency_closure.json').read_bytes()).hexdigest()
                                          if (out / 'dependency_closure.json').is_file() else None),
            'reset_restart_required': profile['reset_restart_required'],
            'supported_profile_sha256': hashlib.sha256(inputs_path.read_bytes()).hexdigest(),
            'exit_code': exit_code}, indent=2) + '\n')
        if args.driver == 'contention':
            # classifies each committed-path point by its precondition (response at T before t0 + readiness); it
            # changes no verdict (committed_precondition_check.py)
            check = subprocess.run([sys.executable, str(HERE / 'committed_precondition_check.py'), str(out)],
                                   capture_output=True, text=True)
            # 0 = all measured, 2 = classified, 3 = checker error (its own JSON record); anything else (an
            # interpreter failure) is recorded here rather than left empty
            (out / 'committed_precondition.json').write_text(
                check.stdout if check.returncode in (0, 2, 3) and check.stdout.strip() else
                json.dumps(dict(error=True, returncode=check.returncode, stderr=check.stderr[-4000:]), indent=1) + '\n')
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())

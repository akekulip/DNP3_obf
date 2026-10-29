"""Run the c72_diag_mirror fidelity driver with mirror sessions on, off and absent, then compare the three runs.

Usage: python3 scripts/model/run_diag_mirror.py BUILD ATTEMPT [--companion DRIVER[,DRIVER...]]
Evidence: results/models/BUILD_NAME/model_diag_mirror_{on,off,absent}_BUILD_NAME_NN/ and diag_mirror_fidelity_NN.json;
with --companion, model_diag_companion_DRIVER_{absent,on}_BUILD_NAME_NN/ and diag_mirror_companion_NN.json instead
(each named c72 driver, unmodified, with sessions absent and on; see model_diag_mirror_companion.py).

Pass criteria (all from model output, no physical claim):
  on:  each frame received on the relay port appears once on the copy port, byte-identical to the injected frame;
       each frame emitted on the relay port appears once on the copy port, byte-identical to the emitted frame;
       a frame dropped in egress toward the relay is not copied; nothing arriving on the copy port goes anywhere.
  off, absent: no frame on the copy port.
  across states: every dev9/dev64 output is byte-identical; ingress passes, recirculations, bypass-egress
       transmissions and loop-port reflections are identical per step; the only extra passes with mirroring on
       are the copies' egress passes and transmissions on the copy port.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
STATES = ('on', 'off', 'absent')
DRIVER = HERE / 'model_diag_mirror.py'
COMPANION = HERE / 'model_diag_mirror_companion.py'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def compare(runs, copy, relay, master):
    """runs: {state: (steps list, results dict)} -> {criterion: [failures]} (empty list = pass)."""
    fails = {k: [] for k in ('driver_checks', 'forwarding_identical', 'pass_counts_identical', 'extra_passes_only_copies',
                             'copies_only_when_on', 'reflections_identical')}
    for state, (_steps, results) in runs.items():
        if results['summary']['failed']:
            fails['driver_checks'].append({state: results['summary']['failed']})
    names = [s['name'] for s in runs['on'][0]]
    for state in STATES[1:]:
        if [s['name'] for s in runs[state][0]] != names:
            fails['forwarding_identical'].append('%s ran different steps' % state)
            return fails
    same_keys = ('ingress_from', 'recirculated', 'bypass_egress_tx')
    for i, name in enumerate(names):
        rows = {state: runs[state][0][i] for state in STATES}
        for state in STATES[1:]:
            for port in (str(master), str(relay)):
                if rows[state]['outputs'][port] != rows['on']['outputs'][port]:
                    fails['forwarding_identical'].append('%s: dev%s differs between on and %s' % (name, port, state))
            for key in same_keys:
                if rows[state]['log'][key] != rows['on']['log'][key]:
                    fails['pass_counts_identical'].append('%s: %s on=%s %s=%s' % (name, key, rows['on']['log'][key],
                                                                                state, rows[state]['log'][key]))
            for key in ('tx_to', 'egress_parser_to'):
                a = {p: n for p, n in rows['on']['log'][key].items() if p != str(copy)}
                b = {p: n for p, n in rows[state]['log'][key].items() if p != str(copy)}
                if a != b:
                    fails['extra_passes_only_copies'].append('%s: %s on=%s %s=%s' % (name, key, a, state, b))
                if rows[state]['log'][key].get(str(copy)):
                    fails['copies_only_when_on'].append('%s: %s %s on dev%d' % (name, state, key, copy))
            if rows[state]['outputs'][str(copy)]:
                fails['copies_only_when_on'].append('%s: %d frame(s) on dev%d with sessions %s'
                                                    % (name, len(rows[state]['outputs'][str(copy)]), copy, state))
        on = rows['on']
        if on['log']['tx_to'].get(str(copy), 0) != len(on['outputs'][str(copy)]):
            fails['extra_passes_only_copies'].append('%s: model sent %s copies, %d captured'
                                                     % (name, on['log']['tx_to'].get(str(copy), 0), len(on['outputs'][str(copy)])))
    refl = {}
    for state in STATES:
        meta = runs[state][1]['meta']
        before = meta.get('reflections_before_steps', {})
        refl[state] = {p: r['frames'] - before.get(p, 0) for p, r in meta.get('reflections', {}).items()}
    for state in STATES[1:]:
        if refl[state] != refl['on']:
            fails['reflections_identical'].append('loop-port reflections on=%s %s=%s' % (refl['on'], state, refl[state]))
    return fails


def launch(build, inputs_path, inputs, target, out, ports, extra_env):
    """One model session in a private namespace; logs retained as run_model.py retains them."""
    import build as compiler_evidence
    import run_model
    from retained_logs import archive_run
    if out.exists():
        raise SystemExit('evidence must not be overwritten: %s' % out)
    command = ['bash', str(HERE / 'launch_model.sh'), '-p', str(build / 'compile_local/out'), '-o', str(out),
               '-P', ports, '-d', str(HERE / 'record_closure.py')]
    env = run_model.gate_environment(inputs_path, inputs, target, out, compiler_evidence.DEFAULT_COMPILER.parents[2])
    env.update(extra_env)
    exit_code = subprocess.run(command, env=env).returncode
    archive_run(out, preserve_startup_stdout=not (out / 'dependency_closure.json').is_file())
    (out / 'driver_source.py').write_bytes(Path(target).read_bytes())
    launch = dict(command=command, exit_code=exit_code, PORT_MAP=str(inputs_path), **extra_env,
                  stimulus_environment={k: env[k] for k in ('PAD_ENABLE', 'MILESTONE', 'ABANDON_T', 'MODEL_SDE',
                                                            'REPEAT_CYCLES', 'REPEAT_TIMED_CYCLES')},
                  dependency_closure_sha256=sha(out / 'dependency_closure.json')
                  if (out / 'dependency_closure.json').is_file() else None)
    (out / 'launch_command.json').write_text(json.dumps(launch, indent=2) + '\n')
    return launch


def companions(build, inputs_path, inputs, names, attempt, copy_port):
    import run_model
    base = ROOT / 'results/models' / build.name
    base.mkdir(parents=True, exist_ok=True)
    report_path = base / ('diag_mirror_companion_%02d.json' % attempt)
    if report_path.exists():
        raise SystemExit('evidence must not be overwritten: %s' % report_path)
    results = {}
    for name in names:
        driver = run_model.DRIVERS[name]
        ports = run_model.model_ports(inputs, driver=name) + ' %d' % copy_port
        runs = {}
        for state in ('absent', 'on'):
            out = base / ('model_diag_companion_%s_%s_%s_%02d' % (name, state, build.name, attempt))
            launch(build, inputs_path, inputs, COMPANION, out, ports,
                   dict(DIAG_MIRROR_STATE=state, DIAG_COMPANION_DRIVER=str(driver)))
            try:
                runs[state] = json.loads((out / 'diag_companion.json').read_text())
            except (OSError, ValueError) as error:
                runs[state] = dict(passed=False, error=str(error))
            results_files = sorted(p.name for p in out.glob('*_results.json'))
            runs[state]['driver_results'] = {}
            for rname in results_files:
                record = json.loads((out / rname).read_text())
                runs[state]['driver_results'][rname] = dict(summary=record.get('summary'), cases=[
                    (case.get('name'), case.get('ok'), json.dumps(case.get('observed'), sort_keys=True))
                    for case in record.get('cases', [])])
        a, b = runs['absent'], runs['on']
        same = {}
        for key in sorted(set(a.get('digests', {})) | set(b.get('digests', {}))):
            x, y = a.get('digests', {}).get(key), b.get('digests', {}).get(key)
            same[key] = 'identical_order' if x == y else ('same_multiset' if sorted(x or []) == sorted(y or []) else 'different')
        verdicts_same = {r: a['driver_results'].get(r) == b['driver_results'].get(r) for r in
                         set(a['driver_results']) | set(b['driver_results'])}
        results[name] = dict(absent=dict(passed=a.get('passed'), checks=a.get('checks'), counts=a.get('counts'),
                                         driver_exit=a.get('driver_exit'), relay_egress_drops=a.get('relay_egress_drops')),
                             on=dict(passed=b.get('passed'), checks=b.get('checks'), counts=b.get('counts'),
                                     copy_kinds=b.get('copy_kinds'), driver_exit=b.get('driver_exit'),
                                     relay_egress_drops=b.get('relay_egress_drops'),
                                     egress_drops_by_port=b.get('egress_drops_by_port'),
                                     unmatched_copies=b.get('unmatched_copies'), uncopied=b.get('uncopied_relay_frames')),
                             forwarding_vs_absent=same, driver_verdicts_identical=verdicts_same,
                             passed=bool(a.get('passed') and b.get('passed') and all(v != 'different' for v in same.values())
                                         and same and all(verdicts_same.values())))
    report = dict(schema='c72-diag-mirror-companion-summary-v1', build=build.name, source_sha256=sha(build / 'response_only.p4'),
                  observation='SDK tofino-model functional output; not hardware, not timing', drivers=results,
                  companion_sha256=sha(COMPANION), runner_sha256=sha(__file__), passed=all(r['passed'] for r in results.values()))
    report_path.write_text(json.dumps(report, indent=1) + '\n')
    print(json.dumps(dict(passed=report['passed'], drivers={k: v['passed'] for k, v in results.items()}, report=str(report_path))))
    return 0 if report['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('build', type=Path)
    parser.add_argument('attempt', type=int)
    parser.add_argument('--companion', help='comma-separated c72 driver names (run_model.REQUIRED)')
    args = parser.parse_args()
    build = args.build.resolve()
    inputs_path = build / 'response_only.inputs.json'
    inputs = json.loads(inputs_path.read_text())
    sys.path[:0] = [str(HERE), str(HERE.parent), str(HERE.parent / 'hardware')]
    import build as compiler_evidence
    from model_profile import resolve
    from telemetry_from_log import verified_observations, OBSERVATIONS
    import diag_mirror_sessions
    import run_model
    profile = resolve(inputs, build / 'response_only.p4')
    if not compiler_evidence.verify_evidence(build / 'compile_local', source_root=build)['compiled_artifacts_verified']:
        raise SystemExit('model requires a verified compile of the selected source')
    verified_observations(build / 'response_only.p4')
    c = diag_mirror_sessions.load(build)
    if diag_mirror_sessions.validate(c):
        raise SystemExit('session constants invalid: %s' % diag_mirror_sessions.validate(c))
    if args.companion:
        return companions(build, inputs_path, inputs, args.companion.split(','), args.attempt, c['copy_port'])
    ports = run_model.model_ports(inputs) + ' %d' % c['copy_port']
    base = ROOT / 'results/models' / build.name
    base.mkdir(parents=True, exist_ok=True)
    report_path = base / ('diag_mirror_fidelity_%02d.json' % args.attempt)
    if report_path.exists():
        raise SystemExit('evidence must not be overwritten: %s' % report_path)
    runs, launches = {}, {}
    for state in STATES:
        out = base / ('model_diag_mirror_%s_%s_%02d' % (state, build.name, args.attempt))
        launches[state] = launch(build, inputs_path, inputs, DRIVER, out, ports, dict(DIAG_MIRROR_STATE=state))
        try:
            runs[state] = (json.loads((out / 'diag_mirror_steps.json').read_text())['steps'],
                           json.loads((out / 'diag_mirror_results.json').read_text()))
        except (OSError, ValueError) as error:
            runs[state] = ([], dict(summary=dict(failed=['no driver output: %s' % error]), meta={}))
    master = inputs['supported_profile']['ports']['master_dev']
    if all(runs[s][0] for s in STATES):
        fails = compare(runs, c['copy_port'], c['relay_in'], master)
    else:
        fails = dict(driver_checks=[{s: runs[s][1]['summary']['failed']} for s in STATES])
    on_steps = runs['on'][0]
    report = dict(schema='c72-diag-mirror-model-fidelity-v1', build=build.name, source_sha256=sha(build / 'response_only.p4'),
                  observation='SDK tofino-model functional output; not hardware, not timing',
                  constants=c, launches=launches, criteria=fails, passed=not any(fails.values()),
                  copy_matches={s['name']: s.get('copy_match') for s in on_steps},
                  copies_per_step={s['name']: len(s['outputs'][str(c['copy_port'])]) for s in on_steps},
                  driver_sha256=sha(DRIVER), runner_sha256=sha(__file__),
                  sessions_script_sha256=sha(HERE.parent / 'hardware/diag_mirror_sessions.py'),
                  observations_file=str(OBSERVATIONS), observations_sha256=sha(OBSERVATIONS),
                  repository_root=str(ROOT))
    report_path.write_text(json.dumps(report, indent=1) + '\n')
    print(json.dumps(dict(passed=report['passed'], criteria={k: len(v) for k, v in fails.items()}, report=str(report_path))))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

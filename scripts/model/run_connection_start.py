"""Run the connection-start loss scenario once on a build. NOT part of the model gate.

Usage: python3 scripts/model/run_connection_start.py BUILD ATTEMPT
Evidence: results/models/BUILD_NAME_connection_start/model_connection_start_BUILD_NAME_NN/

The driver is scripts/model/model_connection_start.py. The launch path, preconditions and environment are run_model's
(run_model.gate_environment unchanged, with this driver as the closure target). The evidence sits outside
results/models/BUILD_NAME/, so model_summary never counts it as a gate run. Refuses to start while another
tofino-model process is running (one model at a time on this host)."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_model  # noqa: E402

DRIVER = HERE / 'model_connection_start.py'
SCENARIO = ('connection-start loss paths (H1, H2, H2r, collision genuine; H1prime forced); a separate labelled '
            'scenario, not part of the 17-driver model gate')


def evidence_dir(build, attempt):
    name = Path(build).name
    return ROOT / 'results/models' / (name + '_connection_start') / ('model_connection_start_%s_%02d' % (name, attempt))


def model_running():
    return subprocess.run(['pgrep', '-x', 'tofino-model'], capture_output=True).returncode == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('attempt', type=int)
    args = parser.parse_args()
    if args.attempt < 1:
        parser.error('attempt must be a positive integer')
    if model_running():
        raise SystemExit('another tofino-model is running; one model at a time')
    build = args.build.resolve()
    inputs_path = build / 'response_only.inputs.json'
    inputs = json.loads(inputs_path.read_text())
    # The same preconditions as run_model.main, in the same order.
    from model_profile import resolve, compiled_t_state_of_build
    profile = resolve(inputs, build / 'response_only.p4')
    sys.path.insert(0, str(HERE.parent))
    import build as compiler_evidence
    if not compiler_evidence.verify_evidence(build / 'compile_local', source_root=build)['compiled_artifacts_verified']:
        raise SystemExit('model requires a verified compile of the selected source')
    sys.path.insert(0, str(HERE.parent / 'hardware'))
    import sealed_profile
    sealed_profile.describe(build / 'compile_local/out')
    audit = compiled_t_state_of_build(build, profile['timing_contract'])
    if audit['problems']:
        raise SystemExit('compiled state/layout precondition failed: ' + '; '.join(audit['problems']))
    from telemetry_from_log import verified_observations
    verified_observations(build / 'response_only.p4')
    out = evidence_dir(build, args.attempt)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        raise SystemExit('model evidence must not be overwritten: ' + str(out))
    command = ['bash', str(HERE / 'launch_model.sh'), '-p', str(build / 'compile_local/out'), '-o', str(out),
               '-P', run_model.model_ports(inputs, driver='connection_start'), '-d', str(HERE / 'record_closure.py')]
    env = run_model.gate_environment(inputs_path, inputs, DRIVER, out, compiler_evidence.DEFAULT_COMPILER.parents[2])
    exit_code = subprocess.run(command, env=env).returncode
    if out.is_dir():
        from retained_logs import archive_run, MANIFEST
        retention_error = None
        try:
            archive_run(out, preserve_startup_stdout=not (out / 'dependency_closure.json').is_file())
        except (OSError, ValueError) as error:
            retention_error = str(error)
            exit_code = exit_code or 1
        (out / 'driver_source.py').write_bytes(DRIVER.read_bytes())

        def sha(path):
            return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        (out / 'launch_command.json').write_text(json.dumps({
            'scenario': SCENARIO, 'model_gate': False, 'command': command, 'PORT_MAP': str(inputs_path),
            'source_sha256': sha(build / 'response_only.p4'), 'driver_sha256': sha(DRIVER),
            'closure_target': str(DRIVER), 'compile_manifest_sha256': sha(build / 'compile_local/manifest.json'),
            'dependency_closure_sha256': sha(out / 'dependency_closure.json'),
            'timing_contract': profile['timing_contract'], 'supported_profile_sha256': sha(inputs_path),
            'observation_source': 'SDK model action log and BFRT register reads; not physical switch counters',
            'stimulus_environment': {name: env[name] for name in ('MODEL_SDE', 'PAD_ENABLE')},
            'model_log_retention_sha256': sha(out / MANIFEST),
            'retention_error': retention_error, 'exit_code': exit_code}, indent=2) + '\n')
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())

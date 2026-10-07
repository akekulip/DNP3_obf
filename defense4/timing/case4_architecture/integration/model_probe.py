#!/usr/bin/env python3
"""Source-bound, no-interface local model startup diagnostic.

This does not load silicon, add interfaces or transmit packets. Startup success
would establish availability only; it never means parser/control/deparser verified.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('architecture_build', ROOT / 'build.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


def probe(evidence, output, sde):
    evidence, output, sde = Path(evidence).resolve(), Path(output).resolve(), Path(sde).resolve()
    check = build.verify_evidence(evidence)
    if not check['compiled_artifacts_verified']:
        raise ValueError('a source-current local successful compile is required')
    manifest = json.loads((evidence / 'manifest.json').read_text())
    configs = [name for name in manifest['artifact_sha256'] if name.endswith('.conf')]
    if len(configs) != 1:
        raise ValueError('exactly one hash-bound model configuration required')
    output.mkdir(parents=True, exist_ok=False)
    logs = output / 'model-runtime'
    logs.mkdir()
    binary = sde / 'install' / 'bin' / 'tofino-model'
    config = evidence / 'out' / configs[0]
    command = [str(binary), '--no-port-monitor', '-d', '1', '-k', '1', '-f', 'None',
               '--p4-target-config', str(config), '--install-dir', str(sde / 'install'),
               '--chip-type', '2', '--log-dir', str(logs), '--pkt-log-len', '256']
    env = os.environ.copy()
    env.update(SDE=str(sde), SDE_INSTALL=str(sde / 'install'))
    env['LD_LIBRARY_PATH'] = ':'.join((str(sde / 'install' / 'lib'), '/usr/local/lib',
                                     env.get('LD_LIBRARY_PATH', '')))
    result = {'source_sha256': manifest['source_sha256'],
              'compile_manifest_sha256': build.sha(evidence / 'manifest.json'),
              'config_sha256': build.sha(config), 'model_path': str(binary),
              'command': command, 'target_model_verified': False,
              'packet_execution_attempted': False, 'hardware_contact': False}
    started = time.monotonic()
    log = output / 'model.log'
    try:
        result['model_sha256'] = build.sha(binary)
        with log.open('w') as stream:
            process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT,
                                       env=env, cwd=logs, start_new_session=True)
            try:
                result['exit_code'] = process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                build.terminate_group(process)
                result.update(exit_code=124, timed_out=True)
            except BaseException:
                build.terminate_group(process)
                result.update(exit_code=130, interrupted=True)
                raise
    except Exception as exc:
        result.update(exit_code=125, error=f'{type(exc).__name__}: {exc}')
    finally:
        result['elapsed_seconds'] = round(time.monotonic() - started, 3)
        text = log.read_text() if log.is_file() else ''
        if 'Unable to drop privileges to purely CAP_NET_RAW' in text:
            result['blocker'] = 'local model requires unavailable CAP_NET_RAW'
        else:
            result['blocker'] = 'startup diagnostic alone does not verify packet execution'
        if log.is_file():
            result['model_log_sha256'] = hashlib.sha256(log.read_bytes()).hexdigest()
        (output / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--sde', type=Path, default=Path('/home/philip/bf-sde-9.13.1'))
    args = parser.parse_args()
    print(json.dumps(probe(args.evidence, args.output, args.sde), indent=2, sort_keys=True))
    raise SystemExit(2)  # A startup-only diagnostic cannot pass the packet/model gate.

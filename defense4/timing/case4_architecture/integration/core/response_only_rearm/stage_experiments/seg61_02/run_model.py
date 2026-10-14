"""Run a pinned E61 driver in the existing private local model launcher."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
SHA = '1b2d62d16d40427d8b7e5d4b93f9e57b75e721e6a6c7e4c184fb84a1dc3665aa'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('driver', choices=('smoke', 'native', 'packets', 'rearm', 'dup', 'repeat', 'abandon'))
    parser.add_argument('attempt', type=int)
    args = parser.parse_args()
    assert args.attempt > 0
    build = HERE / 'evidence/full_04'
    source = build / 'response_only.p4'
    assert hashlib.sha256(source.read_bytes()).hexdigest() == SHA
    manifest = json.loads((build/'compile_local/manifest.json').read_text())
    assert manifest['source_sha256'] == SHA and manifest['exit_code'] == 0
    out = HERE / ('evidence/model_%s_%02d' % (args.driver, args.attempt))
    assert not out.exists(), 'evidence must not be overwritten'
    driver = HERE / ('model_%s.py' % ('smoke' if args.driver == 'native' else args.driver))
    command = ['bash', str(HERE.parents[2]/'launch_model.sh'),
               '-p', str(build/'compile_local/out'), '-o', str(out),
               '-P', '9 48 68 180 181 182 196', '-d', str(driver)]
    env = dict(os.environ, PORT_MAP=str(build/'response_only.inputs.json'))
    env['PAD_ENABLE'] = '0' if args.driver == 'native' else '1'
    driver_bytes = driver.read_bytes()
    result = subprocess.run(command, env=env)
    if out.is_dir():
        (out/'driver_source.py').write_bytes(driver_bytes)
        (out/'launch_command.json').write_text(json.dumps({
            'command': command, 'PORT_MAP': env['PORT_MAP'], 'PAD_ENABLE': env['PAD_ENABLE'], 'hardware': False,
            'source_sha256': SHA, 'driver_sha256': hashlib.sha256(driver_bytes).hexdigest(),
            'exit_code': result.returncode}, indent=2)+'\n')
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())

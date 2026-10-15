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
from pathlib import Path

HERE = Path(__file__).resolve().parent
DRIVERS = {'control_timing': HERE / 'model_control_timing.py'}
for name in ('smoke', 'packets', 'rearm', 'dup', 'repeat', 'abandon'):
    DRIVERS[name] = HERE.parent / 'seg61_02' / ('model_%s.py' % name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build')
    parser.add_argument('driver', choices=sorted(DRIVERS))
    parser.add_argument('attempt', type=int)
    parser.add_argument('--milestone', default='m1')
    parser.add_argument('--pb', type=int, help='run a seg61_02 driver with this pb injected (model ns), via with_pb.py')
    args = parser.parse_args()
    build = (HERE / args.build).resolve() if not Path(args.build).is_absolute() else Path(args.build)
    inputs = json.loads((build / 'response_only.inputs.json').read_text())
    sha = hashlib.sha256((build / 'response_only.p4').read_bytes()).hexdigest()
    manifest = json.loads((build / 'compile_local/manifest.json').read_text())
    assert sha == inputs['source_sha256'] == manifest['source_sha256'] and manifest['exit_code'] == 0
    out = HERE / ('evidence/model_%s_%s_%02d' % (args.driver, build.name, args.attempt))
    assert not out.exists(), 'evidence must not be overwritten'
    driver = DRIVERS[args.driver]
    launched = HERE / 'with_pb.py' if args.pb is not None else driver
    command = ['bash', str(HERE.parents[2] / 'launch_model.sh'), '-p', str(build / 'compile_local/out'),
               '-o', str(out), '-P', '9 48 68 180 181 182 196', '-d', str(launched)]
    env = dict(os.environ, PORT_MAP=str(build / 'response_only.inputs.json'), PAD_ENABLE='1',
               MILESTONE=args.milestone)
    if args.pb is not None:
        env.update(CTL_PB=str(args.pb), CTL_TARGET_DRIVER=str(driver))
    result = subprocess.run(command, env=env)
    if out.is_dir():
        (out / 'driver_source.py').write_bytes(driver.read_bytes())
        (out / 'launch_command.json').write_text(json.dumps({
            'command': command, 'PORT_MAP': env['PORT_MAP'], 'PAD_ENABLE': '1', 'MILESTONE': args.milestone,
            'pb_injected': args.pb,
            'hardware': False, 'source_sha256': sha, 'driver_sha256': hashlib.sha256(driver.read_bytes()).hexdigest(),
            'exit_code': result.returncode}, indent=2) + '\n')
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())

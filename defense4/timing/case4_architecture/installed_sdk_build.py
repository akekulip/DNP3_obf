#!/usr/bin/env python3
"""Compile in a private directory using the switch's existing SDK; never activate it.

No installations, updates, service commands, device access or traffic. Failed
builds remain immutable evidence. Existing build.py creates the source/artifact
manifest; only its local source path is rebound after downloading the evidence.
"""
import argparse
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

import build

HOST = build.SWITCH_BUILD_HOST
SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', HOST]
SCP = ['scp', '-q', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8']


def retrieve_evidence(remote, output, source):
    with tempfile.TemporaryDirectory(prefix='case4_download_') as temporary:
        subprocess.run(SCP + ['-r', HOST + ':' + remote + '/evidence', temporary],
                       check=True, timeout=120)
        for child in (Path(temporary) / 'evidence').iterdir():
            destination = output / child.name
            if destination.exists():
                raise FileExistsError(destination)
            shutil.move(str(child), str(destination))
    manifest = output / 'manifest.json'
    shutil.copyfile(manifest, output / 'remote_manifest.json')
    report = json.loads(manifest.read_text())
    report.update(source=str(source), compiler_host=HOST,
                  remote_source=report['source'])
    manifest.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')


def compile_installed(source, output):
    source, output = Path(source).resolve(), Path(output).resolve()
    files = build.source_files(source)
    output.mkdir(parents=True, exist_ok=False)
    remote = subprocess.check_output(SSH + ['mktemp -d /tmp/case4_compile_XXXXXXXX'],
                                     text=True, timeout=15).strip()
    if not remote.startswith('/tmp/case4_compile_') or '/' in remote[len('/tmp/'):]:
        raise ValueError('unexpected compile directory')
    with tempfile.TemporaryDirectory(prefix='case4_upload_') as temporary:
        stage = Path(temporary)
        for original, relative in files.items():
            target = stage / 'inputs' / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target)
        shutil.copyfile(Path(build.__file__), stage / 'build.py')
        subprocess.run(SCP + ['-r', str(stage / 'inputs'), str(stage / 'build.py'),
                              HOST + ':' + remote + '/'], check=True, timeout=30)
    command = ['python3', remote + '/build.py', remote + '/inputs/' + source.name,
               remote + '/evidence', '--compiler', build.SWITCH_COMPILER]
    (output / 'remote_command.json').write_text(json.dumps({
        'host': HOST, 'command': command, 'remote_directory': remote,
        'activation': False, 'sdk_updates': False}, indent=2) + '\n')
    with (output / 'session.log').open('w') as log:
        result = subprocess.run(SSH + [shlex.join(command)], stdout=log,
                                stderr=subprocess.STDOUT, timeout=330)
    retrieve_evidence(remote, output, source)
    return result.returncode


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    raise SystemExit(compile_installed(args.source, args.output))

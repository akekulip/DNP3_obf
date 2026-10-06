"""Bounded SSH transport for the authorized latency campaign; no credentials stored."""
import io
import shlex
import subprocess
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REMOTE = '/home/decps/dnp3_latency_20260926'
SWITCH = 'decps@10.10.54.81'
VISION = 'decps@10.10.54.166'


def ssh(host, command, **kwargs):
    return subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
                           host, command], check=True, **kwargs)


def upload(host, files):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode='w') as archive:
        for local, name in files:
            archive.add(local, arcname=name, recursive=True)
    ssh(host, 'mkdir -p ' + shlex.quote(REMOTE) + ' && tar -xf - -C ' + shlex.quote(REMOTE),
        input=payload.getvalue(), timeout=60)


def collect(label, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    result = ssh(VISION, 'tar -cf - -C ' + shlex.quote(REMOTE) + ' ' + shlex.quote(label),
                 stdout=subprocess.PIPE, timeout=60)
    # Python 3.8 compatibility: reject links and paths outside the requested block.
    with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
        for member in archive.getmembers():
            parts = Path(member.name).parts
            if not parts or parts[0] != label or '..' in parts or member.issym() or member.islnk():
                raise ValueError('Unsafe archive member: ' + member.name)
            if not (member.isdir() or member.isfile()):
                raise ValueError('Unexpected archive member type')
        archive.extractall(output)


def deploy():
    old = '/home/decps/dnp3_timing7_20260925'
    upload(VISION, [(HERE / name, name) for name in ('run_block.py', 'stop_block.py')])
    ssh(VISION, 'cp -a ' + old + '/active_harness ' + old + '/implementation ' +
        old + '/read_outputs.py ' + REMOTE + '/', timeout=30)
    control = HERE.parent / 'stage_reduction/control'
    files = [(control, 'control')]
    files += [(HERE / name, name) for name in ('configure.py', 'policy.py') if (HERE/name).exists()]
    upload(SWITCH, files)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--collect')
    args = parser.parse_args()
    if args.collect:
        collect(args.collect, HERE / 'evidence/blocks')
    else:
        deploy()

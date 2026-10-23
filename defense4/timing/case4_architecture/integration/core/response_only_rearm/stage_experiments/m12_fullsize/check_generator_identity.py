#!/usr/bin/env python3
"""Byte-identity gate for behavior-preserving generator refactors.

Builds every live make_m12.py mode into a scratch directory and compares the three outputs against the recorded
reference (generator_identity.json): response_only.p4 byte for byte, supported_profile.json byte for byte, and
response_only.inputs.json with only the generator-identity fields (generator_sha256, generator_files) and the
scratch build path normalized.

  python3 check_generator_identity.py            # compare; exit 1 on any difference
  python3 check_generator_identity.py --record   # (re)record the reference from the current generator
"""
import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REFERENCE = HERE / 'generator_identity.json'
POLICY = ['--policy', '--c3', 'cimg', '--shapes', 'passthrough']
MODES = {
    'two_read_c25': POLICY + ['--two-read'],
    'two_read_reduce_c26': POLICY + ['--two-read', '--reduce'],
    'passthrough_c12': POLICY,
    'segmented_full_c20': POLICY + ['--segmented-full'],
    'segmented_pad': POLICY + ['--segmented-pad'],
    'policy_ladder_b08': ['--policy'],
    'policy_cimg': ['--policy', '--c3', 'cimg'],
}
NORMALIZED = ('generator_sha256', 'generator_files')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def normalized_inputs(path):
    d = json.loads(path.read_text())
    for k in NORMALIZED:
        d.pop(k, None)
    d['supported_profile']['candidate'].pop('build', None)
    return sha(json.dumps(d, sort_keys=True).encode())


def build(flags, out):
    subprocess.run([sys.executable, str(HERE / 'make_m12.py'), str(out)] + flags, check=True, capture_output=True)
    profile = json.loads((out / 'supported_profile.json').read_text())
    profile['candidate'].pop('build', None)
    return {'p4': sha((out / 'response_only.p4').read_bytes()),
            'supported_profile': sha(json.dumps(profile, sort_keys=True).encode()),
            'inputs_normalized': normalized_inputs(out / 'response_only.inputs.json')}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--record', action='store_true')
    a = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        got = {name: build(flags, Path(tmp) / name) for name, flags in MODES.items()}
    if a.record:
        REFERENCE.write_text(json.dumps({'modes': {n: {'flags': MODES[n], **got[n]} for n in MODES}}, indent=2) + '\n')
        print('recorded %d modes -> %s' % (len(got), REFERENCE.name))
        return
    ref = json.loads(REFERENCE.read_text())['modes']
    bad = [(n, k) for n in MODES for k in ('p4', 'supported_profile', 'inputs_normalized') if ref[n][k] != got[n][k]]
    for n in MODES:
        print('%-20s p4 %s %s' % (n, got[n]['p4'][:12], 'ok' if not any(b[0] == n for b in bad) else 'DIFF'))
    if bad:
        sys.exit('identity FAILED: %s' % bad)
    print('identity ok: %d modes byte-identical' % len(MODES))


if __name__ == '__main__':
    main()

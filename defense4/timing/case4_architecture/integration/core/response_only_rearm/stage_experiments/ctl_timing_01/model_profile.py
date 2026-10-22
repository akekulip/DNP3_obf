"""Resolve model expectations from a build's source-bound supported profile.

Retained builds keep their recorded milestone expectations. A successor must declare the current reset contract
and child layout; renaming a build cannot select weaker expectations.
"""
import hashlib
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
HISTORICAL_BUILDS = {
    'm1': ('m1_01', 'm1_02'), 'm2': ('m2_01',), 'm3': ('m3_01',), 'm4': ('m4_01',),
    'm5': tuple('m5_%02d' % n for n in range(1, 11)),
    'm6': tuple('m6_%02d' % n for n in range(1, 8)),
    'm7': ('m7_01', 'm7_02', 'm7_03'), 'm8': ('m8_01', 'm8_02'),
    'm9': ('m9_01', 'probe_n_bank_diffs_m9_01', 'probe_n_zero_unused_timestamp_m9_01',
           'probe_t_single_child_m9_01'), 'm9d': ('m9d_01',), 'm10': ('m10_01', 'm10_02', 'm10_03'),
}


def resolve(inputs, source, milestone=None):
    """Return effective semantics after verifying inputs and profile refer to ``source``.

    ``inputs`` is the existing response_only.inputs.json object; ``source`` is a .p4 path. New profiles use the
    existing inline ``supported_profile`` field. The returned milestone is an expectation version, not a build ID.
    """
    if not isinstance(inputs, dict):
        raise ValueError('build inputs must be an object')
    sha = hashlib.sha256(Path(source).read_bytes()).hexdigest()
    if inputs.get('source_sha256') != sha:
        raise ValueError('build inputs do not bind this source')
    recorded = inputs.get('milestone')
    if milestone is not None and recorded is not None and milestone != recorded:
        raise ValueError('requested milestone does not match build inputs')
    selected = recorded if recorded is not None else milestone
    profile = inputs.get('supported_profile')
    if profile is not None:
        if not isinstance(profile, dict) or profile.get('reset_restart_required') is not True:
            raise ValueError('successor profile must require reset restart coverage')
        children = profile.get('t_child_count')
        if type(children) is not int or children not in (1, 2, 3):
            raise ValueError('supported T child count must be 1, 2 or 3')
        candidate = profile.get('candidate')
        if not isinstance(candidate, dict) or candidate.get('source_sha256') != sha:
            raise ValueError('supported profile does not bind this source')
        if inputs.get('segment_sha256') is not None and \
                candidate.get('segment_sha256') != inputs['segment_sha256']:
            raise ValueError('supported profile segment hashes do not match build inputs')
        return dict(profile, milestone='m10', historical_build=None)
    for name in HISTORICAL_BUILDS.get(selected, ()):
        path = HERE / 'evidence' / name / 'response_only.inputs.json'
        if path.is_file() and json.loads(path.read_text()).get('source_sha256') == sha:
            return dict(milestone=selected, reset_restart_required=selected == 'm10',
                        t_child_count=1 if name == 'probe_t_single_child_m9_01' else 3,
                        historical_build=name)
    raise ValueError('unknown source/profile: a successor requires a source-bound supported_profile')


def from_env():
    path = Path(os.environ['PORT_MAP'])
    return resolve(json.loads(path.read_text()), path.with_name('response_only.p4'), os.environ.get('MILESTONE'))

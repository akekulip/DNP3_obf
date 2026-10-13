#!/usr/bin/env python3
"""Derive the candidate57s (strict-response) campaign configs from the candidate56r ones.

Build rearm_57s = rearm_56r + READ two-range re-encoding (read_reencode_01, conforming 58-octet READ) +
strict control policy (SELECT/OPERATE responses native, 37 B) + early-duplicate OPERATE hold
(dup_hold_01). Every difference from the candidate56r config is made here:
  builds          rearm_56r -> rearm_57s (installed-SDK 9.13.2 artifacts, hashes, control_padding false)
  arms[].build    -> rearm_57s
  expectations    padding "1": sbo_resp_len [37] (READ stays 58)
  loss presets    select/operate_resp_padded -> *_resp_native; master_ack_of_padded -> master_ack_of_padded_data, n=1
  notes           a leading line naming the build
  python3 make_candidate57s.py      (rewrites candidate57s_*.json next to this file)
"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
C4 = HERE.parents[3]
# Two profiles of the same mechanism. strict (rearm_57s): SELECT/OPERATE responses native. all58 (rearm_57a): the
# endpoint-specific all-58 profile (control G41 padding, Rule 8 non-conformant, accepted by the tested OpenDNP3).
PROFILES = {
    'strict': dict(build_id='rearm_57s', prefix='candidate57s', control_padding=False, sbo_len=37,
                   build='integration/core/response_only_rearm/stage_experiments/dup_hold_01/evidence/full_02_strict/'
                         'compile_switch_9132',
                   loss_swap={'select_resp_padded': 'select_resp_native', 'operate_resp_padded': 'operate_resp_native',
                              'master_ack_of_padded': 'master_ack_of_padded_data'},
                   note='strict control policy (SELECT/OPERATE responses native)',
                   line='candidate57s: build rearm_57s (strict control policy, conforming READ, duplicate-OPERATE hold); '
                        'derived from the candidate56r config by make_candidate57s.py.',
                   build_note='rearm_56r + read_reencode_01 READ two-range re-encoding (IEEE 1815 conforming 58-octet '
                              'READ) + strict control policy (SELECT/OPERATE responses native) + dup_hold_01 '
                              'early-duplicate OPERATE hold. Installed SDK 9.13.2 N12/E12/T11, mirror guard PASS. '
                              'Compiled model (9.13.1): diag 519/519 and retx 37/37 with strict-frontier drivers; '
                              'duplicate suite in dup_hold_01.'),
    'all58': dict(build_id='rearm_57a', prefix='candidate57a', control_padding=True, sbo_len=58,
                  build='integration/core/response_only_rearm/stage_experiments/dup_hold_01/evidence/full_01/'
                        'compile_switch_9132',
                  loss_swap={'master_ack_of_padded': 'master_ack_of_padded_data'},
                  note='all-58 profile (control G41 padding; Rule 8 non-conformant, endpoint-specific)'),
}
HASHED = ('bfrt.json', 'p0/tofino.bin', 'p1/tofino.bin', 'p1/response_only.bfa')
NAMES = ('fourarm_smoke', 'graceful_800', 'old_external', 'old_tokens', 'rst_950', 'single_loss')


def artifact_hashes(build):
    """The four installer-checked artifact hashes, from the committed compile manifest (out/ is git-ignored, so a
    fresh checkout can still regenerate). When out/ is present each hash is re-checked against the file."""
    recorded = json.loads((C4 / build / 'manifest.json').read_text())['artifact_sha256']
    hashes = {name: recorded[name] for name in HASHED}
    for name, digest in hashes.items():
        path = C4 / build / 'out' / name
        if path.exists():
            assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, ('artifact differs from manifest', name)
    return hashes


def build_entry(old, prof):
    note = prof.get('build_note') or (
        'rearm_56r + read_reencode_01 READ two-range re-encoding (IEEE 1815 conforming 58-octet READ) + %s + '
        'dup_hold_01 early-duplicate OPERATE hold. Installed SDK 9.13.2, mirror guard run before use; '
        'compiled-model results in the read_reencode_01 and dup_hold_01 READMEs.' % prof['note'])
    entry = dict(old)
    entry.update(out_dir=prof['build'] + '/out', manifest=prof['build'] + '/manifest.json',
                 control_padding=prof['control_padding'],
                 hashes=artifact_hashes(prof['build']),
                 _note=note)
    return entry


def derive(cfg, prof):
    old = cfg['builds'].pop('rearm_56r')
    cfg['builds'][prof['build_id']] = build_entry(old, prof)
    for arm in cfg['arms']:
        assert arm['build'] == 'rearm_56r', arm
        arm['build'] = prof['build_id']
    cfg['expectations']['padding']['1']['sbo_resp_len'] = [prof['sbo_len']]
    for preset in cfg.get('loss', {}).get('presets', {}).values():
        for item in preset:
            item['class'] = prof['loss_swap'].get(item['class'], item['class'])
            if item['class'] == 'master_ack_of_padded_data':
                # The master's in-session pure ACK of a padded response is master_ack #2 (#1 is the handshake
                # ACK), i.e. n=1: candidate57s_single_loss_01 t6 showed n=2 is the ACK of the outstation FIN.
                item['n'] = 1
    notes = cfg.get('_notes')
    line = prof.get('line') or ('%s: build %s (%s, conforming READ, duplicate-OPERATE hold); derived from the '
                                'candidate56r config by make_candidate57s.py.' % (prof['prefix'], prof['build_id'], prof['note']))
    if isinstance(notes, list):
        cfg['_notes'] = [line] + [n for n in notes if 'rearm_56r' not in n]
    else:
        cfg['_notes'] = [line]
    return cfg


if __name__ == '__main__':
    import sys
    prof = PROFILES['all58' if '--all58' in sys.argv[1:] else 'strict']
    for name in NAMES:
        cfg = json.loads((HERE / ('candidate56r_%s.json' % name)).read_text())
        out = derive(cfg, prof)
        text = json.dumps(out, indent=2) + '\n'
        bid = prof['build_id']
        assert set(out['builds']) == {bid} and all(a['build'] == bid for a in out['arms']), name
        (HERE / ('%s_%s.json' % (prof['prefix'], name))).write_text(text)
        print('wrote', '%s_%s.json' % (prof['prefix'], name))

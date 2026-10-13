#!/usr/bin/env python3
"""Derive the candidate57s (strict-response) campaign configs from the candidate56r ones.

Build rearm_57s = rearm_56r + READ two-range re-encoding (read_reencode_01, conforming 58-octet READ) +
strict control policy (SELECT/OPERATE responses native, 37 B) + early-duplicate OPERATE hold
(dup_hold_01). Every difference from the candidate56r config is made here:
  builds          rearm_56r -> rearm_57s (installed-SDK 9.13.2 artifacts, hashes, control_padding false)
  arms[].build    -> rearm_57s
  expectations    padding "1": sbo_resp_len [37] (READ stays 58)
  loss presets    select/operate_resp_padded -> *_resp_native; master_ack_of_padded -> master_ack_of_padded_data
  notes           a leading line naming the build
  python3 make_candidate57s.py      (rewrites candidate57s_*.json next to this file)
"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
C4 = HERE.parents[3]
BUILD = 'integration/core/response_only_rearm/stage_experiments/dup_hold_01/evidence/full_02_strict/compile_switch_9132'
HASHED = ('bfrt.json', 'p0/tofino.bin', 'p1/tofino.bin', 'p1/response_only.bfa')
NAMES = ('fourarm_smoke', 'graceful_800', 'old_external', 'old_tokens', 'rst_950', 'single_loss')
LOSS_SWAP = {'select_resp_padded': 'select_resp_native', 'operate_resp_padded': 'operate_resp_native',
             'master_ack_of_padded': 'master_ack_of_padded_data'}


def build_entry(old):
    out = C4 / BUILD / 'out'
    entry = dict(old)
    entry.update(out_dir=BUILD + '/out', manifest=BUILD + '/manifest.json', control_padding=False,
                 hashes={name: hashlib.sha256((out / name).read_bytes()).hexdigest() for name in HASHED},
                 _note='rearm_56r + read_reencode_01 READ two-range re-encoding (IEEE 1815 conforming 58-octet READ) '
                       '+ strict control policy (SELECT/OPERATE responses native) + dup_hold_01 early-duplicate '
                       'OPERATE hold. Installed SDK 9.13.2 N12/E12/T11, mirror guard PASS. Compiled model (9.13.1): '
                       'diag 519/519 and retx 37/37 with strict-frontier drivers; duplicate suite in dup_hold_01.')
    return entry


def derive(cfg):
    old = cfg['builds'].pop('rearm_56r')
    cfg['builds']['rearm_57s'] = build_entry(old)
    for arm in cfg['arms']:
        assert arm['build'] == 'rearm_56r', arm
        arm['build'] = 'rearm_57s'
    cfg['expectations']['padding']['1']['sbo_resp_len'] = [37]
    for preset in cfg.get('loss', {}).get('presets', {}).values():
        for item in preset:
            item['class'] = LOSS_SWAP.get(item['class'], item['class'])
    notes = cfg.get('_notes')
    line = 'candidate57s: build rearm_57s (strict control policy, conforming READ, duplicate-OPERATE hold); ' \
           'derived from the candidate56r config by make_candidate57s.py.'
    if isinstance(notes, list):
        cfg['_notes'] = [line] + [n for n in notes if 'rearm_56r' not in n]
    else:
        cfg['_notes'] = [line]
    return cfg


if __name__ == '__main__':
    for name in NAMES:
        cfg = json.loads((HERE / ('candidate56r_%s.json' % name)).read_text())
        out = derive(cfg)
        text = json.dumps(out, indent=2) + '\n'
        assert set(out['builds']) == {'rearm_57s'} and all(a['build'] == 'rearm_57s' for a in out['arms']), name
        (HERE / ('candidate57s_%s.json' % name)).write_text(text)
        print('wrote', 'candidate57s_%s.json' % name)

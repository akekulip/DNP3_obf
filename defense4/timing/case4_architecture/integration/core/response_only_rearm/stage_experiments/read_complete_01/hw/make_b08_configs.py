"""Derive the m12p_b08 hardware block configs from the m11_09 evaluation configs (no other change).

Copies the m11_09 four-arm reference block and the five recovery blocks, replacing only: the build identity
(m12p_b08: both compiles' artifacts, source, manifest), the per-function response lengths (READ 141 from the
frozen read_complete_01 policy, SELECT/OPERATE 61), the explicit growth expectations, and notes.

  python3 make_b08_configs.py        # writes config/*.json beside this file
"""
import copy
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
STAGE = HERE.parents[1]
ARCH = STAGE.parents[3]
SRC = STAGE / 'seg61_02/evidence/evaluation_campaigns/eval_m11_09_20261018_01/configs'
BUILD = STAGE / 'ctl_timing_01/evidence/m12p_b08'
TEMPLATES = ['reference', 'held_operate_350', 'loss_core_950', 'persistence_graceful_950', 'persistence_rst_950',
             'reconnect_950']
OLD = 'ctl_timing_m11_09'
ROOT_EVIDENCE = HERE.parent / 'evidence/hw_blocks'
NEW = 'm12p_b08'


def rel(path):
    return str(Path(path).resolve().relative_to(ARCH))


def main():
    inputs = json.loads((BUILD / 'response_only.inputs.json').read_text())
    source = hashlib.sha256((BUILD / 'response_only.p4').read_bytes()).hexdigest()
    switch = json.loads((BUILD / 'compile_switch_9132/manifest.json').read_text())
    assert switch['exit_code'] == 0 and switch['source_sha256'] == source
    arts = switch['artifact_sha256']
    policy_read = inputs['output_lengths']['READ']
    out = HERE / 'config'
    out.mkdir(exist_ok=True)
    written = {}
    for name in TEMPLATES:
        cfg = json.loads((SRC / ('eval_m11_09_20261018_01_%s.json' % name)).read_text())
        b = copy.deepcopy(cfg['builds'][OLD])
        b.update(_note='read_complete_01 policy candidate m12p_b08 (READ 49->141 pipe-1 prefix, SBO 37->61, '
                       'N/E/T timing); derived from the m11_09 config by make_b08_configs.py',
                 hashes={k: arts[k] for k in ('bfrt.json', 'p0/tofino.bin', 'p1/response_only.bfa', 'p1/tofino.bin')},
                 manifest=rel(BUILD / 'compile_switch_9132/manifest.json'),
                 out_dir=rel(BUILD / 'compile_switch_9132/out'),
                 source_sha256=source, image_len=61, read_image_len=policy_read)
        cfg['builds'] = {NEW: b}
        for arm in cfg['arms']:
            arm['build'] = NEW
        pad = cfg['expectations']['padding']
        pad['1'].update(read_resp_len=[policy_read], sbo_resp_len=[61], growth='positive')
        pad['0'].update(read_resp_len=[49], sbo_resp_len=[37], growth='zero')
        cid = cfg.get('ctl_timing_identity') or {}
        sc = dict(cid.get('switch_compile') or {})      # field by field (review HIGH 3: never drop out_dir etc.)
        sc.update(artifact_sha256=dict(arts), bfrt_json_sha256=arts['bfrt.json'], compiler=switch['compiler'],
                  manifest=rel(BUILD / 'compile_switch_9132/manifest.json'),
                  manifest_sha256=hashlib.sha256((BUILD / 'compile_switch_9132/manifest.json').read_bytes()).hexdigest(),
                  out_dir=rel(BUILD / 'compile_switch_9132/out'),
                  p4pp_sha256=hashlib.sha256((BUILD / 'compile_switch_9132/out/response_only.p4pp').read_bytes()).hexdigest(),
                  sdk='9.13.2', source_sha256=source, status='compiled')
        cid.update(design=rel(STAGE / 'm12_fullsize/make_m12.py'), source_sha256=source,
                   supported_profile=rel(BUILD / 'supported_profile.json'),
                   supported_profile_sha256=hashlib.sha256((BUILD / 'supported_profile.json').read_bytes()).hexdigest(),
                   switch_compile=sc)
        cfg['ctl_timing_identity'] = cid
        cfg['evidence_dir'] = str(ROOT_EVIDENCE)          # never the m11_09 campaign's own blocks directory
        block = cfg.get('evaluation', {}).get('campaign_block')
        if isinstance(block, dict):
            block['id'] = 'rc01_m12p_b08_%s' % name
            block['template'] = 'eval_m11_09_20261018_01_%s.json' % name
        cfg['_notes'] = list(cfg.get('_notes', [])) + [
            'read_complete_01 (2026-10-21): derived from eval_m11_09_20261018_01_%s.json; build m12p_b08; padded READ '
            '%d (policy 141/247/401, range shape), SELECT/OPERATE 61; padding-0 arms stay native (pipe-1 p1_conn '
            'row only with fwd_conn enable). candidate61_identity is the template\'s and does not describe this build. '
            'Model gate and freeze: read_complete_01/STATUS.md.' % (name, policy_read)]
        path = out / ('rc01_m12p_b08_%s.json' % name)
        path.write_text(json.dumps(cfg, indent=1, sort_keys=True) + '\n')
        written[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    print(json.dumps(written, indent=1))


if __name__ == '__main__':
    main()

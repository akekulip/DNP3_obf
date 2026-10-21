"""Derive the m12p_c12 hardware block configs from the m11_09 evaluation configs (as make_b08_configs did for b08).

m12p_c12 is the policy build with the per-committed-image reverse boundary (c3 cimg) and the pass-through READ
classes. Every block runs the new fixture endpoint case4_socket_gate_read_schedule (its wire bytes equal the pad58b
endpoint's when the schedule is unset, proven on loopback). The four-arm REFERENCE block additionally drives the
rotate4 READ-class schedule on the base database and declares the per-class READ images; the five recovery blocks
stay range-only (the loss/persistence/reconnect rules select packets by a single READ length, so a schedule is
refused there).

  python3 make_c12_configs.py        # writes config/rc01_m12p_c12_*.json beside this file
"""
import copy
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
STAGE = HERE.parents[1]
ARCH = STAGE.parents[3]
SRC = STAGE / 'seg61_02/evidence/evaluation_campaigns/eval_m11_09_20261018_01/configs'
BUILD = STAGE / 'ctl_timing_01/evidence/m12p_c12'
ENDPOINT = ARCH / 'integration/evidence/rearm_01/repeat_sbo_endpoint'
TEMPLATES = ['reference', 'held_operate_350', 'loss_core_950', 'persistence_graceful_950', 'persistence_rst_950',
             'reconnect_950']
OLD = 'ctl_timing_m11_09'
ROOT_EVIDENCE = HERE.parent / 'evidence/hw_blocks'
NEW = 'm12p_c12'
# base-database policy images: range padded 49->141, analog already 141, class0/integrity already 247. The
# segmented (large-DB 377->401) class is NOT in this P4 build, so it is left undeclared (unsupported) here.
READ_IMAGES = {'range': 141, 'analog': 141, 'class0': 247, 'integrity': 247}


def rel(path):
    return str(Path(path).resolve().relative_to(ARCH))


def endpoint_block(old_ep):
    """old_ep re-pinned to the READ-schedule endpoint (same pinned OpenDNP3 library; new binary and source)."""
    man = json.loads((ENDPOINT / 'build/build_manifest.json').read_text())['read_schedule_endpoint']
    ep = dict(old_ep)
    ep['binary'] = 'case4_socket_gate_read_schedule'
    ep['binary_sha256'] = man['binary_sha256']
    ep['lib_sha256'] = man['library_directory_sha256']   # the campaign hashes the lib/ listing (unchanged library)
    ep['source_sha256'] = man['source_hashes']['SocketGateReadSchedule.cpp']
    ep['source_files'] = dict(man['source_hashes'])
    ep['_pin_with'] = 'sha256sum case4_socket_gate_read_schedule; sorted sha256sum listing hash under lib/'
    ep['_pinned'] = ('repeat_sbo_endpoint READ-schedule fork (CASE4_READ_SCHEDULE=rotate4, CASE4_DB; unset = the '
                     'pad58b wire bytes); software handler only.')
    return ep


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
        b.update(_note='read_complete_01 policy candidate m12p_c12 (per-image boundary + pass-through READ classes); '
                       'derived from the m11_09 config by make_c12_configs.py',
                 hashes={k: arts[k] for k in ('bfrt.json', 'p0/tofino.bin', 'p1/response_only.bfa', 'p1/tofino.bin')},
                 manifest=rel(BUILD / 'compile_switch_9132/manifest.json'),
                 out_dir=rel(BUILD / 'compile_switch_9132/out'),
                 source_sha256=source, image_len=61, read_image_len=policy_read)
        if name == 'reference':
            b['read_images'] = dict(READ_IMAGES)        # per-class images (base DB), used only with a schedule
        cfg['builds'] = {NEW: b}
        for arm in cfg['arms']:
            arm['build'] = NEW
        pad = cfg['expectations']['padding']
        pad['1'].update(read_resp_len=[policy_read], sbo_resp_len=[61], growth='positive')
        pad['0'].update(read_resp_len=[49], sbo_resp_len=[37], growth='zero')
        cfg['endpoint'] = endpoint_block(cfg['endpoint'])
        if name == 'reference':
            cfg['traffic']['read_schedule'] = 'rotate4'
            cfg['traffic']['db'] = 'base'
            cfg['traffic']['read_schedule_note'] = (
                'rotate4: READ slots cycle range, analog, class0, integrity (fixture endpoint order) on the base '
                'database; range padded to 141, analog at 141, class0/integrity at 247. The segmented large-DB '
                'class (377->401) is not in this P4 build and is not declared.')
        cid = cfg.get('ctl_timing_identity') or {}
        sc = dict(cid.get('switch_compile') or {})      # field by field (never drop out_dir etc.)
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
        cfg['evidence_dir'] = str(ROOT_EVIDENCE)
        block = cfg.get('evaluation', {}).get('campaign_block')
        if isinstance(block, dict):
            block['id'] = 'rc01_m12p_c12_%s' % name
            block['template'] = 'eval_m11_09_20261018_01_%s.json' % name
        cfg['_notes'] = list(cfg.get('_notes', [])) + [
            'read_complete_01 (2026-10-21): derived from eval_m11_09_20261018_01_%s.json; build m12p_c12; per-image '
            'reverse boundary, pass-through READ classes; endpoint case4_socket_gate_read_schedule. The reference '
            'block drives rotate4 on the base DB; recovery blocks stay range-only. Model gate and freeze: '
            'read_complete_01/STATUS.md.' % name]
        path = out / ('rc01_m12p_c12_%s.json' % name)
        path.write_text(json.dumps(cfg, indent=1, sort_keys=True) + '\n')
        written[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    print(json.dumps(written, indent=1))


if __name__ == '__main__':
    main()

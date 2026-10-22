"""Derive the two-READ-target hardware block configs (build m12p_c25 by default) from the m11_09 evaluation configs,
as make_c12_configs.py did for c12.

m12p_c25 (= m12p_c24's P4 byte for byte, with the corrected declared disposition of the replaced READ classes) pads the mixed READ (one request: g1v2 q00 0-15 + g30v1 q00 0-7; native 91) to 141 and the base-database
full READ (integrity poll; native 247) to 271, with SELECT/OPERATE 37 -> 61 unchanged. Every block runs the
READ-schedule fixture endpoint (case4_socket_gate_read_schedule, the two-READ build: mixed class, mixed_full / mixed /
full schedules, strict CASE4_PAD_EXPECT). The four-arm REFERENCE block drives the mixed_full schedule on the base
database (65 READs per trial: 33 mixed, 32 full, with 64 SELECT/OPERATE cycles) and declares per class:
  read_images   {mixed: 141, integrity: 271}       the image a padded arm must deliver
  read_padding  {mixed: 26, integrity: 4}          the padding points the endpoint's strict check is told to expect on
                                                   a padded arm (CASE4_PAD_EXPECT); an off arm declares nothing
Both come from read_complete_01/vectors/constants_two_read.json (the derivation proved == pad_read).

Recovery blocks reuse the approved m11_09 recovery templates (one combined arm, 20 READs, one SELECT/OPERATE) with
the minimum workload change. Persistence (graceful, rst), held OPERATE and reconnect select no packet by length, so
they run the two-workload schedule mixed_full (10 mixed + 10 full READs per connection). Loss selects packets by
length and frontier, so it runs one READ class per block (schedule mixed, then full): that READ is the only READ on
the connection and every READ selector names it. The core preset keeps the m11_09 entries with the class's own
request selector in place of the 20-byte range request.

  python3 make_two_read_configs.py [--build m12p_c25] [block ...]   # writes config/rc01_<build>_<block>.json
"""
import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
STAGE = HERE.parents[1]
ARCH = STAGE.parents[3]
SRC = STAGE / 'seg61_02/evidence/evaluation_campaigns/eval_m11_09_20261018_01/configs'
ENDPOINT = ARCH / 'integration/evidence/rearm_01/repeat_sbo_endpoint'
CONSTANTS = STAGE / 'read_complete_01/vectors/constants_two_read.json'
OLD = 'ctl_timing_m11_09'
ROOT_EVIDENCE = HERE.parent / 'evidence/hw_blocks'
CORE = [{'class': 'ack_sep', 'n': 3}, {'class': 'read_resp_padded', 'n': 3}, {'class': 'select_resp_padded', 'n': 1},
        {'class': 'operate_req', 'n': 1}, {'class': 'operate_resp_padded', 'n': 1},
        {'class': 'master_ack_of_padded_data', 'n': 1}]
# block -> (m11_09 template, READ schedule, loss preset or None, master port range or None to keep the template's)
SPECS = {
    'reference': ('reference', 'mixed_full', None, None),
    'loss_mixed_950': ('loss_core_950', 'mixed', ('core_mixed', [{'class': 'request_mixed', 'n': 3}] + CORE), None),
    'loss_full_950': ('loss_core_950', 'full', ('core_full', [{'class': 'request_full', 'n': 3}] + CORE),
                      {'first': 59970, 'last': 59976}),
    'persistence_graceful_950': ('persistence_graceful_950', 'mixed_full', None, None),
    'persistence_rst_950': ('persistence_rst_950', 'mixed_full', None, None),
    'reconnect_950': ('reconnect_950', 'mixed_full', None, None),
    'held_operate_350': ('held_operate_350', 'mixed_full', None, None),
}
BLOCKS = list(SPECS)
SCHEDULE_CLASSES = {'mixed_full': ('mixed', 'integrity'), 'mixed': ('mixed',), 'full': ('integrity',)}


def per_class_counts(schedule, reads):
    order = SCHEDULE_CLASSES[schedule]
    return {cls: len(range(i, reads, len(order))) for i, cls in enumerate(order)}
CLASS_OF_SHAPE = {'mixed_g1v2_g30v1_91': 'mixed', 'integrity_247': 'integrity'}


def rel(path):
    return str(Path(path).resolve().relative_to(ARCH))


def shapes():
    doc = json.loads(CONSTANTS.read_text())
    return {CLASS_OF_SHAPE[name]: s for name, s in doc['shapes'].items()}


def endpoint_block(old_ep):
    """old_ep re-pinned to the READ-schedule endpoint (same pinned OpenDNP3 library; the two-READ binary)."""
    man = json.loads((ENDPOINT / 'build/build_manifest.json').read_text())['read_schedule_endpoint']
    ep = dict(old_ep)
    ep['binary'] = 'case4_socket_gate_read_schedule'
    ep['binary_sha256'] = man['binary_sha256']
    ep['lib_sha256'] = man['library_directory_sha256']
    ep['source_sha256'] = man['source_hashes']['SocketGateReadSchedule.cpp']
    ep['source_files'] = dict(man['source_hashes'])
    ep['_pin_with'] = 'sha256sum case4_socket_gate_read_schedule; sorted sha256sum listing hash under lib/'
    ep['_pinned'] = ('repeat_sbo_endpoint READ-schedule fork, two-READ build (mixed class; mixed_full/mixed/full; '
                     'strict CASE4_PAD_EXPECT; unset controls = the pad58b wire bytes); software handler only.')
    return ep


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--build', default='m12p_c25')
    ap.add_argument('blocks', nargs='*')
    a = ap.parse_args(argv)
    global BUILD, NEW
    NEW = a.build
    BUILD = STAGE / 'ctl_timing_01/evidence' / NEW
    blocks = a.blocks or BLOCKS
    inputs = json.loads((BUILD / 'response_only.inputs.json').read_text())
    source = hashlib.sha256((BUILD / 'response_only.p4').read_bytes()).hexdigest()
    assert inputs['source_sha256'] == source and inputs['runnable']
    switch = json.loads((BUILD / 'compile_switch_9132/manifest.json').read_text())
    assert switch['exit_code'] == 0 and switch['source_sha256'] == source
    arts = switch['artifact_sha256']
    sh = shapes()
    images = {cls: s['target'] for cls, s in sh.items()}
    padding = {cls: s['padding_points'] for cls, s in sh.items()}
    natives = {cls: s['native_total'] for cls, s in sh.items()}
    assert inputs['read_images'] == {str(natives[c]): images[c] for c in images}
    out = HERE / 'config'
    out.mkdir(exist_ok=True)
    written = {}
    template_of = {name: spec[0] for name, spec in SPECS.items()}
    for name in blocks:
        template, schedule, preset, ports = SPECS[name]
        cfg = json.loads((SRC / ('eval_m11_09_20261018_01_%s.json' % template_of[name])).read_text())
        b = copy.deepcopy(cfg['builds'][OLD])
        b.update(_note='two-READ-target candidate %s (mixed 91->141, full 247->271, SBO 37->61); derived from '
                       'the m11_09 config by make_two_read_configs.py' % NEW,
                 hashes={k: arts[k] for k in ('bfrt.json', 'p0/tofino.bin', 'p1/response_only.bfa', 'p1/tofino.bin')},
                 manifest=rel(BUILD / 'compile_switch_9132/manifest.json'),
                 out_dir=rel(BUILD / 'compile_switch_9132/out'),
                 source_sha256=source, image_len=61, read_images=dict(images), read_padding=dict(padding))
        b.pop('read_image_len', None)        # no single READ image on this build: per class only
        cfg['builds'] = {NEW: b}
        for arm in cfg['arms']:
            arm['build'] = NEW
        classes = SCHEDULE_CLASSES[schedule]
        pad = cfg['expectations']['padding']
        pad['1'].update(read_resp_len=sorted(images[c] for c in classes), sbo_resp_len=[61], growth='positive')
        pad['0'].update(read_resp_len=sorted(natives[c] for c in classes), sbo_resp_len=[37], growth='zero')
        cfg['endpoint'] = endpoint_block(cfg['endpoint'])
        cfg['traffic']['read_schedule'] = schedule
        cfg['traffic']['db'] = 'base'
        reads = cfg['trials']['reads_per_trial']
        counts = per_class_counts(schedule, reads)
        cfg['traffic']['read_schedule_note'] = (
            '%s on the base database: mixed 91 -> 141, full 247 -> 271 on a padded arm (native on an off arm). '
            'Expected per connection of %d READs: %s%s.'
            % (schedule, reads, ', '.join('%d %s' % (counts[c], c) for c in classes),
               ', 64 SELECT/OPERATE cycles, every READ after the first following a cycle'
               if cfg['traffic'].get('sbo_cycles') else ', one SELECT/OPERATE'))
        cfg['traffic']['expected_reads_per_class'] = counts
        if ports:
            cfg['traffic']['master_port_range'] = dict(ports)
        # a loss block carries exactly its class preset; the other blocks run no preset, and the template's presets
        # (range-workload selectors) are removed so no READ selector can be attached to the two-workload schedule
        cfg['loss']['presets'] = {preset[0]: preset[1]} if preset else {}
        cid = cfg.get('ctl_timing_identity') or {}
        sc = dict(cid.get('switch_compile') or {})
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
            block['id'] = 'rc01_%s_%s' % (NEW, name)
            block['template'] = 'eval_m11_09_20261018_01_%s.json' % template_of[name]
            if preset:
                args = list(block['arguments'])
                args[args.index('--loss') + 1] = preset[0]
                block['arguments'] = args
        cfg['_notes'] = list(cfg.get('_notes', [])) + [
            'two-READ-target directive (2026-10-22): derived from eval_m11_09_20261018_01_%s.json; build %s; '
            'endpoint case4_socket_gate_read_schedule (two-READ build). Model gate and freeze: read_complete_01/STATUS.md.'
            % (template_of[name], NEW)]
        path = out / ('rc01_%s_%s.json' % (NEW, name))
        path.write_text(json.dumps(cfg, indent=1, sort_keys=True) + '\n')
        written[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    print(json.dumps(written, indent=1))


if __name__ == '__main__':
    main(sys.argv[1:])

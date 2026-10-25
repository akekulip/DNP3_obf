#!/usr/bin/env python3
"""Derive a READ acceptance smoke and seven qualification blocks for one source-bound SEL-751 candidate."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ARCH = HERE.parents[5]
sys.path.insert(0, str(ARCH / 'protocol/hw_vepa'))
import endpoint_profiles

BLOCKS = ('smoke', 'reference', 'loss_mixed_950', 'loss_full_950', 'persistence_graceful_950',
          'persistence_rst_950', 'reconnect_950', 'held_operate_350')
# N-ingress MAU snapshot of the READ request's first post-lap pass (hw/mau_snapshot.py; proven on the model).
MAU_SNAPSHOT = 'start=0,end=10,m.packet_kind=9/0xff,m.lap=1/1,m.stage=0/3'
NATIVE_OBSERVATION = HERE.parent / 'evidence/relay_native_capture_20261024/relay_native_20261024_02/relay_wire.json'


def case4_relative(path):
    return str(Path(path).resolve().relative_to(ARCH.resolve()))


def read_link_addresses(native):
    """Logical DNP3 (read_dst, read_src) of the observed native READ requests (little-endian link octets).

    The sel751 profile stores logical addresses (endpoint_profiles.validate); campaign.installer_read_addresses
    turns them into the wire order N compares. rc01_hw_c51_20261024_11's MAU snapshot showed the logical src 1
    passed unconverted, setting m.badh, so every READ was refused before admission."""
    headers = {bytes.fromhex(packet['payload_hex'])[:8] for row in native.get('exchanges', [])
               if row['operation'] == 'READ' for packet in row['request']['packets'][:1]}
    pairs = {(int.from_bytes(h[4:6], 'little'), int.from_bytes(h[6:8], 'little')) for h in headers}
    if len(pairs) != 1 or any(h[:2] != b'\x05\x64' for h in headers):  # also refuses no READ at all
        raise ValueError('native READ requests do not share one link address pair: %s' % sorted(pairs))
    return pairs.pop()


def relay_config(template, read_dst=0, read_src=1):
    cfg = copy.deepcopy(template)
    cfg['endpoint_profile'] = 'sel751'
    cfg['endpoint'] = copy.deepcopy(endpoint_profiles.COMMAND)
    cfg['endpoints'] = dict(master_ip=endpoint_profiles.MASTER_IP, outstation_ip=endpoint_profiles.RELAY_IP,
                            outstation_port=20000, read_src=read_src, read_dst=read_dst)
    cfg['ports_map'].update(master_dev=9, relay_dev=64)
    cfg['hosts'].update(vision='decps@10.10.54.19', vision_run_dir='/home/decps/sel751_guarded_20261024')
    cfg['fixture'] = dict(modes=['physical_relay'], delay_ms=0, jitter_ms=0)
    cfg['traffic'].pop('db', None)
    schedule = cfg['traffic']['read_schedule']
    classes = ['mixed', 'integrity'] if schedule == 'mixed_full' else ['mixed'] if schedule == 'mixed' else ['integrity']
    natives, images = dict(mixed=91, integrity=134), dict(mixed=141, integrity=158)
    cfg['expectations']['padding']['0'].update(read_resp_len=sorted(natives[k] for k in classes), sbo_resp_len=[49])
    cfg['expectations']['padding']['1'].update(read_resp_len=sorted(images[k] for k in classes), sbo_resp_len=[60])
    cfg['expectations']['native_len'] = dict(READ=[91, 134], SELECT=49, OPERATE=49)
    cfg['expectations']['common'] = dict(master_addr=1, relay_addr=0, command_points=[1, 3])
    cfg['expectations']['fixture'] = dict(physical_relay=dict(piggyback_fraction='observed; no fixture assumption'))
    cfg['expectations']['T']['1']['fallback_zero_fixtures'] = ['physical_relay']
    cfg['expectations']['_note'] = 'Complete active-master outcomes and real master NIC packet evidence; switch counters retain their original gates.'
    for build in cfg['builds'].values():
        build.update(image_len=60, read_images=images, read_padding=dict(mixed=26, integrity=4),
                     endpoint_profile='sel751',
                     _note='Physical relay candidate: mixed91->141, integrity134->158, SELECT/OPERATE49->60.')
        build.pop('read_image_len', None)
    for scenario in cfg.get('scenarios', {}).values():
        scenario['fixture'] = 'physical_relay'
    for paired in cfg.get('paired_blocks', {}).values():
        paired['fixture'] = 'physical_relay'
    block = cfg.get('evaluation', {}).get('campaign_block') or {}
    block['arguments'] = ['physical_relay' if x == 'separate_ack' else x for x in block.get('arguments', [])]
    cfg['_notes'] = ['Physical SEL-751, active_harness master, guarded frozen {1,3} SBO.',
                     'Master TX/RX is one observation point; switch residence and J require independent anchors.']
    cfg['traffic']['read_schedule_note'] = 'Physical relay %s schedule; complete READ application validation.' % schedule
    return cfg


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--template-build', default='m12p_c29_sdk9132')
    parser.add_argument('--output', type=Path, default=HERE / 'config')
    parser.add_argument('--native-observation', type=Path, default=NATIVE_OBSERVATION)
    parser.add_argument('--tag', default='', help='name infix for a new config set (e.g. v19 after a host change); '
                        'existing configs bound to retained blocks are never rewritten')
    parser.add_argument('--diagnostic-mau-snapshot', action='store_true',
                        help='write only smoke_mau: the smoke block plus an N-ingress MAU snapshot of the first READ')
    parser.add_argument('--reference-arms', nargs='+', metavar='ARM',
                        help='write only reference_rest: the reference block limited to these arms, for completing a '
                        'reference block that stopped early (rc01_hw_c52_20261024_24 ran only off and timing_only)')
    args = parser.parse_args(argv)
    build = args.build.resolve()
    profile = json.loads((build / 'supported_profile.json').read_text())
    source = hashlib.sha256((build / 'response_only.p4').read_bytes()).hexdigest()
    if profile.get('endpoint_profile') != 'sel751' or profile['candidate']['source_sha256'] != source:
        raise ValueError('selected build is not a source-bound SEL-751 profile')
    if profile['encoding']['native_input_octets'] != dict(READ=[91, 134], SELECT=49, OPERATE=49) or \
            profile['encoding']['output_octets'] != 60 or profile['ports']['relay_dev'] != 64:
        raise ValueError('selected build does not implement the actual relay shapes/ports')
    if profile.get('tcp_profile') != 'sel751_ts' or profile['encoding'].get('tcp_header_octets') != 32 or \
            profile['encoding'].get('syn_tcp_header_octets') != 40 or profile['encoding'].get('synack_tcp_header_octets') != 44 or \
            profile['encoding'].get('ipv4_ihl') != 5 or profile['encoding'].get('timestamp_option_prefix') != '0101080a':
        raise ValueError('selected build does not implement the observed physical timestamp profile')
    native = json.loads(args.native_observation.read_text())
    endpoint_profiles.validate_tcp_observation(native)
    artifacts = native.get('artifacts') or {}
    if set(artifacts) != {'out.pcap', 'in.pcap', 'master.json', 'result.json'} or any(
            not (args.native_observation.parent / name).is_file() or
            hashlib.sha256((args.native_observation.parent / name).read_bytes()).hexdigest() != digest
            for name, digest in artifacts.items()):
        raise ValueError('native observation raw capture/master artifact identities are missing or changed')
    packets = [p for group in native.get('packets', {}).values() for p in group]
    data = [p for p in packets if p['payload_len']]
    if native.get('ok') is not True or not data or any(p['tcp_header_bytes'] != 32 or p['ipv4_header_bytes'] != 20 or
            not p['tcp_options_hex'].startswith('0101080a') for p in data):
        raise ValueError('native observation is empty, failed, or differs from the selected TCP profile')
    controls = [row for row in native.get('exchanges', []) if row['operation'] in ('SELECT', 'OPERATE')]
    if len(controls) != 2 or any(row['response']['actual_payload_lengths'] != [49] for row in controls):
        raise ValueError('native observation does not establish whole49 SELECT and OPERATE')
    local = build / 'compile_local/manifest.json'
    manifest = json.loads(local.read_text())
    compile_dir = build / ('compile_local' if manifest.get('compiler', '').startswith('p4c 9.13.2') else 'compile_switch_9132')
    manifest = json.loads((compile_dir / 'manifest.json').read_text())
    if manifest.get('exit_code') != 0 or manifest.get('source_sha256') != source or \
            not manifest.get('compiler', '').startswith('p4c 9.13.2'):
        raise ValueError('selected SDK compile is not bound to the source')
    args.output.mkdir(parents=True, exist_ok=True)
    blocks = ('smoke',) if args.diagnostic_mau_snapshot else ('reference',) if args.reference_arms else BLOCKS
    for block in blocks:
        template = HERE / 'config' / ('rc01_%s_%s.json' % (args.template_build, 'reference' if block == 'smoke' else block))
        cfg = relay_config(json.loads(template.read_text()), *read_link_addresses(native))
        if block == 'smoke':
            cfg['arms'] = [arm for arm in cfg['arms'] if arm['name'] == 'size_only']
            cfg['trials'] = dict(reads_per_trial=2, trials_per_arm=1)
            cfg['traffic'].update(run_sbo=False, expected_reads_per_class=dict(mixed=1, integrity=1), start_delay_ms=0)
            cfg['traffic'].pop('sbo_cycles', None)  # absence is the existing guarded runner's zero-cycle default
            cfg['traffic']['master_port_note'] = 'One bounded padded mixed/full READ acceptance connection.'
            cfg['scenarios'] = {}
            cfg['evaluation'].update(arm_order=['size_only'], purpose='qualification')
            cfg['evaluation']['campaign_block'].update(arms=['size_only'], expected_exchanges=2, phase='smoke',
                arguments=['--arms', 'size_only', '--fixtures', 'physical_relay'])
        if block == 'reference' and args.reference_arms:
            full = [arm['name'] for arm in cfg['arms']]
            if len(set(args.reference_arms)) != len(args.reference_arms) or not set(args.reference_arms) <= set(full):
                raise ValueError('--reference-arms %r must be distinct arms of %r' % (args.reference_arms, full))
            arms = [name for name in full if name in args.reference_arms]
            per_arm = cfg['evaluation']['campaign_block']['expected_exchanges'] // len(full)
            cfg['arms'] = [arm for arm in cfg['arms'] if arm['name'] in arms]
            cfg['evaluation']['arm_order'] = arms
            cfg['evaluation']['campaign_block'].update(arms=arms, expected_exchanges=per_arm * len(arms),
                arguments=['--arms', ','.join(arms), '--fixtures', 'physical_relay'])
            cfg['reference_split'] = dict(arms=arms, full_reference_arms=full, exchanges_per_arm=per_arm)
        cfg['wire_profile'] = dict(tcp_profile='sel751_ts', ipv4_header_octets=20, tcp_header_octets=32,
                                  native_observation=str(args.native_observation.resolve()),
                                  native_observation_sha256=hashlib.sha256(args.native_observation.read_bytes()).hexdigest(),
                                  native_capture_artifacts=native.get('artifacts'),
                                  observation_scope=native.get('observation_scope'))
        old_build = next(iter(cfg['builds'].values()))
        old_build.update(source_sha256=source, out_dir=case4_relative(compile_dir / 'out'),
                         manifest=case4_relative(compile_dir / 'manifest.json'),
                         hashes={key: manifest['artifact_sha256'][key] for key in old_build['hashes']})
        cfg['builds'] = {build.name: old_build}
        for arm in cfg['arms']:
            arm['build'] = build.name
        identity = cfg.get('ctl_timing_identity') or {}
        identity.update(source_sha256=source, supported_profile=case4_relative(build / 'supported_profile.json'),
                        supported_profile_sha256=hashlib.sha256((build / 'supported_profile.json').read_bytes()).hexdigest())
        identity['switch_compile'] = dict(out_dir=case4_relative(compile_dir / 'out'),
                                         manifest=case4_relative(compile_dir / 'manifest.json'),
                                         manifest_sha256=hashlib.sha256((compile_dir / 'manifest.json').read_bytes()).hexdigest(),
                                         source_sha256=source, artifact_sha256=manifest['artifact_sha256'],
                                         compiler=manifest['compiler'], sdk='9.13.2')
        cfg['ctl_timing_identity'] = identity
        name = (args.tag + '_' if args.tag else '') + block + ('_rest' if args.reference_arms else '')
        if args.diagnostic_mau_snapshot:
            name = (args.tag + '_' if args.tag else '') + block + '_mau'
            cfg['diagnostic_mau_snapshot'] = MAU_SNAPSHOT
            cfg['_notes'].append('Diagnostic: N-ingress MAU snapshot of the first READ post-lap pass; traffic unchanged.')
            cfg['evaluation']['campaign_block']['phase'] = name
        block_identity = cfg.get('evaluation', {}).get('campaign_block')
        if isinstance(block_identity, dict):
            block_identity['id'] = 'rc01_%s_sel751_%s' % (build.name, name)
        path = args.output / ('rc01_%s_sel751_%s.json' % (build.name, name))
        with path.open('x') as stream:
            json.dump(cfg, stream, indent=2, sort_keys=True)
            stream.write('\n')
        print(path)
    return 0


if __name__ == '__main__':
    sys.exit(main())

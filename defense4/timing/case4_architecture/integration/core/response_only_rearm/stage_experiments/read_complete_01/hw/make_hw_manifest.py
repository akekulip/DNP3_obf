"""evaluation_campaign manifest for one build's hardware blocks (existing frozen wrapper, detached supervisor).

  python3 make_hw_manifest.py [--build m12p_b08] FREEZE.json CAMPAIGN_ID [BLOCK ...]   # default: all blocks, reference first

The default block list follows the build's configs: the b08 six, or the two-READ seven (loss per READ class).
Physical SEL-751 defaults prepend the padded mixed/full READ acceptance smoke.

Each step runs run_block_frozen.sh FREEZE TOOL CONFIG RUN_ID with the tool and arguments recorded in the config's
own evaluation.campaign_block (the four-arm reference block runs every arm). Run roots are the configs'
evidence_dir / RUN_ID. Writes read_complete_01/evidence/hw_campaigns/<CAMPAIGN_ID>.manifest.json.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ARCH = HERE.parents[5]
WRAPPER = ARCH / 'integration/evidence/rearm_01/hw/run_block_frozen.sh'
ORDER = ['reference', 'persistence_graceful_950', 'persistence_rst_950', 'reconnect_950', 'held_operate_350',
         'loss_core_950']
ORDER_TWO_READ = ['reference', 'persistence_graceful_950', 'persistence_rst_950', 'loss_mixed_950', 'loss_full_950',
                  'reconnect_950', 'held_operate_350']


def main(argv):
    build = 'm12p_b08'
    profile = None
    config_dir, config_tag = HERE / 'config', ''
    while argv[:1] and argv[0] in ('--build', '--endpoint-profile', '--config-dir', '--config-tag'):
        flag, value, argv = argv[0], argv[1], argv[2:]
        if flag == '--build':
            build = value
        elif flag == '--endpoint-profile':
            profile = value
        elif flag == '--config-dir':
            config_dir = Path(value)
        else:
            config_tag = value + '_'
    config_dir = config_dir.resolve(strict=True)
    if profile is None:
        physical = any((config_dir / ('rc01_%s_sel751_%s%s.json' % (build, config_tag, name))).is_file()
                       for name in ('reference', 'reference_rest'))
        software = any((config_dir / ('rc01_%s_%s%s.json' % (build, config_tag, name))).is_file()
                       for name in ('reference', 'reference_rest'))
        if physical and software:
            raise ValueError('both endpoint profiles have configs; select --endpoint-profile explicitly')
        profile = 'sel751' if physical else 'software'
    if profile not in ('sel751', 'software'):
        raise ValueError('unsupported endpoint profile')
    prefix = build + ('_sel751' if profile == 'sel751' else '')
    freeze, campaign = str(Path(argv[0]).resolve(strict=True)), argv[1]
    two_read = (config_dir / ('rc01_%s_%sloss_mixed_950.json' % (prefix, config_tag))).exists()
    default_blocks = (['smoke'] if profile == 'sel751' else []) + (ORDER_TWO_READ if two_read else ORDER)
    # Prefer the complete reference when both exist; a split reference may be the tag's only block.
    reference_name = next((name for name in ('reference', 'reference_rest')
                           if (config_dir / ('rc01_%s_%s%s.json' % (prefix, config_tag, name))).is_file()), 'reference')
    reference = config_dir / ('rc01_%s_%s%s.json' % (prefix, config_tag, reference_name))
    ready = reference.is_file() and json.loads(reference.read_text()).get('timing_contract') == 'response_ready_ack_d_v1'
    if ready:
        order = ['smoke', reference_name] + [name for name in ORDER_TWO_READ
                                            if name not in ('reference', 'held_operate_350')]
        default_blocks = [name for name in order
                          if (config_dir / ('rc01_%s_%s%s.json' % (prefix, config_tag, name))).is_file()]
    blocks = argv[2:] or default_blocks
    steps = []
    for name in blocks:
        path = config_dir / ('rc01_%s_%s%s.json' % (prefix, config_tag, name))
        cfg = json.loads(path.read_text())
        if cfg.get('endpoint_profile', 'software') != profile:
            raise ValueError('config endpoint profile differs from selected manifest profile')
        if cfg.get('timing_contract') == 'response_ready_ack_d_v1' and 'held_operate_350' in name:
            raise ValueError('response-ready campaign excludes historical 350 ms stress')
        cb = cfg['evaluation']['campaign_block']
        tool = cb['tool']
        args = list(cb.get('arguments') or [])
        if name in ('reference', 'reference_rest') and not args:
            args = ['--arms', ','.join(cfg['evaluation']['arm_order']), '--fixtures',
                    'physical_relay' if profile == 'sel751' else 'separate_ack']
        run_id = '%s_%s' % (campaign, name)
        evidence_root = Path(cfg['evidence_dir'])
        if not evidence_root.is_absolute():
            evidence_root = ARCH / evidence_root
        steps.append(dict(id=run_id, kind='block', run_root=str(evidence_root.resolve() / run_id),
                          argv=['/bin/bash', str(WRAPPER), freeze, tool, str(path), run_id] + args))
    out = HERE.parent / 'evidence/hw_campaigns'
    out.mkdir(parents=True, exist_ok=True)
    manifest = out / ('%s.manifest.json' % campaign)
    with manifest.open('x') as stream:
        stream.write(json.dumps(dict(campaign_id=campaign, evidence_kind='hardware', steps=steps), indent=1) + '\n')
    print(manifest)


if __name__ == '__main__':
    main(sys.argv[1:])

"""evaluation_campaign manifest for one build's hardware blocks (existing frozen wrapper, detached supervisor).

  python3 make_hw_manifest.py [--build m12p_b08] FREEZE.json CAMPAIGN_ID [BLOCK ...]   # default: all blocks, reference first

The default block list follows the build's configs: the b08 six, or the two-READ seven (loss per READ class).

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
    if argv[:1] == ['--build']:
        build, argv = argv[1], argv[2:]
    freeze, campaign = str(Path(argv[0]).resolve(strict=True)), argv[1]
    two_read = (HERE / 'config' / ('rc01_%s_loss_mixed_950.json' % build)).exists()
    blocks = argv[2:] or (ORDER_TWO_READ if two_read else ORDER)
    steps = []
    for name in blocks:
        path = HERE / 'config' / ('rc01_%s_%s.json' % (build, name))
        cfg = json.loads(path.read_text())
        cb = cfg['evaluation']['campaign_block']
        tool = cb['tool']
        args = list(cb.get('arguments') or [])
        if name == 'reference' and not args:
            args = ['--arms', ','.join(cfg['evaluation']['arm_order']), '--fixtures', 'separate_ack']
        run_id = '%s_%s' % (campaign, name)
        steps.append(dict(id=run_id, kind='block', run_root=str(Path(cfg['evidence_dir']) / run_id),
                          argv=['/bin/bash', str(WRAPPER), freeze, tool, str(path), run_id] + args))
    out = HERE.parent / 'evidence/hw_campaigns'
    out.mkdir(parents=True, exist_ok=True)
    manifest = out / ('%s.manifest.json' % campaign)
    manifest.write_text(json.dumps(dict(campaign_id=campaign, evidence_kind='hardware', steps=steps), indent=1) + '\n')
    print(manifest)


if __name__ == '__main__':
    main(sys.argv[1:])

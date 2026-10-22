"""RX-coalescing host-diagnostic block configs (Philip, 2026-10-22): the matched m11_09 control and the c25
reference config, unchanged except `host_diagnostic: {rx_coalescing: off}` (campaign.vision_setup passes
--rx-coalesce-diag; vision_run.py restore puts the recorded baseline back; restore_verify check 6 verifies it).

  python3 make_rxdiag_configs.py      # writes config/rc01_control_m11_09_reference_rxdiag.json, rc01_m12p_c25_rxdiag.json
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
NOTE = ('HOST DIAGNOSTIC (Philip, 2026-10-22): Vision enp59s0f0np0 RX interrupt coalescing off (adaptive RX off, '
        'rx-usecs 0) for this block only; TX, offloads, IRQ affinity and CPU power unchanged. Not a qualification '
        'condition: it isolates whether the idle-dependent receive delay is the shared timing degradation.')
for src, dst in (('rc01_control_m11_09_reference.json', 'rc01_control_m11_09_reference_rxdiag.json'),
                 ('rc01_m12p_c25_reference.json', 'rc01_m12p_c25_rxdiag.json')):
    cfg = json.loads((HERE / 'config' / src).read_text())
    cfg['host_diagnostic'] = {'rx_coalescing': 'off', '_note': NOTE, 'derived_from': src}
    block = (cfg.get('evaluation') or {}).get('campaign_block')
    if isinstance(block, dict):
        block['id'] = block.get('id', src[:-5]) + '_rxdiag'
    cfg['_notes'] = list(cfg.get('_notes', [])) + [NOTE]
    (HERE / 'config' / dst).write_text(json.dumps(cfg, indent=1, sort_keys=True) + '\n')
    print(dst)

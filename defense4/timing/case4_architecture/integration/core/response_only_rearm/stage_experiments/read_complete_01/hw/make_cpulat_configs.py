"""CPU-latency host-diagnostic block configs (Philip, 2026-10-22): the matched m11_09 control and the c25 reference
config, unchanged except `host_diagnostic: {cpu_latency: zero}` (campaign.vision_setup passes --cpu-latency-diag;
vision_run.py restore stops the helper and verifies the baseline; restore_verify check 7 verifies it). The NIC stays
at its restored baseline (no rx_coalescing key).

  python3 make_cpulat_configs.py   # writes config/rc01_control_m11_09_reference_cpulat.json, rc01_m12p_c25_cpulat.json
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
NOTE = ('HOST DIAGNOSTIC (Philip, 2026-10-22): a supervised helper holds a signed 32-bit zero request on Vision '
        '/dev/cpu_dma_latency for this block only (released and verified by restore); NIC at its restored baseline; '
        'other host settings unchanged. Not the original host configuration and not a qualification condition: it '
        'tests a CPU-idle contribution to the idle-dependent receive delay.')


def main():
    for src, dst in (('rc01_control_m11_09_reference.json', 'rc01_control_m11_09_reference_cpulat.json'),
                     ('rc01_m12p_c25_reference.json', 'rc01_m12p_c25_cpulat.json')):
        cfg = json.loads((HERE / 'config' / src).read_text())
        cfg['host_diagnostic'] = {'cpu_latency': 'zero', '_note': NOTE, 'derived_from': src}
        block = (cfg.get('evaluation') or {}).get('campaign_block')
        if isinstance(block, dict):
            block['id'] = block.get('id', src[:-5]) + '_cpulat'
        cfg['_notes'] = list(cfg.get('_notes', [])) + [NOTE]
        (HERE / 'config' / dst).write_text(json.dumps(cfg, indent=1, sort_keys=True) + '\n')
        print(dst)


if __name__ == '__main__':
    main()

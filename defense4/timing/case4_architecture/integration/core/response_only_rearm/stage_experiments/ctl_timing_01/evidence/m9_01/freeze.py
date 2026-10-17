#!/usr/bin/env python3
"""Freeze record for the m9_01 candidate (completion plan gate 4).

  python3 freeze.py           # writes freeze.json
  python3 freeze.py --check   # exit 1 if any frozen file changed or is missing

The record pins every input that qualification of m9_01 depends on:
- the P4 source and the generator copy;
- both compiles' manifests and artifacts;
- the control-plane and installer code;
- the silicon configs and their endpoint binaries;
- the acceptance code;
- the model summary.
Paths are relative to the repository root.
"""
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[10]
A = 'defense4/timing/case4_architecture/'
I = A + 'integration/'
CT = I + 'core/response_only_rearm/stage_experiments/ctl_timing_01/'
B = CT + 'evidence/m9_01/'
FILES = sorted(set(
    [B + f for f in ('response_only.p4', 'response_only.inputs.json', 'generate.py', 'model_summary.json',
                     'resource_review.json', 'NOTES_20261016.md')]
    + [B + c + '/' + f for c in ('compile_local', 'compile_switch_9132')
       for f in ('manifest.json', 'out/bfrt.json', 'out/response_only.p4pp', 'out/p0/tofino.bin',
                 'out/p1/tofino.bin')]
    + [I + 'core/response_only_rearm/' + f for f in ('cp.py', 'hw/bringup_composite.py', 'hw/snapshot_counters.py',
                                                     'hw/sealed_profile.py', 'hw/generation_headroom.py')]
    + [I + 'core/response_only/hw/t_config.py', I + 'core/model_driver.py']
    + [I + 'evidence/rearm_01/hw/' + f for f in ('candidate_campaign.py', 'candidate_isolation.py', 'token_window.py',
                                                 'run_block.sh', 'restore_verify.py', 'diag_poll.py')]
    + [A + 'protocol/hw_vepa/checks.py', CT + 'model_summary.py',
       I + 'core/response_only_rearm/stage_experiments/seg61_02/analysis/isolation_v2.py',
       I + 'evidence/rearm_01/config/ctl_m9_stale_iso20_950.json']
    + [str(p.relative_to(REPO)) for p in sorted((REPO / I / 'core/response_only_rearm/stage_experiments/seg61_02/hw/config')
                                               .glob('ctl_m9_*.json'))]))


def sha(path):
    return hashlib.sha256((REPO / path).read_bytes()).hexdigest()


def endpoints():
    """Endpoint binaries named by the frozen configs (sha256 as each config pins it)."""
    found = {}
    for path in FILES:
        if path.endswith('.json') and '/config/' in path:
            ep = json.loads((REPO / path).read_text()).get('endpoint') or {}
            if ep.get('binary_sha256'):
                found[Path(path).name] = ep['binary_sha256']
    return found


def record():
    return dict(candidate='ctl_timing_01 m9_01', source_sha256=sha(B + 'response_only.p4'),
                files={p: sha(p) for p in FILES}, endpoint_binaries=endpoints(),
                note='E and T byte-identical to m8; N = m8 + transform_n_m9. Silicon qualification must run on '
                     'exactly these files (freeze.py --check before each block).')


if __name__ == '__main__':
    out = Path(__file__).resolve().parent / 'freeze.json'
    if '--check' in sys.argv:
        frozen = json.loads(out.read_text())
        bad = [p for p, h in frozen['files'].items() if not (REPO / p).is_file() or sha(p) != h]
        print('freeze check:', 'OK' if not bad else 'CHANGED ' + ' '.join(bad))
        sys.exit(1 if bad else 0)
    out.write_text(json.dumps(record(), indent=1) + '\n')
    print('wrote', out, len(FILES), 'files')

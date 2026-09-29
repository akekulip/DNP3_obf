#!/usr/bin/env python3
"""Check existing campaign/figure manifests without rewriting them."""
import json
from pathlib import Path
from recovery import ROOT, HERE, digest


def main():
    campaign = ROOT / 'defense4/timing/evidence/campaign_v2'
    jobs = [(p, p.parents[1]) for p in sorted(campaign.glob('s*/provenance/DATASET.sha256'))]
    assert len(jobs) == 22
    jobs.append((campaign / 'sweep/SWEEP.sha256', campaign))
    figures = ROOT / 'paper/rewrite/figures'
    jobs.extend((p, p.parent) for p in sorted(figures.rglob('*.sha256')))
    reports = []
    for manifest, base in jobs:
        checked = 0
        for line in manifest.read_text().splitlines():
            if not line.strip() or line.startswith('#'):
                continue
            expected, relative = line.split(maxsplit=1)
            path = base / relative.lstrip('*')
            assert path.exists() and digest(path) == expected, str(path)
            checked += 1
        reports.append({'manifest': str(manifest.relative_to(ROOT)), 'entries': checked})
    report = {'status': 'passed', 'scope': 'Existing hashes only; not evidence of device configuration or statistical validity', 'manifests': reports}
    (HERE / 'manifest_check.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'Passed {len(reports)} manifests, {sum(r["entries"] for r in reports)} entries')


if __name__ == '__main__':
    main()

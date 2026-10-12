"""Markers for the tests that need a compiled/committed evidence tree, and the skip that keeps a bare checkout green.

  build_tree     needs the compiled build out/ and its compile manifest.json (the shipped campaign.json binds to them)
  evidence_tree  needs committed hardware captures under integration/evidence (real pcaps and snapshots)

HW_VEPA_EVIDENCE_ROOT points at the evidence root (default: <case4_architecture>/integration/evidence); the tests
skip, rather than fail, when what they need is not under it.
"""
import json
import os
from pathlib import Path

import pytest

ARCH = Path(__file__).resolve().parents[3]
EVIDENCE = Path('integration/evidence')


def _shipped_build_files():
    """The compile manifest of the build the shipped campaign.json arms run on, relative to the evidence root."""
    cfg = json.load(open(ARCH / 'protocol' / 'hw_vepa' / 'campaign.json'))
    build = cfg['builds'][cfg['arms'][0]['build']]
    return [Path(build['manifest']).relative_to(EVIDENCE)] + [
        (Path(build['out_dir']) / relative).relative_to(EVIDENCE)
        for relative in ('bfrt.json', 'p0/tofino.bin', 'p1/tofino.bin', 'p1/response_only.bfa')]


NEEDS = {'build_tree': _shipped_build_files(),
         'evidence_tree': [Path('p2_production_01/p_unshaped') / name for name in
                           ('sna_p_unshaped.json', 'snb_p_unshaped.json', 'out.pcap', 'in.pcap', 'master.json', 'outstation.json')] +
                          [Path('mirror_fix_silicon_01/s_r20') / name for name in
                           ('sna_s_r20.json', 'snb_s_r20.json', 'out.pcap', 'in.pcap', 'master.json', 'outstation.json')]}


def evidence_root():
    return Path(os.environ.get('HW_VEPA_EVIDENCE_ROOT') or ARCH / 'integration' / 'evidence')


def pytest_configure(config):
    config.addinivalue_line('markers', 'build_tree: needs the compiled build out/ and its compile manifest')
    config.addinivalue_line('markers', 'evidence_tree: needs committed hardware captures under integration/evidence')


def pytest_collection_modifyitems(config, items):
    root = evidence_root()
    for item in items:
        for name, files in NEEDS.items():
            missing = [relative for relative in files if not (root / relative).is_file()]
            if item.get_closest_marker(name) and missing:
                item.add_marker(pytest.mark.skip(reason='%s: required files missing under%s: %s' % (name, root, missing)))

#!/usr/bin/env python3
"""Write the bf_switchd conf for the composite from a compiled out/ directory.

- pipe_scope is forced to [0] for p0 and [1] for p1: the switch has two pipes and the SDE rejects any pipe
  >= num_pipes (dvm.c), so the compiler's [0, 2] / [1, 3] cannot load.
- every path points at --remote-dir (the persistent copy on the switch), absolute.
- PCIe prefix: the value in the conf that loaded on 2026-09-17 (audit_current/hardware_20260917/frozen_abs.conf),
  0000:04:00.0. The compiler writes 0000:05:00.0, which failed that day. --pcie must agree or this exits 1.
- agent0 (platform manager) is kept; model_json_path (a model-only file, absent from out/) is dropped.

  python3 make_conf.py <out/> --remote-dir /home/decps/Philip_repo/dnp3-defense4/<name>/out \
      --pcie 0000:04:00.0 -o response_only_hw.conf
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

PCIE_LOADED = '0000:04:00.0'
BAREFOOT_VENDOR = '0x1d1c'
PREFIX = '/sys/devices/pci0000:00/0000:00:03.0/'
SCOPES = {'p0': [0], 'p1': [1]}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('out')
    ap.add_argument('--remote-dir', required=True)
    ap.add_argument('--pcie', required=True, help='operator-checked PCIe address; must equal %s' % PCIE_LOADED)
    ap.add_argument('-o', '--output', required=True)
    ap.add_argument('--offline', action='store_true', help='not on the switch: skip the sysfs vendor check')
    a = ap.parse_args(argv)
    print('PCIe prefix from the 2026-09-17 conf that loaded:', PCIE_LOADED, '| operator says:', a.pcie)
    if a.pcie != PCIE_LOADED:
        print('FAIL: operator PCIe address disagrees with the conf that loaded; resolve before launching')
        return 1
    vendor = Path('/sys/bus/pci/devices/%s/vendor' % a.pcie)
    print('operator check on the switch:  cat %s   # must print %s (Barefoot)' % (vendor, BAREFOOT_VENDOR))
    if a.offline:
        print('WARNING: --offline, PCI vendor NOT checked; run the cat command above on the switch before launching')
    elif not vendor.is_file():
        print('FAIL: %s does not exist on this host; run on the switch, or pass --offline to skip the check' % vendor)
        return 1
    else:
        got = vendor.read_text().strip()
        if got != BAREFOOT_VENDOR:
            print('FAIL: %s reads %s, not %s: the Tofino is not at this address' % (vendor, got, BAREFOOT_VENDOR))
            return 1
        print('PCI vendor at %s is %s: OK' % (a.pcie, got))
    out, remote = Path(a.out), a.remote_dir.rstrip('/')
    if not remote.startswith('/'):
        print('FAIL: --remote-dir must be absolute')
        return 1
    src = json.loads(next(out.glob('*.conf')).read_text())
    prog = src['p4_devices'][0]['p4_programs'][0]
    names = [p['p4_pipeline_name'] for p in prog['p4_pipelines']]
    if sorted(names) != sorted(SCOPES):
        print('FAIL: pipelines %s, expected p0 and p1' % names)
        return 1
    src['chip_list'][0]['pcie_sysfs_prefix'] = PREFIX + PCIE_LOADED
    prog['bfrt-config'] = remote + '/bfrt.json'
    prog.pop('model_json_path', None)
    for p in prog['p4_pipelines']:
        n = p['p4_pipeline_name']
        p.update(context='%s/%s/context.json' % (remote, n), config='%s/%s/tofino.bin' % (remote, n),
                 pipe_scope=SCOPES[n], path=remote)
    Path(a.output).write_text(json.dumps(src, indent=4) + '\n')
    print('program', prog['program-name'], '| scopes', {p['p4_pipeline_name']: p['pipe_scope'] for p in prog['p4_pipelines']})
    for rel in ['bfrt.json'] + ['%s/%s' % (n, f) for n in sorted(SCOPES) for f in ('context.json', 'tofino.bin')]:
        print('  sha256 %s  %s' % (hashlib.sha256((out / rel).read_bytes()).hexdigest(), rel))
    print('wrote', a.output, '(copy out/ to %s first; the paths above must exist there)' % remote)
    return 0


if __name__ == '__main__':
    sys.exit(main())

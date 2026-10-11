#!/usr/bin/env python3
"""Switch T's timing on or off on a live install, changing nothing else. Runs on the switch host.

Writes only the `enabled` parameter of T's params default action (p1.t_Ingress.params set_params). Every
other parameter is taken from the bring-up manifest, i.e. exactly as installed. Before writing, the hardware
must still hold what the manifest says (a drifted install is refused); after writing, the default is read
back. The manifest's `enabled` is then updated, so the next call and the teardown see the current state.
For alternating Timing OFF / Obfuscated blocks on one connection.

  DEFENSE4_HW_AUTHORIZED=1 python3 set_enabled.py --manifest bringup_manifest.json --enabled 0|1
Without DEFENSE4_HW_AUTHORIZED=1 it prints what it would write and exits.
"""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import readback  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--manifest', required=True)
    ap.add_argument('--enabled', type=int, choices=(0, 1), required=True)
    ap.add_argument('--client-id', type=int, default=123)
    a = ap.parse_args(argv)
    path = Path(a.manifest)
    m = json.loads(path.read_text())
    found = [op for op in m['installed'] if op['kind'] == 'default' and op['table'].endswith('.params')]
    if len(found) != 1:
        print('REFUSED: manifest has %d T params writes, expected 1' % len(found))
        return 1
    op = found[0]
    now = [(n, v) for n, v in op['data']]
    new = [(n, a.enabled if n == 'enabled' else v) for n, v in now]
    if 'enabled' not in dict(now):
        print('REFUSED: the manifest params write has no `enabled` field')
        return 1
    print('T params: %s' % ', '.join('%s=%s' % nv for nv in new))
    print('enabled: %d -> %d' % (dict(now)['enabled'], a.enabled))
    if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
        print('REFUSED: needs DEFENSE4_HW_AUTHORIZED=1; nothing written')
        return 3
    from switch import Switch
    sw = Switch(m['program'], a.client_id)
    try:
        drift = readback.verify(sw, dict(op, data=now, key=[]))
        if drift:
            print('REFUSED: the switch no longer holds the installed params, nothing written: %s' % drift)
            return 2
        t = sw.table(op['table'])
        t.default_entry_set(sw.target(op['pipe']), sw.data(t, new, op['action']))
        bad = readback.verify(sw, dict(op, data=new, key=[]))
        if bad:
            print('FAILED readback, manifest NOT updated: %s' % bad)
            return 2
    finally:
        sw.close()
    op['data'] = [[n, v] for n, v in new]
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(json.dumps(m, indent=1) + '\n')
    os.replace(str(tmp), str(path))
    print('WROTE enabled=%d and read it back; manifest updated' % a.enabled)
    return 0


if __name__ == '__main__':
    sys.exit(main())

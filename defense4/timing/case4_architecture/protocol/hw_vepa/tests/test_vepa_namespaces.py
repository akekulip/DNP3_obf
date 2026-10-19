"""vepa_namespaces.py: recorded state, idempotent build, refusal without the NIC (no real ip commands)."""
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vepa_namespaces as vn  # noqa: E402


class FakeIp:
    """A tiny model of the ip state the script reads and writes."""
    def __init__(self, nic=True):
        self.nic, self.addrs, self.spaces, self.links, self.neigh, self.calls = nic, set(), set(), {}, {}, []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        out, rc = '', 0
        space = None
        if cmd[:3] == ['ip', 'netns', 'exec']:
            space, cmd = cmd[3], cmd[4:]
        c = tuple(cmd)
        if c[:3] == ('ip', 'link', 'show') and space is None:
            rc = 0 if self.nic else 1
        elif c[:3] == ('ip', '-br', 'addr') and space is None:
            out = 'enp59s0f0np0 UP ' + ' '.join(self.addrs)
        elif c[:3] == ('ip', 'addr', 'replace') and space is None:
            self.addrs.add(c[3])
        elif c[:3] == ('ip', 'netns', 'list'):
            out = '\n'.join(sorted(self.spaces))
        elif c[:3] == ('ip', 'netns', 'add'):
            self.spaces.add(c[3])
        elif c[:3] == ('ip', 'link', 'add'):
            self.links[c[3]] = dict(mac=c[7], space=None, up=False, addr=None)
        elif c[:3] == ('ip', 'link', 'set') and c[4] == 'netns':
            self.links[c[3]]['space'] = c[5]
        elif space is not None:
            ifc = next((n for n, l in self.links.items() if l['space'] == space), None)
            if c[:4] == ('ip', 'link', 'show', c[3] if len(c) > 3 else ''):
                rc = 0 if ifc == c[3] else 1
            elif c[:3] == ('ip', '-d', 'link'):
                l = self.links.get(c[4])
                rc = 0 if l and l['space'] == space else 1
                if not rc:
                    out = 'link/ether %s state %s macvlan mode vepa' % (l['mac'], 'UP' if l['up'] else 'DOWN')
            elif c[:3] == ('ip', 'link', 'set') and c[3] != 'lo':
                self.links[c[3]]['up'] = True
            elif c[:3] == ('ip', 'addr', 'replace'):
                self.links[c[5]]['addr'] = c[3]
            elif c[:3] == ('ip', '-br', 'addr'):
                out = ' '.join(l['addr'] or '' for l in self.links.values() if l['space'] == space)
            elif c[:3] == ('ip', 'neigh', 'replace'):
                self.neigh[(space, c[3])] = c[7]
            elif c[:3] == ('ip', 'neigh', 'show'):
                mac = self.neigh.get((space, c[3]))
                out = '%s dev x lladdr %s PERMANENT' % (c[3], mac) if mac else ''
        if kw.get('check') and rc:
            raise RuntimeError(cmd)
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr='')


class VepaNamespaces(unittest.TestCase):
    def test_build_reaches_the_recorded_state_and_is_idempotent(self):
        ip = FakeIp()
        with patch.object(vn.subprocess, 'run', side_effect=lambda cmd, **kw: ip(list(cmd), **kw)):
            self.assertEqual(vn.main([]), 0)
            self.assertEqual(ip.links['mvA']['mac'], 'd2:9d:1d:1c:f4:dd')
            self.assertEqual(ip.neigh[('ns_vepa_a', '192.168.10.62')], 'ee:df:16:18:b0:a5')
            adds = sum(1 for c in ip.calls if c[:3] == ['ip', 'link', 'add'])
            self.assertEqual(vn.main([]), 0)
            self.assertEqual(sum(1 for c in ip.calls if c[:3] == ['ip', 'link', 'add']), adds)

    def test_check_changes_nothing_and_reports_differences(self):
        ip = FakeIp()
        with patch.object(vn.subprocess, 'run', side_effect=lambda cmd, **kw: ip(list(cmd), **kw)):
            self.assertEqual(vn.main(['--check']), 1)
        self.assertFalse([c for c in ip.calls if 'add' in c or 'replace' in c])

    def test_without_the_nic_nothing_is_changed(self):
        ip = FakeIp(nic=False)
        with patch.object(vn.subprocess, 'run', side_effect=lambda cmd, **kw: ip(list(cmd), **kw)):
            with self.assertRaises(SystemExit):
                vn.main([])
        self.assertFalse([c for c in ip.calls if 'add' in c or 'replace' in c])


if __name__ == '__main__':
    unittest.main()

"""vision_run's pure helpers: tcpdump drop-statistics parsing and the checked sysctl readback. The
subprocess/root orchestration itself needs the Vision host and is not exercised here."""
import sys
import types
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import vision_run as vr  # noqa: E402


class TcpdumpStats(unittest.TestCase):
    def test_full_summary(self):
        s = vr.parse_tcpdump_stats('10 packets captured\n12 packets received by filter\n'
                                   '2 packets dropped by kernel\n1 packet dropped by interface\n')
        self.assertEqual(s, {'captured': 10, 'received': 12, 'dropped_kernel': 2, 'dropped_interface': 1})

    def test_partial_summary_keeps_what_is_present(self):
        s = vr.parse_tcpdump_stats('0 packets captured\n0 packets received by filter\n0 packets dropped by kernel\n')
        self.assertEqual(s, {'captured': 0, 'received': 0, 'dropped_kernel': 0})

    def test_no_summary_is_empty(self):
        self.assertEqual(vr.parse_tcpdump_stats('tcpdump: listening on enp59s0f0np0\n'), {})


class SysctlReadback(unittest.TestCase):
    def _patch(self, written, readback):
        calls = {}

        def fake_nsx(ns, *cmd, **kw):
            if cmd[:2] == ('sysctl', '-w'):
                calls['written'] = cmd[2]
                return types.SimpleNamespace(stdout='', returncode=0)
            if cmd[:2] == ('sysctl', '-n'):
                return types.SimpleNamespace(stdout=readback + '\n', returncode=0)
            raise AssertionError(cmd)

        self._orig = vr.nsx
        vr.nsx = fake_nsx
        self.addCleanup(lambda: setattr(vr, 'nsx', self._orig))
        return calls

    def test_match_returns_the_value(self):
        self._patch('1', '1')
        self.assertEqual(vr.set_sysctl_checked('ns_vepa_a', 'net.ipv4.tcp_sack', '1'), '1')

    def test_port_range_tab_rendering_still_matches(self):
        # the kernel renders a port range tab-separated; a whitespace-token compare must accept it
        self._patch('40000 40000', '40000\t40000')
        self.assertEqual(vr.set_sysctl_checked('ns_vepa_a', 'net.ipv4.ip_local_port_range', '40000 40000'),
                         '40000\t40000')

    def test_mismatch_raises(self):
        self._patch('1', '0')
        with self.assertRaises(RuntimeError):
            vr.set_sysctl_checked('ns_vepa_a', 'net.ipv4.tcp_sack', '1')


if __name__ == '__main__':
    unittest.main()

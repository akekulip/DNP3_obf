"""Single source of every private port/role for the READ timing program (ticket T2).

ports.p4 is the one definition; read_timing.p4 must include it and carry no numeric port.
Rule from STEP2_DESIGN.md section 3: every port value is at most 71 (Tofino-1 has pipe-local
ports 0..71), and no number serves two ingress roles.
"""
import re
import unittest
from pathlib import Path

ARCH = Path(__file__).resolve().parents[3]
READ = ARCH / 'integration/read'
PROBE = ARCH / 'ownership/p4/held_timing_expected_probe.p4'
NATIVE = ARCH / 'integration/connection/binding/native_binding.p4'
DECL = re.compile(r'const\s+PortId_t\s+(\w+)\s*=\s*9w(\d+)\s*;\s*//\s*(ingress|egress)\b')


def strip_comments(text):
    return re.sub(r'//[^\n]*', '', re.sub(r'/\*.*?\*/', '', text, flags=re.S))


def declared():
    text = (READ / 'ports.p4').read_text()
    result = {}
    for name, value, role in DECL.findall(text):
        assert name not in result, 'duplicate constant ' + name
        result[name] = (int(value), role)
    return text, result


class Ports(unittest.TestCase):
    def test_every_port_constant_has_a_role_tag(self):
        text, ports = declared()
        self.assertEqual(len(re.findall(r'const\s+PortId_t', text)), len(ports),
                         'a PortId_t constant lacks the "// ingress|egress" role tag')
        self.assertGreaterEqual(len(ports), 6)

    def test_values_do_not_exceed_71(self):
        _, ports = declared()
        for name, (value, _) in ports.items():
            self.assertLessEqual(value, 71, name)

    def test_no_number_serves_two_ingress_roles(self):
        _, ports = declared()
        seen = {}
        for name, (value, role) in ports.items():
            if role == 'ingress':
                self.assertNotIn(value, seen, '%s and %s share port %d' % (name, seen.get(value), value))
                seen[value] = name

    def test_read_timing_includes_ports_and_has_no_numeric_port(self):
        source = READ / 'read_timing.p4'
        raw = source.read_text()
        self.assertIn('#include "ports.p4"', raw)
        code = strip_comments(raw)
        self.assertEqual(re.findall(r'\b9w\d+', code), [])
        self.assertEqual(re.findall(r'const\s+PortId_t', code), [])
        self.assertEqual(re.findall(r'\b(?:6[4-9]|7[0-3])\b', code), [])
        self.assertEqual(re.findall(r'ingress_port\s*==\s*\d+', code), [])

    def test_read_timing_uses_every_declared_role(self):
        code = strip_comments((READ / 'read_timing.p4').read_text())
        _, ports = declared()
        for name in ports:
            self.assertRegex(code, r'\b%s\b' % name, name + ' declared but unused')

    def test_frozen_probe_uses_ports_72_and_73_flagged(self):
        """The 72/73 problem: the probe's FORWARD_PORT/heartbeat-return are not valid local ports."""
        code = strip_comments(PROBE.read_text())
        self.assertIn('FORWARD_PORT = 9w72', code)
        self.assertRegex(code, r'ucast_egress_port = 73')
        _, ports = declared()
        self.assertNotIn(72, [v for v, _ in ports.values()])
        self.assertNotIn(73, [v for v, _ in ports.values()])

    def test_pktgen_port_collides_with_native_recirculation_only_by_pipe_split(self):
        """Documented, not resolved: N recirculation and T pktgen are both local 68 (gate G-PORTS)."""
        _, ports = declared()
        self.assertEqual(ports['HB_PKTGEN'][0], 68)
        self.assertRegex(strip_comments(NATIVE.read_text()), r'9w68|=\s*68\b')
        self.assertIn('G-PORTS', (READ / 'ports.p4').read_text())


if __name__ == '__main__':
    unittest.main()

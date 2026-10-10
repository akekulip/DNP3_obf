"""Single source of every private port/role for the READ timing program (ticket T2, device-port rule).

TWO-PIPE LAYOUT (2026-10-10): the switch has two physical pipes; N + E are pipe 0, T is pipe 1, M is retired.
The checks below keep their original intent (T's private hops on its own pipe's 68-71, no dead role, N's
handoff equals T_IN) against that layout; the retired N<->M agreement is still checked, directly between the
legacy native_binding.p4 and the ordinary M, since ports.p4 no longer carries M constants.

ports.p4 is the one definition; read_timing.p4 must include it and carry no numeric port. Rules (STEP2_DESIGN 3,
model_28 PORTS_PROPOSAL): device port = pipe*128 + local, local <= 71, every private ingress hop on local 68-71 of
its own pipe, none on local 64-67 of pipes 1-3 or local 64 of pipe 2, no device port serving two roles.
"""
import re
import unittest
from pathlib import Path

ARCH = Path(__file__).resolve().parents[3]
READ = ARCH / 'integration/read'
PROBE = ARCH / 'ownership/p4/held_timing_expected_probe.p4'
NATIVE = ARCH / 'integration/connection/binding/native_binding.p4'
ORDINARY_M = ARCH / 'integration/core/ordinary/m.p4'
RESPONSE_ONLY_N = ARCH / 'integration/core/response_only/n_response_only.p4'
QUEUE_T = READ / 'read_queue_timing.p4'
DECL = re.compile(r'const\s+PortId_t\s+(\w+)\s*=\s*9w(\d+)\s*;\s*//\s*(ingress|egress|peer)\b')
NATIVE_DECL = re.compile(r'const\s+PortId_t\s+(\w+)\s*=\s*9w(\d+)\s*;')


def strip_comments(text):
    return re.sub(r'//[^\n]*', '', re.sub(r'/\*.*?\*/', '', text, flags=re.S))


def declared():
    text = (READ / 'ports.p4').read_text()
    result = {}
    for name, value, role in DECL.findall(text):
        assert name not in result, 'duplicate constant ' + name
        result[name] = (int(value), role)
    return text, result


def native_declared(path=NATIVE):
    """N's own `const PortId_t` declarations (the binding carries no role-tagged comment)."""
    text = path.read_text()
    result = {}
    for name, value in NATIVE_DECL.findall(text):
        result.setdefault(name, int(value))
    return result


class Ports(unittest.TestCase):
    def test_every_port_constant_has_a_role_tag(self):
        text, ports = declared()
        self.assertEqual(len(re.findall(r'const\s+PortId_t', text)), len(ports),
                         'a PortId_t constant lacks the "// ingress|egress|peer" role tag')
        self.assertGreaterEqual(len(ports), 7)

    def test_device_port_rule(self):
        _, ports = declared()
        for name, (value, role) in ports.items():
            pipe, local = value >> 7, value & 0x7f
            self.assertLessEqual(local, 71, name)                 # local >= 72 aborts the model start
            self.assertLessEqual(pipe, 1, name + ': the switch has two pipes')
            if role == 'ingress':
                self.assertIn(local, (68, 69, 70, 71), name + ': private hop must be a recirculating local port')
                self.assertEqual(pipe, 1, name + ': T runs in pipe 1')
            if pipe >= 1:
                self.assertFalse(64 <= local <= 67, name + ': local 64-67 differs per pipe on the model')

    def test_no_device_port_serves_two_roles(self):
        _, ports = declared()
        seen = {}
        for name, (value, _) in ports.items():
            self.assertNotIn(value, seen, '%s and %s share device port %d' % (name, seen.get(value), value))
            seen[value] = name

    def test_n_to_t_handoff_crosses_pipes(self):
        _, ports = declared()
        self.assertEqual(ports['T_IN'][0], 197)
        self.assertNotEqual(ports['T_IN'][0] >> 7, ports['N_RETURN'][0] >> 7)   # N's pipe 0 never reaches T's pipe

    def test_retired_m_ports_are_gone(self):
        """No stale M route may land on T's input: 196/197 were M's N_TO_M / T_TO_M and are now T's."""
        text, ports = declared()
        self.assertNotIn('N_TO_M', ports)
        self.assertNotIn('T_TO_M', ports)
        self.assertNotIn('STEP3_M_PORT', native_declared(RESPONSE_ONLY_N))

    def test_read_timing_includes_ports_and_has_no_numeric_port(self):
        source = READ / 'read_timing.p4'
        raw = source.read_text()
        self.assertIn('#include "ports.p4"', raw)
        code = strip_comments(raw)
        self.assertEqual(re.findall(r'\b9w\d+', code), [])
        self.assertEqual(re.findall(r'const\s+PortId_t', code), [])
        self.assertEqual(re.findall(r'\b(?:6[4-9]|7[0-3]|19[67]|32[4-7])\b', code), [])
        self.assertEqual(re.findall(r'ingress_port\s*==\s*\d+', code), [])

    def test_queue_t_includes_ports_and_has_no_numeric_port(self):
        code = strip_comments(QUEUE_T.read_text())
        self.assertIn('#include "ports.p4"', QUEUE_T.read_text())
        self.assertEqual(re.findall(r'\b9w\d+', code), [])
        self.assertEqual(re.findall(r'const\s+PortId_t', code), [])

    def test_t_uses_every_role_it_owns(self):
        """The composed T (read_queue_timing.p4) uses every non-peer role; the legacy read_timing.p4 still uses
        every role it was written for (PKTGEN_RETURN is the queue T's mirror-clone return only)."""
        _, ports = declared()
        queue = strip_comments(QUEUE_T.read_text())
        legacy = strip_comments((READ / 'read_timing.p4').read_text())
        for name, (_, role) in ports.items():
            if role != 'peer':
                self.assertRegex(queue, r'\b%s\b' % name, name + ' declared but unused by read_queue_timing.p4')
                if name != 'PKTGEN_RETURN':
                    self.assertRegex(legacy, r'\b%s\b' % name, name + ' unused by read_timing.p4')

    def test_heartbeat_is_recognised_by_the_timer_header_not_a_port(self):
        code = strip_comments((READ / 'read_timing.p4').read_text())
        self.assertNotIn('HB_PKTGEN', code)
        self.assertRegex(code, r'default : heartbeat_timer;')
        self.assertRegex(code, r'select\(hdr\.timer\.pipe_id, hdr\.timer\.app_id\)')
        self.assertIn('PKTGEN_PIPE', (READ / 'ports.p4').read_text())

    def test_frozen_probe_uses_ports_72_and_73_flagged(self):
        """The 72/73 problem: the probe's FORWARD_PORT/heartbeat-return are not valid local ports."""
        code = strip_comments(PROBE.read_text())
        self.assertIn('FORWARD_PORT = 9w72', code)
        self.assertRegex(code, r'ucast_egress_port = 73')
        _, ports = declared()
        self.assertNotIn(72, [v for v, _ in ports.values()])
        self.assertNotIn(73, [v for v, _ in ports.values()])


class CrossFileAgreement(unittest.TestCase):
    """M3 (2026-10-07 review): port agreement between N (native_binding.p4), T (ports.p4,
    read_timing.p4 only #includes it so it cannot drift on its own) and the live ordinary M
    (integration/core/ordinary/m.p4; the frozen single-pass canary under integration/core/m/ is a
    separate, retired artifact per LEDGER.md) was asserted by hand, not cross-checked. These parse
    the actual generated/compiled sources, not a restated copy of the numbers."""

    def test_response_only_n_read_handoff_port_matches_t_in(self):
        """The N composed with this T (core/response_only) hands off exactly where T listens. The legacy
        native_binding.p4 keeps the retired three-pipe 325 (its profile is byte-pinned) and is not paired with
        this T."""
        _, ports = declared()
        self.assertEqual(native_declared(RESPONSE_ONLY_N)['READ_HANDOFF_PORT'], ports['T_IN'][0],
                          "N's READ_HANDOFF_PORT must equal the device port T listens on (T_IN)")

    def test_legacy_native_binding_step3_m_port_matches_ordinary_m(self):
        """Retired M-era agreement, kept: legacy N's STEP3_M_PORT is a port the ordinary M dispatches."""
        source = ORDINARY_M.read_text()
        cases = dict(re.findall(r'9w(\d+):(\w+);', re.search(r'select\(ig\.ingress_port\)\{([^}]*)\}', source)[1]))
        self.assertIn(str(native_declared()['STEP3_M_PORT']), cases)

    def test_ordinary_m_dispatches_the_n_to_m_port_to_a_real_parser_state(self):
        """Confirms the live ordinary M (m_activate_06; see LEDGER.md) listens where N actually sends,
        not on the retired canary's port 68."""
        source = ORDINARY_M.read_text()
        block = re.search(r'select\(ig\.ingress_port\)\{([^}]*)\}', source)[1]
        cases = dict(re.findall(r'9w(\d+):(\w+);', block))
        n_to_m = str(native_declared()['STEP3_M_PORT'])
        self.assertIn(n_to_m, cases, 'ordinary M must dispatch an ingress case for N_TO_M (%s)' % n_to_m)
        self.assertNotIn(cases[n_to_m], ('accept', 'reject'),
                          'N_TO_M must route to a real parser state, not fall through to the default')
        self.assertNotIn('68', cases, "the retired canary's port 68 must not reappear in the live M")


if __name__ == '__main__':
    unittest.main()

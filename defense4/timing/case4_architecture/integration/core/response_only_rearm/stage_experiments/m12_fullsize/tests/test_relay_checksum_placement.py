"""Separate synthesized checksum condition writes without changing packet code."""
import sys
import re
import unittest
import hashlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from m12gen import relay_sbo
from m12gen.build import build
import test_n_read_shapes as shared
from interp_ext import Control
from tna_dialect import normalize


class ChecksumConditionPlacement(unittest.TestCase):
    def test_hint_only_separates_generated_ip_and_tcp_checksum_conditions(self):
        original = 'before\ncontrol r_Egress(inout r_headers_t hdr, more) { runtime(); }\nafter\n'
        result = relay_sbo.separate_checksum_conditions(original)
        fields = ('hdr.tcp.checksum.$deparse_original_csum',
                  'hdr.tcp.checksum.$deparse_updated_csum_0',
                  'hdr.tcp.checksum.$deparse_updated_csum_1')
        annotation = ''.join('@pa_no_pack("egress","hdr.ip.checksum.%s","%s")\n' % (ip, field)
                             for ip in ('$deparse_original_csum', '$deparse_updated_csum_0') for field in fields)
        self.assertEqual(result.count(annotation), 1)
        self.assertEqual(result.replace(annotation, ''), original)
        self.assertIn(annotation + 'control r_Egress(', result)

    def test_hint_is_attached_to_active_egress_only_in_selected_relay_build(self):
        flags = dict(c3='cimg', shapes='passthrough', two_read_build=True, reduce=True,
                     ack_retry=True, read_handshake=True, headroom=True, relay=True)
        original, _ = build(**flags)
        selected, _ = build(**flags, relay_sbo=True, relay_ts=True)
        self.assertNotIn('@pa_no_pack(', original)
        lines = [line for line in selected.splitlines() if line.startswith('@pa_no_pack(')]
        self.assertEqual(len(lines), 6)
        self.assertIn('\n'.join(lines) + '\ncontrol r_Egress(', selected)
        self.assertTrue(all(line.count('$deparse_') == 2 for line in lines))

    def test_sequential_updates_preserve_c38_egress_bytes_and_all_eight_cases(self):
        flags = dict(c3='cimg', shapes='passthrough', two_read_build=True, reduce=True,
                     ack_retry=True, read_handshake=True, headroom=True, relay=True,
                     relay_sbo=True, relay_ts=True)
        selected, _ = build(**flags)
        # c40's equivalent else-if is rejected by SDK9.13.2 deparser lowering.
        # Parser scheduling can change independently; c38's exact deparser
        # lists and independent sequential predicates must remain unchanged.
        runtime = ''.join(line for line in selected.splitlines(keepends=True)
                          if not line.startswith('@pa_no_pack('))
        egress = shared.role(runtime, 'E')
        deparser = egress[egress.index('control EgDeparser('):]
        self.assertEqual(hashlib.sha256(deparser.encode()).hexdigest(),
                         'aaf2730c70c84bd2381bfdce49fb0bf40ef55c78f711898f943b5d56acde2431')
        code = re.sub(r'/\*.*?\*/|//[^\n]*', '', shared.role(selected, 'E'), flags=re.S)
        statements = Control(normalize(code), 'EgDeparser').apply_body

        def calls(nodes):
            result = {}
            for node in nodes:
                if node[0] == 'if':
                    result.update(calls(node[2])); result.update(calls(node[3]))
                elif node[0] == 'assign':
                    result[node[2][1]] = node[2]
            return result
        for name in ('tcp_plain.update', 'tcp_ctl.update'):
            self.assertNotIn(('name', 'hdr.tcp.checksum'), calls(statements)[name][2][0][1])

        def evaluate(nodes, pad, changed, encoded):
            state = {'hdr.ip.checksum': 0xabcd, 'hdr.tcp.checksum': 0x1234}
            def value(expr):
                if expr[0] == 'num':
                    return expr[1]
                if expr[0] == 'name':
                    return {'m.pad': pad, 'm.changed': changed}[expr[1]]
                if expr[0] == 'bin':
                    self.assertEqual(expr[1], '==')
                    return value(expr[2]) == value(expr[3])
                self.assertEqual(expr[0], 'call')
                return {'hdr.cd2.isValid': encoded, 'ip_new.update': 0x1111,
                        'tcp_plain.update': 0x2222, 'tcp_ctl.update': 0x3333}[expr[1]]
            def execute(statements):
                for node in statements:
                    if node[0] == 'if':
                        execute(node[2] if value(node[1]) else node[3])
                    elif node[0] == 'assign':
                        state[node[1][1]] = value(node[2])
            execute(nodes)
            return state
        for pad in (0, 1):
            for changed in (0, 1):
                for encoded in (0, 1):
                    self.assertEqual(evaluate(statements, pad, changed, encoded),
                        {'hdr.ip.checksum': 0x1111 if pad else 0xabcd,
                         'hdr.tcp.checksum': 0x3333 if encoded else 0x2222 if changed else 0x1234},
                        (pad, changed, encoded))
        predicates = [node for node in statements if node[0] == 'if']
        self.assertEqual(len(predicates), 3)
        self.assertTrue(all(not node[3] for node in predicates))
        self.assertEqual(predicates[-1][1], ('call', 'hdr.cd2.isValid', []))


if __name__ == '__main__':
    unittest.main()

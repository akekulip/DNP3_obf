"""c69 generator boundary: remove J while preserving common timing and the frozen legacy sources."""
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from m12gen.build import build
from m12gen.common import combined

EVIDENCE = HERE.parent / 'ctl_timing_01/evidence'
FLAGS = dict(c3='cimg', shapes='passthrough', two_read_build=True, reduce=True, ack_retry=True,
             read_handshake=True, headroom=True, relay=True, relay_sbo=True, relay_ts=True,
             response_ready_timing=True)
CLI = ['--policy', '--c3', 'cimg', '--shapes', 'passthrough', '--two-read', '--reduce', '--ack-retry',
       '--read-handshake', '--headroom', '--relay', '--relay-sbo', '--relay-ts', '--response-ready-timing']


def block(text, name):
    """An emitted action/table body, including nested blocks."""
    start = text.index(name)
    brace = text.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


class StripOperateHold(unittest.TestCase):
    def generate(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        out = Path(tmp.name)
        result = subprocess.run([sys.executable, str(HERE / 'make_m12.py'), str(out), *CLI,
                                 '--strip-telemetry', '--strip-operate-hold'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return (out / 'response_only.p4').read_text(), json.loads((out / 'supported_profile.json').read_text()), \
            json.loads((out / 'response_only.inputs.json').read_text())

    def test_cli_generates_no_j_profile_and_ports(self):
        text, profile, inputs = self.generate()
        self.assertEqual(profile['timing_contract'], 'response_ready_ack_d_no_j_v3')
        self.assertEqual(profile['timing_ns'], {'D_release_budget': 5000000})
        self.assertNotIn('hb_return', profile['ports'])
        self.assertNotIn('hb_return', inputs['port_map'])
        self.assertEqual(profile, inputs['supported_profile'])
        self.assertEqual(profile['candidate']['source_sha256'], hashlib.sha256(text.encode()).hexdigest())
        self.assertEqual(inputs['transforms_applied'][-1], 'strip_operate_hold')
        self.assertTrue(inputs['runnable'])
        self.assertNotIn('op_j', block(text, 'action set_params('))
        self.assertIn('default_action=set_params(19534,60000,1)', text)

    def test_legacy_sources_and_n_e_are_unchanged(self):
        new, _, _ = self.generate()
        for name, telemetry in (('c67', False), ('c68', True)):
            old = build(None, **FLAGS, strip_telemetry=telemetry)[0]
            self.assertEqual(old, (EVIDENCE / ('m12p_' + name + '_sdk9132') / 'response_only.p4').read_text())
            if telemetry:
                for segment in ('N', 'E'):
                    self.assertEqual(combined.segment(old, segment), combined.segment(new, segment))

    def test_operate_uses_common_request_and_response_retry_path(self):
        text, _, _ = self.generate()
        t = combined.segment(text, 'T')
        verdict = block(t, 'table tin_verdict')
        self.assertIn('(t_KIND_OPERATE, _, 0, _, _, _, _, _, _) : admit_request();', verdict)
        self.assertIn('(t_KIND_OPERATE_DUP, _, 0, _, 0, _, _, _, _) : passthrough_operate_dup();', verdict)
        self.assertIn('(t_KIND_OPERATE_DUP, _, 0, _, _, _, 0, _, _) : drop_request_duplicate();', verdict)
        self.assertIn('(t_KIND_OPERATE_DUP, _, 0, _, _, _, _, _, _) : passthrough_operate_dup();', verdict)
        self.assertIn('hdr.tev.kind=t_KIND_OPERATE;', block(t, 'action passthrough_operate_dup'))
        self.assertIn('16w0xE100 ++ md.cur_gen[15:0]', block(t, 'action admit_request'))
        self.assertIn('(t_T_IN, t_KIND_OPERATE, _, _, 0) : live_admit_gen();', block(t, 'table gen_access'))

    def test_common_ack_and_d_logic_is_byte_identical(self):
        new, _, _ = self.generate()
        old = build(None, **FLAGS, strip_telemetry=True)[0]
        for name in ('action admit_request', 'table gen_access', 'table child_seen0_access',
                     'table ack_go_check', 'table ack_completion_access', 'table commit_at_access',
                     'table commit_generation_access', 'table response_completion_access', 'table held_verdict',
                     'action seed_ack_blocker', 'action seed_resp_blocker', 'action hold_ack',
                     'action admit_response', 'control t_IngressDeparser'):
            self.assertEqual(block(new, name), block(old, name), name)

    def test_j_machinery_and_legacy_parser_admissions_are_removed(self):
        text, _, _ = self.generate()
        t = combined.segment(text, 'T')
        for name in ('op_j', 'op_gen_alloc_reg', 'op_t0_reg', 'op_done_reg', 'operate_generation_access',
                     'operate_anchor_access', 'op_go_check', 'operate_completion_access', 'hb_verdict',
                     't_ROLE_OP_', 'hold_operate', 'admit_operate_held', 'seed_op_blocker', 't_HB_RETURN',
                     'E101', 'op_tok_diff', 'op_lgen_diff', 'op_delta', 'drop_operate_dup'):
            self.assertNotIn(name, t, name)
        ladder = block(t, 'state single_ladder_role')
        self.assertNotIn('13 :', ladder)
        self.assertNotIn('16 :', ladder)
        self.assertNotIn('(t_PKTGEN_PIPE, 1)', block(t, 'state parse_timer'))
        self.assertIn('16w0xE100', block(t, 'state parse_clone'))
        self.assertIn('default : reject;', block(t, 'state parse_clone'))

    def test_clone_parser_selects_fit_tofino_match_registers(self):
        # SDK 9.13.2 has one 16-bit and two 8-bit parser match registers.
        # A single tag16 + kind8 + reserved16 select failed the first c69 compile.
        text, _, _ = self.generate()
        widths = {'hdr.clone.tag[31:16]': 16, 'hdr.tev.kind': 8, 'hdr.tev.reserved': 16}
        t = combined.segment(text, 'T')
        for state in re.findall(r'state (parse_clone\w*) \{', t):
            body = block(t, 'state ' + state + ' {')
            for select in re.findall(r'transition select\(([^)]+)\)', body):
                fields = [field.strip() for field in select.split(',')]
                self.assertLessEqual(sum(widths[field] for field in fields), 32, state)

    def test_cli_rejects_missing_telemetry_dependency(self):
        with tempfile.TemporaryDirectory() as out:
            result = subprocess.run([sys.executable, str(HERE / 'make_m12.py'), out, *CLI,
                                     '--strip-operate-hold'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('--strip-operate-hold requires --strip-telemetry', result.stderr)
            self.assertFalse((Path(out) / 'response_only.p4').exists())

    def test_api_rejects_missing_telemetry_dependency(self):
        with self.assertRaisesRegex(ValueError, 'OPERATE hold removal requires telemetry removal'):
            build(None, **FLAGS, strip_operate_hold=True)

    def test_transform_rejects_missing_anchor(self):
        from m12gen.strip_operate_hold import transform
        old = build(None, **FLAGS, strip_telemetry=True)[0]
        with self.assertRaises(SystemExit):
            transform(old.replace('default_action=set_params(19534,9377,60000,1)',
                                  'default_action=set_params(19534,9378,60000,1)'))


if __name__ == '__main__':
    unittest.main()

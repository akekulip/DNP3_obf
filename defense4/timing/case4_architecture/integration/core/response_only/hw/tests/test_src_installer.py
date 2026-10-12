"""Pure-source installer tests: no compiled evidence tree, no SDE. Runs on a fresh clone.

Uses fixture.py (a synthetic build whose p4pp holds the pinned production port map). Covers identity, the port
checks, refusals, write order, the token buffer, the ladder/app ids and the teardown order. The schema name
check is NOT here: see test_build_validation.py.
"""
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fixture as fx  # noqa: E402
import bringup_composite as bc  # noqa: E402
import bringup_teardown as bt  # noqa: E402
import build_ports  # noqa: E402
import t_config as tc  # noqa: E402

N_PORTS, N_CONN, E_CONN = 'p0.n_Ingress.ports', 'p0.n_Ingress.connection', 'p0.r_Egress.conn'


class Refusals(unittest.TestCase):
    def test_a_wrong_artifact_hash_is_refused(self):
        for rel in bc.REQUIRED_EXPECT:
            with self.subTest(rel):
                self.assertTrue(bc.identity(fx.args(sha=dict(fx.SHA, **{rel: '0' * 64}))))
        self.assertEqual(bc.identity(fx.args()), [])

    def test_a_missing_expected_hash_is_refused(self):
        a = fx.args()
        a.expect = a.expect[:2]
        self.assertTrue(any('required' in e for e in bc.identity(a)))

    def test_a_build_compiled_for_other_ports_is_refused(self):
        self.assertEqual(build_ports.check_endpoints(fx.PORTS, fx.PORTS['forward'], fx.PORTS['relay']), [])
        other = 9 if fx.PORTS['relay'] != 9 else 64
        self.assertTrue(any('t_RELAY_PORT' in e for e in build_ports.check_endpoints(fx.PORTS, fx.PORTS['forward'], other)))
        self.assertTrue(any('t_FORWARD_PORT' in e for e in build_ports.check_endpoints(fx.PORTS, 10, fx.PORTS['relay'])))

    def test_a_looping_port_that_is_a_port_in_use_is_refused(self):
        for role in ('n_ack_return', 't_in', 'hb_return', 'held_return'):
            for port in (9, 10, 11, 64):
                with self.subTest(role=role, port=port):
                    errs = build_ports.check_endpoints(dict(fx.PORTS, **{role: port}), fx.PORTS['forward'], fx.PORTS['relay'])
                    self.assertTrue(any('must never be put in loopback' in e for e in errs), errs)

    def test_a_build_looping_through_a_dead_recirc_entry_is_refused(self):
        for port in (70, 197, 198, 199):
            with self.subTest(port=port):
                role = 'n_ack_return' if port < 128 else 'hb_return'
                errs = build_ports.check_endpoints(dict(fx.PORTS, **{role: port}), fx.PORTS['forward'], fx.PORTS['relay'])
                self.assertTrue(any('do not recirculate' in e for e in errs), errs)

    def test_an_inconsistent_or_unreadable_build_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(build_ports.read(tmp)[1])                                  # no p4pp at all
            text = (fx.OUT / 'response_only.p4pp').read_text(errors='replace')
            for bad in (re.sub(r'(const PortId_t t_T_IN\s*=\s*9w)\d+', r'\g<1>181', text),          # N and T disagree
                        re.sub(r'const PortId_t t_HELD_RETURN[^\n]*\n', '', text),                 # constant missing
                        re.sub(r'(const PortId_t t_PKTGEN_RETURN\s*=\s*9w)\d+', r'\g<1>180', text)):  # generator off 68
                (Path(tmp) / 'response_only.p4pp').write_text(bad)
                self.assertTrue(build_ports.read(tmp)[1])

    def test_rows_use_the_ports_of_the_build_not_cp_constants(self):
        ops = fx.plan(fx.args())
        ack, ret = fx.PORTS['n_ack_return'], fx.PORTS['return_port']
        ingress = {k[1] for op in ops if op['table'] == N_PORTS for k in op['key'] if k[0] == 'ig.ingress_port'}
        self.assertTrue({ack, ret} <= ingress)
        rev = [op for op in ops if op.get('action') == 'r_Egress.rev_conn']
        self.assertEqual([dict((k[0], k[1]) for k in op['key'])['eg.egress_port'] for op in rev], [ack])
        default = bc.rows.cp.N_ACK_RETURN
        if default != ack:                                        # the model's lap port appears nowhere
            self.assertFalse(bc.rows._uses([(op['table'], [(k[0], k[1]) for k in op.get('key', [])], op.get('action'),
                                             op['data'], None) for op in ops if op['kind'] == 'p4'], default))

    def test_a_shared_port_without_addresses_is_refused(self):
        with self.assertRaises(SystemExit):
            bc.parse(['--build-out', 'x', '--master-port', '54321', '--master-dev', '9', '--relay-dev', '9'])
        self.assertEqual(bc.parse(['--build-out', 'x', '--master-port', '54321']).relay_ip, '192.168.10.7')

    def test_T_params_out_of_range_are_refused(self):
        good = dict(tc.T_PARAM_DEFAULTS)
        self.assertEqual(tc.check_params(good), [])
        for k, v in (('da', 0), ('readiness', 10 ** 9), ('gap', -1), ('op_j', 2 ** 31), ('budget', 0),
                     ('budget', 2 ** 31), ('enabled', 2), ('da', 12000000), ('readiness', 16000001)):
            with self.subTest(k=k, v=v):
                self.assertTrue(tc.check_params(dict(good, **{k: v})))
        self.assertEqual(tc.check_params(dict(good, enabled=0)), [])     # the Timing OFF arm

    def test_apply_without_authorization_writes_nothing(self):
        os.environ.pop('DEFENSE4_HW_AUTHORIZED', None)
        argv = ['--build-out', str(fx.OUT), '--fixed-schema-dir', fx.FIXED, '--apply'] + fx.ENDPOINTS
        for rel in bc.REQUIRED_EXPECT:
            argv += ['--expect', '%s=%s' % (rel, fx.SHA[rel])]
        with fx.no_name_check():
            self.assertEqual(bc.main(argv), 3)


class Order(unittest.TestCase):
    def test_T_state_first_E_next_N_connection_rows_last(self):
        ops = [op for op in fx.plan(fx.args()) if op['kind'] != 'loopback']
        kinds = [('n_conn' if op['table'] == N_CONN else 'n' if op['table'].startswith('p0.n_') else
                  'e' if op['table'].startswith('p0.r_') else 't') for op in ops]
        self.assertEqual(kinds, sorted(kinds, key=['t', 'e', 'n', 'n_conn'].index))
        self.assertEqual(kinds[-4:], ['n_conn'] * 4)

    def test_enable_is_written_without_an_action_and_the_full_app_is_reverified(self):
        import readback
        for op in tc.enable_ops(fx.PORTS):
            self.assertIsNone(op['action'])
            self.assertEqual(op['data'], [('app_enable', True)])
        app = tc.pktgen_ops(2, fx.PORTS)[2]
        full = dict(readback.enabled_app_op(app)['data'])
        self.assertTrue(full['app_enable'])
        self.assertEqual((full['pattern_value'], full['pattern_mask'], full['pipe_local_source_port'],
                          full['packets_per_batch_cfg']), (0xE1010000, 0xFFFF0000, 68, 3))

    def test_the_token_buffer_is_not_dropped_by_a_mac_loopback(self):
        # Every seeded blocker is [8 B ladder][buffer], so buffer[4:6] is wire offset 12:13. A MAC reads a
        # 0x0000 there as an 802.3 length and drops the frame (combined_silicon_01); it must be a real ethertype.
        buf = tc.token_buffer()
        self.assertEqual(len(buf), tc.TOKEN_LEN)
        self.assertEqual(buf[4:6], b'\x08\x00')
        self.assertEqual(bytes(tc.TOKEN_LEN)[4:6], b'\x00\x00')      # the old all-zero buffer was the bug
        self.assertEqual(dict(tc.pktgen_ops(2, fx.PORTS)[1]['data'])['buffer'], buf)

    def test_ladder_and_apps_match_T(self):
        held, hb = fx.PORTS['held_return'], fx.PORTS['hb_return']
        self.assertEqual({(p, q) for p, q, _ in tc.queue_plan(fx.PORTS)}, {(held, 7), (held, 6), (held, 5), (held, 4), (hb, 3), (hb, 2)})
        self.assertEqual({op['pipe'] for op in tc.queue_ops(fx.PORTS)}, {held // 128, hb // 128})   # the port's own pipe
        self.assertEqual({(n, i, hex(p)) for n, i, p in tc.PKTGEN_APPS}, {('OPERATE', 1, '0xe1010000'), ('READ', 0, '0xe1000000')})
        # app ids are the ids read_queue_timing.p4 parse_timer admits: 1 OPERATE, 0 READ (defect B was READ on app 2)
        self.assertEqual({i for _n, i, _p in tc.PKTGEN_APPS}, {0, 1})


class Teardown(unittest.TestCase):
    def manifest(self, tmp):
        undo = {'p4': 'delete', 'mirror': 'delete', 'default': 'default_reset'}
        ops = fx.plan(fx.args()) + tc.enable_ops(fx.PORTS)
        done = [dict(op, undo=undo.get(op['kind'], 'restore'), before={n: v for n, v in op['data']}) for op in ops]
        path = Path(tmp) / 'm.json'
        path.write_text(json.dumps(dict(program='response_only', installed=done), default=bc.encode))
        return bt.load(path)

    def test_generator_off_then_T_off_then_N_connection_rows_first(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            order = bt.steps(self.manifest(tmp)['installed'])
        self.assertEqual([op['undo'] for op in order[:3]], ['disable', 'disable', 't_off'])
        self.assertEqual([op['table'] for op in order[3:7]], [N_CONN] * 4)
        loops = len(build_ports.loopback_ports(fx.PORTS))
        self.assertEqual([op['kind'] for op in order[len(order) - loops:]], ['loopback'] * loops)   # loopback comes off last
        self.assertEqual([op['kind'] for op in fx.plan(fx.args())[:loops]], ['loopback'] * loops)        # and goes on first

    def test_the_packet_buffer_bytes_survive_the_manifest(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            ops = self.manifest(tmp)['installed']
        buf = next(op for op in ops if op['kind'] == 'pktgen_buffer')
        self.assertEqual(dict(buf['data'])['buffer'], tc.token_buffer())
        self.assertEqual(dict(buf['data'])['buffer'][4:6], b'\x08\x00')          # not 0x0000 at wire offset 12:13
        self.assertNotEqual(tc.token_buffer(), bytes(tc.TOKEN_LEN))               # an all-zero buffer (the bug) differs


if __name__ == '__main__':
    unittest.main()


class MirrorGuard(unittest.TestCase):
    """The token_stale_01 compiler-mirror defect must never be loadable: bringup refuses it before any write."""

    def setUp(self):
        self.bfa = fx.OUT / 'p1' / 'response_only.bfa'
        self.addCleanup(self.bfa.write_text, fx.BFA_PASS)

    def argv(self):
        argv = ['--build-out', str(fx.OUT), '--fixed-schema-dir', fx.FIXED] + fx.ENDPOINTS
        for rel in bc.REQUIRED_EXPECT:
            argv += ['--expect', '%s=%s' % (rel, fx.SHA[rel])]
        return argv

    def run_main(self):
        import contextlib
        import io
        buf = io.StringIO()
        with fx.no_name_check(), contextlib.redirect_stdout(buf):
            rc = bc.main(self.argv())
        return rc, buf.getvalue()

    def test_a_fixed_build_passes(self):
        rc, out = self.run_main()
        self.assertEqual(rc, 0, out[-400:])
        self.assertIn('MIRROR GUARD', out)
        self.assertIn(': PASS', out)

    def test_a_defective_build_is_refused_with_the_failing_note(self):
        self.bfa.write_text(fx.BFA_FAIL)
        rc, out = self.run_main()
        self.assertEqual(rc, 1)
        self.assertIn('REFUSED', out)
        self.assertIn('mirror guard: FAIL: non-clone mirror entries [0]', out)

    def test_a_defective_build_is_refused_on_apply_before_any_grpc_call(self):
        self.bfa.write_text(fx.BFA_FAIL)
        os.environ['DEFENSE4_HW_AUTHORIZED'] = '1'
        self.addCleanup(os.environ.pop, 'DEFENSE4_HW_AUTHORIZED', None)
        import contextlib
        import io
        buf = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, fx.no_name_check(), contextlib.redirect_stdout(buf):
            rc = bc.main(self.argv() + ['--apply', '--manifest-out', str(Path(tmp) / 'm.json')])
            self.assertFalse((Path(tmp) / 'm.json').exists())
        self.assertEqual(rc, 1)
        self.assertIn('mirror guard: FAIL', buf.getvalue())       # refused by the guard, not by a later check
        self.assertNotIn('RUNNING DAEMON', buf.getvalue())         # before the daemon check and any gRPC

    def test_a_build_without_the_p1_assembly_is_refused(self):
        self.bfa.unlink()
        rc, out = self.run_main()
        self.assertEqual(rc, 1)
        self.assertIn('expected one p1/*.bfa', out)


class GuardedFileIsBound(unittest.TestCase):
    """The p1 .bfa the mirror guard reads must be hash-bound to the loaded binaries (required --expect)."""

    def argv(self, bfa_sha='keep', apply=False, tmp=None):
        argv = ['--build-out', str(fx.OUT), '--fixed-schema-dir', fx.FIXED] + fx.ENDPOINTS
        for rel in bc.REQUIRED_EXPECT:
            if rel == 'p1/response_only.bfa':
                if bfa_sha is None:
                    continue
                argv += ['--expect', '%s=%s' % (rel, fx.SHA[rel] if bfa_sha == 'keep' else bfa_sha)]
            else:
                argv += ['--expect', '%s=%s' % (rel, fx.SHA[rel])]
        if apply:
            argv += ['--apply', '--manifest-out', str(Path(tmp) / 'm.json')]
        return argv

    def run_main(self, argv):
        import contextlib
        import io
        buf = io.StringIO()
        with fx.no_name_check(), contextlib.redirect_stdout(buf):
            rc = bc.main(argv)
        return rc, buf.getvalue()

    def test_the_bfa_hash_is_required(self):
        self.assertIn('p1/response_only.bfa', bc.REQUIRED_EXPECT)

    def test_a_missing_bfa_hash_is_refused_in_dry_run_and_apply(self):
        rc, out = self.run_main(self.argv(bfa_sha=None))
        self.assertEqual(rc, 1)
        self.assertIn('--expect p1/response_only.bfa=<sha256> is required', out)
        os.environ['DEFENSE4_HW_AUTHORIZED'] = '1'
        self.addCleanup(os.environ.pop, 'DEFENSE4_HW_AUTHORIZED', None)
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = self.run_main(self.argv(bfa_sha=None, apply=True, tmp=tmp))
            self.assertFalse((Path(tmp) / 'm.json').exists())
        self.assertEqual(rc, 1)
        self.assertIn('--expect p1/response_only.bfa=<sha256> is required', out)

    def test_a_wrong_bfa_hash_is_refused(self):
        rc, out = self.run_main(self.argv(bfa_sha='0' * 64))
        self.assertEqual(rc, 1)
        self.assertIn('p1/response_only.bfa: sha256 %s, expected %s' % (fx.SHA['p1/response_only.bfa'], '0' * 64), out)

    def test_a_bfa_swapped_from_another_build_is_refused(self):
        bfa = fx.OUT / 'p1' / 'response_only.bfa'
        self.addCleanup(bfa.write_text, fx.BFA_PASS)
        bfa.write_text(fx.BFA_PASS + '# another build\n')               # still passes the guard on its own
        rc, out = self.run_main(self.argv())
        self.assertEqual(rc, 1)
        self.assertIn('p1/response_only.bfa: sha256', out)

    def test_the_correct_bfa_hash_passes(self):
        rc, out = self.run_main(self.argv())
        self.assertEqual(rc, 0, out[-300:])


class OutDirName(unittest.TestCase):
    """The compiled output directory is used as given, whatever it is called: the campaign deploys builds as
    <aux>/out_<buildname>. Judged correctly for a passing and a failing assembly under several names."""

    def run_named(self, name, bfa_text):
        import contextlib
        import io
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / name
            shutil.copytree(str(fx.OUT), str(out))
            (out / 'p1' / 'response_only.bfa').write_text(bfa_text)
            sha = dict(fx.SHA, **{'p1/response_only.bfa':
                                  __import__('hashlib').sha256(bfa_text.encode()).hexdigest()})
            argv = ['--build-out', str(out), '--fixed-schema-dir', fx.FIXED] + fx.ENDPOINTS
            for rel in bc.REQUIRED_EXPECT:
                argv += ['--expect', '%s=%s' % (rel, sha[rel])]
            buf = io.StringIO()
            with fx.no_name_check(), contextlib.redirect_stdout(buf):
                rc = bc.main(argv)
        return rc, buf.getvalue()

    def test_any_name_with_a_fixed_build_passes(self):
        for name in ('out_mirror_fix_01', 'out', 'build-under-test'):
            with self.subTest(name=name):
                rc, out = self.run_named(name, fx.BFA_PASS)
                self.assertEqual(rc, 0, out[-300:])
                self.assertIn(': PASS', out)

    def test_any_name_with_a_defective_build_is_refused_by_the_guard(self):
        for name in ('out_mirror_fix_01', 'out', 'build-under-test'):
            with self.subTest(name=name):
                rc, out = self.run_named(name, fx.BFA_FAIL)
                self.assertEqual(rc, 1)
                self.assertIn('mirror guard: FAIL: non-clone mirror entries [0]', out)
                self.assertNotIn('expected one', out)            # judged on content, not refused for its name

    def test_the_guard_module_reads_the_out_dir_given(self):
        sys.path.insert(0, str(Path(bc.__file__).resolve().parent.parent))
        import check_mirror_select as cms
        self.assertTrue(cms.check_out(fx.OUT)[0])
        self.assertTrue(cms.check(fx.BUILD)[0] is False)        # check(build) still means <build>/out: absent here

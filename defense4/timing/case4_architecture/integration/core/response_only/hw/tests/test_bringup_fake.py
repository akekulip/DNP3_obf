"""apply(), switch.py and the teardown driven against tests/fake/bfrt_grpc (an in-memory client). This tests
our logic and the client-side quirks the fake copies; it is NOT evidence about the switch.

  python3 -m unittest discover -s integration/core/response_only/hw/tests -v
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path[:0] = [str(TESTS / 'fake'), str(TESTS)]
import bfrt_grpc.client as fake  # noqa: E402  (must be imported before switch.py looks for the SDE's)
import test_bringup_offline as off  # noqa: E402  (build discovery; raises SkipTest when no build matches cp.py)
import bringup_composite as bc  # noqa: E402
import bringup_teardown as bt  # noqa: E402
import switch  # noqa: E402
import t_config as tc  # noqa: E402

assert switch.gc is fake, 'switch.py imported a real bfrt_grpc'
N_CONN, APP, BUF = 'p0.n_Ingress.connection', 'tf1.pktgen.app_cfg', 'tf1.pktgen.pkt_buffer'


def run(main, argv):
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            rc = main(argv)
    except SystemExit as e:
        rc = e.code
    return rc, out.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        fake.reset()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.manifest = Path(self.tmp.name) / 'manifest.json'
        self.conf = Path(self.tmp.name) / 'daemon.conf'
        out = (off.BUILD / 'out').resolve()
        self.conf.write_text(json.dumps({'p4_devices': [{'p4_programs': [{
            'program-name': 'response_only', 'bfrt-config': str(out / 'bfrt.json'),
            'p4_pipelines': [dict(p4_pipeline_name=n, context=str(out / n / 'context.json'),
                                  config=str(out / n / 'tofino.bin')) for n in ('p0', 'p1')]}]}]}))
        self._conf, bc.running_conf = bc.running_conf, lambda: str(self.conf)
        self.addCleanup(setattr, bc, 'running_conf', self._conf)
        os.environ['DEFENSE4_HW_AUTHORIZED'] = '1'
        self.addCleanup(os.environ.pop, 'DEFENSE4_HW_AUTHORIZED', None)

    def argv(self, *extra):
        base = (['--build-out', str(off.BUILD / 'out'), '--fixed-schema-dir', off.FIXED, '--manifest-out',
                 str(self.manifest), '--apply'] + off.ENDPOINTS)
        for rel in bc.REQUIRED_EXPECT:
            base += ['--expect', '%s=%s' % (rel, off.SHA[rel])]
        return base + list(extra)

    def installed(self):
        return json.loads(self.manifest.read_text())['installed']

    def teardown(self):
        return run(bt.main, ['--manifest', str(self.manifest), '--apply', '--quiet', '0.2', '--settle-timeout', '1.5'])

    def apps(self):
        return {dict(k)['app_id'] if isinstance(k, dict) else k[0][1]: v for k, v in fake.STATE[APP].e.items()}

    def buffer(self):
        return bytes(next(iter(fake.STATE[BUF].e.values()))['buffer'])


class Apply(Base):
    def test_full_apply_with_enable_installs_everything_and_reads_it_back(self):
        rc, out = run(bc.main, self.argv('--enable-pktgen'))
        self.assertEqual(rc, 0, out[-600:])
        self.assertIn('INSTALLED 31 writes', out)
        self.assertEqual(len(self.installed()), 31)
        self.assertEqual(self.buffer(), bytes(tc.TOKEN_LEN))                    # the 60 B buffer read back as bytes
        apps = self.apps()
        self.assertEqual({i: (a['app_enable'], a['pattern_value'], a['pattern_mask'], a['pipe_local_source_port'],
                              a['action_name']) for i, a in apps.items()},
                         {1: (True, 0xE1010000, 0xFFFF0000, 68, 'trigger_recirc_pattern'),
                          2: (True, 0xE1000000, 0xFFFF0000, 68, 'trigger_recirc_pattern')})
        enables = [c for c in fake.LOG if c[0] == 'mod' and c[1] == APP and c[3][0] == {'app_enable': True}]
        self.assertEqual([c[3][1] for c in enables], [None, None])               # enabled without an action
        writes = [c[1] for c in fake.LOG if c[0] in ('add', 'mod', 'default_set')]
        self.assertEqual(writes[-6:-2], [N_CONN] * 4)                           # N connection rows, then the enables
        self.assertEqual(len(fake.STATE[N_CONN].e), 4)

    def test_without_the_flag_the_apps_stay_disabled(self):
        rc, out = run(bc.main, self.argv())
        self.assertEqual(rc, 0, out[-600:])
        self.assertEqual({a['app_enable'] for a in self.apps().values()}, {False})
        self.assertEqual(len(self.installed()), 29)

    def test_a_failed_add_midway_stops_with_the_detail_and_a_manifest_of_what_was_written(self):
        fake.FAIL_ADD = ('p0.n_Ingress.ports', 2)
        rc, out = run(bc.main, self.argv('--enable-pktgen'))
        self.assertEqual(rc, 2)
        self.assertIn('FAIL-CLOSED: write failed', out)
        self.assertIn("INTERNAL, 'boom in the driver'", out)                     # line 2 of the gRPC error is kept
        done = self.installed()
        self.assertEqual(done[-1]['table'], 'p0.n_Ingress.ports')
        self.assertEqual(sum(1 for op in done if op['table'] == 'p0.n_Ingress.ports'), 1)
        self.assertEqual(len(fake.STATE.get(N_CONN, fake.Table('x')).e), 0)        # stopped before any connection row
        self.assertEqual({a['app_enable'] for a in self.apps().values()}, {False})
        rc, out = self.teardown()                                                # and the partial install comes off
        self.assertEqual(rc, 0, out[-600:])
        self.assertEqual(len(fake.STATE['p0.n_Ingress.ports'].e), 0)

    def test_a_second_apply_is_refused_and_leaves_the_manifest_alone(self):
        self.assertEqual(run(bc.main, self.argv())[0], 0)
        before, calls = self.manifest.read_text(), len(fake.LOG)
        rc, out = run(bc.main, self.argv())
        self.assertEqual(rc, 4)
        self.assertIn('already exists', out)
        self.assertEqual(self.manifest.read_text(), before)
        self.assertEqual(len(fake.LOG), calls)                                   # not one gRPC call

    def test_a_precheck_failure_writes_nothing_and_creates_no_manifest(self):
        t = fake.Info().table_get(N_CONN)
        t.e[(('x', 1, None),)] = {'action_name': 'old'}
        rc, out = run(bc.main, self.argv())
        self.assertEqual(rc, 2)
        self.assertIn('is not empty before bring-up', out)
        self.assertFalse(self.manifest.exists())
        self.assertFalse([c for c in fake.LOG if c[0] in ('add', 'mod', 'default_set')])

    def test_a_daemon_running_another_build_is_refused_before_any_grpc_call(self):
        self.conf.write_text(self.conf.read_text().replace('/p1/tofino.bin', '/p1/other.bin'))
        rc, out = run(bc.main, self.argv())
        self.assertEqual(rc, 1)
        self.assertIn('p1 config', out)
        self.assertEqual(fake.LOG, [])
        self.assertFalse(self.manifest.exists())

    def test_a_register_off_its_reset_value_is_refused(self):
        fake.T_INIT['quarantine_reg'] = 0
        self.addCleanup(fake.T_INIT.__setitem__, 'quarantine_reg', 0xffffffff)
        rc, out = run(bc.main, self.argv())
        self.assertEqual(rc, 2)
        self.assertIn('quarantine_reg', out)
        self.assertFalse(self.manifest.exists())


class SwitchReads(Base):
    def test_absent_is_None_only_with_the_not_found_text(self):
        sw = switch.Switch('response_only', 1)
        self.assertIsNone(sw.get('$mirror.cfg', 0xffff, [('$sid', 7, None)]))
        fake.EMPTY_READ = '$mirror.cfg'
        with self.assertRaisesRegex(RuntimeError, 'empty read'):
            sw.get('$mirror.cfg', 0xffff, [('$sid', 7, None)])

    def test_the_packet_buffer_reads_back_as_bytes(self):
        fake.PRIOR_BUFFER = b'\xaa' * 60
        sw = switch.Switch('response_only', 1)
        got = sw.get(BUF, 1, [('pkt_buffer_offset', 0, None), ('pkt_buffer_size', 60, None)])
        self.assertEqual(got['buffer'], b'\xaa' * 60)

    def test_a_write_whose_preread_has_no_value_is_refused(self):
        sw = switch.Switch('response_only', 1)
        sw.as_dict = lambda d: d.to_dict()                                       # the raw client: buffer reads None
        with self.assertRaisesRegex(RuntimeError, 'pre-read has no value'):
            sw.write(tc.pktgen_ops(2)[1])
        self.assertFalse([c for c in fake.LOG if c[0] == 'mod'])


class Teardown(Base):
    def test_everything_goes_back_including_a_nonzero_buffer(self):
        fake.PRIOR_BUFFER = b'\xaa' * 60
        self.assertEqual(run(bc.main, self.argv('--enable-pktgen'))[0], 0)
        self.assertEqual(self.buffer(), bytes(60))
        rc, out = self.teardown()
        self.assertEqual(rc, 0, out[-800:])
        self.assertEqual(self.buffer(), b'\xaa' * 60)                             # restored from the real pre-read
        self.assertEqual({n: len(t.e) for n, t in fake.STATE.items() if n.startswith('p0.') or n == '$mirror.cfg'},
                         {n: 0 for n in fake.STATE if n.startswith('p0.') or n == '$mirror.cfg'})
        self.assertEqual(fake.STATE['p1.t_Ingress.params'].default, fake.PARAMS)
        self.assertEqual({(a['app_enable'], a['pattern_value']) for a in self.apps().values()}, {(False, 0)})
        sched = fake.STATE['tf1.tm.queue.sched_cfg'].e.values()
        self.assertEqual({(q['max_priority'], q['max_rate_enable']) for q in sched}, {('0', True)})
        calls = [c for c in fake.LOG if c[0] in ('mod', 'default_set', 'del', 'default_reset')]
        first_del = next(i for i, c in enumerate(calls) if c[0] == 'del')
        off_write = next(i for i, c in enumerate(calls) if c[0] == 'default_set' and c[2][0]['enabled'] == 0)
        self.assertLess(off_write, first_del)                                    # T switched off before any row goes
        self.assertEqual(calls[first_del][1], N_CONN)

    def test_no_row_is_deleted_while_T_has_not_settled(self):
        self.assertEqual(run(bc.main, self.argv())[0], 0)
        fake.OUTCOMES_MOVE = True
        rc, out = self.teardown()
        self.assertEqual(rc, 2)
        self.assertIn('STOPPED before deleting any row', out)
        self.assertEqual(len(fake.STATE[N_CONN].e), 4)

    def test_an_app_that_held_another_trigger_type_is_reported_not_claimed(self):
        fake.PRIOR_APP_ACTION = 'trigger_timer_one_shot'
        self.assertEqual(run(bc.main, self.argv('--enable-pktgen'))[0], 0)
        rc, out = self.teardown()
        self.assertEqual(rc, 1)
        self.assertIn('NOT restored: was trigger_timer_one_shot', out)
        self.assertEqual({a['app_enable'] for a in self.apps().values()}, {False})
        self.assertEqual(len(fake.STATE[N_CONN].e), 0)                            # the rest was still undone

    def test_a_restore_with_no_recorded_value_is_refused(self):
        self.assertEqual(run(bc.main, self.argv())[0], 0)
        m = json.loads(self.manifest.read_text())
        for op in m['installed']:
            if op['kind'] == 'pktgen_buffer':
                op['before'] = {'buffer': None}
        self.manifest.write_text(json.dumps(m))
        rc, out = self.teardown()
        self.assertEqual(rc, 1)
        self.assertIn('no pre-write value', out)
        self.assertEqual(self.buffer(), bytes(60))                               # untouched, and said so


if __name__ == '__main__':
    unittest.main()

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
import build_ports  # noqa: E402
import set_enabled  # noqa: E402
import switch  # noqa: E402
import t_config as tc  # noqa: E402

assert switch.gc is fake, 'switch.py imported a real bfrt_grpc'
N_CONN, APP, BUF = 'p0.n_Ingress.connection', 'tf1.pktgen.app_cfg', 'tf1.pktgen.pkt_buffer'
LOOPS = sorted(build_ports.loopback_ports(off.PORTS).values())     # front-panel ports the build loops
N_WRITES = 29 + len(LOOPS)


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

    def writes(self, table):
        """{(pg_id, pg_queue): data dict} for each entry_mod WRITTEN to a TM queue table (reads excluded: the
        fake, like the driver, materializes an entry on read, so STATE alone cannot tell a write from a read)."""
        out = {}
        for c in fake.LOG:
            if c[0] == 'mod' and c[1] == table:
                out[tuple(v for _, v, _ in c[2])] = dict(c[3][0])
        return out

    def hold_pgq(self, role_qid):
        """(pg_id, pg_queue) the installer resolves for a hold queue on the build's ladder port."""
        role = {6: 'held_return', 4: 'held_return', 2: 'hb_return'}[role_qid]
        port = off.PORTS[role]
        return port % 128 // 4, (port % 4) * 8 + role_qid          # mirrors the fake's tf1.tm.port.cfg map


class Shaping(Base):
    def test_unset_rates_leave_the_hold_queues_unshaped(self):
        rc, out = run(bc.main, self.argv())
        self.assertEqual(rc, 0, out[-500:])
        self.assertEqual(self.writes('tf1.tm.queue.sched_shaping'), {})          # no shaping row written at all
        for data in self.writes('tf1.tm.queue.sched_cfg').values():
            self.assertFalse(data['max_rate_enable'])                            # every sched_cfg write unshaped

    def test_a_configured_ack_rate_writes_enable_and_the_shaping_row_only_for_qid6(self):
        rc, out = run(bc.main, self.argv('--shape-ack-pps', '1000'))
        self.assertEqual(rc, 0, out[-500:])
        shp = self.writes('tf1.tm.queue.sched_shaping')
        self.assertEqual(set(shp), {self.hold_pgq(6)})                           # ONLY the ACK hold queue is shaped
        row = shp[self.hold_pgq(6)]
        self.assertEqual((row['unit'], row['max_rate'], row['max_burst_size']), ('PPS', 1000, 1))
        cfg = self.writes('tf1.tm.queue.sched_cfg')
        self.assertTrue(cfg[self.hold_pgq(6)]['max_rate_enable'])                # ACK hold enabled
        self.assertFalse(cfg[self.hold_pgq(4)]['max_rate_enable'])               # RESP hold untouched
        blk7 = (off.PORTS['held_return'] % 128 // 4, (off.PORTS['held_return'] % 4) * 8 + 7)
        self.assertNotIn(blk7, shp)                                              # blocker queue 7 is never shaped
        self.assertFalse(cfg[blk7]['max_rate_enable'])

    def test_all_three_roles_shape_their_own_hold_queue(self):
        rc, out = run(bc.main, self.argv('--shape-ack-pps', '1000', '--shape-resp-pps', '500', '--shape-op-pps', '200'))
        self.assertEqual(rc, 0, out[-500:])
        shp = self.writes('tf1.tm.queue.sched_shaping')
        self.assertEqual({k: shp[k]['max_rate'] for k in shp},
                         {self.hold_pgq(6): 1000, self.hold_pgq(4): 500, self.hold_pgq(2): 200})
        self.assertEqual(len(shp), 3)                                            # exactly the three hold queues

    def test_the_run_records_requested_and_quantized_achieved_pps(self):
        from switch import Switch
        import readback
        rc, out = run(bc.main, self.argv('--shape-ack-pps', '1000'))
        self.assertEqual(rc, 0, out[-500:])                               # quantized 930 is within tolerance -> passes
        snap = readback.snapshot(Switch('response_only', 140), off.PORTS, {'ack': 1000})
        ack = snap['shaping']['ACK_HOLD']
        self.assertEqual(ack['requested_pps'], 1000)
        self.assertEqual(ack['achieved_pps'], 930)                        # hardware-quantized, recorded as achieved
        self.assertEqual((ack['unit'], ack['max_burst_size']), ('PPS', 1))
        self.assertTrue(ack['max_rate_enable'])
        self.assertIsNone(snap['shaping']['RESP_HOLD']['requested_pps'])
        self.assertFalse(snap['shaping']['RESP_HOLD']['max_rate_enable'])

    def test_an_exact_shaper_readback_also_passes(self):
        fake.SHAPE_QUANTIZE = lambda req: req                            # a chip that returns the exact rate
        rc, out = run(bc.main, self.argv('--shape-ack-pps', '1000'))
        self.assertEqual(rc, 0, out[-500:])

    def test_an_implausible_achieved_rate_fails_closed(self):
        for quant, why in ((lambda req: 0, 'zero'), (lambda req: req * 2, 'off by 2x'),
                           (lambda req: int(req * 0.5), 'off by 50%')):
            with self.subTest(why=why):
                fake.reset()                                 # fresh switch for this subcase
                self.manifest.unlink(missing_ok=True)        # else bring-up refuses a pre-existing manifest (rc 4)
                fake.SHAPE_QUANTIZE = quant
                rc, out = run(bc.main, self.argv('--shape-ack-pps', '1000'))
                self.assertEqual(rc, 2, out[-400:])
                self.assertIn('max_rate', out)

    def test_a_within_tolerance_rate_passes(self):
        fake.SHAPE_QUANTIZE = lambda req: int(req * 0.80)                # 20% low: a coarse but plausible step
        rc, out = run(bc.main, self.argv('--shape-ack-pps', '1000'))
        self.assertEqual(rc, 0, out[-500:])

    def test_a_shaping_data_field_mismatch_fails_closed(self):
        import switch as sw_mod
        orig = sw_mod.Switch.write

        def bad_write(self, op):               # corrupt an EXACT shaping field (max_burst_size) so readback disagrees
            if op.get('table') == 'tf1.tm.queue.sched_shaping':
                op = dict(op, data=[(n, (v + 7 if n == 'max_burst_size' else v)) for n, v in op['data']])
                return orig(self, op)
            return orig(self, op)
        sw_mod.Switch.write = bad_write
        self.addCleanup(setattr, sw_mod.Switch, 'write', orig)
        rc, out = run(bc.main, self.argv('--shape-ack-pps', '1000'))
        self.assertEqual(rc, 2)
        self.assertIn('readback mismatch', out)


class Apply(Base):
    def test_full_apply_with_enable_installs_everything_and_reads_it_back(self):
        rc, out = run(bc.main, self.argv('--enable-pktgen'))
        self.assertEqual(rc, 0, out[-600:])
        self.assertIn('INSTALLED %d writes' % (N_WRITES + 2), out)
        self.assertEqual(len(self.installed()), N_WRITES + 2)
        self.assertEqual(self.buffer(), tc.token_buffer())                     # the buffer read back as bytes
        self.assertEqual(self.buffer()[4:6], b'\x08\x00')                         # wire offset 12:13 not 0x0000 (combined_silicon_01)
        apps = self.apps()
        self.assertEqual({i: (a['app_enable'], a['pattern_value'], a['pattern_mask'], a['pipe_local_source_port'],
                              a['action_name']) for i, a in apps.items()},
                         {1: (True, 0xE1010000, 0xFFFF0000, 68, 'trigger_recirc_pattern'),
                          0: (True, 0xE1000000, 0xFFFF0000, 68, 'trigger_recirc_pattern')})
        enables = [c for c in fake.LOG if c[0] == 'mod' and c[1] == APP and c[3][0] == {'app_enable': True}]
        self.assertEqual([c[3][1] for c in enables], [None, None])               # enabled without an action
        writes = [c[1] for c in fake.LOG if c[0] in ('add', 'mod', 'default_set')]
        self.assertEqual(writes[-6:-2], [N_CONN] * 4)                           # N connection rows, then the enables
        self.assertEqual(len(fake.STATE[N_CONN].e), 4)

    def test_without_the_flag_the_apps_stay_disabled(self):
        rc, out = run(bc.main, self.argv())
        self.assertEqual(rc, 0, out[-600:])
        self.assertEqual({a['app_enable'] for a in self.apps().values()}, {False})
        self.assertEqual(len(self.installed()), N_WRITES)

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


class Loopback(Base):
    def test_loopback_is_the_first_write_and_the_link_is_awaited(self):
        rc, out = run(bc.main, self.argv())
        self.assertEqual(rc, 0, out[-600:])
        writes = [c for c in fake.LOG if c[0] in ('add', 'mod', 'default_set')]
        self.assertEqual([c[1] for c in writes[:len(LOOPS)]], ['$PORT'] * len(LOOPS))
        self.assertEqual([c[3][0] for c in writes[:len(LOOPS)]], [{'$LOOPBACK_MODE': 'BF_LPBK_MAC_NEAR'}] * len(LOOPS))
        self.assertEqual(len([c for c in writes if c[1] == '$PORT']), len(LOOPS))          # the only $PORT writes
        self.assertEqual({p: (fake.PORTS[p]['$LOOPBACK_MODE'], fake.PORTS[p]['$PORT_UP']) for p in LOOPS},
                         {p: ('BF_LPBK_MAC_NEAR', True) for p in LOOPS})
        self.assertEqual([op['before'] for op in self.installed()[:len(LOOPS)]], [{'$LOOPBACK_MODE': 'BF_LPBK_NONE'}] * len(LOOPS))

    def refused(self, text):
        rc, out = run(bc.main, self.argv())
        self.assertEqual(rc, 2, out[-400:])
        self.assertIn(text, out)
        self.assertFalse([c for c in fake.LOG if c[0] in ('add', 'mod', 'default_set')])  # not one write
        self.assertFalse(self.manifest.exists())

    def test_a_port_with_link_up_is_refused(self):
        fake.PORTS[LOOPS[0]]['$PORT_UP'] = True
        self.refused('a port with link up is not ours to loop')

    def test_a_missing_port_entry_is_refused(self):
        del fake.PORTS[LOOPS[-1]]
        self.refused('no $PORT entry')

    def test_a_disabled_port_is_refused(self):
        fake.PORTS[LOOPS[0]]['$PORT_ENABLE'] = False
        self.refused('$PORT_ENABLE is False')

    def test_a_port_already_in_loopback_is_refused(self):
        fake.PORTS[LOOPS[0]]['$LOOPBACK_MODE'] = 'BF_LPBK_MAC_NEAR'
        self.refused('$LOOPBACK_MODE is already')

    def test_a_cage_with_a_module_is_refused_unless_allowed(self):
        fake.PORTS[LOOPS[0]]['$MEDIA_TYPE'] = 'BF_MEDIA_TYPE_COPPER'
        self.refused('--allow-loopback-port %d' % LOOPS[0])
        rc, out = run(bc.main, self.argv('--allow-loopback-port', str(LOOPS[0])))
        self.assertEqual(rc, 0, out[-400:])

    def test_a_build_that_loops_a_port_in_use_is_refused_before_any_grpc_call(self):
        out_dir = Path(self.tmp.name) / 'out'
        off.shutil.copytree(str(off.BUILD / 'out'), str(out_dir))
        p4pp = out_dir / 'response_only.p4pp'
        text = p4pp.read_text(errors='replace')
        ack = off.PORTS['n_ack_return']                         # move N's ACK lap onto dev 10, a cabled port
        text = off.re.sub(r'(const PortId_t n_N_ACK_RETURN\s*=\s*9w)\d+', r'\g<1>10', text)
        p4pp.write_text(off.re.sub(r'9w%d(\s*:\s*eth;)' % ack, r'9w10\1', text))
        argv = self.argv()
        argv[argv.index('--build-out') + 1] = str(out_dir)
        rc, out = run(bc.main, argv)
        self.assertEqual(rc, 1)
        self.assertIn('n_ack_return is dev_port 10, a port in use', out)
        self.assertEqual(fake.LOG, [])

    def test_a_link_that_never_comes_up_stops_bringup_and_is_undone(self):
        fake.LINK_NEVER_UP = {LOOPS[1]}
        rc, out = run(bc.main, self.argv('--loopback-wait', '0.5'))
        self.assertEqual(rc, 2)
        self.assertIn('$PORT_UP did not become True', out)
        self.assertEqual(len(self.installed()), 2)                                        # two loopback writes recorded
        rc, out = self.teardown()
        self.assertEqual(rc, 0, out[-600:])
        self.assertEqual({fake.PORTS[p]['$LOOPBACK_MODE'] for p in LOOPS}, {'BF_LPBK_NONE'})

    def test_a_recirc_entry_that_cannot_loop_stops_at_its_readback(self):
        # the pre-loopback builds name 70 / 197-199: the write does not take there (measured)
        fake.PORTS[LOOPS[0]] = dict(fake.PORTS[70], **{'$PORT_UP': False})
        fake_internal, fake.INTERNAL_PORTS = fake.INTERNAL_PORTS, fake.INTERNAL_PORTS + (LOOPS[0],)
        self.addCleanup(setattr, fake, 'INTERNAL_PORTS', fake_internal)
        rc, out = run(bc.main, self.argv())
        self.assertEqual(rc, 2)
        self.assertIn('readback mismatch', out)
        self.assertIn("reads 'BF_LPBK_NONE', wrote 'BF_LPBK_MAC_NEAR'", out)


class SetEnabled(Base):
    def call(self, value):
        return run(set_enabled.main, ['--manifest', str(self.manifest), '--enabled', str(value)])

    def test_only_enabled_changes_and_it_is_read_back(self):
        self.assertEqual(run(bc.main, self.argv('--t-da', '3000000'))[0], 0)
        calls = len(fake.LOG)
        rc, out = self.call(0)
        self.assertEqual(rc, 0, out)
        now = fake.STATE['p1.t_Ingress.params'].default
        self.assertEqual({k: now[k] for k in tc.T_PARAM_DEFAULTS}, dict(tc.T_PARAM_DEFAULTS, da=3000000, enabled=0))
        self.assertEqual([c[0] for c in fake.LOG[calls:]], ['default_set', 'close'])       # one write, nothing else
        self.assertEqual(dict(next(op for op in self.installed() if op['kind'] == 'default')['data'])['enabled'], 0)
        self.assertEqual(self.call(1)[0], 0)
        self.assertEqual(fake.STATE['p1.t_Ingress.params'].default['enabled'], 1)
        rc, out = self.teardown()                                                         # the manifest still tears down
        self.assertEqual(rc, 0, out[-600:])

    def test_a_drifted_install_is_refused(self):
        self.assertEqual(run(bc.main, self.argv())[0], 0)
        fake.STATE['p1.t_Ingress.params'].default['gap'] = 1
        calls = len(fake.LOG)
        rc, out = self.call(0)
        self.assertEqual(rc, 2)
        self.assertIn('no longer holds the installed params', out)
        self.assertFalse([c for c in fake.LOG[calls:] if c[0] == 'default_set'])

    def test_without_authorization_nothing_is_written(self):
        self.assertEqual(run(bc.main, self.argv())[0], 0)
        os.environ.pop('DEFENSE4_HW_AUTHORIZED')
        calls = len(fake.LOG)
        self.assertEqual(self.call(0)[0], 3)
        self.assertEqual(len(fake.LOG), calls)


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
            sw.write(tc.pktgen_ops(2, off.PORTS)[1])
        self.assertFalse([c for c in fake.LOG if c[0] == 'mod'])


class Teardown(Base):
    def test_everything_goes_back_including_a_nonzero_buffer(self):
        fake.PRIOR_BUFFER = b'\xaa' * 60
        self.assertEqual(run(bc.main, self.argv('--enable-pktgen'))[0], 0)
        self.assertEqual(self.buffer(), tc.token_buffer())
        rc, out = self.teardown()
        self.assertEqual(rc, 0, out[-800:])
        self.assertEqual(self.buffer(), b'\xaa' * 60)                             # restored from the real pre-read
        self.assertEqual({n: len(t.e) for n, t in fake.STATE.items() if n.startswith('p0.') or n == '$mirror.cfg'},
                         {n: 0 for n in fake.STATE if n.startswith('p0.') or n == '$mirror.cfg'})
        self.assertEqual(fake.STATE['p1.t_Ingress.params'].default, fake.PARAMS)
        self.assertEqual({a['app_enable'] for a in self.apps().values()}, {False})
        self.assertEqual(out.count('left disabled (default was a disabled one-shot)'), 2)   # said, and exit 0
        self.assertEqual({p: (fake.PORTS[p]['$LOOPBACK_MODE'], fake.PORTS[p]['$PORT_UP']) for p in LOOPS},
                         {p: ('BF_LPBK_NONE', False) for p in LOOPS})                  # loopback undone, link down
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

    def test_an_app_that_was_a_recirc_pattern_app_gets_its_old_values_back(self):
        fake.PRIOR_APP_ACTION = 'trigger_recirc_pattern'
        self.assertEqual(run(bc.main, self.argv('--enable-pktgen'))[0], 0)
        rc, out = self.teardown()
        self.assertEqual(rc, 0, out[-800:])
        self.assertEqual({(a['app_enable'], a['pattern_value']) for a in self.apps().values()}, {(False, 0)})

    def test_an_app_that_held_another_trigger_type_is_reported_not_claimed(self):
        fake.PRIOR_APP_ACTION = 'trigger_timer_periodic'
        self.assertEqual(run(bc.main, self.argv('--enable-pktgen'))[0], 0)
        rc, out = self.teardown()
        self.assertEqual(rc, 1)
        self.assertIn('NOT restored: was trigger_timer_periodic', out)
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
        self.assertEqual(self.buffer(), tc.token_buffer())                       # left as bring-up wrote it, and said so


if __name__ == '__main__':
    unittest.main()

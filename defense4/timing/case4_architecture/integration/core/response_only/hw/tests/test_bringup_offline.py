"""Offline tests of the hardware bring-up plan: no switch, no gRPC.

  python3 -m unittest discover -s integration/core/response_only/hw/tests -v

Build under test, in this order:
  1. HW_BUILD: a directory holding manifest.json and out/.
  2. The newest switch-compiled composite under evidence/route_ab_01 that matches cp.py (N `ports` keyed on
     hdr.ip.src) AND whose looping ports can loop on this switch (pipe-local 68, or a front-panel port).
  3. If none exists yet: a SYNTHETIC build in a temporary directory, made from the newest composite that
     matches cp.py by rewriting only the port constants in out/response_only.p4pp to the loopback-port plan
     of evidence/recirc_ports_01/STATUS.md (N_ACK_RETURN 48, T_IN 180, HB_RETURN 181, HELD_RETURN 182).
     bfrt.json and the binaries are the real ones. It exercises the installer; it is not a build to load.
Shared schemas: FIXED_SCHEMA_DIR (default /home/philip/bf-sde-9.13.1/install/share/bf_rt_shared).
"""
import copy
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HW = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HW))
import bringup_composite as bc  # noqa: E402
import bringup_teardown as bt  # noqa: E402
import build_ports  # noqa: E402
import t_config as tc  # noqa: E402

FIXED = os.environ.get('FIXED_SCHEMA_DIR', '/home/philip/bf-sde-9.13.1/install/share/bf_rt_shared')
DEAD_INTERNAL = (69, 70, 71, 197, 198, 199)      # `recirc` $PORT entries that do not recirculate (measured)
LOOPBACK_PLAN = {'n_N_ACK_RETURN': 48, 'n_READ_HANDOFF_PORT': 180, 't_T_IN': 180, 't_HB_RETURN': 181, 't_HELD_RETURN': 182}


def matches_cp(build):
    """True when the build's N `ports` table has the keys the current cp.py emits (hdr.ip.src included)."""
    try:
        tables = json.loads((build / 'out/bfrt.json').read_text())['tables']
        keys = [k['name'] for t in tables if t['name'] == 'p0.n_Ingress.ports' for k in t['key']]
    except (OSError, ValueError, KeyError):
        return False
    return 'hdr.ip.src' in keys and (build / 'manifest.json').is_file()


def can_loop(build):
    ports, errs = build_ports.read(build / 'out')
    return not errs and not set(build_ports.loopback_ports(ports).values()) & set(DEAD_INTERNAL)


def synthesize(source, tmp):
    """Copy `source`'s out/ and rewrite the port constants of its p4pp to LOOPBACK_PLAN."""
    out = Path(tmp) / 'out'
    (out / 'p0').mkdir(parents=True)
    (out / 'p1').mkdir()
    for rel in ('bfrt.json', 'p0/tofino.bin', 'p1/tofino.bin'):
        shutil.copy(str(source / 'out' / rel), str(out / rel))
    text = (source / 'out/response_only.p4pp').read_text(errors='replace')
    old_ack = re.search(r'const PortId_t n_N_ACK_RETURN\s*=\s*9w(\d+)', text).group(1)
    for const, port in LOOPBACK_PLAN.items():
        text, n = re.subn(r'(const PortId_t %s\s*=\s*9w)\d+' % const, r'\g<1>%d' % port, text)
        assert n == 1, const
    text, n = re.subn(r'(transition select\(eg\.egress_port\)\s*\{[^}]*?9w)%s(\s*:\s*eth;)' % old_ack,
                      r'\g<1>%d\2' % LOOPBACK_PLAN['n_N_ACK_RETURN'], text)
    assert n == 1, 'E dispatch'
    (out / 'response_only.p4pp').write_text(text)
    return Path(tmp)


def find_build():
    """(build directory, is it synthetic)."""
    if os.environ.get('HW_BUILD'):
        return Path(os.environ['HW_BUILD']), False
    found = sorted((p.parent for p in (HW.parents[2] / 'evidence/route_ab_01').glob('*/*switch_9132/manifest.json')
                    if matches_cp(p.parent)), key=lambda p: (p / 'out/bfrt.json').stat().st_mtime)
    real = [p for p in found if can_loop(p)]
    if real:
        return real[-1], False
    if not found:
        return None, False
    global _TMP
    _TMP = tempfile.TemporaryDirectory()
    return synthesize(found[-1], _TMP.name), True


BUILD, SYNTHETIC = find_build()
if BUILD is None or not Path(FIXED).is_dir():
    raise unittest.SkipTest('no composite build matching cp.py (ports keyed on hdr.ip.src) under evidence/route_ab_01, '
                            'or no shared schemas at %s; set HW_BUILD / FIXED_SCHEMA_DIR' % FIXED)
SHA = {rel: hashlib.sha256((BUILD / 'out' / rel).read_bytes()).hexdigest() for rel in bc.REQUIRED_EXPECT}
if not SYNTHETIC:
    _manifest = json.loads((BUILD / 'manifest.json').read_text())['artifact_sha256']
    assert all(_manifest[rel] == SHA[rel] for rel in SHA), 'build files differ from their manifest'
PORTS, _errs = build_ports.read(BUILD / 'out')
assert not _errs, _errs
# Endpoints that fit the ports compiled into the build: one dev port for a shared-port build, two otherwise.
ENDPOINTS = ['--master-port', '54321', '--master-dev', str(PORTS['forward']), '--relay-dev', str(PORTS['relay'])]
if PORTS['forward'] == PORTS['relay']:
    ENDPOINTS += ['--master-ip', '192.168.10.61', '--relay-ip', '192.168.10.62']
print('build under test:', 'SYNTHETIC loopback-port rewrite (no such build exists yet)' if SYNTHETIC else BUILD,
      '| endpoints', ' '.join(ENDPOINTS), file=sys.stderr)


def plan(a):
    return bc.plan(a, PORTS)


def offline(ops, a):
    return bc.offline(ops, a, PORTS)


def args(*extra, sha=None):
    sha = sha or SHA
    base = ['--build-out', str(BUILD / 'out'), '--fixed-schema-dir', FIXED] + ENDPOINTS
    for rel in bc.REQUIRED_EXPECT:
        base += ['--expect', '%s=%s' % (rel, sha[rel])]
    return bc.parse(base + list(extra))


def first(ops, **match):
    return next(i for i, op in enumerate(ops) if all(op.get(k) == v for k, v in match.items()))


def setkey(op, i, new):
    op['key'][i] = new


def setdata(op, i, new):
    op['data'][i] = new


N_PORTS, N_CONN, E_CONN = 'p0.n_Ingress.ports', 'p0.n_Ingress.connection', 'p0.r_Egress.conn'
# name -> (which op, mutation). Each is one wrong name, type, width or count the validator must catch.
MUTATIONS = {
    'table typo': (dict(table=N_PORTS), lambda op: op.update(table='p0.n_Ingress.port')),
    'key field typo': (dict(table=N_CONN), lambda op: setkey(op, 0, ('hdr.ip.srcx',) + tuple(op['key'][0][1:]))),
    'missing priority': (dict(table=N_PORTS), lambda op: op.update(priority=None)),
    'exact key given a mask': (dict(table=N_CONN), lambda op: setkey(op, 0, (op['key'][0][0], op['key'][0][1], 0xffffffff))),
    'ternary key without mask': (dict(table=N_PORTS), lambda op: setkey(op, 1, (op['key'][1][0], 1, None))),
    'ports row without hdr.ip.src': (dict(table=N_PORTS), lambda op: op['key'].pop()),
    'action typo': (dict(table=E_CONN), lambda op: op.update(action='r_Egress.fwd_con')),
    'data field typo': (dict(kind='default'), lambda op: setdata(op, 0, ('dax', 1))),
    'data field missing': (dict(table='p0.n_Ingress.data_connection'), lambda op: op['data'].pop()),
    'T param missing': (dict(kind='default'), lambda op: op['data'].pop()),
    'value too wide': (dict(table=E_CONN), lambda op: setdata(op, 1, ('idx', 16))),
    'mirror field typo': (dict(kind='mirror'), lambda op: setdata(op, 4, ('$max_len', 2048))),
    'queue field typo': (dict(kind='queue'), lambda op: setdata(op, 2, ('max_prio', '7'))),
    'pktgen action typo': (dict(kind='pktgen_app'), lambda op: op.update(action='trigger_recirc')),
    'pktgen field typo': (dict(kind='pktgen_app'), lambda op: setdata(op, 4, ('pipe_local_src_port', 68))),
    'pktgen port field typo': (dict(kind='pktgen_port'), lambda op: setdata(op, 0, ('pktgen_on', True))),
}


class NameCheck(unittest.TestCase):
    def setUp(self):
        self.a = args()
        self.ops = plan(self.a)

    def test_the_plan_validates_clean(self):
        self.assertEqual(offline(self.ops, self.a), [])

    def test_each_single_fault_is_caught(self):
        for name, (match, mutate) in MUTATIONS.items():
            with self.subTest(name):
                ops = copy.deepcopy(self.ops)
                mutate(ops[first(ops, **match)])
                self.assertTrue(offline(ops, self.a), name + ' was not caught')

    def test_more_rows_than_the_table_holds_is_caught(self):
        ops = copy.deepcopy(self.ops)
        row = ops[first(ops, table=N_CONN)]
        for port in range(4):
            extra = copy.deepcopy(row)
            extra['key'][1] = (row['key'][1][0], port, None)
            ops.append(extra)
        self.assertTrue(any('size' in e for e in offline(ops, self.a)))

    def test_a_duplicate_key_is_caught(self):
        ops = self.ops + [copy.deepcopy(self.ops[first(self.ops, table=N_PORTS)])]
        self.assertTrue(any('duplicate key' in e for e in offline(ops, self.a)))


class Refusals(unittest.TestCase):
    def test_a_wrong_artifact_hash_is_refused(self):
        for rel in bc.REQUIRED_EXPECT:
            with self.subTest(rel):
                self.assertTrue(bc.identity(args(sha=dict(SHA, **{rel: '0' * 64}))))
        self.assertEqual(bc.identity(args()), [])

    def test_a_missing_expected_hash_is_refused(self):
        a = args()
        a.expect = a.expect[:2]
        self.assertTrue(any('required' in e for e in bc.identity(a)))

    def test_a_build_compiled_for_other_ports_is_refused(self):
        self.assertEqual(build_ports.check_endpoints(PORTS, PORTS['forward'], PORTS['relay']), [])
        other = 9 if PORTS['relay'] != 9 else 64
        self.assertTrue(any('t_RELAY_PORT' in e for e in build_ports.check_endpoints(PORTS, PORTS['forward'], other)))
        self.assertTrue(any('t_FORWARD_PORT' in e for e in build_ports.check_endpoints(PORTS, 10, PORTS['relay'])))

    def test_a_looping_port_that_is_a_port_in_use_is_refused(self):
        for role in ('n_ack_return', 't_in', 'hb_return', 'held_return'):
            for port in (9, 10, 11, 64):
                with self.subTest(role=role, port=port):
                    errs = build_ports.check_endpoints(dict(PORTS, **{role: port}), PORTS['forward'], PORTS['relay'])
                    self.assertTrue(any('must never be put in loopback' in e for e in errs), errs)

    def test_a_build_looping_through_a_dead_recirc_entry_is_refused(self):
        for port in (70, 197, 198, 199):
            with self.subTest(port=port):
                role = 'n_ack_return' if port < 128 else 'hb_return'
                errs = build_ports.check_endpoints(dict(PORTS, **{role: port}), PORTS['forward'], PORTS['relay'])
                self.assertTrue(any('do not recirculate' in e for e in errs), errs)

    def test_an_inconsistent_or_unreadable_build_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(build_ports.read(tmp)[1])                                  # no p4pp at all
            text = (BUILD / 'out/response_only.p4pp').read_text(errors='replace')
            for bad in (re.sub(r'(const PortId_t t_T_IN\s*=\s*9w)\d+', r'\g<1>181', text),          # N and T disagree
                        re.sub(r'const PortId_t t_HELD_RETURN[^\n]*\n', '', text),                 # constant missing
                        re.sub(r'(const PortId_t t_PKTGEN_RETURN\s*=\s*9w)\d+', r'\g<1>180', text)):  # generator off 68
                (Path(tmp) / 'response_only.p4pp').write_text(bad)
                self.assertTrue(build_ports.read(tmp)[1])

    def test_rows_use_the_ports_of_the_build_not_cp_constants(self):
        ops = plan(args())
        ack, ret = PORTS['n_ack_return'], PORTS['return_port']
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
        argv = ['--build-out', str(BUILD / 'out'), '--fixed-schema-dir', FIXED, '--apply'] + ENDPOINTS
        for rel in bc.REQUIRED_EXPECT:
            argv += ['--expect', '%s=%s' % (rel, SHA[rel])]
        self.assertEqual(bc.main(argv), 3)


    def test_both_endpoints_on_one_dev_port_plan_and_validate(self):
        a = args('--master-ip', '192.168.10.61', '--master-dev', '9', '--relay-ip', '192.168.10.62', '--relay-dev', '9',
                 '--read-dst', '0x0a00', '--read-src', '0x0100')
        ops = plan(a)
        self.assertEqual(offline(ops, a), [])
        ports = [op for op in ops if op['table'] == N_PORTS]
        self.assertIn(('hdr.ip.src', 0xc0a80a3d, 0xffffffff), ports[0]['key'])     # master row keyed on its address


class Order(unittest.TestCase):
    def test_T_state_first_E_next_N_connection_rows_last(self):
        ops = [op for op in plan(args()) if op['kind'] != 'loopback']
        kinds = [('n_conn' if op['table'] == N_CONN else 'n' if op['table'].startswith('p0.n_') else
                  'e' if op['table'].startswith('p0.r_') else 't') for op in ops]
        self.assertEqual(kinds, sorted(kinds, key=['t', 'e', 'n', 'n_conn'].index))
        self.assertEqual(kinds[-4:], ['n_conn'] * 4)

    def test_enable_is_written_without_an_action_and_the_full_app_is_reverified(self):
        import readback
        for op in tc.enable_ops(PORTS):
            self.assertIsNone(op['action'])
            self.assertEqual(op['data'], [('app_enable', True)])
        app = tc.pktgen_ops(2, PORTS)[2]
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
        self.assertEqual(dict(tc.pktgen_ops(2, PORTS)[1]['data'])['buffer'], buf)

    def test_ladder_and_apps_match_T(self):
        held, hb = PORTS['held_return'], PORTS['hb_return']
        self.assertEqual({(p, q) for p, q, _ in tc.queue_plan(PORTS)}, {(held, 7), (held, 6), (held, 5), (held, 4), (hb, 3), (hb, 2)})
        self.assertEqual({op['pipe'] for op in tc.queue_ops(PORTS)}, {held // 128, hb // 128})   # the port's own pipe
        self.assertEqual({(n, i, hex(p)) for n, i, p in tc.PKTGEN_APPS}, {('OPERATE', 1, '0xe1010000'), ('READ', 2, '0xe1000000')})


class Teardown(unittest.TestCase):
    def manifest(self, tmp):
        undo = {'p4': 'delete', 'mirror': 'delete', 'default': 'default_reset'}
        ops = plan(args()) + tc.enable_ops(PORTS)
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
        loops = len(build_ports.loopback_ports(PORTS))
        self.assertEqual([op['kind'] for op in order[len(order) - loops:]], ['loopback'] * loops)   # loopback comes off last
        self.assertEqual([op['kind'] for op in plan(args())[:loops]], ['loopback'] * loops)        # and goes on first

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

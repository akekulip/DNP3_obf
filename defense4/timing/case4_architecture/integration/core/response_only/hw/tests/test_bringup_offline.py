"""Offline tests of the hardware bring-up plan: no switch, no gRPC.

  python3 -m unittest discover -s integration/core/response_only/hw/tests -v
Needs a compiled build (default: evidence/route_ab_01/op_tag_composite_02/compile_switch_9132) and an SDE
shared-schema directory (default: /home/philip/bf-sde-9.13.1/install/share/bf_rt_shared; env FIXED_SCHEMA_DIR).
"""
import copy
import json
import os
import re
import sys
import unittest
from pathlib import Path

HW = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HW))
import bringup_composite as bc  # noqa: E402
import bringup_teardown as bt  # noqa: E402
import t_config as tc  # noqa: E402

FIXED = os.environ.get('FIXED_SCHEMA_DIR', '/home/philip/bf-sde-9.13.1/install/share/bf_rt_shared')


def matches_cp(build):
    """True when the build's N `ports` table has the keys the current cp.py emits (hdr.ip.src included)."""
    try:
        tables = json.loads((build / 'out/bfrt.json').read_text())['tables']
        keys = [k['name'] for t in tables if t['name'] == 'p0.n_Ingress.ports' for k in t['key']]
    except (OSError, ValueError, KeyError):
        return False
    return 'hdr.ip.src' in keys and (build / 'manifest.json').is_file()


def find_build():
    """HW_BUILD (a directory holding manifest.json and out/), else the newest switch-compiled composite under
    evidence/route_ab_01 that matches cp.py, else None."""
    if os.environ.get('HW_BUILD'):
        return Path(os.environ['HW_BUILD'])
    found = [p.parent for p in (HW.parents[2] / 'evidence/route_ab_01').glob('*/*switch_9132/manifest.json')
             if matches_cp(p.parent)]
    return max(found, key=lambda p: (p / 'out/bfrt.json').stat().st_mtime) if found else None


BUILD = find_build()
if BUILD is None or not Path(FIXED).is_dir():
    raise unittest.SkipTest('no composite build matching cp.py (ports keyed on hdr.ip.src) under evidence/route_ab_01, '
                            'or no shared schemas at %s; set HW_BUILD / FIXED_SCHEMA_DIR' % FIXED)
SHA = json.loads((BUILD / 'manifest.json').read_text())['artifact_sha256']
_ports = dict(re.findall(r'const PortId_t t_(FORWARD|RELAY)_PORT\s*=\s*9w(\d+)', (BUILD / 'out/response_only.p4pp').read_text()))
# Endpoints that fit the ports compiled into the build: one dev port for a shared-port build, two otherwise.
ENDPOINTS = ['--master-port', '54321', '--master-dev', _ports['FORWARD'], '--relay-dev', _ports['RELAY']]
if _ports['FORWARD'] == _ports['RELAY']:
    ENDPOINTS += ['--master-ip', '192.168.10.61', '--relay-ip', '192.168.10.62']
print('build under test:', BUILD, '| endpoints', ' '.join(ENDPOINTS), file=sys.stderr)


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
        self.ops = bc.plan(self.a)

    def test_the_plan_validates_clean(self):
        self.assertEqual(bc.offline(self.ops, self.a), [])

    def test_each_single_fault_is_caught(self):
        for name, (match, mutate) in MUTATIONS.items():
            with self.subTest(name):
                ops = copy.deepcopy(self.ops)
                mutate(ops[first(ops, **match)])
                self.assertTrue(bc.offline(ops, self.a), name + ' was not caught')

    def test_more_rows_than_the_table_holds_is_caught(self):
        ops = copy.deepcopy(self.ops)
        row = ops[first(ops, table=N_CONN)]
        for port in range(4):
            extra = copy.deepcopy(row)
            extra['key'][1] = (row['key'][1][0], port, None)
            ops.append(extra)
        self.assertTrue(any('size' in e for e in bc.offline(ops, self.a)))

    def test_a_duplicate_key_is_caught(self):
        ops = self.ops + [copy.deepcopy(self.ops[first(self.ops, table=N_PORTS)])]
        self.assertTrue(any('duplicate key' in e for e in bc.offline(ops, self.a)))


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
        compiled_relay = int(re.search(r't_RELAY_PORT\s*=\s*9w(\d+)', (BUILD / 'out/response_only.p4pp').read_text()).group(1))
        ips = ('--master-ip', '192.168.10.61', '--relay-ip', '192.168.10.62')   # required when the dev ports are equal
        self.assertEqual(bc.source_ports(args('--relay-dev', str(compiled_relay), *ips)), [])
        other = 9 if compiled_relay != 9 else 64
        self.assertTrue(any('t_RELAY_PORT' in e for e in bc.source_ports(args('--relay-dev', str(other), *ips))))

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
        ops = bc.plan(a)
        self.assertEqual(bc.offline(ops, a), [])
        ports = [op for op in ops if op['table'] == N_PORTS]
        self.assertIn(('hdr.ip.src', 0xc0a80a3d, 0xffffffff), ports[0]['key'])     # master row keyed on its address


class Order(unittest.TestCase):
    def test_T_state_first_E_next_N_connection_rows_last(self):
        ops = bc.plan(args())
        kinds = [('n_conn' if op['table'] == N_CONN else 'n' if op['table'].startswith('p0.n_') else
                  'e' if op['table'].startswith('p0.r_') else 't') for op in ops]
        self.assertEqual(kinds, sorted(kinds, key=['t', 'e', 'n', 'n_conn'].index))
        self.assertEqual(kinds[-4:], ['n_conn'] * 4)

    def test_enable_is_written_without_an_action_and_the_full_app_is_reverified(self):
        import readback
        for op in tc.enable_ops():
            self.assertIsNone(op['action'])
            self.assertEqual(op['data'], [('app_enable', True)])
        app = tc.pktgen_ops(2)[2]
        full = dict(readback.enabled_app_op(app)['data'])
        self.assertTrue(full['app_enable'])
        self.assertEqual((full['pattern_value'], full['pattern_mask'], full['pipe_local_source_port'],
                          full['packets_per_batch_cfg']), (0xE1010000, 0xFFFF0000, 68, 3))

    def test_ladder_and_apps_match_T(self):
        self.assertEqual({(p, q) for p, q, _ in tc.QUEUE_PLAN}, {(199, 7), (199, 6), (199, 5), (199, 4), (198, 3), (198, 2)})
        self.assertEqual({(n, i, hex(p)) for n, i, p in tc.PKTGEN_APPS}, {('OPERATE', 1, '0xe1010000'), ('READ', 2, '0xe1000000')})


class Teardown(unittest.TestCase):
    def manifest(self, tmp):
        undo = {'p4': 'delete', 'mirror': 'delete', 'default': 'default_reset'}
        ops = bc.plan(args()) + tc.enable_ops()
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
        self.assertEqual(order[-1]['kind'], 'queue')

    def test_the_packet_buffer_bytes_survive_the_manifest(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            ops = self.manifest(tmp)['installed']
        buf = next(op for op in ops if op['kind'] == 'pktgen_buffer')
        self.assertEqual(buf['before']['buffer'], bytes(tc.TOKEN_LEN))
        self.assertEqual(dict(buf['data'])['buffer'], bytes(tc.TOKEN_LEN))


if __name__ == '__main__':
    unittest.main()

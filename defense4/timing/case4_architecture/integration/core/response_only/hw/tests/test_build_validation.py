"""Build-dependent hw tests: they need the COMPILED evidence tree of the pinned build and, for the schema name
check, the SDE 9.13.1 shared schemas. Run them with:

  FIXED_SCHEMA_DIR=<sde>/install/share/bf_rt_shared python3 -m unittest discover -s tests -p 'test_build_*.py'

Build under test: pinned_build.json (paths relative to integration/), or HW_BUILD=<dir holding manifest.json and
out/>. No mtime discovery. If the compiled out/ tree is absent the class FAILS with the path and the command
that produces it (the evidence out/ trees are not tracked in git, so a fresh clone does not have them). If the
schemas are absent, only the tests that need them are skipped, with the variable to set.
"""
import copy
import hashlib
import json
import os
import sys
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
HW = TESTS.parent
INTEG = HW.parents[2]
sys.path.insert(0, str(HW))
import bringup_composite as bc  # noqa: E402
import build_ports  # noqa: E402

PIN = json.loads((TESTS / 'pinned_build.json').read_text())


def _schema_dir():
    if os.environ.get('FIXED_SCHEMA_DIR'):
        return os.environ['FIXED_SCHEMA_DIR']
    if os.environ.get('SDE_INSTALL'):
        return os.path.join(os.environ['SDE_INSTALL'], 'share', 'bf_rt_shared')
    if os.environ.get('SDE'):
        return os.path.join(os.environ['SDE'], 'install', 'share', 'bf_rt_shared')
    return None


if os.environ.get('HW_BUILD'):
    BUILD = Path(os.environ['HW_BUILD'])
    SHA = json.loads((BUILD / 'manifest.json').read_text())['artifact_sha256'] if (BUILD / 'manifest.json').is_file() else {}
    EXPECT_PORTS = None
else:
    BUILD = INTEG / PIN['build_dir']
    SHA = PIN['sha256']
    EXPECT_PORTS = PIN['ports']
FIXED = _schema_dir()
MISSING_TREE = ('needs the compiled build tree %s (bfrt.json, p0/ and p1/tofino.bin, response_only.p4pp); it is not '
                'tracked in git. Produce it with: %s -- note tofino.bin embeds a random run id, so a recompile will '
                'not reproduce the pinned sha256 and pinned_build.json must then be updated; or copy the original '
                'out/ from the machine that compiled it.' % (BUILD / 'out', PIN['produce']))
MISSING_SCHEMAS = ('needs the SDE 9.13.1 shared schemas (bf_rt_*_tf1.json): set FIXED_SCHEMA_DIR=<sde>/install/share/'
                   'bf_rt_shared, or SDE_INSTALL / SDE')
PORTS = ENDPOINTS = None


def _load():
    global PORTS, ENDPOINTS
    out = BUILD / 'out'
    if not all((out / rel).is_file() for rel in ('bfrt.json', 'p0/tofino.bin', 'p1/tofino.bin', 'response_only.p4pp')):
        raise AssertionError(MISSING_TREE)
    PORTS, errs = build_ports.read(out)
    if errs:
        raise AssertionError('build ports unreadable: %s' % errs)
    ENDPOINTS = ['--master-port', '54321', '--master-dev', str(PORTS['forward']), '--relay-dev', str(PORTS['relay'])]
    if PORTS['forward'] == PORTS['relay']:
        ENDPOINTS += ['--master-ip', '192.168.10.61', '--relay-ip', '192.168.10.62']


def args(*extra):
    base = ['--build-out', str(BUILD / 'out'), '--fixed-schema-dir', FIXED or 'unset'] + ENDPOINTS
    for rel in bc.REQUIRED_EXPECT:
        base += ['--expect', '%s=%s' % (rel, SHA[rel])]
    return bc.parse(base + list(extra))


def plan(a):
    return bc.plan(a, PORTS)


def offline(ops, a):
    return bc.offline(ops, a, PORTS)


class BuildTest(unittest.TestCase):
    needs_schemas = False

    @classmethod
    def setUpClass(cls):
        _load()                                      # fails loudly (AssertionError) if the tree is missing

    def setUp(self):
        if self.needs_schemas and not (FIXED and Path(FIXED).is_dir()):
            self.skipTest(MISSING_SCHEMAS)


class PinnedBuild(BuildTest):
    def test_on_disk_files_match_the_pinned_sha256(self):
        for rel in bc.REQUIRED_EXPECT:
            with self.subTest(rel):
                got = hashlib.sha256((BUILD / 'out' / rel).read_bytes()).hexdigest()
                self.assertEqual(got, SHA[rel], '%s differs from the pin' % rel)

    def test_the_tracked_manifest_agrees_with_the_pin(self):
        manifest = json.loads((BUILD / 'manifest.json').read_text())['artifact_sha256']
        self.assertEqual({rel: manifest[rel] for rel in bc.REQUIRED_EXPECT}, {rel: SHA[rel] for rel in bc.REQUIRED_EXPECT})

    def test_the_build_ports_are_the_pinned_ports(self):
        if EXPECT_PORTS is None:
            self.skipTest('HW_BUILD override: no pinned port map to compare')
        self.assertEqual({k: PORTS[k] for k in EXPECT_PORTS}, EXPECT_PORTS)
        self.assertEqual(build_ports.check_endpoints(PORTS, PORTS['forward'], PORTS['relay']), [])

    def test_identity_accepts_the_build_and_refuses_a_wrong_hash(self):
        self.assertEqual(bc.identity(args()), [])
        a = args()
        a.expect = ['bfrt.json=' + '0' * 64] + a.expect[1:]
        self.assertTrue(bc.identity(a))


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


class NameCheck(BuildTest):
    needs_schemas = True

    def setUp(self):
        super().setUp()
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




class RealBuildEndToEnd(BuildTest):
    needs_schemas = True

    def test_both_endpoints_on_one_dev_port_plan_and_validate(self):
        a = args('--master-ip', '192.168.10.61', '--master-dev', '9', '--relay-ip', '192.168.10.62', '--relay-dev', '9',
                 '--read-dst', '0x0a00', '--read-src', '0x0100')
        ops = plan(a)
        self.assertEqual(offline(ops, a), [])
        ports = [op for op in ops if op['table'] == N_PORTS]
        self.assertIn(('hdr.ip.src', 0xc0a80a3d, 0xffffffff), ports[0]['key'])     # master row keyed on its address



    def test_dry_run_against_the_real_build_exits_0(self):
        argv = ['--build-out', str(BUILD / 'out'), '--fixed-schema-dir', FIXED] + ENDPOINTS
        for rel in bc.REQUIRED_EXPECT:
            argv += ['--expect', '%s=%s' % (rel, SHA[rel])]
        self.assertEqual(bc.main(argv), 0)


if __name__ == '__main__':
    unittest.main()

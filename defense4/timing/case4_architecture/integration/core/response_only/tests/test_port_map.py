"""The four looping ports as build parameters (port_map.py, compose.py, cp.py).

On the switch only pipe-local 68 recirculates (evidence/recirc_ports_01/STATUS.md), so the hardware build names
front-panel ports in MAC loopback: N_ACK_RETURN 48, T_IN 180, HB_RETURN 181, HELD_RETURN 182. These tests hold
the default build still, show that no port number is left hardcoded, and run N from source on the hardware map.
"""
import collections
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
RO = HERE.parent
sys.path[:0] = [str(RO), str(RO.parent.parent / 'connection' / 'binding' / 'tests')]
import compose  # noqa: E402
import cp  # noqa: E402
import make_n  # noqa: E402
import port_map as pm  # noqa: E402
import response_path_cp as rp  # noqa: E402
import read_support as rs  # noqa: E402
import vectors  # noqa: E402
from read_support import ReadPipeline, drop_runtime  # noqa: E402
import test_response_only_binding as base  # noqa: E402

HW = pm.HARDWARE_SHARED_PORT
DEFAULT_SRC, DEFAULT_META = compose.generate()
HW_SRC, HW_META = compose.generate(ports=HW)
LITERAL = re.compile(r'\b9w(\d+)\b')


def literals(text):
    return collections.Counter(int(v) for v in LITERAL.findall(text))


class Build(unittest.TestCase):
    def test_default_map_changes_nothing(self):
        self.assertEqual(compose.generate(ports=pm.DEFAULT)[0], DEFAULT_SRC)
        self.assertNotIn('port override', DEFAULT_SRC)
        self.assertEqual(DEFAULT_META['port_map'], dict(pm.DEFAULT._asdict()))

    def test_relay_port_alone_is_the_shared_port_build_as_before(self):
        self.assertEqual(compose.generate(relay_port=9)[0], compose.generate(ports=pm.DEFAULT._replace(relay_port=9))[0])

    def test_every_port_literal_is_a_declaration_or_the_one_e_dispatch(self):
        """No port number is hardcoded anywhere else in N, E or T: each 9-bit literal in the composed program is
        on a `const PortId_t` line or in E's egress-port dispatch. So changing the declarations changes every use."""
        for text in (DEFAULT_SRC, HW_SRC):
            for line in text.splitlines():
                if LITERAL.search(line):
                    self.assertTrue(re.match(r'\s*const PortId_t \w+\s*=\s*9w\d+;', line)
                                    or 'transition select(eg.egress_port)' in line, line)

    def test_hardware_map_leaves_no_old_port(self):
        got = literals(HW_SRC)
        for old in (pm.DEFAULT.n_ack_return, pm.DEFAULT.t_in, pm.DEFAULT.hb_return, pm.DEFAULT.held_return,
                    pm.DEFAULT.relay_port):
            self.assertNotIn(old, got)
        # N_ACK_RETURN: N's constant + E's dispatch. T_IN: N's handoff + T's input. 9: FORWARD, RELAY, E's dispatch.
        self.assertEqual(got, {48: 2, 180: 2, 181: 1, 182: 1, 9: 3, 68: 2, 196: 1, 0: 1})
        self.assertEqual(literals(DEFAULT_SRC), {70: 2, 197: 2, 198: 1, 199: 1, 9: 2, 64: 1, 68: 2, 196: 1, 0: 1})

    def test_n_handoff_equals_t_input_and_e_dispatch_equals_n_lap(self):
        def const(name):
            return int(re.search(r'const PortId_t %s\s*=\s*9w(\d+);' % name, HW_SRC)[1])
        self.assertEqual((const('n_READ_HANDOFF_PORT'), const('t_T_IN')), (HW.t_in, HW.t_in))
        self.assertEqual((const('n_N_ACK_RETURN'), const('t_HB_RETURN'), const('t_HELD_RETURN'), const('t_RELAY_PORT')),
                         (HW.n_ack_return, HW.hb_return, HW.held_return, HW.relay_port))
        self.assertIn('{ 9w9: eth; 9w%d: eth; default: accept; }' % HW.n_ack_return, HW_SRC)
        self.assertEqual((const('t_PKTGEN_RETURN'), const('n_RETURN_PORT')), (pm.PKTGEN_RETURN, pm.RETURN_PORT))

    def test_only_the_named_lines_differ(self):
        changed = [(a, b) for a, b in zip(DEFAULT_SRC.splitlines(), HW_SRC.splitlines()) if a != b]
        self.assertEqual(len(DEFAULT_SRC.splitlines()), len(HW_SRC.splitlines()))
        self.assertEqual(len(changed), 7, changed)   # N lap, N handoff, E dispatch, T_IN, HB, HELD, RELAY

    def test_a_moved_declaration_is_refused(self):
        text = make_n.generate()
        with self.assertRaises(AssertionError):
            compose.set_port(text.replace('N_ACK_RETURN=9w70;', 'N_ACK_RETURN=9w71;'), 'N_ACK_RETURN', 48, 70)
        with self.assertRaises(AssertionError):
            compose.set_port(text, 'NO_SUCH_PORT', 48, 70)
        with self.assertRaises(AssertionError):
            compose.set_e_lap_port('parser x { }', 48)


class Map(unittest.TestCase):
    def test_flags(self):
        rest, ports = pm.parse_args(['out.p4', '--relay-port=9', '--n-ack-return=48', '--t-in=180', '--hb-return=181',
                                     '--held-return=182'])
        self.assertEqual((rest, ports), (['out.p4'], HW))
        self.assertEqual(pm.parse_args(['out.p4']), (['out.p4'], pm.DEFAULT))

    def test_wrong_pipe_or_collision_is_refused(self):
        for bad in (HW._replace(n_ack_return=180), HW._replace(t_in=48), HW._replace(hb_return=HW.held_return),
                    HW._replace(t_in=pm.PKTGEN_RETURN), HW._replace(n_ack_return=pm.RETURN_PORT),
                    HW._replace(relay_port=HW.n_ack_return)):
            with self.assertRaises(ValueError):
                pm.check(bad)

    def test_rows_load_the_map_the_build_was_composed_with(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'x.inputs.json'
            path.write_text(json.dumps(HW_META))
            self.assertEqual(pm.load(path), HW)
            path.write_text(json.dumps(dict(relay_port=9)))          # a build from before the map was recorded
            self.assertEqual(pm.load(path), pm.DEFAULT._replace(relay_port=9))


SHARED = HW.relay_port
S_MASTER = rp.Endpoint('10.0.0.1', vectors.CLIENT_PORT, SHARED)
S_OUTSTATION = rp.Endpoint('10.0.0.2', vectors.SERVER_PORT, SHARED)
N_HW = compose.set_port(compose.set_port(make_n.generate(), 'N_ACK_RETURN', HW.n_ack_return, 70),
                        'READ_HANDOFF_PORT', HW.t_in, 197)


def hw_pipe(rows_lap=HW.n_ack_return):
    pipe = ReadPipeline(text=N_HW).start(base.OWNER['after_ack'], base.SELECT_SEQ, base.SERVER_SEQ)
    drop_runtime(pipe, 'ports')
    drop_runtime(pipe, 'connection')
    cp.install_ingress(pipe.src, cp.n_ports_rows(SHARED, SHARED, S_MASTER.ip_int, S_OUTSTATION.ip_int, n_ack_return=rows_lap)
                       + cp.n_connection_rows(S_OUTSTATION, S_MASTER, n_ack_return=rows_lap))
    return pipe


class NOnTheHardwareMap(unittest.TestCase):
    """N run from source with N_ACK_RETURN = 48 and READ_HANDOFF_PORT = 180, both endpoints on port 9."""

    def test_document_vector_laps_on_48_and_hands_off_to_180(self):
        pipe = hw_pipe()
        out = pipe.inject(SHARED, base.select_packet())
        self.assertEqual((out.passes, out.emitted), (1, [(HW.n_ack_return, base.select_packet())]))
        for port, frame, owner in ((HW.n_ack_return, base.select_packet(), 'select'), (SHARED, base.response1(), 'response'),
                                   (HW.n_ack_return, base.operate_packet(), 'operate'), (SHARED, base.response2(), 'idle')):
            out = pipe.inject(port, frame)
            self.assertFalse(out.dropped, out.drop_reason)
            self.assertEqual(pipe.state()['owner'], base.OWNER[owner])
            self.assertEqual([p for p, _ in out.emitted], [HW.t_in if owner == 'operate' else SHARED])

    def test_the_old_lap_port_is_just_another_port(self):
        pipe = hw_pipe()
        before = pipe.state()
        out = pipe.inject(pm.DEFAULT.n_ack_return, base.select_packet())
        self.assertEqual(out.emitted, [])
        self.assertEqual(pipe.state(), before)

    def test_loop_guards_follow_the_constant(self):
        """make_n edit 7 (head of chain) and edit 8 (guard's first const entry) name N_ACK_RETURN, so they guard
        48 here: a ports row or a connection row that sends a lap packet back to 48 emits nothing."""
        pipe = hw_pipe()
        pipe.src.install('ports', (HW.n_ack_return, base.ANY, base.ANY, base.ANY), 'route', (HW.n_ack_return,), priority=0)
        self.assertEqual(pipe.inject(HW.n_ack_return, base.select_packet()).emitted, [])
        pipe = hw_pipe()
        drop_runtime(pipe, 'connection')
        key = (S_MASTER.ip_int, S_OUTSTATION.ip_int, S_MASTER.port, S_OUTSTATION.port)
        for port in (HW.n_ack_return, pm.RETURN_PORT):
            pipe.src.install('connection', key + (port,), 'forward_flow', (HW.n_ack_return,))
        out = pipe.inject(HW.n_ack_return, base.select_packet())
        self.assertNotIn(HW.n_ack_return, [p for p, _ in out.emitted])

    def test_rows_built_for_another_lap_port_do_not_admit(self):
        """Rows for the default port (70) on the 48 build: the master's packet goes to 70 by the row, and nothing
        on 48 is admitted. This is the disagreement port_map.load exists to prevent."""
        pipe = hw_pipe(rows_lap=pm.DEFAULT.n_ack_return)
        out = pipe.inject(HW.n_ack_return, base.select_packet())
        self.assertEqual(out.emitted, [])
        self.assertEqual(pipe.state()['owner'], base.OWNER['after_ack'])


class Rows(unittest.TestCase):
    def test_rows_use_the_given_lap_port_everywhere(self):
        n = (cp.n_ports_rows(SHARED, SHARED, S_MASTER.ip_int, S_OUTSTATION.ip_int, n_ack_return=48)
             + cp.n_connection_rows(S_OUTSTATION, S_MASTER, n_ack_return=48))
        ports = [dict(k)['ig.ingress_port'] for _t, k, *_ in n]
        self.assertEqual(sorted(set(ports)), [9, 48, 68])
        e = [r for r in cp.e_conn_rows(0, S_OUTSTATION, S_MASTER, n_ack_return=48) if r[0] == 'Egress.conn']
        self.assertEqual({r[2]: dict(r[1])['eg.egress_port'] for r in e}, {'Egress.fwd_conn': 9, 'Egress.rev_conn': 48})

    def test_default_rows_are_unchanged(self):
        self.assertEqual(cp.n_ports_rows(9, 64), cp.n_ports_rows(9, 64, n_ack_return=70))
        self.assertEqual(cp.n_connection_rows(base.OUTSTATION, base.MASTER),
                         cp.n_connection_rows(base.OUTSTATION, base.MASTER, master_ingress=70, n_ack_return=70))

    def test_loop_check_follows_the_lap_port(self):
        k = (('ig.ingress_port', 9), ('hdr.ip.$valid', base.ANY), ('hdr.ip.proto', base.ANY), ('hdr.ip.src', base.ANY))
        row = ('Ingress.ports', k, 'Ingress.route', (('port', 48),), 0)
        cp.check_no_loop([row])                       # 48 is an ordinary port for the default build
        with self.assertRaises(ValueError):
            cp.check_no_loop([row], n_ack_return=48)
        with self.assertRaises(ValueError):
            cp.n_ports_rows(48, 9, 1, 2, n_ack_return=48)   # an endpoint on the lap port


if __name__ == '__main__':
    unittest.main()

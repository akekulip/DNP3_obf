"""Control-plane invariants for case4_response_path.p4 (code review HIGH 2, W2, W3) and a source guard (S2)."""
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import response_path_cp as cp

O = cp.Endpoint('192.168.10.7', 20000, 64)      # outstation relay leg
M = cp.Endpoint('192.168.10.1', 40000, 9)       # master


class FakeSwitch:
    """Duplicate keys are refused like BFRT; `fail_on` makes the n-th add raise."""
    def __init__(self, fail_on=None):
        self.tables, self.adds, self.fail_on, self.log = {}, 0, fail_on, []

    def add(self, table, key, action, data):
        self.adds += 1
        k = (table, tuple(sorted(key.items())))
        if self.adds == self.fail_on:
            raise RuntimeError('injected switch refusal')
        if k in self.tables:
            raise RuntimeError('ALREADY_EXISTS %r' % (k,))
        self.tables[k] = (action, data); self.log.append(('add', table))

    def delete(self, table, key):
        del self.tables[(table, tuple(sorted(key.items())))]; self.log.append(('delete', table))

    def modify(self, table, key, action, data):
        k = (table, tuple(sorted(key.items())))
        assert k in self.tables
        self.tables[k] = (action, data); self.log.append(('modify', table))


class Registry(unittest.TestCase):
    def setUp(self):
        self.sw, self.reg = FakeSwitch(), cp.Registry()

    def install(self, slot, o=O, m=M):
        return self.reg.install(slot, o, m, self.sw.add, self.sw.delete)

    def test_rig_connection_includes_its_own_forwarding(self):
        rows = self.install(0)
        self.assertEqual(sorted(r.table for r in rows), ['Egress.conn', 'Egress.conn', 'Egress.odd_ip_t',
                         'Egress.odd_ip_t', 'Ingress.forwarding', 'Ingress.forwarding'])
        fwd = {r.key_dict['ig.ingress_port']: r.data_dict['port'] for r in rows if r.table == 'Ingress.forwarding'}
        self.assertEqual(fwd, {64: 9, 9: 64})

    def test_cross_pipe_refused_before_any_write(self):
        for o, m in ((64, 128), (9, 300), (200, 1)):
            with self.assertRaises(cp.PipeMismatch):
                self.reg.install(1, cp.Endpoint('10.0.0.1', 20000, o), cp.Endpoint('10.0.0.2', 40000, m),
                                 self.sw.add, self.sw.delete)
        self.assertEqual(self.sw.tables, {})

    def test_reconnect_from_same_master_ip_needs_removal_first(self):
        self.install(0)
        before = dict(self.sw.tables)
        new_port = cp.Endpoint(M.ip, 40001, M.dev_port)
        with self.assertRaises(cp.Conflict):                       # host pair already mapped
            self.install(1, m=new_port)
        self.assertEqual(self.sw.tables, before)                    # nothing partial was written
        self.reg.remove(0, self.sw.delete, closed=True)
        self.install(1, m=new_port)
        self.assertEqual(len(self.sw.tables), 6)

    def test_switch_refusal_mid_install_rolls_back(self):
        for n in range(1, 7):
            sw, reg = FakeSwitch(fail_on=n), cp.Registry()
            with self.assertRaises(RuntimeError):
                reg.install(0, O, M, sw.add, sw.delete)
            self.assertEqual((sw.tables, reg.slots, reg.rows), ({}, {}, {}))

    def test_forwarding_conflict_refused(self):
        self.install(0)
        other = cp.Endpoint('10.9.9.9', 40000, 10)                  # port 64 already forwards to 9
        with self.assertRaises(cp.Conflict):
            self.install(1, m=other)

    def test_policy_change_modifies_never_deletes(self):
        self.install(0)
        self.reg.set_enable(0, False, self.sw.modify)
        self.assertEqual([e for e in self.sw.log if e[0] != 'add'], [('modify', 'Egress.conn')])
        fwd_key = [k for k in self.sw.tables if k[0] == 'Egress.conn' and dict(k[1])['hdr.ip.src'] == O.ip_int][0]
        self.assertEqual(self.sw.tables[fwd_key], ('Egress.fwd_conn', {'enable': 0, 'idx': 0}))

    def test_retirement_rule(self):
        self.install(0)
        with self.assertRaises(cp.Conflict):
            self.reg.remove(0, self.sw.delete)
        with self.assertRaises(cp.Conflict):                       # growth D = W - N != 0
            self.reg.remove(0, self.sw.delete, registers={'front': 100, 'acct_lo': 109, 'acct_hi': 0})
        with self.assertRaises(cp.Conflict):                       # unacknowledged bytes
            self.reg.remove(0, self.sw.delete, registers={'front': 100, 'acct_lo': 100, 'acct_hi': 3})
        self.reg.remove(0, self.sw.delete, registers={'front': 100, 'acct_lo': 100, 'acct_hi': 0})
        self.assertEqual(self.sw.tables, {})

    def test_shared_forwarding_is_reference_counted(self):
        self.install(0)
        self.install(1, o=cp.Endpoint('192.168.10.8', 20000, 64), m=cp.Endpoint('192.168.10.2', 40000, 9))
        self.reg.remove(0, self.sw.delete, closed=True)
        self.assertEqual(sum(1 for k in self.sw.tables if k[0] == 'Ingress.forwarding'), 2)
        self.reg.remove(1, self.sw.delete, closed=True)
        self.assertEqual(self.sw.tables, {})

    def test_endpoints_sharing_one_port_get_one_forwarding_row(self):
        # Two software endpoints in VEPA namespaces on Vision's one test NIC: both are dev_port 9, and the
        # switch reflects 9 -> 9. Direction comes from the 4-tuple in Egress.conn, not from the port.
        o, m = cp.Endpoint('192.168.10.62', 20000, 9), cp.Endpoint('192.168.10.61', 54400, 9)
        rows = self.install(0, o=o, m=m)
        fwd = [(r.key_dict['ig.ingress_port'], r.data_dict['port']) for r in rows if r.table == 'Ingress.forwarding']
        self.assertEqual(fwd, [(9, 9)])
        self.assertEqual(len(self.sw.tables), 5)
        self.reg.remove(0, self.sw.delete, closed=True)
        self.assertEqual(self.sw.tables, {})

    def test_bounds(self):
        with self.assertRaises(ValueError):
            cp.pipe_of(512)
        with self.assertRaises(ValueError):
            self.install(16)


class SourceGuard(unittest.TestCase):
    def test_no_parser_copies_of_header_fields(self):
        """bf-p4c 9.13.1 compiled `m.x = hdr.ip.len` in a parser state to a load of the wrong halfword, with
        no message (TRANSPORT_MAPPER_SPEC.md section 10). Keep that class out by construction."""
        src = (HERE / 'case4_response_path.p4').read_text()
        parsers = re.findall(r'\nparser \w+\(.*?\n\}', src, re.S)
        self.assertEqual(len(parsers), 2)
        for body in parsers:
            self.assertEqual(re.findall(r'\bm\.\w+\s*=\s*[^;]*\bhdr\.', body), [])


if __name__ == '__main__':
    unittest.main()

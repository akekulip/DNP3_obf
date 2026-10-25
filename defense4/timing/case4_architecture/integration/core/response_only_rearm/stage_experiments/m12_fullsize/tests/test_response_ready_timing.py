"""Run emitted P4 in the existing parser/control/deparser and queue scheduler.

The frozen c52 source remains a RED witness, selected with RESPONSE_READY_RED=1.
Traffic-manager timing is the explicit QueueSim assumption, never target evidence.
"""
import hashlib
import os
import re
import json
import subprocess
import struct
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
INTEGRATION = HERE.parents[3]
sys.path[:0] = [str(HERE), str(INTEGRATION / 'read/tests'), str(HERE.parents[2] / 'response_only/hw')]
from t_config import t_units
from m12gen.build import build
from m12gen.common import combined
from queue_sim import QueueSim, ACK_FRAME, RSP_FRAME, REQ_FRAME, OP_FRAME, T0, FORWARD, RELAY, LADDER, OP_LADDER
import test_relay_ts as ts

C52 = HERE.parent / 'ctl_timing_01/evidence/m12p_c52_sdk9132/response_only.p4'


def role(text):
    text = re.sub(r'\bt_(\w+)', r'\1', combined.segment(text, 'T'))
    for name, old, new in (('T_IN', 180, 197), ('HB_RETURN', 181, 198), ('HELD_RETURN', 182, 199)):
        text = re.sub(r'(const PortId_t ' + name + r'\s*=\s*)9w' + str(old) + ';', r'\g<1>9w' + str(new) + ';', text)
    return '#include <core.p4>\n#include <tna.p4>\n' + text


class SourceSim(QueueSim):
    def set_params(self, gap=5_000_000, response_wait_timeout=500_000_000, budget=60000, enabled=1):
        unit = lambda ns: t_units({'gap': ns}, unit_ns=256, grid_ns=512)['gap']
        table = self.src.controls['Ingress'].tables['params']
        table['runtime'] = []
        names = self.src.controls['Ingress'].actions['set_params'][0]
        if len(names) == 5:
            values = [unit(gap), unit(2_400_000), unit(response_wait_timeout), budget, enabled]
        else:
            values = [unit(2_000_000), unit(12_000_000), unit(16_000_000), unit(gap), unit(2_400_000), budget, enabled, unit(12_000_000)]
        self.src.install('params', (), 'set_params', values)

    def emissions(self, frame, port=None):
        # T exports its original behind a typed provenance header consumed by E.
        return [t for t, p, raw in self.emitted if (raw == frame or raw[16:] == frame) and (port is None or p == port)]


class ResponseReadyTiming(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.legacy = C52.read_text()
        cls.text = cls.legacy if os.environ.get('RESPONSE_READY_RED') else build(**ts.FLAGS, relay_ts=True, response_ready_timing=True)[0]
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.tmp.name) / 'timing.p4'
        cls.path.write_text(role(cls.text))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def sim(self, **kw):
        s = SourceSim(source=self.path, **kw)
        s.event(T0 - 10000, 14, REQ_FRAME)
        return s

    def test_missing_response_never_releases_ack_and_expires(self):
        s = self.sim(); s.request(T0); s.ack(T0 + 50000)
        s.run(T0 + 510_000_000)
        self.assertEqual(s.emissions(ACK_FRAME), [])
        self.assertEqual(s.cell('ack_done_reg') >> 16, 2)
        self.assertEqual(s.counter(8), 1)
        self.assertTrue(not s.heap)

    def test_response_without_standalone_ack_expires_without_unshaped_release(self):
        s = self.sim(); s.request(T0); s.response(T0 + 100000)
        s.run(T0 + 510_000_000)
        self.assertEqual(s.emissions(RSP_FRAME), [])
        self.assertEqual(s.counter(8), 1)

    def test_late_response_holds_ack_then_full_d_for_each_supported_d(self):
        for gap in (5_000_000, 10_000_000, 15_000_000, 20_000_000):
            for ackoff, rspoff in ((50000, 98_000_000), (98_000_000, 50000)):
                with self.subTest(gap=gap, ack=ackoff):
                    s = self.sim(gap=gap); s.request(T0); s.ack(T0 + ackoff); s.response(T0 + rspoff)
                    s.run(T0 + 125_000_000)
                    ack, rsp = s.emissions(ACK_FRAME), s.emissions(RSP_FRAME)
                    self.assertEqual((len(ack), len(rsp)), (1, 1))
                    self.assertGreaterEqual(ack[0], T0 + max(ackoff, rspoff))
                    self.assertGreaterEqual(rsp[0] - ack[0], gap)
                    self.assertLess(rsp[0] - ack[0], gap + 200000)
                    self.assertEqual(s.counter(8), 0)

    def test_commit_before_timeout_keeps_full_d_across_deadline(self):
        s = self.sim(gap=20_000_000); s.request(T0); s.ack(T0 + 50000); s.response(T0 + 499_000_000)
        s.run(T0 + 525_000_000)
        ack, rsp = s.emissions(ACK_FRAME), s.emissions(RSP_FRAME)
        self.assertEqual((len(ack), len(rsp)), (1, 1))
        self.assertGreaterEqual(rsp[0] - ack[0], 20_000_000)
        self.assertEqual(s.counter(8), 0)

    def test_expired_exchange_cannot_reopen_with_late_or_new_request_payloads(self):
        s = self.sim(); s.request(T0); s.ack(T0 + 50000)
        s.response(T0 + 501_000_000)
        s.request(T0 + 502_000_000); s.ack(T0 + 503_000_000); s.response(T0 + 504_000_000)
        s.run(T0 + 530_000_000)
        self.assertEqual(s.emissions(ACK_FRAME), [])
        self.assertEqual(s.emissions(RSP_FRAME), [])
        self.assertEqual(s.counter(8), 1)

    def test_stale_and_reset_held_originals_drop(self):
        s = self.sim(); s.request(T0); s.ack(T0 + 50000); s.response(T0 + 100000)
        s.reset(T0 + 200000); s.run(T0 + 30_000_000)
        self.assertEqual(s.emissions(RSP_FRAME), [])

    def test_whole_child_zero_required_and_duplicates_release_once(self):
        s = self.sim(); s.request(T0); s.ack(T0 + 50000); s.response(T0 + 100000, child=1)
        s.run(T0 + 20_000_000)
        self.assertEqual(s.emissions(ACK_FRAME), [])
        s.response(T0 + 21_000_000); s.response(T0 + 22_000_000); s.ack(T0 + 23_000_000)
        s.run(T0 + 35_000_000)
        self.assertEqual(len(s.emissions(ACK_FRAME)), 1)
        self.assertEqual(len(s.emissions(RSP_FRAME)), 1)

    def test_atomic_commit_expiry_boundary_and_full_d_after_commit(self):
        timeout = 2_048_000  # exactly4000 clock grid steps
        for offset, committed in ((-512, True), (0, False), (512, False)):
            with self.subTest(offset=offset):
                s = self.sim(response_wait_timeout=timeout)
                s.request(T0); s.response(T0 + 100000)
                # Genuine held record returned by the traffic manager; epoch1
                # and generation2 are OPEN1 then REQUEST2, not a lap budget.
                held = struct.pack('!BBHI', 14, 0, 2, 1) + ACK_FRAME
                s.at(T0 + 2_048_512 + offset, LADDER, held)
                s.run(T0 + 10_000_000)
                ack, rsp = s.emissions(ACK_FRAME), s.emissions(RSP_FRAME)
                if committed:
                    self.assertEqual((len(ack), len(rsp)), (1, 1))
                    self.assertGreaterEqual(rsp[0] - ack[0], 5_000_000)
                    self.assertEqual(s.counter(8), 0)
                else:
                    self.assertEqual((ack, rsp), ([], []))
                    self.assertEqual(s.counter(8), 1)

    def test_expired_lifetime_recovers_only_through_close_and_new_open(self):
        s = self.sim(response_wait_timeout=2_048_000)
        s.request(T0); s.ack(T0 + 50000)
        s.reset(T0 + 3_000_000)
        s.event(T0 + 4_000_000, 14, REQ_FRAME, epoch=2)
        s.request(T0 + 5_000_000, epoch=2)
        s.ack(T0 + 5_050_000, epoch=2); s.response(T0 + 5_100_000, epoch=2)
        s.run(T0 + 15_000_000)
        self.assertEqual(len(s.emissions(ACK_FRAME)), 1)
        self.assertEqual(len(s.emissions(RSP_FRAME)), 1)
        self.assertEqual(s.counter(8), 1)

    def test_wrong_epoch_response_cannot_open_ack_gate(self):
        s = self.sim(response_wait_timeout=2_048_000)
        s.request(T0); s.ack(T0 + 50000); s.response(T0 + 100000, epoch=2)
        s.run(T0 + 10_000_000)
        self.assertEqual(s.emissions(ACK_FRAME), [])
        self.assertEqual(s.emissions(RSP_FRAME), [])
        self.assertEqual(s.counter(8), 1)

    def test_selected_cli_manifest_seals_only_response_ready_parameters(self):
        if os.environ.get('RESPONSE_READY_RED'):
            self.skipTest('generator ABI checked on selected source only')
        flags = ['--policy', '--c3', 'cimg', '--shapes', 'passthrough', '--two-read', '--reduce',
                 '--ack-retry', '--read-handshake', '--headroom', '--relay', '--relay-sbo',
                 '--relay-ts', '--response-ready-timing']
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run([sys.executable, str(HERE / 'make_m12.py'), tmp] + flags, check=True, capture_output=True)
            p = json.loads((Path(tmp) / 'supported_profile.json').read_text())
            self.assertEqual(p['timing_contract'], 'response_ready_ack_d_v1')
            self.assertEqual(p['timing_ns'], {'D_release_budget': 5000000, 'J_operate_hold': 2400000,
                                            'response_wait_timeout': 500000000})
        with self.assertRaises(ValueError):
            build(**ts.FLAGS, response_ready_timing=True)

    def test_duplicate_held_record_cannot_release_response_twice(self):
        s = self.sim(); s.request(T0); s.ack(T0 + 50000); s.response(T0 + 100000)
        held = struct.pack('!BBHI', 15, 0, 2, 1) + RSP_FRAME
        s.at(T0 + 10_000_000, LADDER, held)
        s.run(T0 + 15_000_000)
        self.assertEqual(len(s.emissions(RSP_FRAME)), 1)
        self.assertEqual(s.counter(3), 1)

    def test_foreign_ingress_and_wrong_token_formats_cannot_expire_live_state(self):
        for port, raw in ((164, bytes(64)), (0, bytes([0xff]) + bytes(63)), (196, bytes([0xff]) + bytes(63))):
            s = self.sim(response_wait_timeout=2_048_000)
            # Remove all blocker delivery: unrelated ingress still cannot
            # arbitrate or count this exchange's timeout in their place.
            s.lose = lambda time, port, qid, raw: raw[0] in (11, 12)
            s.request(T0); s.run(T0 + 1_000_000)
            state = s.cell('ack_done_reg')
            s.at(T0 + 3_000_000, port, raw); s.run(T0 + 4_000_000)
            self.assertEqual(s.cell('ack_done_reg'), state)
            self.assertEqual(s.counter(8), 0)

    def test_operate_original_delayed_beyond_wait_timeout_is_dropped(self):
        s = self.sim()
        held = []
        def delay_original(time, port, qid, raw):
            if raw[0] == 16:
                held.append(raw)
                return True
            return False
        s.lose = delay_original
        s.operate(T0); s.run(T0 + 10_000_000)
        self.assertEqual(len(held), 1)
        # The traffic manager returns the genuine original after an outage.
        # Its ladder budget is still epoch1, never a decrementing lap count.
        s.at(T0 + 501_000_000, OP_LADDER, held[0])
        s.run(T0 + 510_000_000)
        self.assertEqual(s.emissions(OP_FRAME, RELAY), [])
        self.assertEqual(s.counter(8), 1)
        self.assertEqual(s.counter(5), 0)

    def test_old_queued_blocker_during_long_idle_cannot_poison_next_epoch_request(self):
        s = self.sim()
        s.lose = lambda time, port, qid, raw: raw[0] in (11, 12)
        s.request(T0); s.run(T0 + 100000)
        old = next(raw for _, port, qid, raw in s.enqueued if qid == 7 and raw[0] == 11)
        # Return a genuine A blocker to expire A, then close/reopen. No B
        # request exists while A's delayed copy returns after a >500ms idle.
        s.at(T0 + 501_000_000, LADDER, old)
        s.reset(T0 + 502_000_000)
        s.event(T0 + 503_000_000, 14, REQ_FRAME, epoch=2)
        s.at(T0 + 1_008_000_000, 164, bytes(64))
        s.at(T0 + 1_009_000_000, 196, bytes([0xff]) + bytes(63))
        s.token(T0 + 1_009_500_000, gen=1, packet_id=0, profile=0)
        s.at(T0 + 1_010_000_000, LADDER, old)
        s.run(T0 + 1_010_500_000)
        self.assertEqual(s.counter(8), 1, 'idle ownership must not acquire a fresh expiry')
        s.lose = lambda time, port, qid, raw: False
        s.request(T0 + 1_011_000_000, epoch=2)
        s.ack(T0 + 1_011_050_000, epoch=2)
        s.response(T0 + 1_011_100_000, epoch=2)
        s.run(T0 + 1_020_000_000)
        self.assertEqual(len(s.emissions(ACK_FRAME)), 1)
        self.assertEqual(len(s.emissions(RSP_FRAME)), 1)
        self.assertEqual(s.counter(8), 1)

    def test_response_completion_has_one_global_access_before_port_dispatch(self):
        # A source interpreter has one cell per register and cannot reproduce
        # bf-p4c's bank replication across two independently placed accesses.
        # Require one named access point, then validate its actual bank below.
        code = re.sub(r'//[^\n]*|/\*.*?\*/', '', role(self.text), flags=re.S)
        self.assertEqual(code.count('response_completion_access.apply();'), 1)
        self.assertLess(code.index('response_completion_access.apply();'), code.index('if (hdr.clone.isValid())'))
        self.assertNotIn('read_resp_done();', code)

    @unittest.skipUnless(os.environ.get('RESPONSE_READY_CONTEXT'), 'compiled context supplied by compiler gate')
    def test_compiled_completion_domains_each_have_one_physical_bank(self):
        context = json.loads(Path(os.environ['RESPONSE_READY_CONTEXT']).read_text())
        for name in ('ack_done_reg', 'resp_done_reg', 'op_done_reg'):
            with self.subTest(register=name):
                registers = [table for table in context['tables'] if table.get('table_type') == 'stateful'
                             and table['name'].endswith('.' + name)]
                self.assertEqual(len(registers), 1)
                self.assertEqual(len(registers[0]['stage_tables']), 1, registers[0]['stage_tables'])

    def test_response_replay_after_release_passes_before_any_master_completion_ack(self):
        s = self.sim(); s.request(T0); s.ack(T0 + 50000); s.response(T0 + 100000)
        s.run(T0 + 10_000_000)
        self.assertEqual(len(s.emissions(RSP_FRAME)), 1)
        # No master ACK is injected between original release and this replay.
        s.response(T0 + 11_000_000); s.run(T0 + 12_000_000)
        self.assertEqual(len(s.emissions(RSP_FRAME)), 2)
        self.assertEqual(s.counter(3), 1, 'replay must not create a second original release')
        self.assertEqual(s.counter(4), 0)

    def test_operate_request_retains_independent_j(self):
        s = self.sim(); s.operate(T0); s.run(T0 + 5_000_000)
        emitted = s.emissions(OP_FRAME, RELAY)
        self.assertEqual(len(emitted), 1)
        self.assertGreaterEqual(emitted[0], T0 + 2_400_000)

    def test_native_late_ack_after_response_routes_to_t_with_exact_request_ack_boundary(self):
        import test_n_read_shapes as shared
        n = shared.n_source(self.text)
        wire = ts.packet(b'', reverse=True, flags=16)
        for phase, length in ((5, 91), (5, 134), (5, 49), (10, 49)):
            for boundary in (146, 147):
                n.begin_pass(64); n.packet_parser(wire)
                n.env.update({'m.direction': 2, 'm.kind': 10, 'm.client': boundary,
                              'm.server': 900 + length, 'm.observed': phase << 16 | 1,
                              'm.matched': 0})
                n.table('sequence_diff'); n.table('sequence_guard'); n.table('first_event')
                if boundary == 146:
                    self.assertEqual(n.env.get('hdr.event.event'), 0x010a, (phase, length))
                else:
                    self.assertNotEqual(n.env.get('hdr.event.event'), 0x010a)

    def test_unselected_build_is_exact_frozen_source(self):
        plain, _ = build(**ts.FLAGS, relay_ts=True)
        self.assertEqual(hashlib.sha256(plain.encode()).hexdigest(), '8f37f70240ffa03daf887349e5e52a6abf7e32eb4b43ec559e35077902e3dce4')
        self.assertEqual(plain, self.legacy)
        self.assertEqual(combined.segment(self.text, 'E'), combined.segment(self.legacy, 'E'))


if __name__ == '__main__':
    unittest.main()

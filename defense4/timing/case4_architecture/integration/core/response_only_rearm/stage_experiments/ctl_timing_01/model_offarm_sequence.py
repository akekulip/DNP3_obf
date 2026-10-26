"""Diagnostic (not a gate driver): the physical 'off' arm on the model -- T off AND padding off, native frames.

rc01_hw_c68_20261025_01 (c68, D5): in the off arm the relay's first integrity READ response (134 octets, after
mixed READ, SELECT, OPERATE) entered the switch (port 64 RX) and never reached the master (port 9 TX); c67's off
arm forwarded it. No gate driver runs T off with padding off over SBO, so this replays that schedule: per cycle a
mixed READ, SELECT, OPERATE, integrity READ, SELECT, OPERATE, every frame expected to cross unchanged.
"""
import hashlib
import os
import traceback
from pathlib import Path

from model_relay_sbo import RelayGate, mp

CYCLES = 4
# the physical master acknowledges each response only on its next request (out.pcap: seq 115:142 ack 190)
PIGGYBACK = os.environ.get('OFFARM_PIGGYBACK', '1') == '1'


class OffArmGate(RelayGate):
    def configure(self):
        """PacketGate.configure with the installer's --pad-enable 0 rows; T stays off (enabled=0)."""
        h, m, cp, rp = self.h, self.m, self.cp, mp.rp
        m.enable_ports(self.ports + h.FRONT_LOOPS)
        m.enable_ports([p for p in h.LOOP_PORTS if p not in h.FRONT_LOOPS])
        self.reflectors = [h.Reflector(p) for p in h.FRONT_LOOPS]
        for reflector in self.reflectors:
            reflector.start()
        rows = cp.n_ports_rows(self.master.dev_port, self.relay.dev_port, self.master.ip_int, self.relay.ip_int,
                               n_ack_return=self.pm.n_ack_return)
        rows += cp.n_connection_rows(self.relay, self.master, n_ack_return=self.pm.n_ack_return)
        rows += cp.n_read_rows(self.relay, self.master)
        for table, key, action, data, priority in rows:
            m.add('p0.n_' + table, dict(key), 'n_' + action, dict(data), priority)
        dc = dict(zip(('index', 'code', 'repeat', 'on', 'off'), self.v.decoy_config()))
        for source, dest in ((self.master, self.relay), (self.relay, self.master)):
            key = {'hdr.ip.src': source.ip_int, 'hdr.ip.dst': dest.ip_int,
                   'hdr.tcp.sport': source.port, 'hdr.tcp.dport': dest.port}
            m.add('p0.n_Ingress.data_connection', key, 'n_Ingress.configure', dc)
        for table, key, action, data, priority in cp.e_conn_rows(0, self.relay, self.master, pad_enable=False,
                                                                 n_ack_return=self.pm.n_ack_return):
            m.add('p0.r_' + table, dict(key), 'r_' + action, dict(data), priority)
        if rp.POLICY:
            for table, key, action, data, priority in cp.p1_pad_rows(self.relay, self.master, False):
                m.add(table, dict(key), action, dict(data), priority)
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params',
                      dict(da=50_000_000, readiness=400_000_000, cap=16_000_000,
                           gap=5_000_000, op_j=2_400_000, budget=240_000, enabled=0))
        from model_relay_sbo import select_templates, HERE
        self.templates, self.template_path = select_templates(HERE.parent / 'read_complete_01/vectors', rp.SHAPES)
        self.seqs = dict(master=0, app=0, server=0)

    def native_exchange(self, tag, cls, cseq, nsq, fc=3):
        request, native, _image = self.frames(cls, 0, fc)
        frame = self.v.packet(24, cseq, nsq, payload=request)
        self.exchange(tag + '_request', frame, frame)
        cseq += len(request)
        ack = self.v.packet(16, nsq, cseq, reverse=True)
        self.exchange(tag + '_ACK', ack, ack, reverse=True)
        response = self.v.packet(24, nsq, cseq, reverse=True, payload=native)
        self.exchange(tag + '_native_response', response, response, reverse=True)
        nsq += len(native)
        if not PIGGYBACK:
            master_ack = self.v.packet(16, cseq, nsq)
            self.exchange(tag + '_master_ACK', master_ack, master_ack)
        return cseq, nsq

    def run(self):
        meta = self.report.record['meta']
        meta.update(planned_cycles=CYCLES, completed_cycles=0)
        cseq, nsq, _wsq = self.handshake(10000, 20000, 'off_')
        for cycle in range(CYCLES):
            for cls in ('mixed', 'integrity'):
                tag = 'cy%d_%s' % (cycle, cls)
                cseq, nsq = self.native_exchange(tag + '_READ', cls, cseq, nsq)
                cseq, nsq = self.native_exchange(tag + '_SELECT', 'CONTROL', cseq, nsq, fc=3)
                cseq, nsq = self.native_exchange(tag + '_OPERATE', 'CONTROL', cseq, nsq, fc=4)
            meta['completed_cycles'] = cycle + 1


def main():
    h = mp.load('_relay_helpers', Path(__file__).resolve().parents[3] / 'response_only/model_drive_composite.py')
    cp = mp.load('_relay_cp', Path(__file__).resolve().parents[2] / 'cp.py')
    report = h.Report(os.environ['PROG'], physical=False,
                      scope='diagnostic: physical off arm (T off, padding off) mixed/SBO/integrity sequence',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    gate = OffArmGate(report, h.Model(ports=[], enable=False), h, cp)
    try:
        gate.configure(); gate.run()
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    report.add('all_cycles_completed', CYCLES, report.record['meta'].get('completed_cycles', 0))
    return 0 if report.finish(Path(os.environ['OUT']) / 'offarm_sequence_results.json') else 1


if __name__ == '__main__':
    raise SystemExit(main())

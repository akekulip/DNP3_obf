"""Deterministic busy FIN race probe. Model only; no physical endpoint.

Seed the N work cell busy after a genuine handshake, inject both TCP close directions,
release the cell, then require immediate complete close and a same-tuple reconnect.
The evidence retains before/after epoch, owner, work and retry counters; a run without
busy_retry_rst is explicitly not a reproduction of c29's incident.
"""
import hashlib
import json
import os
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'seg61_02'))
import model_packets as mp


def main():
    h = mp.load('_fin_helpers', HERE.parents[2] / 'response_only/model_drive_composite.py')
    cp = mp.load('_fin_cp', HERE.parents[1] / 'cp.py')
    report = h.Report(os.environ['PROG'], physical=False, scope='c29 busy FIN race and same-port recovery',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    inputs = json.loads(Path(os.environ['PORT_MAP']).read_text())
    actual = inputs.get('supported_profile', {}).get('endpoint_profile') == 'sel751'
    if actual:
        from model_relay_sbo import RelayGate
    gate = (RelayGate if actual else mp.PacketGate)(report, h.Model(ports=[], enable=False), h, cp)
    m, v = gate.m, gate.v
    def snapshot():
        state = {n: m.register_read('p0.n_Ingress.' + n, 0, pipe=0)
                 for n in ('epoch', 'retry_epoch', 'owner', 'work.work')}
        state['busy'] = [h.scalar(m.register_read('p0.n_Ingress.count_busy', i, pipe=0)) for i in range(8)]
        return state
    report.record['meta'].update(planned_connections=3, attempted_connections=0, completed_connections=0, connections=[])
    gate.configure()
    for connection in range(3):
        c, s, w = None, None, None
        master_half_close_accepted = False
        point = {'connection': connection, 'status': 'attempted'}
        report.record['meta']['connections'].append(point)
        report.record['meta']['attempted_connections'] += 1
        case_start = len(report.record['cases'])
        try:
            c, s, w = gate.handshake(70000 + connection * 100000, 90000 + connection * 100000, 'race_%d_' % connection)
            if actual:
                for cls in ('mixed', 'integrity'):
                    c, s, w = gate.actual_exchange('c%d_%s' % (connection, cls), cls, c, s, w, k=connection)
                    c, s, w = gate.actual_exchange('c%d_SELECT_%s' % (connection, cls), 'CONTROL', c, s, w, fc=3)
                    c, s, w = gate.actual_exchange('c%d_OPERATE_%s' % (connection, cls), 'CONTROL', c, s, w, fc=4)
            before = snapshot()
            point['before'] = before
            fin = v.packet(17, c, w)
            gate.exchange('master_half_close_FIN', fin, v.packet(17, c, s))
            master_half_close_accepted = True
            half = snapshot()
            point['after_master_half_close'] = half
            # The physical trace's next pair is the relay's pure ACK followed by its FIN.
            # Keep the work cell occupied until the FIN has taken the actual retry path.
            m.register_write('p0.n_Ingress.work.work', 0,
                             {'n_Ingress.work.work.generation': 0x7ffffffe, 'n_Ingress.work.work.phase': 1}, pipe=0)
            m.drain(gate.ports)
            peer_ack = v.packet(16, s, c + 1, reverse=True)
            peer = v.packet(17, s, c + 1, reverse=True)
            m.send(gate.relay.dev_port, peer_ack)
            m.send(gate.relay.dev_port, peer)
            anchor, deadline = None, time.monotonic() + 3
            while time.monotonic() < deadline:
                current = snapshot()
                if current['busy'][2] > half['busy'][2]:
                    anchor = current
                    break
            point['busy_anchor_before_unlock'] = anchor
            m.register_write('p0.n_Ingress.work.work', 0,
                             {'n_Ingress.work.work.generation': 0x7ffffffe, 'n_Ingress.work.work.phase': 4}, pipe=0)
            got = m.capture(gate.ports, timeout=3, quiet=.3)
            after = snapshot()
            point['after_race'] = after
            point['received'] = {str(p): [f.hex() for f in fs] for p, fs in got.items()}
            report.add('busy_retry_rst_anchor_before_unlock', True, anchor is not None)
            report.add('half_close_keeps_current_retry_epoch', h.scalar(half['epoch']), h.scalar(half['retry_epoch']))
            report.add('same_epoch_retry_not_stale', 0, after['busy'][4] - half['busy'][4])
            report.add('retry_not_exhausted', 0, after['busy'][3] - half['busy'][3])
            report.add('relay_FIN', 1, sum(h.same_frame(f, v.packet(17, w, c + 1, reverse=True), peer) for f in got.get(gate.master.dev_port, [])))
            gate.exchange('c%d_last_ACK' % connection, v.packet(16, c + 1, w + 1), v.packet(16, c + 1, s + 1))
            qualified = all(row['ok'] for row in report.record['cases'][case_start:])
            point['status'] = 'completed' if qualified else 'failed_checks'
            report.record['meta']['completed_connections'] += int(qualified)
        except Exception:
            point['status'] = 'failed'
            report.add('c%d_exception' % connection, 'none', traceback.format_exc(), ok=False)
            # A bounded reset allows the remaining planned connection attempts to run.
            try:
                if c is not None and w is not None:
                    m.send(gate.master.dev_port, v.packet(20, c + int(master_half_close_accepted), w))
                    m.capture(gate.ports, timeout=2, quiet=.3)
            except Exception:
                point['reset_exception'] = traceback.format_exc()
    report.add('all_three_planned_connections_completed', 3, report.record['meta']['completed_connections'])
    return 0 if report.finish(Path(os.environ['OUT']) / 'fin_busy_results.json') else 1

if __name__ == '__main__':
    raise SystemExit(main())

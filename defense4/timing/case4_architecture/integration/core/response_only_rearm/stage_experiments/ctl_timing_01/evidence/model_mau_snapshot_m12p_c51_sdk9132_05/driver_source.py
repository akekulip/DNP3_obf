"""Diagnostic: prove hw/mau_snapshot.py on the model with the silicon smoke frames. NOT a gate driver.

Replays the rc01_hw_c51_20261024_09 handshake (spaced), arms the N-ingress snapshot on the READ's
post-lap pass (m.packet_kind 9 at ingress port 48), sends the READ and records every stage.
"""
import hashlib
import importlib.util
import os
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'seg61_02'))
import model_packets as mp
import model_hw_replay as replay

SPEC = 'start=0,end=10,m.packet_kind=9/0xff,m.lap=1/1,m.stage=0/3'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    h = mp.load('_mau_helpers', HERE.parents[2] / 'response_only/model_drive_composite.py')
    cp = mp.load('_mau_cp', HERE.parents[1] / 'cp.py')
    sys.path.insert(0, str(HERE.parents[2] / 'response_only/hw'))
    from switch import Switch
    mau = load('_mau_snapshot', HERE.parents[1] / 'hw/mau_snapshot.py')
    out = Path(os.environ['OUT'])
    bfrt = Path(os.environ['PORT_MAP']).parent / 'compile_local/out/bfrt.json'
    report = h.Report(os.environ['PROG'], physical=False, qualification_driver=False, spec=SPEC,
                      scope='diagnostic: MAU snapshot tool proven on the model',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    try:
        gate = mp.PacketGate(report, h.Model(ports=[], enable=False), h, cp)
        gate.master = h.rp.Endpoint('192.168.10.1', 60000, 9)
        gate.configure()
        for name, side, frame in replay.FRAMES[:3]:
            sent = replay.wire_checksum(bytes.fromhex(frame)) if side == 'master' else bytes.fromhex(frame)
            gate.m.exchange(gate.master.dev_port if side == 'master' else gate.relay.dev_port, sent, gate.ports,
                            timeout=3, quiet=.3)
        # The driver's client owns the program binding; reuse it through the switch helper's methods.
        sw = Switch.__new__(Switch)
        sw.iface, sw.bi, sw.sw_read = gate.m.iface, gate.m.info, set()
        spec = mau.parse(SPEC)
        armed = mau.arm(sw, spec, bfrt)
        report.add('snapshot_armed', 'ARMED', str(armed['state']), ok='ARMED' in str(armed['state']))
        got = gate.m.exchange(gate.master.dev_port, replay.wire_checksum(bytes.fromhex(replay.FRAMES[3][2])),
                              gate.ports, timeout=3, quiet=.5)
        report.add('READ_forwarded', 1, len(got.get(gate.relay.dev_port, [])))
        snap = mau.read(sw, spec)
        report.record['meta']['snapshot'] = snap
        report.add('snapshot_full', 'FULL', str(snap['state']), ok='FULL' in str(snap['state']))
        hits = {s: [(t.get('table_name'), t.get('table_hit')) for t in (d or {}).get('table_info', [])]
                for s, d in snap['stages'].items()}
        report.record['meta']['stage_tables'] = hits
        names = [n for tables in hits.values() for n, hit in tables if hit]
        report.add('snapshot_sees_first_read_request', True, any('first_event' in str(n) for n in names), names=names)
        report.add('snapshot_deleted', True, snap.get('deleted'))
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    return 0 if report.finish(out / 'mau_snapshot_results.json') else 1


if __name__ == '__main__':
    raise SystemExit(main())

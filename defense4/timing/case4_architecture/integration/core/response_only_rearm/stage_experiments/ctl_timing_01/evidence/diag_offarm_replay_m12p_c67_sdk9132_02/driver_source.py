"""Diagnostic (not a gate driver): the exact silicon frames of the failing c68 off-arm trial, replayed on the model.

rc01_hw_c68_20261025_01 and _05 (c68, D5, off arm: T off, padding off) both lost every relay frame after the relay's
ACK of the first integrity READ. offarm_replay_frames_c68_05.json holds the trial's master (out.pcap) and relay
(in.pcap) frames in capture order up to that ACK, then the relay's 134-octet integrity response (c67 trial
rc01_hw_c67_20261025_03 off arm, re-sequenced onto this connection; the c68 one never reached the master NIC).
Master frames get their checksums restored (the NIC TX capture carries offload partials). OFFARM_TIGHT=1 sends
every frame back to back, as close to the silicon spacing as the model allows; otherwise each frame is one exchange.
"""
import hashlib
import json
import os
import traceback
from pathlib import Path

from model_hw_replay import wire_checksum
from model_offarm_sequence import OffArmGate, mp

HERE = Path(__file__).resolve().parent
FRAMES = HERE / 'offarm_replay_frames_c68_05.json'


def main():
    h = mp.load('_offarm_helpers', HERE.parents[2] / 'response_only/model_drive_composite.py')
    cp = mp.load('_offarm_cp', HERE.parents[1] / 'cp.py')
    tight = os.environ.get('OFFARM_TIGHT') == '1'
    report = h.Report(os.environ['PROG'], physical=False, qualification_driver=False,
                      scope='diagnostic: c68 off-arm silicon frames replayed on the model (tight=%s)' % tight,
                      frames_sha256=hashlib.sha256(FRAMES.read_bytes()).hexdigest(),
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    frames = json.loads(FRAMES.read_text())
    try:
        gate = OffArmGate(report, h.Model(ports=[], enable=False), h, cp)
        gate.master = h.rp.Endpoint('192.168.10.1', 60000, 9)       # the hardware tuple
        gate.configure()
        sent = [(item['side'], wire_checksum(bytes.fromhex(item['hex'])) if item['side'] == 'master'
                 else bytes.fromhex(item['hex'])) for item in frames]
        if tight:
            gate.m.drain(gate.ports)
            for side, frame in sent:
                gate.m.send(gate.master.dev_port if side == 'master' else gate.relay.dev_port, frame)
            got = gate.m.capture(gate.ports, timeout=5, quiet=1.0)
            to_relay, to_master = len(got.get(gate.relay.dev_port, [])), len(got.get(gate.master.dev_port, []))
            want = (sum(side == 'master' for side, _ in sent), sum(side == 'relay' for side, _ in sent))
            report.add('tight_all_frames_forwarded', list(want), [to_relay, to_master],
                       received={str(p): [f.hex() for f in fs] for p, fs in got.items()})
        else:
            for index, (side, frame) in enumerate(sent):
                got = gate.m.exchange(gate.master.dev_port if side == 'master' else gate.relay.dev_port, frame,
                                      gate.ports, timeout=3, quiet=.3)
                forward = gate.relay.dev_port if side == 'master' else gate.master.dev_port
                report.add('frame_%02d_%s_%d_forwarded' % (index, side, len(frame)), 1, len(got.get(forward, [])),
                           ok=len(got.get(forward, [])) == 1, received={str(p): [f.hex() for f in fs] for p, fs in got.items()})
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    return 0 if report.finish(Path(os.environ['OUT']) / 'offarm_replay_results.json') else 1


if __name__ == '__main__':
    raise SystemExit(main())

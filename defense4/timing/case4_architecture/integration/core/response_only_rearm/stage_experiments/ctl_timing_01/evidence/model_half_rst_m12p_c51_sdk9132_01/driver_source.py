"""Diagnostic: run only seg61_02 PacketGate.half_closed_rst (sel751). Model only; no physical endpoint.

Reproduces (c50) or checks (c51+) the half-closed RSTACK case without the rest of the
packets driver. It is a counterexample record, NOT a qualification driver: the required
gate runs the same method at the end of the full `packets` driver.
"""
import hashlib
import json
import os
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'seg61_02'))
import model_packets as mp


def main():
    h = mp.load('_half_rst_helpers', HERE.parents[2] / 'response_only/model_drive_composite.py')
    cp = mp.load('_half_rst_cp', HERE.parents[1] / 'cp.py')
    out = Path(os.environ['OUT'])
    report = h.Report(os.environ['PROG'], physical=False, scope='diagnostic: half-closed RSTACK counterexample only',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      qualification_driver=False)
    inputs = json.loads(Path(os.environ['PORT_MAP']).read_text())
    if not mp.rp.SEL751 or inputs.get('supported_profile', {}).get('endpoint_profile') != 'sel751':
        raise SystemExit('half_rst is defined for the sel751 profile only')
    gate = None
    try:
        gate = mp.PacketGate(report, h.Model(ports=[], enable=False), h, cp)
        gate.configure()
        gate.half_closed_rst(*gate.handshake(70000, 90000, 'half_rst_'))
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    if gate is not None:
        for name, packets in gate.captures.items():
            mp.pcaptk.write_pcap(str(out / (name + '.pcap')), packets)
    return 0 if report.finish(out / 'half_rst_results.json') else 1


if __name__ == '__main__':
    raise SystemExit(main())

"""Diagnostic: determine which p0.snapshot trigger writes the 9.13.2 driver accepts. Model only, not a gate."""
import hashlib
import importlib.util
import os
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'seg61_02'))
import model_packets as mp


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    h = mp.load('_probe_helpers', HERE.parents[2] / 'response_only/model_drive_composite.py')
    cp = mp.load('_probe_cp', HERE.parents[1] / 'cp.py')
    sys.path.insert(0, str(HERE.parents[2] / 'response_only/hw'))
    from switch import Switch, oneline
    mau = load('_probe_mau', HERE.parents[1] / 'hw/mau_snapshot.py')
    out = Path(os.environ['OUT'])
    bfrt = Path(os.environ['PORT_MAP']).parent / 'compile_local/out/bfrt.json'
    report = h.Report(os.environ['PROG'], physical=False, qualification_driver=False,
                      scope='diagnostic: snapshot trigger write semantics',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    meta = report.record['meta']
    try:
        gate = mp.PacketGate(report, h.Model(ports=[], enable=False), h, cp)
        gate.configure()
        sw = Switch.__new__(Switch)
        sw.iface, sw.bi, sw.sw_read = gate.m.iface, gate.m.info, set()
        widths = mau.trigger_widths(bfrt)
        cfg, trig = sw.table(mau.CFG), sw.table(mau.TRIGGER)
        cfg_key = [sw.key(cfg, [('start_stage', 0, None), ('end_stage', 10, None)])]
        cfg.entry_add(sw.target(0), cfg_key, [sw.data(cfg, [('thread', 'INGRESS')])])
        live = sw.table('p0.snapshot.ingress_liveness')
        meta['liveness'] = {}
        for field in ('m.packet_kind', 'ig.ingress_port', 'hdr.tcp.dport', 'm.stage'):
            try:
                meta['liveness'][field] = sw.get('p0.snapshot.ingress_liveness', 0, [('field_name', field, None)])
            except Exception as error:
                meta['liveness'][field] = 'error: ' + oneline(error)
        meta['trigger_before'] = sw.get(mau.TRIGGER, 0, [('stage', 0, None)])

        def attempt(label, fields, op='mod'):
            try:
                key = [sw.key(trig, [('stage', 0, None)])]
                data = [sw.data(trig, fields)]
                (trig.entry_mod if op == 'mod' else trig.entry_add)(sw.target(0), key, data)
                result = 'ok'
            except Exception as error:
                result = oneline(error)
            meta.setdefault('attempts', {})[label] = result
            report.add('attempt_' + label, 'recorded', 'recorded', result=result)

        e = mau.encode
        attempt('enable_only', [('enable', True)])
        attempt('packet_kind_only', [('trig.m.packet_kind', e(9, 8)), ('trig.m.packet_kind_mask', e(0xff, 8))])
        attempt('ingress_port_only', [('trig.ig.ingress_port', e(48, 9)), ('trig.ig.ingress_port_mask', e(0x1ff, 9))])
        attempt('dport_only', [('trig.hdr.tcp.dport', e(20000, 16)), ('trig.hdr.tcp.dport_mask', e(0xffff, 16))])
        attempt('packet_kind_int', [('trig.m.packet_kind', 9), ('trig.m.packet_kind_mask', 0xff)])
        attempt('add_packet_kind', [('enable', True), ('trig.m.packet_kind', e(9, 8)),
                                    ('trig.m.packet_kind_mask', e(0xff, 8))], op='add')
        meta['trigger_after'] = sw.get(mau.TRIGGER, 0, [('stage', 0, None)])
        cfg.entry_del(sw.target(0), cfg_key)
        meta['widths'] = {k: widths[k] for k in ('m.packet_kind', 'ig.ingress_port', 'hdr.tcp.dport')}
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    return 0 if report.finish(out / 'mau_probe_results.json') else 1


if __name__ == '__main__':
    raise SystemExit(main())

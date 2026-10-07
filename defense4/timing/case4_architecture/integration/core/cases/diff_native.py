#!/usr/bin/env python3
"""Model-vs-source differential for native_binding.p4 (ARCH integration/connection/binding).

For every scenario the same frames and the same preset registers go through
  (a) the whole-program source interpreter (integration/core/harness), and
  (b) the compiled program on the local Tofino-1 model (bfrt gRPC preset, veth inject/capture),
and the emitted frames, pass count and every register are compared after every step.
A step is MATCH only when all three agree. Env: ONLY=<substring> filters scenarios, EPOCH0=1 runs the
non-terminating epoch-0 scenario alone (the model has no recirculation limit; the harness stops at 8)."""
import os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); CORE = os.path.dirname(HERE)
ARCH = os.path.abspath(os.path.join(CORE, '..', '..'))
sys.path[:0] = [os.path.join(CORE, 'harness'), os.path.join(CORE, 'harness', 'tests'), CORE, HERE,
                os.path.join(ARCH, 'framework', 'size'), os.path.join(ARCH, '..', 'framework', 'size'),
                os.path.join(ARCH, 'integration', 'connection'), os.path.join(ARCH, 'protocol', 'tests'),
                os.path.join(ARCH, 'protocol', 'egress'), os.path.join(ARCH, 'protocol', 'egress', 'tests'),
                os.path.join(ARCH, 'tests'), os.path.join(ARCH, 'integration', 'connection', 'binding', 'tests')]
import json
from driver import Pipeline
import vectors as V
import read_support as RS
import re
import reference as REF
from model_driver import Model, Report, same_frame

from pathlib import Path
NATIVE_SRC = Path(os.environ.get('NATIVE_SRC', os.path.join(ARCH, 'integration/evidence/native_11/source/native_binding.p4')))
SRC_TEXT = NATIVE_SRC.read_text()   # pinned snapshot: the working-tree source is being edited by another agent
OUT = os.environ['OUT']
MODEL_OUT = os.path.join(OUT, 'model.out')


def new_harness():
    return RS.ReadPipeline(text=SRC_TEXT)


# ------------------------------------------------------------------ model side
HANDOFF = int(re.search(r'const\s+PortId_t\s+READ_HANDOFF_PORT\s*=\s*9w(\d+)', SRC_TEXT)[1])
m = Model(ports=[1, 2, 9, HANDOFF])
print('port enable errors:', m.port_errors, 'handoff port', HANDOFF)
for ing, eg in ((1, 2), (2, 1), (68, 68)):
    m.add('Ingress.ports', {'ig.ingress_port': ing}, 'Ingress.route', {'port': eg})
for src, dst, sp, dp, kind, port in V.topology().flows:
    m.add('Ingress.connection', {'hdr.ip.src': src, 'hdr.ip.dst': dst, 'hdr.tcp.sport': sp, 'hdr.tcp.dport': dp},
          'Ingress.%s_flow' % kind, {'port': port})
for src, dst, sp, dp, index, code, repeat, on, off in V.topology().data_connections:
    m.add('Ingress.data_connection', {'hdr.ip.src': src, 'hdr.ip.dst': dst, 'hdr.tcp.sport': sp, 'hdr.tcp.dport': dp},
          'Ingress.configure', {'index': index, 'code': code, 'repeat': repeat, 'on': on, 'off': off})


for a, b, sp, dp, dst, src in ((V.CLIENT, V.SERVER, V.CLIENT_PORT, V.SERVER_PORT, 0x0000, 0x0100),
                               (V.SERVER, V.CLIENT, V.SERVER_PORT, V.CLIENT_PORT, 0x0100, 0x0000)):
    m.add('Ingress.read_connection', {'hdr.ip.src': a, 'hdr.ip.dst': b, 'hdr.tcp.sport': sp, 'hdr.tcp.dport': dp},
          'Ingress.read_configure', {'dst': dst, 'src': src})

def norm(port, data):
    """tev t0q (bytes 8..12 of the handoff frame) is a hardware timestamp: masked for the comparison, checked separately."""
    return data[:8] + b'\0\0\0\0' + data[12:] if port == HANDOFF else data


def reg_target(path, name):
    return 'Ingress.work.work' if path == 'work' else 'Ingress.' + name


def write_cells(cells):
    for (path, name), val in cells.items():
        t = reg_target(path, name)
        if isinstance(val, dict):
            m.register_write(t, 0, {'%s.%s' % (t, k): v for k, v in val.items()})
        else:
            m.register_write(t, 0, {t + '.f1': val})


def read_cells(cells):
    out = {}
    for (path, name), val in cells.items():
        t = reg_target(path, name)
        d = m.register_read(t, 0)
        if isinstance(val, dict):
            out[(path, name)] = {k: d['%s.%s' % (t, k)][0] for k in val}
        else:
            out[(path, name)] = d[t + '.f1'][0]
    return out


def harness_cells(h):
    return {k: (dict(v[0]) if isinstance(v[0], dict) else v[0]) for k, v in h.src.cells.items()}


def model_inject(port, frame):
    start = os.path.getsize(MODEL_OUT) if os.path.exists(MODEL_OUT) else 0
    out = m.exchange(port, frame, [1, 2, 9, HANDOFF], timeout=1.2, quiet=0.4)
    time.sleep(0.3)
    with open(MODEL_OUT, 'rb') as f:
        f.seek(start)
        seg = f.read().decode('latin-1')
    passes = seg.count('Ingress Pkt from port')
    return [(p, x) for p, v in out.items() for x in v], passes


rep = Report(os.environ['PROG'], ports=m.ports, harness_source_sha=__import__('hashlib').sha256(SRC_TEXT.encode()).hexdigest())
CLASS = {}


def scenario(name, preset, steps, port_of=None):
    """preset: kwargs for Pipeline.preset; steps: [(label, port, frame)]."""
    if os.environ.get('ONLY') and (os.environ['ONLY'] != name if os.environ.get('EXACT') else os.environ['ONLY'] not in name):
        return
    if bool(os.environ.get('EPOCH0')) != name.startswith('epoch0'):
        return
    if name.startswith('order_') and not os.environ.get('ONLY'):
        return        # these start endless recirculation in the model: run each isolated with ONLY=<name> EXACT=1
    h = new_harness()
    preset = dict(preset); app = preset.pop('app', None)
    h.preset(**preset)
    if app is not None:
        h.src.cells[('', 'read_app')][0] = app
    start = harness_cells(h)
    write_cells(start)
    for i, (label, port, frame) in enumerate(steps):
        ho = h.inject(port, frame)
        hcells = harness_cells(h)
        got, passes = model_inject(port, frame)
        mcells = read_cells(start)
        # frames
        h_frames = [(p, f) for p, f in ho.emitted]
        frame_ok = (len(got) == len(h_frames) and all(
            any(gp == hp and same_frame(norm(gp, gf), norm(hp, hf), frame) for gp, gf in got) for hp, hf in h_frames))
        stray = [(p, x.hex()) for p, x in got if not any(p == hp and same_frame(norm(p, x), norm(hp, hf), frame) for hp, hf in h_frames)]
        t0q_model = [int.from_bytes(x[8:12], 'big') for p, x in got if p == HANDOFF]
        t0q_ok = all(t & 0xff == 0 for t in t0q_model)
        diffs = {('/'.join(k)): (mcells[k], hcells[k]) for k in hcells if mcells[k] != hcells[k]}
        pass_ok = passes == ho.passes
        ok = frame_ok and pass_ok and not diffs and t0q_ok
        wk = mcells[('work', 'work')]
        rep.add('%s/%d:%s' % (name, i, label), 'harness', 'MATCH' if ok else 'MISMATCH', ok=ok,
                in_port=port, frame=frame,
                harness=dict(emitted=[(p, f.hex()) for p, f in h_frames], dropped=ho.dropped, drop_reason=ho.drop_reason, passes=ho.passes),
                model=dict(emitted=[(p, x.hex()) for p, x in got], passes=passes),
                frames_equal=frame_ok, passes_equal=pass_ok, model_t0q=t0q_model, t0q_low_byte_zero=t0q_ok, register_diffs=diffs, stray_model_frames=stray,
                model_work_record=wk, model_work_free=(wk['phase'] == 4), model_registers=mcells,
                harness_registers=hcells)
        # keep the model and harness aligned for the next step even after a mismatch
        if not ok:
            write_cells(hcells)


WIT = (('lost_SYN_native_retry', 2, 100, 0, False, 1500, 0x20001, 101, 0),
       ('lost_SYNACK_native_retry', 18, 900, 101, True, 1500, 0x40001, 101, 901),
       ('lost_final_ACK_native_retry', 16, 101, 901, False, None, 0x50001, 101, 901),
       ('established_client_ACK', 16, 136, 958, False, None, 0x90001, 136, 958))
for label, flags, seq, ack, reverse, mss, owner, client, server in WIT:
    scenario('witness_' + label, dict(owner=owner, client=client, server=server, epoch=17),
             [('frame', 2 if reverse else 1, V.frame(flags, seq, ack, reverse, mss))])

SEL = V.native_select()
SELECT_FR = V.packet(24, 101, 901, payload=SEL)
for owner in (0x40001, 0x50001):
    scenario('select_first_contact_owner%x' % owner, dict(owner=owner, client=101, server=901, epoch=17), [('select', 1, SELECT_FR)])
scenario('select_replay_after_accept', dict(owner=0x40001, client=101, server=901, epoch=17),
         [('select', 1, SELECT_FR), ('select_replay', 1, SELECT_FR)])
OPERATE_FR = V.packet(24, 136, 901, payload=V.native_select(app=1, fc=4))
scenario('select_then_operate', dict(owner=0x40001, client=101, server=901, epoch=17),
         [('select', 1, SELECT_FR), ('operate', 1, OPERATE_FR), ('operate_replay', 1, OPERATE_FR)])
scenario('operate_first_contact_owner90001', dict(owner=0x90001, client=136, server=901, epoch=17), [('operate', 1, OPERATE_FR)])
try:
    import test_carving as TC
    RESP = TC.response()
    RESP_FR = V.packet(24, 901, 136, reverse=True, payload=RESP)
    scenario('select_then_response', dict(owner=0x40001, client=101, server=901, epoch=17),
             [('select', 1, SELECT_FR), ('response', 2, RESP_FR), ('response_replay', 2, RESP_FR)])
    scenario('response_first_contact', dict(owner=0x90001, client=136, server=901, epoch=17), [('response', 2, RESP_FR)])
except Exception as exc:  # recorded, not hidden
    rep.record['meta']['response_fixture_error'] = '%s: %s' % (type(exc).__name__, exc)

# full handshake then SELECT, from a free connection
scenario('full_handshake_then_select', dict(epoch=0),
         [('syn', 1, V.frame(2, 100, 0, False, 1500)), ('synack', 2, V.frame(18, 900, 101, True, 1500)),
          ('ack', 1, V.frame(16, 101, 901, False, None)), ('select', 1, SELECT_FR)])
scenario('established_then_fin', dict(owner=0x90001, client=136, server=958, epoch=17), [('fin', 1, V.packet(17, 136, 958))])
scenario('established_then_rst', dict(owner=0x90001, client=136, server=958, epoch=17), [('rst', 1, V.packet(4, 136, 0))])

# negatives
def flip(b, off): r = bytearray(b); r[off] ^= 1; return bytes(r)
good_ack = V.packet(16, 136, 958)
EST = dict(owner=0x90001, client=136, server=958, epoch=17)
scenario('neg_bad_ip_csum', EST, [('ack', 1, flip(good_ack, 24))])
scenario('neg_bad_tcp_csum', EST, [('ack', 1, flip(good_ack, 50))])
scenario('neg_wrong_tuple', EST, [('ack', 1, V.packet(16, 136, 958, tuple4=(V.CLIENT, V.SERVER, 30002, 20000)))])
scenario('neg_wrong_ethertype', EST, [('ack', 1, good_ack[:12] + b'\x08\x06' + good_ack[14:])])
scenario('neg_unrouted_port9', EST, [('ack', 9, good_ack)])
scenario('neg_out_of_sequence_duplicate', EST, [('old_ack', 1, V.packet(16, 101, 901))])
scenario('neg_wrong_ack_number', EST, [('ack', 1, V.packet(16, 136, 959))])
SELP = dict(owner=0x40001, client=101, server=901, epoch=17)
for nm, off in (('dl_crc', 62), ('block_crc', 80), ('tail_crc', 87), ('data_byte', 70)):
    scenario('neg_select_bad_%s' % nm, SELP, [('select', 1, flip(SELECT_FR, off))])
scenario('neg_select_wrong_function', SELP, [('select', 1, V.packet(24, 101, 901, payload=V.native_select(fc=5)))])
scenario('artifact_sub60_truncated_tcp', EST, [('ack', 1, good_ack[:40])])   # the model pads frames <60 B: not a valid truncation test
scenario('neg_truncated_in_dl', SELP, [('select', 1, SELECT_FR[:60])])
scenario('neg_truncated_in_first_block', SELP, [('select', 1, SELECT_FR[:75])])
scenario('neg_truncated_in_tail', SELP, [('select', 1, SELECT_FR[:86])])
scenario('neg_truncated_select', SELP, [('select', 1, SELECT_FR[:70])])
scenario('neg_ttl0', EST, [('ack', 1, V.packet(16, 136, 958, ttl=0))])


# ---------------------------------------------------------------- READ kinds 9 / 10 / 11 (tev handoff on the handoff port)
import test_native_read as TR
IDLE, OUTST = 0x50001, 0xe0001
RP = dict(epoch=17)
rq, rk, rp = RS.request_packet, RS.ack_packet, RS.response_packet
scenario('read_request', dict(owner=IDLE, client=1000, server=2000, **RP), [('request', 1, rq(app=0xc3))])
scenario('read_ack', dict(owner=OUTST, client=1020, server=2000, **RP), [('ack', 2, rk())])
scenario('read_response', dict(owner=OUTST, client=1020, server=2000, app=3, **RP), [('response', 2, rp(app=0xc3))])
scenario('read_full_exchange', dict(owner=IDLE, client=1000, server=2000, **RP),
         [('request', 1, rq(app=0xc5)), ('ack', 2, rk()), ('response', 2, rp(app=0xc5))])
scenario('read_request_replay', dict(owner=IDLE, client=1000, server=2000, **RP), [('request', 1, rq(app=0xc3)), ('request_replay', 1, rq(app=0xc3))])
scenario('read_response_replay', dict(owner=OUTST, client=1020, server=2000, app=3, **RP), [('response', 2, rp(app=0xc3)), ('response_replay', 2, rp(app=0xc3))])
scenario('read_response_wrong_app_seq', dict(owner=OUTST, client=1020, server=2000, app=3, **RP), [('response_app4', 2, rp(app=0xc4))])
scenario('read_request_owner_outstanding', dict(owner=OUTST, client=1020, server=2000, **RP), [('request', 1, rq())])
scenario('read_response_owner_idle', dict(owner=IDLE, client=1000, server=2000, **RP), [('response', 2, rp())])
scenario('read_ack_owner_idle', dict(owner=IDLE, client=1000, server=2000, **RP), [('ack', 2, rk(seq=2000, ack=1000))])
scenario('read_request_wrong_seq', dict(owner=IDLE, client=1000, server=2000, **RP), [('request', 1, rq(seq=1001))])
scenario('read_response_wrong_ack', dict(owner=OUTST, client=1020, server=2000, app=3, **RP), [('response', 2, rp(app=0xc3, ack=1021))])
scenario('read_foreign_tuple', dict(owner=IDLE, client=1000, server=2000, **RP),
         [('request', 1, V.packet(24, 1000, 2000, payload=RS.request_frame(), tuple4=(V.CLIENT, V.SERVER, 30002, V.SERVER_PORT)))])
for kw in (dict(dst=0x0001), dict(src=0x0101)):
    scenario('read_foreign_link_req_%s' % list(kw)[0], dict(owner=IDLE, client=1000, server=2000, **RP), [('request', 1, rq(**kw))])
for kw in (dict(dst=0x0101), dict(src=0x0001)):
    scenario('read_foreign_link_rsp_%s' % list(kw)[0], dict(owner=OUTST, client=1020, server=2000, app=3, **RP), [('response', 2, rp(**kw))])
for off in (8, 18):
    b = bytearray(rq()); b[54 + off] ^= 1
    scenario('read_bad_crc_req_%d' % off, dict(owner=IDLE, client=1000, server=2000, **RP), [('request', 1, TR.ReadNeverMutates.repair_tcp(bytes(b)))])
for off in (8, 26, 44, 47):
    b = bytearray(rp()); b[54 + off] ^= 1
    scenario('read_bad_crc_rsp_%d' % off, dict(owner=OUTST, client=1020, server=2000, app=3, **RP), [('response', 2, TR.ReadNeverMutates.repair_tcp(bytes(b)))])
scenario('read_bad_ip_csum', dict(owner=IDLE, client=1000, server=2000, **RP), [('request', 1, flip(rq(), 24))])
scenario('read_bad_tcp_csum', dict(owner=IDLE, client=1000, server=2000, **RP), [('request', 1, flip(rq(), 50))])
scenario('read_truncated_request', dict(owner=IDLE, client=1000, server=2000, **RP), [('request', 1, rq()[:70])])
scenario('read_request_from_server_side', dict(owner=IDLE, client=1000, server=2000, **RP), [('request_wrong_dir', 2, rq())])

# first packet in the wrong order, free connection (finding 2 of the handshake study)
FREE = dict(epoch=0)
scenario('order_synack_first', FREE, [('synack', 2, V.frame(18, 900, 101, True, 1500))])
scenario('order_ack_first', FREE, [('ack', 1, V.frame(16, 101, 901, False, None))])
scenario('order_syn_ack_nonzero', FREE, [('syn', 1, V.frame(2, 100, 5, False, 1500))])
scenario('order_select_first', FREE, [('select', 1, SELECT_FR)])
scenario('order_fin_first', FREE, [('fin', 1, V.packet(17, 100, 0))])
scenario('order_rst_first', FREE, [('rst', 1, V.packet(4, 100, 0))])
scenario('order_synack_first_epoch17', dict(epoch=17), [('synack', 2, V.frame(18, 900, 101, True, 1500))])
scenario('order_dup_syn', FREE, [('syn', 1, V.frame(2, 100, 0, False, 1500)), ('syn_again', 1, V.frame(2, 100, 0, False, 1500))])

if os.environ.get('EPOCH0'):
    # harness: stops at 8 passes. Model: no limit; read what it did inside a short window then leave.
    scenario('epoch0_never_terminates', dict(owner=0x90001, client=136, server=958, epoch=0), [('ack', 1, good_ack)])

ok = rep.finish(os.path.join(OUT, 'cases.json'))
sys.exit(0 if ok else 1)

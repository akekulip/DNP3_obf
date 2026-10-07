"""Model run of the HELD path of read_timing on the new device ports, with the model's own packet generator (one-shot app re-armed per tick).

Program: read_timing_xpipe.p4 (pipe 0 = N stand-in, pipe 2 = T, pipes 1 and 3 stubs). Functional only: tofino-model,
no timing, no hardware. Differences from model_drive_held.py: every private hop is native (T_IN 325 reached from
pipe 0, HELD_RETURN 327 and HB_RETURN 326 recirculate in pipe 2), no bridge threads, and the heartbeat comes from
pipe 2's packet generator (app 0) whose packets arrive with ingress_port 0 behind a 6-byte timer header.

  integration/core/launch_model.sh -p integration/evidence/read_timing_xpipe_01/out \
      -o integration/evidence/read_timing_model_NN -P "9 64" -d integration/read/model_drive_held_xpipe.py
"""
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE / 'tests'), str(HERE.parent / 'core')]
import whole_program as w  # noqa: E402
from model_driver import Model, same_frame, gc  # noqa: E402

P = w.PORTS
FORWARD, RELAY = P['FORWARD_PORT'], P['RELAY_PORT']
m = Model(ports=[FORWARD, RELAY])
ack_frame, rsp_frame = w.pure_ack(), w.RESPONSE_FRAME
GEN_DEV = (2 << 7) | 68                              # pipe 2 packet generator (device 324)

pc, pb, pa = m.table('pktgen.port_cfg', raw=True), m.table('pktgen.pkt_buffer', raw=True), m.table('pktgen.app_cfg', raw=True)
tgt = gc.Target(device_id=0)
pc.entry_mod(tgt, [pc.make_key([gc.KeyTuple('dev_port', GEN_DEV)])], [pc.make_data([gc.DataTuple('pktgen_enable', bool_val=True)])])
buf = w.pktgen_frame()[6:].ljust(64, b'\0')          # the generator prepends the 6-byte timer header itself
pb.entry_mod(tgt, [pb.make_key([gc.KeyTuple('pkt_buffer_offset', 0), gc.KeyTuple('pkt_buffer_size', 64)])],
             [pb.make_data([gc.DataTuple('buffer', bytearray(buf))])])
fields = [gc.DataTuple('timer_nanosec', 1000), gc.DataTuple('pkt_len', 64), gc.DataTuple('pkt_buffer_offset', 0),
          gc.DataTuple('batch_count_cfg', 0), gc.DataTuple('packets_per_batch_cfg', 0), gc.DataTuple('ipg', 0),
          gc.DataTuple('ibg', 0), gc.DataTuple('trigger_counter', 0), gc.DataTuple('batch_counter', 0),
          gc.DataTuple('pkt_counter', 0)]


def app(enable, trigger='trigger_timer_one_shot'):
    pa.entry_mod(tgt, [pa.make_key([gc.KeyTuple('app_id', 0)])],
                 [pa.make_data(fields + [gc.DataTuple('app_enable', bool_val=enable)], trigger)])


def tick():
    """One generator packet: re-arm the one-shot timer app. (A periodic 100 us app floods the model, which then
    starves the recirculated handoff frames: run 06.)"""
    app(False)
    app(True)


def kind(d):
    for name, frame in (('ACK', ack_frame), ('RSP', rsp_frame), ('REQ', w.REQUEST_FRAME)):
        if same_frame(d, frame):
            return name
    return 'REPORT'


def collect(seconds):
    got = m.capture([FORWARD, RELAY], timeout=seconds, quiet=seconds)
    return [(p, d) for p in got for d in got[p]]


seen = []
reports = []
end = time.time() + 20
while time.time() < end and not reports:
    tick()
    seen += collect(0.5)
    reports = [d for p, d in seen if kind(d) == 'REPORT']
if not reports:
    print('RESULT NO HEARTBEAT REPORT from the generator-driven service passes')
    app(False)
    sys.exit(2)
t0q = int.from_bytes(reports[-1][12:16], 'big') & 0xffffff00
m.send(FORWARD, w.event_frame(9, w.REQUEST_FRAME, epoch=7, t0q=t0q))
seen += collect(1.0)
m.send(FORWARD, w.event_frame(10, ack_frame, epoch=7))
seen += collect(1.0)
m.send(FORWARD, w.event_frame(11, rsp_frame, epoch=7))
end = time.time() + 25
while time.time() < end:
    tick()
    seen += collect(0.3)
    kinds = [kind(d) for _, d in seen]
    if 'ACK' in kinds and 'RSP' in kinds:
        break
app(False)
order = [(p, kind(d)) for p, d in seen if kind(d) != 'REPORT']
nows = [int.from_bytes(d[12:16], 'big') for _, d in seen if kind(d) == 'REPORT']
print('non-report frames out (port, kind) in arrival order:', order)
print('reports', len(nows), 'model clock first/last', nows[:1], nows[-1:])
for name in ('timing_binding', 'admission_anchor', 'observations', 'releases', 'committed_response_deadline',
             'ready_response', 'debt_cell'):
    try:
        print(name, {k: v[2] if len(v) > 2 else v for k, v in m.register_read('p2.Ingress.' + name, 0).items() if isinstance(v, list)})
    except Exception as exc:  # noqa: BLE001
        print(name, 'readback failed:', type(exc).__name__, str(exc)[:80])
ok = [k for _, k in order] == ['REQ', 'ACK', 'RSP'] and order[0][0] == RELAY and order[1][0] == FORWARD
print('RESULT', 'HELD PATH OK on device ports 325/326/327: request to relay, ACK then response to master' if ok else 'INCOMPLETE')
sys.exit(0 if ok else 1)

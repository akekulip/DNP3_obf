"""Model run of the HELD path of read_timing: request, ACK and response originals, heartbeat ticks (functional only).

NOT the target: tofino-model, bf_switchd and a user-space bridge in one user namespace. The model's
--int-port-loop loops every pipe-0 port (front ports included), so it cannot be used here. Instead the
private loopbacks HELD_RETURN and HB_RETURN are closed by bridge threads (frame leaving veth(2p+1) is written
back to the same veth, which the model sees as ingress on port p), and heartbeat ticks are frames injected on
HB_PKTGEN every few wall milliseconds (the packet generator itself is NOT configured). Latencies are wall time
of Python threads, not the program's recirculation latency; the model's own clock stamps each pass.

  integration/core/launch_model.sh -p integration/evidence/read_timing_04/out \
     -o integration/evidence/read_timing_model_NN -P "9 10 64 68 69 71" -d integration/read/model_drive_held.py
"""
import select
import socket
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE / 'tests'), str(HERE.parent / 'core')]
import whole_program as w  # noqa: E402
from model_driver import Model, same_frame, veth_for  # noqa: E402

P = w.PORTS
T_IN, HELD, HB_RET, PKTGEN, RELAY, FORWARD = (P['T_IN'], P['HELD_RETURN'], P['HB_RETURN'], P['HB_PKTGEN'],
                                              P['RELAY_PORT'], P['FORWARD_PORT'])
PACKET_OUTGOING = 4
stop = threading.Event()
captured = []          # (wall seconds, dev port, bytes) leaving the model on FORWARD / RELAY
bridged = {HELD: 0, HB_RET: 0}


def bridge(port):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    s.bind((veth_for(port), 0))
    s.setblocking(False)
    while not stop.is_set():
        r, _, _ = select.select([s], [], [], 0.02)
        if r:
            data, addr = s.recvfrom(4096)
            if addr[2] != PACKET_OUTGOING:
                bridged[port] += 1
                s.send(data)
    s.close()


def watch(ports):
    socks = {}
    for p in ports:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        s.bind((veth_for(p), 0))
        s.setblocking(False)
        socks[s] = p
    while not stop.is_set():
        r, _, _ = select.select(list(socks), [], [], 0.02)
        for s in r:
            data, addr = s.recvfrom(4096)
            if addr[2] != PACKET_OUTGOING:
                captured.append((time.time(), socks[s], data))


m = Model(ports=[FORWARD, RELAY, T_IN, PKTGEN, HELD, HB_RET])
for target, args in ((bridge, (HELD,)), (bridge, (HB_RET,)), (watch, ([FORWARD, RELAY],))):
    threading.Thread(target=target, args=args, daemon=True).start()
time.sleep(0.5)

t0 = time.time()
ack_frame, rsp_frame = w.pure_ack(), w.RESPONSE_FRAME


def kind(d):
    for name, frame in (('ACK', ack_frame), ('RSP', rsp_frame), ('REQ', w.REQUEST_FRAME)):
        if same_frame(d, frame):
            return name
    return 'REPORT'


def report_now(d):
    return int.from_bytes(d[12:16], 'big')


def tick_until(predicate, limit):
    global ticks
    end = time.time() + limit
    while time.time() < end:
        m.send(PKTGEN, w.pktgen_frame())
        ticks += 1
        time.sleep(0.05)
        if predicate():
            return True
    return False


ticks = 0
reports = lambda: [report_now(d) for _, p, d in captured if p == FORWARD and kind(d) == 'REPORT']
if not tick_until(lambda: reports(), 20):
    print('RESULT NO HEARTBEAT REPORT (service passes did not complete)')
    stop.set()
    sys.exit(2)
t0q = reports()[-1] & 0xffffff00                    # model clock as the request's arrival stamp
m.send(T_IN, w.event_frame(9, w.REQUEST_FRAME, epoch=7, t0q=t0q))
tick_until(lambda: False, 0.4)                      # the request's four pinned passes finish first
m.send(T_IN, w.event_frame(10, ack_frame, epoch=7))
tick_until(lambda: False, 0.4)                      # a response inside the ACK's pin window would bypass (T2-RACE)
m.send(T_IN, w.event_frame(11, rsp_frame, epoch=7))
outs = lambda: [kind(d) for _, p, d in captured if p == FORWARD]
tick_until(lambda: 'ACK' in outs() and 'RSP' in outs(), 25)
stop.set()
time.sleep(0.2)


print('ticks injected', ticks, 'bridged', bridged)
order = [(round(t - t0, 3), p, kind(d)) for t, p, d in captured if kind(d) != 'REPORT']
print('non-report frames out (wall s since start, port, kind):', order)
reps = [report_now(d) for _, _, d in captured if kind(d) == 'REPORT']
print('reports out', len(reps), 'model clock (now) first/last', reps[:1], reps[-1:], 'span ns', (reps[-1] - reps[0]) if reps else None)
for name in ('Ingress.timing_binding', 'Ingress.admission_anchor', 'Ingress.observations', 'Ingress.releases',
             'Ingress.committed_response_deadline', 'Ingress.ready_response', 'Ingress.debt_cell'):
    try:
        print(name, {k: v[0] for k, v in m.register_read(name, 0).items() if isinstance(v, list)})
    except Exception as exc:  # noqa: BLE001
        print(name, 'readback failed:', type(exc).__name__)
kinds_out = [k for _, _, k in order]
print('order', kinds_out)
print('RESULT', 'HELD PATH OK: request, ACK, response all forwarded' if
      kinds_out.count('REQ') == 1 and kinds_out.count('ACK') == 1 and kinds_out.count('RSP') == 1 else 'INCOMPLETE')
sys.exit(0 if kinds_out.count('ACK') == 1 and kinds_out.count('RSP') == 1 else 1)

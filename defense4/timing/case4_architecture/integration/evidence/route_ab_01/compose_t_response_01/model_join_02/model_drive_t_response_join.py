"""Local Tofino-1 model run of the COMPOSED program (compose_t_response.py): T in pipe 2, the B' response
path's egress in pipe 0. Checks the cross-pipe join and final-pass qualification, not the transform itself.

Functional model execution only (not hardware, not timing). T originals are injected on T_IN (325, pipe 2)
as N would hand them over; T holds them on its pipe-2 ladder ports (326, 327) and releases them to
FORWARD 9 / RELAY 64, which are pipe-0 ports, so every release crosses into pipe 0's egress and the
response path's egress control. The response path counts every egress pass in r_Egress.outcome
(count_t is unconditional), so:
  * the pipe-0 egress pass count must equal the number of frames T releases (final passes only), while
  * T's own hold laps (OUT_HELD_REWAIT, many) and T's dropped duplicate must add none;
  * on these unconfigured flows the response path must leave every frame byte-identical.

  integration/core/launch_model.sh -p <composed out/> -o <new dir> -P "9 64 324 325 326 327" \
      -d integration/read/model_drive_t_response_join.py
"""
import os
import struct
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE / 'tests'), str(HERE.parent / 'core')]
import queue_sim as qs  # noqa: E402
import whole_program as w  # noqa: E402
from model_driver import Model, Report, gc  # noqa: E402

T_IN, PKTGEN_RETURN, FORWARD, RELAY, SID = 325, 324, 9, 64, 7
WATCH = [FORWARD, RELAY]
KIND = {'request': 9, 'ack': 10, 'response': 11, 'operate': 12, 'reset': 4}
PARAMS = dict(da=50_000_000, readiness=400_000_000, cap=16_000_000, gap=50_000_000, op_j=200_000_000,
              budget=240_000, enabled=1)


def tagged(tag):
    return w.ETH + bytes([tag]) * 24


def tev(kind, epoch, stage, original):
    return struct.pack('!IIIBBH', epoch, 0, 0, KIND[kind], stage, 0) + original


def strip_pad(got, want):
    return got[:len(want)] == want and not any(got[len(want):])


# (offset s, kind, epoch, stage, original); a duplicate response at 0.11 is dropped inside T.
EVENTS = [(0.00, 'request', 1, 0, tagged(0xA0)), (0.05, 'ack', 1, 0, w.pure_ack()),
          (0.10, 'response', 1, 0, tagged(0xA2)), (0.11, 'response', 1, 0, tagged(0xA3)),
          (0.30, 'operate', 1, 0, tagged(0xC0))]
EXPECT = {RELAY: [tagged(0xA0), tagged(0xC0)], FORWARD: [w.pure_ack(), tagged(0xA2)]}


def main():
    m = Model(ports=[], enable=False)
    rep = Report(os.environ['PROG'], params=PARAMS)
    m.enable_ports(WATCH)
    time.sleep(2.0)
    rep.add('ports_enabled', {}, m.port_errors, ok=not m.port_errors)
    target = gc.Target(device_id=0, pipe_id=0xffff)
    mc = m.table('$mirror.cfg', raw=True)
    mc.entry_add(target, [mc.make_key([gc.KeyTuple('$sid', SID)])], [mc.make_data([
        gc.DataTuple('$direction', str_val='INGRESS'), gc.DataTuple('$ucast_egress_port', PKTGEN_RETURN),
        gc.DataTuple('$ucast_egress_port_valid', bool_val=True), gc.DataTuple('$session_enable', bool_val=True)],
        '$normal')])
    m.set_default('p2.t_Ingress.params', 't_Ingress.set_params', PARAMS)
    consts = qs.QueueSim().consts()
    egress_counter = m.table('p0.r_Egress.outcome')

    def egress_passes():
        for op in ('Sync', 'SyncCounters'):
            try:
                egress_counter.operations_execute(m.target, op)
                break
            except Exception:
                pass
        total = 0
        for code in range(32):
            for data, _k in egress_counter.entry_get(m.target, [egress_counter.make_key(
                    [gc.KeyTuple('$COUNTER_INDEX', code)])], {'from_hw': True}):
                v = data.to_dict()['$COUNTER_SPEC_PKTS']
                total += sum(v) if isinstance(v, list) else v
        return total

    def t_counter(name):
        r = m.register_read('p2.t_Ingress.outcomes', consts[name])
        v = [val for k, val in r.items() if k.endswith('.f1')][0]
        return sum(v) if isinstance(v, list) else v

    e0 = egress_passes()
    t0 = {n: t_counter(n) for n in ('OUT_HELD_REWAIT', 'OUT_RESP_DUP_DROP', 'OUT_ACK_COMMIT', 'OUT_RESP_RELEASE',
                                    'OUT_OP_RELEASE')}
    m.drain(WATCH)
    start = time.time()
    for off, kind, epoch, stage, original in EVENTS:
        delay = start + off - time.time()
        if delay > 0:
            time.sleep(delay)
        m.send(T_IN, tev(kind, epoch, stage, original))
    got = m.capture(WATCH, timeout=3.0, quiet=3.0)
    e1 = egress_passes()
    t1 = {n: t_counter(n) for n in t0}
    td = {n: t1[n] - t0[n] for n in t0}
    for port in WATCH:
        ok = len(got[port]) == len(EXPECT[port]) and all(strip_pad(g, e) for g, e in zip(got[port], EXPECT[port]))
        rep.add('port%d_released_frames_byte_identical_in_order' % port, len(EXPECT[port]), len(got[port]), ok=ok,
                frames=[x.hex() for x in got[port]])
    released = sum(len(got[p]) for p in WATCH)
    rep.add('pipe0_egress_passes_equal_T_releases', released, e1 - e0)
    rep.add('T_decisions', dict(OUT_RESP_DUP_DROP=1, OUT_ACK_COMMIT=1, OUT_RESP_RELEASE=1, OUT_OP_RELEASE=1),
            {k: td[k] for k in ('OUT_RESP_DUP_DROP', 'OUT_ACK_COMMIT', 'OUT_RESP_RELEASE', 'OUT_OP_RELEASE')})
    rep.add('T_hold_laps_never_reach_pipe0_egress', '> 0 laps, none counted in pipe 0', td['OUT_HELD_REWAIT'],
            ok=td['OUT_HELD_REWAIT'] > 0 and e1 - e0 == released)
    sys.exit(0 if rep.finish(os.path.join(os.environ['OUT'], 'cases.json')) else 1)


if __name__ == '__main__':
    main()

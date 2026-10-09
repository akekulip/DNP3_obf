"""Local Tofino-1 model run of the WHOLE compiled read_queue_timing.p4, checked against the interpreter.

Functional model execution only: not hardware, not timing (the model clock advances in ~1 ms quanta and
one pass costs several ms, evidence/operate_handoff_clk_01). Every scenario is replayed twice:
  * as real packets through the compiled, stage-placed program on the model (mirror session bound locally;
    no packet generator, so READ blocker tokens do not exist and held originals re-wait every lap);
  * through queue_sim.QueueSim (the source-level interpreter the invariant tests use), on the same event
    list with times and deadlines scaled so every hold spans several recirculation laps in both.
For each phase it compares the per-port order of released frames and the decision counters. Token and
re-wait counters (OUT_TOKEN_*, OUT_HELD_REWAIT) are excluded: they count laps and generator tokens, which
differ between the two by construction.

  integration/core/launch_model.sh -p <compiled out/> -o <new evidence dir> -P "9 64 324 325 326 327" \
      -d integration/read/model_drive_t_queue.py
"""
import os
import struct
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE / 'tests'), str(HERE.parent / 'core')]
import queue_sim as qs  # noqa: E402
from model_driver import Model, Report, gc  # noqa: E402

T_IN, PKTGEN_RETURN, FORWARD, RELAY, SID = 325, 324, 9, 64, 7
WATCH = [FORWARD, RELAY]
KIND = {'request': 9, 'ack': 10, 'response': 11, 'operate': 12, 'reset': 4}
DECISION = ['OUT_UNMATCHED', 'OUT_ACK_COMMIT', 'OUT_RESP_RELEASE', 'OUT_RESP_DUP_DROP', 'OUT_OP_RELEASE',
            'OUT_HELD_STALE_FLUSH', 'OUT_ACK_FALLBACK', 'OUT_RESP_FALLBACK', 'OUT_HELD_OFF_FLUSH',
            'OUT_REQ_BYPASS']
# Model deadlines in model clock ticks (~1.25 per wall ns); one recirculation lap is ~8e6 ticks.
MODEL = dict(da=50_000_000, readiness=400_000_000, cap=16_000_000, gap=50_000_000, op_j=200_000_000,
             budget=240_000)
SIM_SCALE = 0.008          # QueueSim ns per model tick: QueueSim laps are 50 us, model laps ~8e6 ticks
SIM_NS_PER_S = 10_000_000  # QueueSim timeline: 1 s of the model run's wall schedule -> 10 ms


def frame(tag):
    """A distinct opaque original per (phase, role), so emissions can be attributed exactly."""
    return qs.w.ETH + bytes([tag]) * 24


# Each phase: (name, duration_s, params-or-None, [(offset_s, kind, epoch, stage, frame_tag)]).
PHASES = [
    ('A_read_normal_and_duplicate', 1.2, None,
     [(0.00, 'request', 1, 0, 0xA0), (0.05, 'ack', 1, 0, 0xA1), (0.10, 'response', 1, 0, 0xA2),
      (0.11, 'response', 1, 0, 0xA3)]),
    ('B_fallback_ack_then_late_response', 1.6, None,
     [(0.00, 'request', 1, 0, 0xB0), (0.05, 'ack', 1, 0, 0xB1), (0.80, 'response', 1, 0, 0xB2)]),
    ('C_operate_held_then_released', 1.0, None, [(0.00, 'operate', 1, 0, 0xC0)]),
    ('D_operate_then_immediate_reset', 1.0, None,
     [(0.00, 'operate', 1, 0, 0xD0), (0.00, 'reset', 1, 0, 0xD9)]),
    ('E_quarantined_epoch_passes_through', 0.6, None,
     [(0.00, 'request', 1, 0, 0xE0), (0.05, 'ack', 1, 0, 0xE1)]),
    ('F_reset_while_ack_held', 1.0, None,
     [(0.00, 'request', 2, 0, 0xF0), (0.05, 'ack', 2, 0, 0xF1), (0.15, 'reset', 2, 0, 0xF9)]),
    ('G_policy_off_passthrough', 0.8, dict(enabled=0),
     [(0.00, 'request', 3, 0, 0x10), (0.05, 'ack', 3, 0, 0x11), (0.10, 'operate', 3, 0, 0x12),
      (0.15, 'reset', 3, 0, 0x19)]),
]


def tev(kind, epoch, stage, original):
    return struct.pack('!IIIBBH', epoch, 0, 0, KIND[kind], stage, 0) + original


def tag_of(raw):
    """Frame tag of a released original (model frames may be padded to the 60-byte minimum)."""
    body = raw[len(qs.w.ETH):len(qs.w.ETH) + 24]
    return body[0] if len(body) == 24 and len(set(body)) == 1 else None


# ---- interpreter prediction ---------------------------------------------------------------------------
def predict():
    sim_params = {k: (int(v * SIM_SCALE) & ~0xff if k not in ('budget',) else v) for k, v in MODEL.items()}
    sim = qs.QueueSim()
    sim.set_params(**sim_params)
    snaps, starts, t = [], [], qs.T0
    for name, dur, params, events in PHASES:
        start = t
        starts.append(start)
        if params:
            sim.call(start - 1, lambda s, p=dict(sim_params, **params): s.set_params(**p))
        for off, kind, epoch, stage, ftag in events:
            ev = start + int(off * SIM_NS_PER_S)
            sim.event(ev, KIND[kind], frame(ftag), epoch, stage)
        t = start + int(dur * SIM_NS_PER_S)
        sim.call(t - 1, lambda s: snaps.append({n: s.counter(s.consts()[n]) for n in DECISION}))
    sim.run(t)
    out, prev = [], {n: 0 for n in DECISION}
    for i, (name, dur, params, events) in enumerate(PHASES):
        lo, hi = starts[i], starts[i] + int(dur * SIM_NS_PER_S)
        em = {p: [tag_of(raw) for tt, pp, raw in sim.emitted if pp == p and lo <= tt < hi] for p in WATCH}
        out.append(dict(emissions=em, counters={n: snaps[i][n] - prev[n] for n in DECISION}))
        prev = snaps[i]
    regs = {r: sim.cell(r) for r in ('gen_alloc_reg', 'op_gen_alloc_reg', 'quarantine_reg')}
    return out, regs


# ---- model run ----------------------------------------------------------------------------------------
def main():
    expected, expected_regs = predict()
    m = Model(ports=[], enable=False)
    rep = Report(os.environ['PROG'], model_params=MODEL, sim_scale=SIM_SCALE, sim_ns_per_s=SIM_NS_PER_S)
    m.enable_ports(WATCH)
    time.sleep(2.0)
    rep.add('ports_enabled', {}, m.port_errors, ok=not m.port_errors)
    target = gc.Target(device_id=0, pipe_id=0xffff)
    mc = m.table('$mirror.cfg', raw=True)
    mc.entry_add(target, [mc.make_key([gc.KeyTuple('$sid', SID)])], [mc.make_data([
        gc.DataTuple('$direction', str_val='INGRESS'), gc.DataTuple('$ucast_egress_port', PKTGEN_RETURN),
        gc.DataTuple('$ucast_egress_port_valid', bool_val=True), gc.DataTuple('$session_enable', bool_val=True)],
        '$normal')])
    codes = {n: qs.QueueSim().consts()[n] for n in DECISION + ['OUT_HELD_REWAIT']}

    def counters():
        res = {}
        for n, c in codes.items():
            r = m.register_read('Ingress.outcomes', c)
            res[n] = [v for k, v in r.items() if k.endswith('.f1')][0][2]   # pipe 2 = T's pipe
        return res

    def set_params(**over):
        m.set_default('Ingress.params', 'Ingress.set_params', dict(MODEL, **dict(dict(enabled=1), **over)))

    set_params()
    prev = counters()
    for i, (name, dur, params, events) in enumerate(PHASES):
        set_params(**(params or {}))
        m.drain(WATCH)
        t0 = time.time()
        for off, kind, epoch, stage, ftag in events:
            delay = t0 + off - time.time()
            if delay > 0:
                time.sleep(delay)
            m.send(T_IN, tev(kind, epoch, stage, frame(ftag)))
        rest = t0 + dur - time.time()
        got = m.capture(WATCH, timeout=max(rest, 0.1), quiet=max(rest, 0.1))
        now = counters()
        observed = dict(emissions={p: [tag_of(x) for x in got[p]] for p in WATCH},
                        counters={n: now[n] - prev[n] for n in DECISION})
        laps = now['OUT_HELD_REWAIT'] - prev['OUT_HELD_REWAIT']
        prev = now
        exp = expected[i]
        hexs = lambda d: {p: ['%02x' % x if x is not None else None for x in v] for p, v in d.items()}
        rep.add(name + '_emissions', hexs(exp['emissions']), hexs(observed['emissions']))
        rep.add(name + '_decision_counters', exp['counters'], observed['counters'])
        if name[0] in 'ABCF':   # an original was held: it must have waited laps in its hold queue on the model
            rep.add(name + '_held_across_laps', '> 0', laps, ok=laps > 0)
    regs = {}
    for r in ('gen_alloc_reg', 'op_gen_alloc_reg', 'quarantine_reg'):
        v = m.register_read('Ingress.' + r, 0)
        regs[r] = [val for k, val in v.items() if k.endswith('.f1')][0][2]
    rep.add('final_generation_registers', expected_regs, regs)
    sys.exit(0 if rep.finish(os.path.join(os.environ['OUT'], 'cases.json')) else 1)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--predict':
        import json
        phases, regs = predict()
        for (name, *_), ph in zip(PHASES, phases):
            print(name, {p: ['%02x' % x if x is not None else None for x in v] for p, v in ph['emissions'].items()},
                  {k: v for k, v in ph['counters'].items() if v})
        print('final registers', regs)
    else:
        main()

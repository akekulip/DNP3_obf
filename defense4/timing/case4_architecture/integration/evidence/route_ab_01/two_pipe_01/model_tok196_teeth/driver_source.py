"""Local Tofino-1 model check: a packet-generator token that arrives on PKTGEN_RETURN (196, pipe 1 local 68),
as the generator delivers it on this switch (app_cfg.pipe_local_source_port = 68), is handled by T as a TOKEN,
not as a mirror clone. The model's own generator reports ingress_port 0, so the tokens are injected on 196
explicitly through a veth. Functional model only: not hardware.

Expected, from the deterministic source-level run (read/tests: M_CloneOrTokenByContent): on a fresh switch each
token is stale and dropped by the token verdict: OUT_TOKEN_STALE +1 per token, OUT_UNMATCHED unchanged,
nothing emitted.

  integration/core/launch_model.sh -p <compile out/> -o <new dir> -P "9 64 196" \\
      -d integration/core/response_only/model_drive_pktgen_port.py
"""
import hashlib
import os
import struct
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
INTEG = HERE.parent.parent
sys.path[:0] = [str(INTEG / 'core'), str(INTEG / 'read' / 'tests')]
from model_driver import Model, Report  # noqa: E402
import queue_sim as qs  # noqa: E402

PKTGEN_RETURN = qs.PORTS['PKTGEN_RETURN']
PORTS = [9, 64, PKTGEN_RETURN]


def token(gen, packet_id, profile, pipe=1):
    """Tofino-1 pktgen timer header (pad(3)=0 | pipe(2) | app(3), pad, batch, packet) + padding."""
    return bytes([pipe << 3 | profile]) + bytes([profile]) + struct.pack('!HH', gen, packet_id) + bytes(58)


def main():
    out_dir = Path(os.environ['OUT'])
    rep = Report(os.environ['PROG'], physical=False,
                 driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 scope='generator tokens injected on PKTGEN_RETURN (196): handled as tokens, not clones')
    ok = False
    try:
        m = Model(ports=[], enable=False)
        consts = qs.QueueSim().consts()

        def t_count(name):
            r = m.register_read('p1.t_Ingress.outcomes', consts[name])
            v = [val for k, val in r.items() if k.endswith('.f1')][0]
            return sum(v) if isinstance(v, list) else v
        names = ('OUT_TOKEN_STALE', 'OUT_UNMATCHED')
        before = {n: t_count(n) for n in names}
        m.drain(PORTS)
        for profile in (1, 2, 3):
            m.send(PKTGEN_RETURN, token(gen=1, packet_id=profile, profile=profile))
            time.sleep(0.2)
        got = m.capture(PORTS, timeout=3.0, quiet=1.5)
        after = {n: t_count(n) for n in names}
        delta = {n: after[n] - before[n] for n in names}
        rep.add('three_tokens_on_196_reach_the_token_verdict', {'OUT_TOKEN_STALE': 3, 'OUT_UNMATCHED': 0}, delta)
        rep.add('nothing_emitted', {p: 0 for p in PORTS}, {p: len(got[p]) for p in PORTS})
        ok = True
    except BaseException as error:
        rep.record['error'] = type(error).__name__ + ': ' + str(error)
        rep.record['traceback'] = traceback.format_exc()
        rep.add('execution', 'completed', 'error', ok=False)
    finally:
        passed = rep.finish(str(out_dir / 'cases.json'))
        (out_dir / 'driver_source.py').write_bytes(Path(__file__).read_bytes())
    return 0 if (ok and passed) else 1


if __name__ == '__main__':
    sys.exit(main())

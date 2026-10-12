"""Model sweep: a T pass that does not clone must never be mirrored, whatever the live READ generation is.

route_ab_01/token_stale_01: Tofino-1's ingress deparser selects a mirror entry on every pass. In the builds up to
close_reset_fix_01, the entry a non-cloning pass selected took its session id from a compiler temporary sharing
md.cur_gen's container, so the pass was mirrored to session = live READ generation [9:0]. That was harmless for
unconfigured sessions, and a storm at the configured session 7.

This driver configures EVERY valid session id 1..1015 to a sink port (session 7 included; no READ clone is
created here, so nothing legitimate uses it). Then for each generation value g in 0..1023 it writes the live READ
generation register (p1.t_Ingress.gen_alloc_reg) to g and sends one non-cloning frame into T on PKTGEN_RETURN
(first byte 0x00: not a clone, not a generator token, so T drops it as foreign; gen_access's default peek_gen still
reads the generation on that pass). Every frame reaching the sink is a mirror of a pass that never asked for one.

  integration/core/launch_model.sh -p <compile out/> -o <new dir> -P "2 196" -d .../model_drive_mirror_guard.py
  (SINK=<dev port> to change the sink; it needs a veth, as does 196.)
"""
import hashlib
import json
import os
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
INTEG = HERE.parent.parent
sys.path[:0] = [str(HERE), str(INTEG / 'core')]
from model_driver import Model, Report, gc  # noqa: E402
import port_map  # noqa: E402
from model_drive_composite import Sink  # noqa: E402

SINK = int(os.environ.get('SINK', '2'))
GEN_REG, GEN_FIELD = 'p1.t_Ingress.gen_alloc_reg', 't_Ingress.gen_alloc_reg.f1'
FOREIGN = bytes(64)            # first byte 0x00: pipe 0 app 0, not CLONE_MARKER -> T's drop_foreign
SESSIONS = range(1, 1016)      # Tofino-1 valid mirror session ids; 0 is not valid


def main():
    out_dir = Path(os.environ['OUT'])
    rep = Report(os.environ['PROG'], physical=False, params={},
                 driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 scope='non-cloning T pass vs mirror sessions 1..1015, live READ generation 0..1023')
    try:
        m = Model(ports=[], enable=False)
        m.enable_ports([SINK, port_map.PKTGEN_RETURN])
        time.sleep(2.0)
        mc = m.table('$mirror.cfg', raw=True)
        failed = []
        for sid in SESSIONS:
            try:
                mc.entry_add(gc.Target(device_id=0, pipe_id=0xffff), [mc.make_key([gc.KeyTuple('$sid', sid)])], [mc.make_data([
                    gc.DataTuple('$direction', str_val='INGRESS'), gc.DataTuple('$ucast_egress_port', SINK),
                    gc.DataTuple('$ucast_egress_port_valid', bool_val=True), gc.DataTuple('$session_enable', bool_val=True)],
                    '$normal')])
            except Exception as exc:
                failed.append((sid, str(exc).splitlines()[0][:80]))
        rep.record['meta'].update(sink=SINK, sessions_configured=len(SESSIONS) - len(failed), session_errors=failed[:5])
        sink = Sink(SINK)
        sink.start()
        per_gen = {}
        for g in range(1024):
            m.register_write(GEN_REG, 0, {GEN_FIELD: g})
            before = sink.frames
            m.send(port_map.PKTGEN_RETURN, FOREIGN)
            time.sleep(0.02)
            if sink.frames != before:
                per_gen[g] = sink.frames - before
        time.sleep(2.0)
        rep.record['meta']['mirror_sink'] = sink.summary()
        rep.add('generation_register_reads_back', 1023, m.register_read(GEN_REG, 0, GEN_FIELD)[0])
        rep.add('no_mirror_of_a_non_cloning_pass_for_any_generation_0_1023', {}, {str(k): v for k, v in per_gen.items()},
                total_mirrored=sink.frames, configured_session_7_hit=7 in per_gen)
        rep.add('in_particular_not_at_the_configured_session_7', False, 7 in per_gen)
    except BaseException as error:
        rep.record['error'] = type(error).__name__ + ': ' + str(error)
        rep.record['traceback'] = traceback.format_exc()
        rep.add('execution', 'completed', 'error', ok=False)
    finally:
        passed = rep.finish(str(out_dir / 'cases.json'))
        (out_dir / 'driver_source.py').write_bytes(Path(__file__).read_bytes())
    sys.exit(0 if passed else 1)


if __name__ == '__main__':
    main()

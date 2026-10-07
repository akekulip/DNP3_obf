"""Model run of the READ ADMIT path (T8) through the compiled read_timing program (functional only).

Inside launch_model.sh's namespace, with MODEL_INT_PORT_LOOP=0x1 so the model recirculates local ports 68-71:
  MODEL_INT_PORT_LOOP=0x1 integration/core/launch_model.sh -p integration/evidence/read_timing_03/out \
     -o integration/evidence/read_timing_model_NN -P "9 64 69 71" -d integration/read/model_drive_admit.py

One tev kind-9 request enters T_IN; it must take four passes on HELD_RETURN and leave unchanged on RELAY_PORT.
Registers are read back through BF Runtime. Not hardware, not timing, not stage-fit evidence.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE / 'tests'), str(HERE.parent / 'core')]
import whole_program as w  # noqa: E402
from model_driver import Model, same_frame  # noqa: E402

T_IN, RELAY, FORWARD = w.PORTS['T_IN'], w.PORTS['RELAY_PORT'], w.PORTS['FORWARD_PORT']
m = Model(ports=[FORWARD, RELAY, T_IN])
frame = w.event_frame(9, w.REQUEST_FRAME, epoch=7, t0q=0x01000100)
out = m.exchange(T_IN, frame, [RELAY, FORWARD], timeout=3.0)
print('TX', len(frame), 'bytes on dev port', T_IN)
print('RX relay', [(len(x), x[:20].hex()) for x in out[RELAY]], 'forward', [len(x) for x in out[FORWARD]])
ok = len(out[RELAY]) == 1 and same_frame(out[RELAY][0], w.REQUEST_FRAME) and not out[FORWARD]
for name, field in (('Ingress.timing_binding', None), ('Ingress.admission_anchor', None),
                    ('Ingress.cookie_counter', None), ('Ingress.debt_cell', None)):
    try:
        print(name, m.register_read(name, 0))
    except Exception as exc:  # noqa: BLE001
        print(name, 'readback failed', type(exc).__name__, exc)
print('RESULT', 'REQUEST FORWARDED to relay, identical' if ok else 'NOT as expected')
sys.exit(0 if ok else 1)

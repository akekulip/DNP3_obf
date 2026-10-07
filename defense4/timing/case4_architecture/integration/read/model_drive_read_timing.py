"""Optional one-frame model run of read_timing.p4 (functional only: not hardware, timing or stage-fit evidence).

Run inside the namespace made by integration/core/launch_model.sh:
  integration/core/launch_model.sh -p integration/evidence/read_timing_01/out \
      -o integration/evidence/read_timing_model_NN -P "9 69" -d integration/read/model_drive_read_timing.py

With holding policy 0 the program takes the refused-producer path: a pure ACK on ACK_INPUT is
forwarded unchanged to FORWARD_PORT with no recirculation, so one frame exercises the compiled
parser, ack_guard, off_outcome and deparser. The held path needs pktgen and loopback ports and is
NOT exercised here.
"""
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE / 'tests'), str(HERE.parent / 'core')]
import whole_program as w  # noqa: E402  (frame builder and the ports.p4 constants)
from model_driver import Model  # noqa: E402

ACK_INPUT, FORWARD = w.PORTS['ACK_INPUT'], w.PORTS['FORWARD_PORT']
m = Model(ports=[FORWARD, ACK_INPUT])
frame = w.pure_ack()
m.register_write('Ingress.holding_policy', 0, {'Ingress.holding_policy.f1': 0})
print('policy readback', m.register_read('Ingress.holding_policy', 0))
out = m.exchange(ACK_INPUT, frame, [FORWARD], timeout=2.0)
got = out[FORWARD]
print('TX', len(frame), 'bytes on dev port', ACK_INPUT, frame.hex())
print('RX', [(len(x), x.hex()) for x in got])
from model_driver import same_frame  # noqa: E402
ok = len(got) == 1 and same_frame(got[0], frame)
print('RESULT', 'FORWARDED identical' if ok else 'NOT forwarded identical')
sys.exit(0 if ok else 1)

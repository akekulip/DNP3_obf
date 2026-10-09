"""Local Tofino-1 model run of mirror_probe.p4 (F1): what the ingress-deparser Mirror() clone really is.

Functional model execution only: not hardware, not timing. Mirror sessions are configured on the LOCAL model.

  integration/core/launch_model.sh -p integration/evidence/mirror_f1_01/compile_probe_local/out \
     -o integration/evidence/mirror_f1_01/model_NN -P "1 2 9 324" -d integration/read/model_drive_mirror_probe.py

Case A binds session 7 to front port 2 so the clone's bytes can be captured on the wire.
Case B rebinds session 7 to PKTGEN_RETURN (324, pipe 2 local 68) and reads what parse_clone latched there.
"""
import os
import struct
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent / 'core')]
from model_driver import Model, Report, gc  # noqa: E402

PROBE_IN, PROBE_OUT, CAPTURE, PKTGEN_RETURN, SID = 9, 1, 2, 324, 7
ETH = bytes.fromhex('0a0000000002' '0a0000000001') + b'\x88\xb5'
PAYLOAD = bytes(range(200, 230))                                # OP_FRAME's payload in queue_sim.py
EPOCH = 0x00000005
TEV = struct.pack('!IIIBBH', EPOCH, 0x0000abcd, 0x01000000, 12, 0, 0)   # kind 12 = OPERATE
FRAME = TEV + ETH + PAYLOAD
TAG = (EPOCH + 0x10000) & 0xffffffff
LADDER = struct.pack('!BBHI', 13, 0, 0x0102, 0x0a0b0c0d)
MODIFIED = LADDER + PAYLOAD                                     # what the ingress deparser emits for the original


def strip_pad(got, want):
    return got[:len(want)] == want and not any(got[len(want):])


m = Model(ports=[], enable=False)
rep = Report(os.environ['PROG'], frame=FRAME.hex(), tag=hex(TAG), modified_original=MODIFIED.hex())
for p in (PROBE_IN, PROBE_OUT, CAPTURE):
    m.enable_ports([p])
time.sleep(2.0)
rep.add('ports_enabled', {}, m.port_errors, ok=not m.port_errors)
target = gc.Target(device_id=0, pipe_id=0xffff)
mc = m.table('$mirror.cfg', raw=True)


def bind(port):
    key = mc.make_key([gc.KeyTuple('$sid', SID)])
    try:
        mc.entry_del(target, [key])
    except Exception:
        pass
    mc.entry_add(target, [key], [mc.make_data([
        gc.DataTuple('$direction', str_val='INGRESS'), gc.DataTuple('$ucast_egress_port', port),
        gc.DataTuple('$ucast_egress_port_valid', bool_val=True), gc.DataTuple('$session_enable', bool_val=True)],
        '$normal')])


def reg(name):
    r = m.register_read('Ingress.' + name, 0)
    vals = [v for k, v in r.items() if k.endswith('.f1')][0]
    return vals


# ---- A: clone to a front port, bytes on the wire ------------------------------------------------
bind(CAPTURE)
out = m.exchange(PROBE_IN, FRAME, [PROBE_OUT, CAPTURE, PKTGEN_RETURN], timeout=2.0, quiet=0.6)
orig, clones = out[PROBE_OUT], out[CAPTURE]
rep.add('A_original_once_on_port1', 1, len(orig), originals=[x.hex() for x in orig])
rep.add('A_original_is_modified_image', True, bool(orig) and strip_pad(orig[0], MODIFIED))
rep.add('A_clone_once_on_session_port', 1, len(clones), clones=[x.hex() for x in clones])
c = clones[0] if clones else b''
rep.add('A_clone_tag_first_4_bytes', hex(TAG), hex(struct.unpack('!I', c[:4])[0]) if len(c) >= 4 else None)
pristine = strip_pad(c[4:], FRAME)
modified = strip_pad(c[4:], MODIFIED)
rep.add('A_clone_body_kind', 'recorded', 'pristine' if pristine else 'modified' if modified else 'other', ok=True,
        clone_body=c[4:].hex())
rep.add('A_clone_body_is_pristine_original', True, pristine)

# ---- B: clone to PKTGEN_RETURN (pipe 2 local 68), what parse_clone sees ----------------------------
bind(PKTGEN_RETURN)
before = reg('clone_arrivals')
out = m.exchange(PROBE_IN, FRAME, [PROBE_OUT, CAPTURE, PKTGEN_RETURN], timeout=2.0, quiet=0.6)
time.sleep(0.5)
after = reg('clone_arrivals')
arrivals = [a - b for a, b in zip(after, before)]
rep.add('B_original_once_on_port1', 1, len(out[PROBE_OUT]))
rep.add('B_nothing_on_capture_port', 0, len(out[CAPTURE]))
rep.add('B_frames_on_veth_of_324', 'recorded', len(out[PKTGEN_RETURN]), ok=True,
        frames=[x.hex() for x in out[PKTGEN_RETURN]])
rep.add('B_clone_reentered_ingress_324_exactly_once', [0, 0, 1, 0], arrivals)
seen = {n: reg('seen_' + n)[2] for n in ('tag', 'epoch', 'kind', 'eth_type')}
rep.add('B_parse_clone_tag', hex(TAG), hex(seen['tag']))
rep.add('B_parse_clone_tev_kind_is_operate', 12, seen['kind'], seen=seen)
rep.add('B_parse_clone_tev_epoch', EPOCH, seen['epoch'])

# ---- C: no duplicate later -------------------------------------------------------------------------
time.sleep(1.0)
rep.add('C_no_late_second_clone', arrivals, [a - b for a, b in zip(reg('clone_arrivals'), before)])
sys.exit(0 if rep.finish(os.path.join(os.environ['OUT'], 'cases.json')) else 1)

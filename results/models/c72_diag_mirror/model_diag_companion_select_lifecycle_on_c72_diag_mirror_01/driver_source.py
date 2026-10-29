"""Run one unmodified c72 model driver on the c72_diag_mirror build with the diagnostic sessions in a chosen state,
while passively recording dev64 (both directions), dev9 (both directions) and the copy port.

Env: DIAG_COMPANION_DRIVER = the c72 driver file; DIAG_MIRROR_STATE = on | absent; run_model's gate environment.
Before the driver starts, a separate BF Runtime client (client_id 2) enables the copy port and writes the session
state through diag_mirror_sessions.apply, then disconnects; the driver then binds as usual (client_id 1).
Writes OUT/diag_companion.json and five pcaps; the driver writes its own results file. Model evidence only.

Copy criteria (state on): every copy equals one frame injected on dev64 or one frame emitted on dev64 (each used
once; a short injected frame may carry the model's Ethernet minimum padding), and every such frame has its copy.
A frame dropped in dev64 egress has no emitted frame, so a copy of it would stay unmatched. State absent: no copy.
"""
import hashlib
import json
import os
import re
import runpy
import socket
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent / 'hardware'), str(HERE.parent / 'checks')]
import diag_mirror_sessions  # noqa: E402
import telemetry_from_log  # noqa: E402
from model_driver import Model, same_frame  # noqa: E402

PACKET_OUTGOING, ETH_P_ALL = 4, 3
EGRESS_DROPS = ('r_Egress.drop_lifetime', 'r_Egress.out_drop', 'r_Egress.drop_odd')


class Tap(threading.Thread):
    """Passive capture on a device port's test-side veth: 'in' = emitted by the model, 'out' = injected into it.
    Opened with protocol 0 and bound to ETH_P_ALL, so it never hears traffic from other interfaces."""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.port, self.frames, self.stop = port, [], False
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
        self.sock.bind(('veth%d' % (2 * port + 1), ETH_P_ALL))
        self.sock.settimeout(0.1)

    def run(self):
        while not self.stop:
            try:
                frame, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            self.frames.append((time.time_ns() // 1000, 'out' if addr[2] == PACKET_OUTGOING else 'in', frame))

    def side(self, direction):
        return [(t, f) for t, d, f in self.frames if d == direction]


def match_copies(copies, injected, emitted):
    """Multiset matching of copies to relay-port frames; returns (unmatched copies, uncopied frames, kinds)."""
    pool = [('emitted', f) for f in emitted] + [('injected', f) for f in injected]
    used, unmatched, kinds = [False] * len(pool), [], {'emitted_exact': 0, 'injected_exact': 0, 'injected_min_padding': 0}
    for copy in copies:
        for exact in (True, False):
            hit = next((i for i, (k, f) in enumerate(pool) if not used[i] and
                        (copy == f if exact else (k == 'injected' and len(f) < 60 and same_frame(copy, f)))), None)
            if hit is not None:
                used[hit] = True
                kinds['%s_%s' % (pool[hit][0], 'exact' if exact else 'min_padding')] += 1
                break
        else:
            unmatched.append(copy.hex())
    return unmatched, [pool[i][1].hex() for i in range(len(pool)) if not used[i]], kinds


def egress_drops_by_port(log):
    port, drops = {}, {}
    with log.open('rb') as f:
        for raw in f:
            if b'Packet to egress parser: to port' not in raw and b'Action: r_Egress.' not in raw:
                continue
            line = raw.decode(errors='replace')
            ids = re.search(r':(0x[0-9a-f]+|-):(0x[0-9a-f]+|-):<', line)
            if not ids:
                continue
            p = re.search(r'to port (\d+)', line)
            if p:
                port[ids.group(2)] = p.group(1)
            a = re.search(r'Action: (r_Egress\.\w+)', line)
            if a and a.group(1) in EGRESS_DROPS:
                key = '%s@%s' % (a.group(1), port.get(ids.group(2)))
                drops[key] = drops.get(key, 0) + 1
    return drops


def digests(frames):
    return [hashlib.sha256(f).hexdigest() for _t, f in frames]


def main():
    state, driver = os.environ['DIAG_MIRROR_STATE'], Path(os.environ['DIAG_COMPANION_DRIVER']).resolve()
    out, build = Path(os.environ['OUT']), Path(os.environ['PORT_MAP']).parent
    c = diag_mirror_sessions.load(build)
    relay, copy = c['relay_in'], c['copy_port']
    master = json.loads(Path(os.environ['PORT_MAP']).read_text())['supported_profile']['ports']['master_dev']
    setup = Model(ports=[copy], client_id=2)                 # enables the copy port in every state
    import switch
    sw = switch.Switch.__new__(switch.Switch)
    sw.iface, sw.bi, sw.sw_read = setup.iface, setup.info, set()
    applied = diag_mirror_sessions.apply(sw, c, state)
    sw.close()
    taps = {p: Tap(p) for p in (master, relay, copy)}
    for tap in taps.values():
        tap.start()
    sys.argv = [str(driver)]
    try:
        runpy.run_path(str(driver), run_name='__main__')
        driver_exit = 0
    except SystemExit as stop:
        driver_exit = stop.code if isinstance(stop.code, int) else (0 if stop.code is None else 1)
    time.sleep(1.0)
    for tap in taps.values():
        tap.stop = True
        tap.join(1)
    import pcaptk
    sides = {'dev%d_injected' % master: taps[master].side('out'), 'dev%d_emitted' % master: taps[master].side('in'),
             'dev%d_injected' % relay: taps[relay].side('out'), 'dev%d_emitted' % relay: taps[relay].side('in'),
             'dev%d_copies' % copy: taps[copy].side('in')}
    for name, frames in sides.items():
        pcaptk.write_pcap(str(out / ('companion_%s.pcap' % name)), frames)
    copies = [f for _t, f in sides['dev%d_copies' % copy]]
    unmatched, uncopied, kinds = match_copies(copies, [f for _t, f in sides['dev%d_injected' % relay]],
                                              [f for _t, f in sides['dev%d_emitted' % relay]])
    drops = egress_drops_by_port(telemetry_from_log.model_log())
    if state == 'on':
        checks = dict(every_copy_matches_a_relay_frame=not unmatched, every_relay_frame_copied=not uncopied)
    else:
        checks = dict(no_copies=not copies)
    report = dict(schema='c72-diag-mirror-companion-v1', state=state, driver=driver.name,
                  driver_sha256=hashlib.sha256(driver.read_bytes()).hexdigest(), driver_exit=driver_exit,
                  session_apply=json.loads(json.dumps(applied, default=str)), counts={k: len(v) for k, v in sides.items()},
                  copy_kinds=kinds, unmatched_copies=unmatched[:20], uncopied_relay_frames=uncopied[:20],
                  egress_drops_by_port=drops, relay_egress_drops=sum(n for k, n in drops.items() if k.endswith('@%d' % relay)),
                  digests={k: digests(v) for k, v in sides.items() if not k.endswith('copies')},
                  checks=checks, passed=all(checks.values()) and driver_exit == 0)
    (out / 'diag_companion.json').write_text(json.dumps(report, indent=1) + '\n')
    print('COMPANION', state, driver.name, 'driver_exit', driver_exit, json.dumps(checks), report['counts'], kinds,
          'relay egress drops', report['relay_egress_drops'])
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

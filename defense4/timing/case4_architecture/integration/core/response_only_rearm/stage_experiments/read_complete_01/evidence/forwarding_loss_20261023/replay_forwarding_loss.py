"""Model replay of the 2026-10-23 forwarding-loss trial (c26 reference, separate_ack/off, t0).

NOT RUN YET: do not launch while another compile/model job is active.

Two modes:
  launcher:  python3 replay_forwarding_loss.py --launch SCENARIO [--attempt N]
             starts launch_model.sh on ctl_timing_01/evidence/m12p_c26/compile_local/out with SHARED_PORT=1
             (both endpoints on dev port 9, as on hardware) and runs this file as the driver.
  driver:    (inside launch_model.sh; env PROG, OUT, REPLAY_SCENARIO set)

The driver installs the exact table rows and T parameters the hardware trial wrote (parsed from its
install.log), injects the trial's own frames from out.pcap on port 9 (Ethernet-padded to 60 bytes as the
Vision NIC does), and after every injected frame records: frames emitted on 9 / 48 / 180, and the N and E
registers that decide the path (work cell, owner, N epoch, client, server, retry_epoch, counter,
count_first/busy/term, E epoch/master_isn/mode slot 0). Results: $OUT/replay_results.json, sent/received pcaps.

Scenarios (each a fresh model):
  exact        hardware order, one frame at a time (quiet capture between frames)
  prelude      exact, preceded by the two calibration segments (.62:20001 -> .61:61998) and the two RSTs the
               master kernel answers with (they explain 2 of the 12 n_ack_return laps)
  synack_b2b   SYN, then SYN-ACK injected with NO wait (SYN-ACK arrives while SYN's N passes / T hold are in
               progress), then the rest as exact
  ack_b2b      SYN-ACK and the master's final ACK injected back-to-back (ACK reaches stage 0 while the
               SYN-ACK still owns the work cell) -- the condition that yields busy_pass for kind 3
  ack_dup      final ACK injected twice back-to-back (second copy must find the cell busy)
Hardware signature to match: port 9 egress = SYN + 3 SYN-ACK (+2 RST, +2 calibration in 'prelude');
no final ACK / READ / FIN crosses; count_busy[1] == 1, count_busy[0] == 0; one frame to 180 (the SYN, 0x0e00).
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
STAGE = HERE.parents[2]                                  # .../stage_experiments
CORE = STAGE.parents[1]                                  # .../integration/core
BUILD = STAGE / 'ctl_timing_01/evidence/m12p_c26'
TRIAL = (STAGE / 'read_complete_01/evidence/hw_blocks/rc01_hw_c26_20261023_01_reference/separate_ack/off/'
         'rc01_hw_c26_20261023_01_reference_separate_ack_off_t0')
SCENARIOS = ('exact', 'prelude', 'synack_b2b', 'ack_b2b', 'ack_dup')
PORTS = '9 48 68 180 181 182 196'

REGS = [  # (bfrt name, index, pipe)
    ('p0.n_Ingress.work.work', 0), ('p0.n_Ingress.owner', 0), ('p0.n_Ingress.epoch', 0),
    ('p0.n_Ingress.client', 0), ('p0.n_Ingress.server', 0), ('p0.n_Ingress.retry_epoch', 0),
    ('p0.n_Ingress.counter', 0), ('p0.n_Ingress.read_app', 0),
] + [('p0.n_Ingress.count_first', i) for i in range(4)] \
  + [('p0.n_Ingress.count_busy', i) for i in range(8)] \
  + [('p0.n_Ingress.count_term', i) for i in range(4)] \
  + [('p0.r_Egress.epoch', 0), ('p0.r_Egress.master_isn', 0), ('p0.r_Egress.mode', 0)]


# ------------------------------------------------------------------ pcap / frames (no model needed)
def read_pcap(path):
    import struct
    data = Path(path).read_bytes()
    endian = '<' if data[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    nano = data[:4] in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    off, out = 24, []
    while off + 16 <= len(data):
        sec, frac, incl, _ = struct.unpack(endian + 'IIII', data[off:off + 16])
        out.append((sec + frac / (1e9 if nano else 1e6), data[off + 16:off + 16 + incl]))
        off += 16 + incl
    return out


def pad60(frame):
    return frame + bytes(max(0, 60 - len(frame)))


def describe(frame):
    if len(frame) < 54 or frame[12:14] != b'\x08\x00':
        return dict(len=len(frame), head=frame[:16].hex())
    ihl = (frame[14] & 15) * 4
    t = 14 + ihl
    total = int.from_bytes(frame[16:18], 'big')
    return dict(len=len(frame), src='.'.join(map(str, frame[26:30])), sport=int.from_bytes(frame[t:t + 2], 'big'),
                dport=int.from_bytes(frame[t + 2:t + 4], 'big'), seq=int.from_bytes(frame[t + 4:t + 8], 'big'),
                ack=int.from_bytes(frame[t + 8:t + 12], 'big'), flags='0x%02x' % frame[t + 13],
                payload=total - ihl - (frame[t + 12] >> 4) * 4)


def trial_frames():
    # out.pcap is captured on Vision TX before checksum offload: the TCP checksum field holds the partial
    # pseudo-header sum (model run exact_01: N's network table missed, tcp_sum 0x4A8B). The wire carried the
    # completed checksum, so recompute it.
    frames = [(ts, fix_checksums(pad60(f))) for ts, f in read_pcap(TRIAL / 'out.pcap')]
    names, counts = [], {}
    for _, f in frames:
        d = describe(f)
        base = {'0x02': 'SYN', '0x12': 'SYNACK', '0x10': 'ACK', '0x18': 'READ', '0x19': 'FINPSH'}.get(d['flags'], d['flags'])
        counts[base] = counts.get(base, 0) + 1
        names.append('%s%d' % (base, counts[base]))
    return [(n, ts, f) for n, (ts, f) in zip(names, frames)]


def calibration_prelude():
    """The two calibration segments (captured) and the RST|ACK the master kernel sends for each (not captured;
    reconstructed: .61:61998 -> .62:20001, seq = segment ack, ack = segment seq + 256)."""
    import struct
    segs = [pad60(f) for _, f in read_pcap(TRIAL / 'calibration_out.pcap')]
    out = []
    for i, s in enumerate(segs):
        out.append(('CAL%d' % (i + 1), s, 'outstation'))
        d = describe(s)
        eth = s[6:12] + s[0:6] + b'\x08\x00'
        ip = bytearray(b'\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00' + s[30:34] + s[26:30])
        tcp = bytearray(struct.pack('!HHIIBBHHH', d['dport'], d['sport'], d['ack'], (d['seq'] + d['payload']) & 0xffffffff,
                                    0x50, 0x14, 0, 0, 0))
        out.append(('RST%d' % (i + 1), fix_checksums(pad60(bytes(eth + ip + tcp))), 'master'))
    return out


def fix_checksums(packet):
    import struct
    f = bytearray(packet)
    ihl = (f[14] & 15) * 4
    t = 14 + ihl
    total = int.from_bytes(f[16:18], 'big')

    def cs(b):
        b = bytes(b) + (b'\0' if len(b) & 1 else b'')
        s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
        while s >> 16:
            s = (s & 0xffff) + (s >> 16)
        return ~s & 0xffff
    f[24:26] = b'\0\0'
    f[24:26] = struct.pack('!H', cs(f[14:t]))
    f[t + 16:t + 18] = b'\0\0'
    f[t + 16:t + 18] = struct.pack('!H', cs(f[26:34] + bytes((0, 6)) + struct.pack('!H', total - ihl) + f[t:14 + total]))
    return bytes(f)


# ------------------------------------------------------------------ hardware rows from install.log
ROW = re.compile(r'^OK\s+(p4|default)\s+pipe=\S+\s+(\S+)\s+\[(.*)\](?:\s+prio=(\d+))?\s+->\s+([\w.]+)\((.*)\)\s*$')


def parse_value(text):
    text = text.strip()
    if '&&&' in text:
        v, m = text.split('&&&')
        return (int(v, 0), int(m, 0))
    return int(text, 0)


def hardware_rows():
    rows = []
    for line in (TRIAL / 'install.log').read_text().splitlines():
        m = ROW.match(line)
        if not m:
            continue
        kind, table, keys, prio, action, data = m.groups()
        key = {}
        for item in filter(None, [k.strip() for k in keys.split(',')]):
            k, v = item.split('=', 1)
            key[k.replace('$valid', '$valid')] = parse_value(v)
        dat = {}
        for item in filter(None, [d.strip() for d in data.split(',')]):
            k, v = item.split('=', 1)
            dat[k] = int(v, 0)
        rows.append(dict(kind=kind, table=table, key=key, priority=int(prio) if prio else None, action=action, data=dat))
    if not rows:
        raise SystemExit('no OK p4/default rows parsed from install.log')
    return rows


# ------------------------------------------------------------------ driver (inside launch_model.sh)
def driver():
    sys.path[:0] = [str(CORE), str(CORE / 'response_only')]
    from model_driver import Model, Report  # noqa: E402
    import importlib.util
    spec = importlib.util.spec_from_file_location('_composite', CORE / 'response_only/model_drive_composite.py')
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
    scenario = os.environ['REPLAY_SCENARIO']
    out = Path(os.environ['OUT'])
    report = Report(os.environ['PROG'], physical=False, scope='forwarding-loss replay ' + scenario,
                    driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    m = Model(ports=[], enable=False)
    log, sent, received = [], [], []
    try:
        m.enable_ports([9] + h.FRONT_LOOPS)
        m.enable_ports([p for p in h.LOOP_PORTS if p not in h.FRONT_LOOPS])
        reflectors = [h.Reflector(p) for p in h.FRONT_LOOPS]
        for r in reflectors:
            r.start()
        for row in hardware_rows():
            name = row['table'] if row['table'].startswith('p') else row['table']
            if row['kind'] == 'default':      # T params: raw build units exactly as the hardware wrote them
                t = m.table(name)
                import bfrt_grpc.client as gc
                t.default_entry_set(m.target, t.make_data([gc.DataTuple(k, v) for k, v in row['data'].items()],
                                                          row['action']))
            else:
                m.add(name, row['key'], row['action'], row['data'], row['priority'])
        import bfrt_grpc.client as gc
        mc = m.table('$mirror.cfg', raw=True)    # hardware: $sid=7 INGRESS -> 196, max_pkt_len 2048
        mc.entry_add(gc.Target(device_id=0, pipe_id=0xffff), [mc.make_key([gc.KeyTuple('$sid', 7)])], [mc.make_data([
            gc.DataTuple('$direction', str_val='INGRESS'), gc.DataTuple('$ucast_egress_port', 196),
            gc.DataTuple('$ucast_egress_port_valid', bool_val=True), gc.DataTuple('$session_enable', bool_val=True)],
            '$normal')])

        def regs():
            snap = {}
            for name, idx in REGS:
                try:
                    v = m.register_read(name, idx, pipe=0)
                    snap['%s[%d]' % (name.split('.', 1)[1], idx)] = {k.rsplit('.', 1)[-1]: (x[0] if isinstance(x, list) else x)
                                                                    for k, x in v.items()}
                except Exception as exc:
                    snap['%s[%d]' % (name, idx)] = 'read error: %s' % str(exc).splitlines()[0][:120]
            return snap

        def inject(batch, label):
            """batch: frames injected back-to-back on port 9, then one capture window."""
            m.drain([9, 48, 180])
            for name, frame in batch:
                sent.append((time.time_ns() // 1000, frame))
                m.send(9, frame)
            got = m.capture([9, 180], timeout=3, quiet=0.5)
            for frames in got.values():
                received.extend((time.time_ns() // 1000, f) for f in frames)
            log.append(dict(step=label, injected=[(n, describe(f)) for n, f in batch],
                            out={str(p): [describe(f) for f in fs] for p, fs in got.items()},
                            registers=regs()))

        frames = trial_frames()
        log.append(dict(step='initial', registers=regs()))
        if scenario == 'prelude':
            for name, frame, _side in calibration_prelude():
                inject([(name, frame)], name)
        steps = [[(n, f)] for n, _, f in frames]
        if scenario == 'synack_b2b':          # SYN and SYN-ACK in one batch
            steps = [steps[0] + steps[1]] + steps[2:]
        elif scenario == 'ack_b2b':           # SYN-ACK and final ACK in one batch
            steps = [steps[0], steps[1] + steps[2]] + steps[3:]
        elif scenario == 'ack_dup':           # final ACK twice back-to-back
            steps = [steps[0], steps[1], steps[2] + steps[2]] + steps[3:]
        for batch in steps:
            inject(batch, '+'.join(n for n, _ in batch))
        report.record['meta']['reflections'] = {r.port: r.summary() for r in reflectors}
        crossed = [d for s in log for d in s.get('out', {}).get('9', [])]
        report.add('replay_completed', True, True, crossed=crossed)
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    (out / 'replay_steps.json').write_text(json.dumps(log, indent=1) + '\n')
    try:
        sys.path.insert(0, str(CORE.parent.parent / 'protocol/hw_vepa/tests'))
        import pcaptk
        pcaptk.write_pcap(str(out / 'sent.pcap'), sent)
        pcaptk.write_pcap(str(out / 'received.pcap'), received)
    except Exception as exc:
        log.append(dict(pcap_error=str(exc)))
    return 0 if report.finish(out / 'replay_results.json') else 1


def launch(scenario, attempt, build_out=None, tag=''):
    build_out = Path(build_out) if build_out else BUILD / 'compile_local/out'
    out = HERE / ('model_replay_%s%s_%02d' % (tag, scenario, attempt))
    assert not out.exists(), 'evidence must not be overwritten'
    env = dict(os.environ, PORT_MAP=str(BUILD / 'response_only.inputs.json'), SHARED_PORT='1', PAD_ENABLE='0',
               MILESTONE='m12', REPLAY_SCENARIO=scenario)
    cmd = ['bash', str(CORE / 'launch_model.sh'), '-p', str(build_out), '-o', str(out),
           '-P', PORTS, '-d', str(Path(__file__).resolve())]
    rc = subprocess.run(cmd, env=env).returncode
    if out.is_dir():
        (out / 'launch_command.json').write_text(json.dumps(dict(command=cmd, scenario=scenario, hardware=False,
                                                                 exit_code=rc, build_out=str(build_out)), indent=1) + '\n')
    return rc


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--launch', choices=SCENARIOS)
    p.add_argument('--attempt', type=int, default=1)
    p.add_argument('--build-out', help='compiled out/ of a variant (same ports as c26); default c26 compile_local/out')
    p.add_argument('--tag', default='', help='evidence directory prefix for a variant, e.g. f1_')
    p.add_argument('--dry-run', action='store_true', help='parse pcaps and install.log only; no model')
    a = p.parse_args()
    if a.dry_run:
        print(json.dumps(dict(frames=[(n, describe(f)) for n, _, f in trial_frames()],
                              prelude=[(n, describe(f), s) for n, f, s in calibration_prelude()],
                              rows=len(hardware_rows())), indent=1))
        return 0
    if a.launch:
        return launch(a.launch, a.attempt, a.build_out, a.tag)
    if os.environ.get('REPLAY_SCENARIO') and os.environ.get('OUT'):
        return driver()
    p.error('give --launch SCENARIO or --dry-run')


if __name__ == '__main__':
    raise SystemExit(main())

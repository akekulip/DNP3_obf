"""Independent physical-switch readout of one campaign block (Python >= 3.10). Fail-closed.

The expected set comes from the FROZEN block config, not from any file the run generated: the planned trials are
arms x fixtures x trials_per_arm (label <run>_<fixture>_<arm>_t<i>), and each trial's expected exchanges are
reads_per_trial READs and, when run_sbo, sbo_cycles SELECT and OPERATE each. The run's own records
(standards.json expected.counts, master.json, campaign_run.json) are only cross-checked against that expectation.

Per trial, both Vision captures are read with integer nanosecond timestamps (wire_check.read_pcap_records; a
truncated capture fails). The trial's one TCP connection (its master port <-> the outstation port, exactly one
incarnation) is reassembled per direction by sequence number; a gap, an overlap with different bytes, or a
missing handshake fails, and retransmitted segments are counted. Out.pcap holds what Vision SENT (the master's
requests, the outstation's native responses), in.pcap what it RECEIVED (requests at the outstation, responses
through the switch at the master).

DNP3 link frames are cut from each byte stream with every block CRC checked, and transport segments are
reassembled into application fragments. A response is the whole fragment: its link frames, the TCP segments that
carried them and its aggregate octets are recorded separately, never assuming one response is one TCP payload.
Requests and responses pair by application sequence in order; any missing, extra or mismatched exchange fails.
Each response the master received must equal its expected image exactly:
  READ   padding on: general_read_padding.pad_read(request at the outstation, native, targets) (the reference
         encoder); targets are the frozen policy's, or on a two-READ-target build (builds[b].read_padding declared)
         the config's own read_images values, and then each padded READ must also be its class's declared image
         (target), declared padding point count and the prefix construction; padding off: the native bytes;
  SELECT/OPERATE   padding on: the candidate61 control image (read_reencode_01/profile_check.expected_image);
                   padding off: the native bytes.
Latency is reported to the first response frame and to the complete response (the segment that delivered its
last byte), both from the master's request in integer ns, per kind and per READ class. Percentiles are nearest-rank.

  python3 hw_read_readout.py BLOCK_DIR --config FROZEN_CONFIG.json [--arms a,b] [--fixtures f] [--out R.json]
Exit 0 only when every planned trial is present and every check passes.
"""
import argparse
import collections
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
STAGE = ROOT.parent
ARCH = STAGE.parents[3]
sys.path.insert(0, str(ROOT / 'software/source/full_read_01'))
sys.path.insert(0, str(ROOT / 'software/source/read_reencode_01'))
sys.path.insert(0, str(ARCH / 'protocol/hw_vepa'))
import general_read_padding as gp  # noqa: E402
import read_classes as rcls  # noqa: E402  (the harness's schedules: one source of the endpoint's slot order)
import wire_check  # noqa: E402

std = gp.std
POLICY = json.loads((ROOT / 'policy/policy.json').read_text())
TARGETS = POLICY['selected']['targets']
PAD_START, PAD_STOP = POLICY['profile']['reserved_padding_range']
KINDS = {1: 'READ', 3: 'SELECT', 4: 'OPERATE'}
ROTATE4 = ('range', 'analog', 'class0', 'integrity')   # the fixture endpoint's fixed order (repeat_sbo_endpoint README)


def read_class(request_app):
    """READ class from the request's first object header (application bytes after func): never from position."""
    g, v = request_app[2], request_app[3]
    if g == 10:
        return 'range'
    if (g, v) == (1, 2):
        return 'mixed'
    if g == 30:
        return 'analog'
    if g == 60:
        return 'class0' if (v == 1 and len(request_app) <= 5) else 'integrity'
    return 'g%dv%d' % (g, v)


def schedule_counts(schedule, total):
    """Per-class READ counts of one trial of the fixed schedule of n classes: class j gets floor(T/n) + (j < T mod n)."""
    if not schedule:
        return {'range': total}
    if schedule not in rcls.SCHEDULES:
        raise ReadoutError('unknown READ schedule %r' % schedule)
    order = rcls.SCHEDULES[schedule]
    return {c: total // len(order) + (1 if j < total % len(order) else 0) for j, c in enumerate(order)}


def two_read_declaration(cfg, arm):
    """(read_images, read_padding) of a two-READ-target build (read_padding declared), else None."""
    build = cfg['builds'][next(a['build'] for a in cfg['arms'] if a['name'] == arm)]
    if build.get('read_padding') is None:
        return None
    return build['read_images'], build['read_padding']


def read_targets(declaration):
    return sorted(set(declaration[0].values())) if declaration else TARGETS


def check_read_encoding(rclass, info, master_len, declaration):
    """[failure] for a padded READ of a two-READ-target build: its class's declared image, padding and the prefix."""
    images, padding = declaration
    want = (images.get(rclass), padding.get(rclass), 'prefix', 'padded')
    got = (master_len, (info or {}).get('padding_points'), (info or {}).get('construction'), (info or {}).get('status'))
    if images.get(rclass) is None or got != want or (info or {}).get('target') != images[rclass]:
        return ['READ %s: (image, padding points, construction, status) %r, target %r; declared %r'
                % (rclass, got, (info or {}).get('target'), want)]
    return []
SYN, ACK = 0x02, 0x10


def _profile_check():
    path = STAGE / 'read_reencode_01/profile_check.py'
    spec = importlib.util.spec_from_file_location('readout_profile_check', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROFILE = _profile_check()


class ReadoutError(ValueError):
    pass


def nearest_rank(values, q):
    v = sorted(values)
    return v[max(0, -(-int(q * len(v)) // 100) - 1)] if v else None


def plan(cfg, arms, fixtures):
    """{label: {'arm', 'fixture', 'padding', 'counts'}} from the frozen config alone."""
    t, traffic = cfg['trials'], cfg.get('traffic', {})
    counts = {'READ': int(t['reads_per_trial'])}
    classes = schedule_counts(traffic.get('read_schedule'), int(t['reads_per_trial']))
    if traffic.get('run_sbo', True):
        counts.update(SELECT=int(traffic['sbo_cycles']), OPERATE=int(traffic['sbo_cycles']))
    padding = {a['name']: int(a['padding']) for a in cfg['arms']}
    out = {}
    for fixture in fixtures:
        for arm in arms:
            for i in range(int(t['trials_per_arm'])):
                out['%s_%s_%s_t%d' % (cfg['_run_id'], fixture, arm, i)] = dict(
                    arm=arm, fixture=fixture, padding=padding[arm], counts=dict(counts), classes=dict(classes))
    return out


def tcp_packets(path):
    """[(t_ns, src_ip, sport, dst_ip, dport, flags, seq, payload, frame_len)] from one capture; fails on truncation."""
    data = Path(path).read_bytes()
    records, _res = wire_check.read_pcap_records(path)
    if 24 + sum(16 + r['captured_len'] for r in records) != len(data):
        raise ReadoutError('%s: truncated or trailing bytes after the last whole record' % path)
    out = []
    for r in records:
        f = r['frame']
        if len(f) < 54 or f[12:14] != b'\x08\x00' or f[23] != 6:
            continue
        ihl = (f[14] & 15) * 4
        o = 14 + ihl
        if len(f) < o + 20:
            continue
        doff = (f[o + 12] >> 4) * 4
        total = int.from_bytes(f[16:18], 'big')
        payload = f[o + doff:14 + total]
        if len(payload) != total - ihl - doff:
            raise ReadoutError('%s: packet %d payload shorter than its IP length (snap?)' % (path, len(out)))
        out.append((r['timestamp_ns'], '.'.join(map(str, f[26:30])), int.from_bytes(f[o:o + 2], 'big'),
                    '.'.join(map(str, f[30:34])), int.from_bytes(f[o + 2:o + 4], 'big'), f[o + 13],
                    int.from_bytes(f[o + 4:o + 8], 'big'), bytes(payload), len(f)))
    return out


def stream(packets, src, dst):
    """One direction of the trial's single TCP incarnation: (bytes, byte_time_ns[], segments[], retransmissions)."""
    mine = [p for p in packets if (p[1], p[2]) == src and (p[3], p[4]) == dst]
    isns = {p[6] for p in mine if p[5] & SYN}         # a retransmitted SYN repeats the same ISN
    if len(isns) != 1:
        raise ReadoutError('%s->%s: %d SYN incarnations, expected exactly 1' % (src, dst, len(isns)))
    isn = (isns.pop() + 1) & 0xFFFFFFFF
    data, times, segs, seen, retx = {}, {}, [], set(), 0
    for p in mine:
        if not p[7]:
            continue
        off = (p[6] - isn) & 0xFFFFFFFF
        if (off, p[7]) in seen:
            retx += 1
            continue
        if off in {o for o, _ in seen}:
            retx += 1                                  # repacketized retransmission: bytes checked below
        seen.add((off, p[7]))
        segs.append(dict(offset=off, length=len(p[7]), t_ns=p[0], frame_len=p[8]))
        for i, b in enumerate(p[7]):
            if data.get(off + i, b) != b:
                raise ReadoutError('%s->%s: overlapping segments disagree at offset %d' % (src, dst, off + i))
            data[off + i] = b
            times.setdefault(off + i, p[0])
    n = max(data) + 1 if data else 0
    if len(data) != n:
        raise ReadoutError('%s->%s: byte stream has a gap (%d of %d octets)' % (src, dst, len(data), n))
    return bytes(data[i] for i in range(n)), [times[i] for i in range(n)], segs, retx


def fragments(buf, times, segs):
    """Application fragments in stream order, each with its link frames and carrying TCP segments."""
    out, cur, pos = [], None, 0
    while pos < len(buf):
        if buf[pos:pos + 2] != b'\x05\x64' or pos + 10 > len(buf):
            raise ReadoutError('stream offset %d is not a DNP3 link frame start' % pos)
        size = std.frame_length(buf[pos + 2] - 5)
        if pos + size > len(buf):
            raise ReadoutError('stream ends inside a link frame at offset %d' % pos)
        frame = buf[pos:pos + size]
        _header, user = std.deframe(frame)                  # every block CRC checked
        th = user[0]
        if th & std.FIR:
            if cur is not None:
                raise ReadoutError('FIR at offset %d before the previous fragment finished' % pos)
            cur = dict(app=bytearray(), frames=[], start=pos, t_first_ns=times[pos])
        elif cur is None:
            raise ReadoutError('continuation frame at offset %d without FIR' % pos)
        cur['app'] += user[1:]
        cur['frames'].append(size)
        pos += size
        if th & std.FIN:
            cur.update(end=pos, t_complete_ns=max(times[cur['start']:pos]), bytes=buf[cur['start']:pos],
                       tcp_segments=[s['length'] for s in segs if s['offset'] < pos and
                                     s['offset'] + s['length'] > cur['start']])
            out.append(cur)
            cur = None
    if cur is not None:
        raise ReadoutError('stream ends inside an application fragment')
    return out


def expected_image(kind, request_at_outstation, native, padding, targets=None):
    if not padding:
        return native, None
    if kind == 'READ':
        r = gp.pad_read(request_at_outstation, native, targets or TARGETS, pad_start=PAD_START, pad_stop=PAD_STOP)
        if r.status not in ('padded', 'already_at_target'):
            raise ReadoutError('padding-on READ of %d octets is %s under the policy: %s'
                               % (len(native), r.status, r.reason))
        return r.output, dict(status=r.status, target=r.target, padding_points=r.padding_points,
                              construction=r.construction)
    return PROFILE.expected_image(kind, native, 61), None


def analyse_trial(tdir, spec, cfg):
    fail = []
    result = json.loads((tdir / 'result.json').read_text()) if (tdir / 'result.json').is_file() else {}
    port = result.get('master_port')
    rng = cfg['traffic']['master_port_range']
    if not isinstance(port, int) or not rng['first'] <= port <= rng['last']:
        raise ReadoutError('master port %r outside the configured range %r' % (port, rng))
    master = (cfg['endpoints']['master_ip'], port)
    outstation = (cfg['endpoints']['outstation_ip'], int(cfg['endpoints']['outstation_port']))
    sent, recv = tcp_packets(tdir / 'out.pcap'), tcp_packets(tdir / 'in.pcap')
    resolution = sorted({wire_check.read_pcap_records(tdir / n)[1] for n in ('out.pcap', 'in.pcap')})
    m_req = stream(sent, master, outstation)
    o_rsp = stream(sent, outstation, master)
    o_req = stream(recv, master, outstation)
    m_rsp = stream(recv, outstation, master)
    req_m = [f for f in fragments(*m_req[:3]) if f['app'][1] != 0]          # CONFIRM (func 0) has no response
    req_o = [f for f in fragments(*o_req[:3]) if f['app'][1] != 0]
    nat = fragments(*o_rsp[:3])
    got = fragments(*m_rsp[:3])
    lens = (len(req_m), len(req_o), len(nat), len(got))
    if len(set(lens)) != 1:
        fail.append('exchange counts differ: master requests %d, outstation requests %d, native responses %d, '
                    'master responses %d' % lens)
    declaration = two_read_declaration(cfg, spec['arm'])
    targets = read_targets(declaration)
    rows = []
    for i in range(min(lens)):
        q, qo, n, g = req_m[i], req_o[i], nat[i], got[i]
        kind = KINDS.get(q['app'][1], 'func%d' % q['app'][1])
        seqs = (q['app'][0] & 15, qo['app'][0] & 15, n['app'][0] & 15, g['app'][0] & 15)
        if len(set(seqs)) != 1 or bytes(q['bytes']) != bytes(qo['bytes']):
            fail.append('exchange %d: request/response application sequences or request bytes differ %r' % (i, seqs))
            continue
        try:
            want, info = expected_image(kind, bytes(qo['bytes']), bytes(n['bytes']), spec['padding'], targets)
        except (gp.UnsupportedRead, std.StdError, ValueError, AssertionError) as error:
            fail.append('exchange %d (%s): no expected image: %s' % (i, kind, error))
            continue
        exact = bytes(g['bytes']) == want
        if not exact:
            fail.append('exchange %d (%s): master received %d octets, expected image %d octets%s'
                        % (i, kind, len(g['bytes']), len(want), '' if len(g['bytes']) != len(want) else ' (bytes differ)'))
        rclass = read_class(bytes(qo['app'])) if kind == 'READ' else None
        if declaration and kind == 'READ' and spec['padding']:
            fail += ['exchange %d: %s' % (i, f) for f in check_read_encoding(rclass, info, len(g['bytes']), declaration)]
        rows.append(dict(index=i, kind=kind, read_class=rclass, app_seq=seqs[0], native_len=len(n['bytes']), master_len=len(g['bytes']),
                         native_frames=n['frames'], master_frames=g['frames'], native_tcp=n['tcp_segments'],
                         master_tcp=g['tcp_segments'], exact=exact, encoding=info,
                         latency_first_ns=g['t_first_ns'] - q['t_first_ns'],
                         latency_complete_ns=g['t_complete_ns'] - q['t_first_ns']))
    counts = collections.Counter(r['kind'] for r in rows)
    if dict(counts) != spec['counts'] or len(rows) != sum(spec['counts'].values()):
        fail.append('exchanges by kind %r, planned %r' % (dict(counts), spec['counts']))
    got_classes = dict(collections.Counter(r['read_class'] for r in rows if r['kind'] == 'READ'))
    if got_classes != spec['classes']:
        fail.append('READ classes %r, planned by the schedule %r' % (got_classes, spec['classes']))
    std_counts = (json.loads((tdir / 'standards.json').read_text()).get('expected') or {}).get('counts') \
        if (tdir / 'standards.json').is_file() else None
    if std_counts != spec['counts']:
        fail.append('standards.json expected.counts %r differs from the frozen plan %r' % (std_counts, spec['counts']))
    m = json.loads((tdir / 'master.json').read_text()) if (tdir / 'master.json').is_file() else {}
    if m.get('reads_completed') != spec['counts']['READ']:
        fail.append('master.json reads_completed %r, planned %d' % (m.get('reads_completed'), spec['counts']['READ']))
    o2m_native = sum(s['frame_len'] for s in o_rsp[2])
    o2m_master = sum(s['frame_len'] for s in m_rsp[2])
    duration_ns = (got[-1]['t_complete_ns'] - req_m[0]['t_first_ns']) if got and req_m else 0
    by_kind = {}
    for kind in sorted(counts):
        sel = [r for r in rows if r['kind'] == kind]
        by_kind_classes = sorted(collections.Counter((r['read_class'], r['master_len']) for r in sel if r['read_class']).items())
        by_kind[kind] = dict(
            n=len(sel), exact=sum(r['exact'] for r in sel), class_lengths=by_kind_classes,
            master_lens=sorted(collections.Counter(r['master_len'] for r in sel).items()),
            master_tcp=sorted(collections.Counter(tuple(r['master_tcp']) for r in sel).items()),
            latency_first_ns={q: nearest_rank([r['latency_first_ns'] for r in sel], q) for q in (50, 99)},
            latency_complete_ns={q: nearest_rank([r['latency_complete_ns'] for r in sel], q) for q in (50, 99)})
        if kind == 'READ':
            by_kind[kind]['by_class'] = {
                c: dict(n=len(cs), exact=sum(r['exact'] for r in cs),
                        master_lens=sorted(collections.Counter(r['master_len'] for r in cs).items()),
                        latency_first_ns={q: nearest_rank([r['latency_first_ns'] for r in cs], q) for q in (50, 99)},
                        latency_complete_ns={q: nearest_rank([r['latency_complete_ns'] for r in cs], q)
                                             for q in (50, 99)})
                for c in sorted({r['read_class'] for r in sel})
                for cs in [[r for r in sel if r['read_class'] == c]]}
    summary = dict(planned=spec['counts'], by_kind=by_kind, retransmissions=dict(
                       native_o2m=o_rsp[3], master_o2m=m_rsp[3], m2o_sent=m_req[3], m2o_received=o_req[3]),
                   o2m_unique_segment_frame_octets=dict(native=o2m_native, master=o2m_master,
                                                        overhead_percent=round(100 * (o2m_master / o2m_native - 1), 3)
                                                        if o2m_native else None),
                   duration_ns=duration_ns,
                   exchanges_per_s=round(len(rows) / (duration_ns / 1e9), 3) if duration_ns > 0 else None,
                   percentile_estimator='nearest-rank', capture_resolution=resolution)
    return dict(trial=tdir.name, arm=spec['arm'], padding=spec['padding'], master_port=port,
                summary=summary, failures=fail, rows=rows)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('block')
    ap.add_argument('--config', required=True, help='the frozen config the block ran')
    ap.add_argument('--arms', help='comma list; default: the config evaluation.arm_order')
    ap.add_argument('--fixtures', default='separate_ack')
    ap.add_argument('--out')
    a = ap.parse_args(argv)
    block = Path(a.block)
    cfg_bytes = Path(a.config).read_bytes()
    cfg = json.loads(cfg_bytes)
    cfg['_run_id'] = block.name
    config_sha = hashlib.sha256(cfg_bytes).hexdigest()
    bound = {name: (json.loads((block / name).read_text()).get(key) if (block / name).is_file() else None)
             for name, key in (('campaign_run.json', 'config_file_sha256'), ('freeze_check.json', 'config_sha256'))}
    arms = a.arms.split(',') if a.arms else cfg['evaluation']['arm_order']
    planned = plan(cfg, arms, a.fixtures.split(','))
    run = json.loads((block / 'campaign_run.json').read_text()) if (block / 'campaign_run.json').is_file() else {}
    ran = {t['label'] for arm in run.get('arms', []) for t in arm.get('trials', [])}
    trials, failures = [], []
    for name, sha in bound.items():
        if sha != config_sha:
            failures.append('--config sha256 %s is not the config this block ran (%s records %r)' % (config_sha[:12], name, sha))
    for label, spec in planned.items():
        tdir = block / spec['fixture'] / spec['arm'] / label
        if label not in ran:
            failures.append('%s: planned trial absent from campaign_run.json' % label)
        if not ((tdir / 'out.pcap').is_file() and (tdir / 'in.pcap').is_file()):
            failures.append('%s: planned trial has no capture pair' % label)
            continue
        try:
            trials.append(analyse_trial(tdir, spec, cfg))
        except Exception as error:  # noqa: BLE001 - every analysis error is a recorded failure, never a pass
            trials.append(dict(trial=label, arm=spec['arm'], failures=['analysis error: %s' % error]))
    extra = ran - set(plan(cfg, cfg['evaluation']['arm_order'], a.fixtures.split(',')))
    if extra:
        failures.append('trials not in the frozen plan: %s' % sorted(extra))
    for t in trials:
        failures += ['%s: %s' % (t['trial'], f) for f in t['failures']]
    partial = sorted(set(cfg['evaluation']['arm_order']) - set(arms))
    report = dict(block=str(block), config=str(a.config), config_sha256=config_sha, partial_arms_omitted=partial,
                  planned=sorted(planned), policy_targets=TARGETS,
                  read_targets={a: read_targets(two_read_declaration(cfg, a)) for a in arms},
                  trials=trials, failures=failures, ok=bool(planned) and not failures)
    if a.out:
        Path(a.out).write_text(json.dumps(report, indent=1) + '\n')
    for t in trials:
        print(json.dumps(dict(trial=t['trial'], by_kind=(t.get('summary') or {}).get('by_kind'),
                              failures=t['failures'][:3]))[:1500])
    print('READOUT %s%s: %d planned trials, %d failures' % ('OK' if report['ok'] else 'FAILED',
          ' (PARTIAL: arms %s not read)' % ','.join(partial) if partial else '', len(planned), len(failures)))
    for f in failures[:20]:
        print('  ' + f)
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())

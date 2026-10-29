#!/usr/bin/env python3
"""D3a-D3d and E2 of the registered diagnostic-mirror design, with a thin E1 entry that runs preservation_check.

The design is results/analysis/diag_mirror_d3/DESIGN.json. Trial directories are <block>/<arm>/<trial>/ (arm = the
parent directory name, as eval_rows). --on: d3_mirror_on_d20 trials (D3a, D3b off arm, D3c, E1 size_only/combined,
E2); --off: d3_mirror_off_d20 trials (D3d; E2 retransmission count only); --e2: e2_first_request_d20 trials (E2).

  $RESEARCH_PYTHON scripts/analysis/diag_mirror_d3.py --on TRIAL... --off TRIAL... --e2 TRIAL... \
      --build-label c72_diag_mirror --source-sha256 SHA --out OUT.json

Every count carries its denominator. The output is labelled with the build identity given on the command line; the
tool refuses to run without it, or when it disagrees with results/builds/<label>/response_only.inputs.json.
"""
import argparse
import contextlib
import io
import json
import statistics
import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(HERE), str(ROOT / 'scripts/checks')]
import diag_mirror_capture as cap  # noqa: E402
import preservation_check as pc  # noqa: E402
import relay_check as rc  # noqa: E402

frac = cap.frac
SCHEMA = 'c72-diag-mirror-d3-v1'
DESIGN = ROOT / 'results/analysis/diag_mirror_d3/DESIGN.json'
INTENDED_INTERFACE = 'enp59s0f1np1'               # DESIGN.json capture.intended_interface
INTENDED_BUS = '0000:3b:00.1'                       # DESIGN.json capture.intended_interface (i40e bus-info)
NIC_LOSS = ('drop', 'miss', 'discard', 'err')       # ethtool -S rx counter names reported as possible capture loss
PORTS = ('9', '64', '10')
COUNTERS = dict(rx='$FramesReceivedOK', tx='$FramesTransmittedOK')
CLASSES = ('READ mixed', 'READ integrity', 'SELECT', 'OPERATE')
TIMED_ARMS, E1_ARMS = ('timing_only', 'combined'), ('size_only', 'combined')
CLRT_BOUND_US = 50.0                              # DESIGN.json D3d falsifier: median CLRT difference, timed arms
ASSUMPTIONS = [
    'trial directories are <block>/<arm>/<trial>/; the arm is the parent directory name (off, timing_only, size_only,'
    ' combined); trial.json carries label and master_port; one connection (one master SYN) per trial',
    'out.pcap / in.pcap: classic pcap, tcpdump -s0 -Q out / -Q in on the master NIC (vision_run.py); out.pcap frames '
    'may carry the TX-offload placeholder TCP checksum, replaced by the NIC-computed checksum before comparison; no '
    'TSO/GSO split of master frames',
    'mirror.pcap: classic pcap (not pcapng), tcpdump -s0 -Q in, promiscuous, on the capture interface, GRO/LRO off, no '
    'FCS in captured frames, no VLAN tag',
    'out.pcap, in.pcap and mirror.pcap are timestamped by the same Vision host clock (E2 orders them)',
    'mirror_capture.json: vision_run.MirrorCapture record; its tcpdump key is parse_tcpdump_stats of the mirror '
    'tcpdump (captured, received, dropped_kernel, dropped_interface)',
    'mirror_iface_before.json / mirror_iface_after.json: MirrorCapture.identity (interface; driver = parsed ethtool -i;'
    ' link = ip -j -s link show, whose stats64.rx.packets is the interface RX count)',
    'the switch counter snapshots bracket the Vision step, so dev10/dev64 counters may include relay-leg frames '
    'outside the mirror capture window: copies against counters are bounds (copies <= counter), not equalities',
    'snapshots/<label>_before.json and _after.json: snapshot_counters.py run with --ports 9,64,10; ports keyed by the '
    'port number as a string; $FramesReceivedOK / $FramesTransmittedOK are the counted frames',
    'relay_wire.json: relay_check v3 output (sel751-wire-v3) of the same trial',
    'an ingress copy is a mirror frame whose Ethernet source is the relay MAC seen in the relay TCP copies; every '
    'other copy is an egress copy',
    'E1: mirror.pcap is preservation_check --relay-pcap (both mirror directions in one file)',
]


def counters(trial):
    """({devN: {rx, tx}} deltas after - before, None) or (None, reason)."""
    snaps = [cap.read_json(trial['dir'] / 'snapshots' / ('%s_%s.json' % (trial['label'], when)))
             for when in ('before', 'after')]
    if None in snaps:
        return None, 'counter snapshots snapshots/%s_before/_after.json missing' % trial['label']
    out = {}
    for port in PORTS:
        before, after = ((snap.get('ports') or {}).get(port) or {} for snap in snaps)
        try:
            out['dev' + port] = {key: after[field] - before[field] for key, field in COUNTERS.items()}
        except (KeyError, TypeError):
            return None, 'port %s counters missing from a snapshot' % port
    return out, None


def interface(trial):
    before, after = (cap.read_json(trial['dir'] / ('mirror_iface_%s.json' % when)) for when in ('before', 'after'))
    if before is None or after is None:
        return None, 'mirror_iface_before/after.json missing'
    def identity(d):
        driver = d.get('driver') or {}
        return dict(interface=d.get('interface'), driver=driver.get('driver'), bus_info=driver.get('bus-info'))

    def rx_packets(d):
        return d['link'][0]['stats64']['rx']['packets']
    try:
        rx = rx_packets(after) - rx_packets(before)
    except (KeyError, IndexError, TypeError):
        rx = None
    loss = {k: (after.get('rx_counters') or {}).get(k, 0) - v for k, v in (before.get('rx_counters') or {}).items()
            if any(word in k.lower() for word in NIC_LOSS) and (after.get('rx_counters') or {}).get(k, 0) != v}
    return dict(identity=identity(before), unchanged=identity(before) == identity(after), rx_packets_delta=rx,
                nic_loss_counter_deltas=loss), None


def mapping(trial):
    """D3a for one mirror-on trial: copies received against the dev10 TX delta and the master NIC relay-leg frames."""
    cnt, cnt_error = counters(trial)
    iface, iface_error = interface(trial)
    failures = [e for e in (cnt_error, iface_error) if e]
    failures += ['mirror.pcap missing'] if 'mirror.pcap' in trial['missing'] else []
    copies = sum(len(trial['mirror'][d]) for d in cap.DIRS)
    master = sum(len(trial['master'][d]) for d in cap.DIRS)
    dev10 = cnt['dev10']['tx'] if cnt else None
    name = iface['identity']['interface'] if iface else None
    bus = iface['identity']['bus_info'] if iface else None
    if iface and (name != INTENDED_INTERFACE or bus != INTENDED_BUS or not iface['unchanged']):
        failures.append('capture interface %r bus %r (unchanged %s), intended %s %s'
                        % (name, bus, iface['unchanged'], INTENDED_INTERFACE, INTENDED_BUS))
    falsified = bool(dev10) and copies == 0
    if falsified:
        failures.append('no relay-leg copies on the capture interface while switch dev10 TX advanced by %d' % dev10)
    if dev10 is not None and dev10 <= 0:
        failures.append('switch dev10 TX did not advance')
    return dict(trial=trial['name'], arm=trial['arm'], interface=iface, intended_interface=INTENDED_INTERFACE,
                copies_received=frac(len(trial['records']), dev10), relay_leg_copies=frac(copies, master),
                switch_dev10_tx=dev10, mapped=not failures and copies > 0, falsified=falsified, failures=failures)


def completeness(trial):
    """D3c for one mirror-on trial: copies per direction against the master NIC and the switch counters, tcpdump
    capture/drop statistics, and truncation (caplen < wire length, or a frame shorter than its IPv4 length)."""
    cnt, cnt_error = counters(trial)
    iface, _ = interface(trial)
    stats = (cap.read_json(trial['dir'] / 'mirror_capture.json') or {}).get('tcpdump')
    records = trial['records']
    macs = {s['frame'][6:12] for s in trial['mirror']['from_relay']}
    attributed = Counter(cap.record_direction(r['frame'], macs) for r in records)
    failures = [cnt_error] if cnt_error else []
    failures += ['inputs missing: ' + ', '.join(trial['missing'])] if trial['missing'] else []
    checks = []

    def check(name, n, of, gate=True, bound=False):
        # bound: the counter window is wider than the capture window, so only n <= of is required
        checks.append(dict(check=name, n=n, of=of, equal=n == of, gate=gate, bound=bound,
                           passed=(n <= of) if bound else n == of))
    if cnt:
        check('copies captured / switch dev10 TX', len(records), cnt['dev10']['tx'], bound=True)
        check('switch dev10 TX / switch dev64 RX + TX', cnt['dev10']['tx'], cnt['dev64']['rx'] + cnt['dev64']['tx'])
        check('ingress copies / switch dev64 RX', attributed['from_relay'], cnt['dev64']['rx'], bound=True)
        check('egress copies / switch dev64 TX', attributed['to_relay'], cnt['dev64']['tx'], bound=True)
    if iface and iface['rx_packets_delta'] is not None:
        check('copies captured / capture interface RX packets', len(records), iface['rx_packets_delta'], bound=True)
    if stats is None:
        failures.append('mirror_capture.json tcpdump statistics missing')
    else:
        check('copies in mirror.pcap / tcpdump captured', len(records), stats.get('captured'))
        failures += ['tcpdump %s %r' % (key, stats.get(key)) for key in ('dropped_kernel', 'dropped_interface')
                     if stats.get(key, 0 if key == 'dropped_interface' else None) != 0]
    off = trial['arm'] == 'off'      # other arms may hold or drop frames by design: descriptive there
    for d, where in (('from_relay', 'in.pcap'), ('to_relay', 'out.pcap')):
        check('connection %s copies / frames at the master NIC (%s)' % (d, where), len(trial['mirror'][d]),
              len(trial['master'][d]), gate=off)
    truncated = [r for r in records if r['captured_len'] < r['original_len']]
    short = [r for r in records if r['frame'][12:14] == b'\x08\x00' and len(r['frame']) >= 18 and
             len(r['frame']) < 14 + int.from_bytes(r['frame'][16:18], 'big')]
    failures += ['%s: %d of %d' % (c['check'], c['n'], c['of']) for c in checks if c['gate'] and not c['passed']]
    failures += ['%d copies truncated (caplen < wire length)' % len(truncated)] if truncated else []
    failures += ['%d copies shorter than their IPv4 length' % len(short)] if short else []
    directions = {d: dict(copies_connection=len(trial['mirror'][d]), copies_attributed=attributed[d],
                          master_nic_frames=len(trial['master'][d]),
                          switch_dev64=cnt['dev64']['rx' if d == 'from_relay' else 'tx'] if cnt else None)
                  for d in cap.DIRS}
    return dict(trial=trial['name'], arm=trial['arm'], copies=len(records), directions=directions,
                unattributed=frac(attributed['unattributed'], len(records)), counters=cnt, tcpdump=stats,
                interface_rx_packets_delta=iface['rx_packets_delta'] if iface else None,
                nic_loss_counter_deltas=iface['nic_loss_counter_deltas'] if iface else None, checks=checks,
                truncated=frac(len(truncated), len(records)), ip_length_short=frac(len(short), len(records)),
                uncaptured=cnt['dev10']['tx'] - len(records) if cnt else None, ok=not failures, failures=failures)


def class_summary(reports, cls):
    op, _, workload = cls.partition(' ')
    rows = [row for report in reports for row in report.get('exchanges') or [] if row.get('operation') == op and
            (not workload or row.get('workload') == workload)]
    values = sorted(v for report in reports for v in rc.visible_clrt(report)[cls]['values_us'])
    sizes = Counter(str(len(row['response']['wire_hex']) // 2) if row.get('response') else 'missing' for row in rows)
    return dict(exchanges=len(rows), verdict_ok=frac(sum(bool((r.get('application') or {}).get('ok')) for r in rows),
                                                     len(rows)),
                missing_response=sizes.get('missing', 0), piggyback=sum(bool(r.get('piggyback')) for r in rows),
                response_sizes=dict(sorted(sizes.items())),
                clrt=dict(n=len(values), median_us=statistics.median(values) if values else None,
                          min_us=values[0] if values else None, max_us=values[-1] if values else None,
                          spread_us=values[-1] - values[0] if values else None))


def on_off(on_trials, off_trials):
    """D3d: per arm and class, mirror-on against mirror-off: delivery (exchanges, verdicts), response sizes, CLRT
    (piggybacked exchanges counted apart, no CLRT). Timed arms: median difference > CLRT_BOUND_US is flagged;
    untimed arms: CLRT descriptive only."""
    flags, arms = [], {}
    groups = [{}, {}]
    for group, trials in zip(groups, (on_trials, off_trials)):
        for t in trials:
            group.setdefault(t['arm'], []).append(t)
    for arm in sorted(set(groups[0]) | set(groups[1])):
        on, off = groups[0].get(arm, []), groups[1].get(arm, [])
        reports = [[cap.read_json(t['dir'] / 'relay_wire.json') for t in side] for side in (on, off)]
        flags += ['%s: relay_wire.json missing in %s' % (arm, t['name']) for side, rep in zip((on, off), reports)
                  for t, r in zip(side, rep) if r is None]
        reports = [[r for r in rep if r is not None] for rep in reports]
        if not on or not off:
            flags.append('%s: arm missing from the mirror-%s block' % (arm, 'on' if not on else 'off'))
        timed = arm in TIMED_ARMS
        wire_ok = [frac(sum(bool(r.get('ok')) for r in rep), len(side)) for rep, side in zip(reports, (on, off))]
        if wire_ok[0] != wire_ok[1]:
            flags.append('%s: relay_wire verdicts differ (on %r, off %r)' % (arm, wire_ok[0], wire_ok[1]))
        classes = {}
        for cls in CLASSES:
            a, b = class_summary(reports[0], cls), class_summary(reports[1], cls)
            delivery = any(a[k] != b[k] for k in ('exchanges', 'verdict_ok', 'missing_response'))
            size = a['response_sizes'] != b['response_sizes']
            ma, mb = a['clrt']['median_us'], b['clrt']['median_us']
            diff = ma - mb if ma is not None and mb is not None else None
            clrt_flag = (diff is None or abs(diff) > CLRT_BOUND_US) if timed else None
            classes[cls] = dict(on=a, off=b, delivery_differs=delivery, size_differs=size,
                                clrt_median_difference_us=diff, clrt_bound_us=CLRT_BOUND_US if timed else None,
                                clrt_flag=clrt_flag, clrt_role='gated' if timed else 'descriptive (untimed arm)')
            flags += ['%s %s: delivery differs' % (arm, cls)] if delivery else []
            flags += ['%s %s: response size differs' % (arm, cls)] if size else []
            flags += ['%s %s: median CLRT difference %r us exceeds %.0f us or is not evaluable'
                      % (arm, cls, diff, CLRT_BOUND_US)] if clrt_flag else []
        arms[arm] = dict(timed=timed, trials=dict(on=len(on), off=len(off)),
                         relay_wire_ok=dict(on=wire_ok[0], off=wire_ok[1]), classes=classes)
    return dict(arms=arms, flags=flags, ok=bool(arms) and not flags)


def add(totals, counts):
    for key, value in (counts or {}).items():
        if isinstance(value, dict) and set(value) == {'n', 'of'}:
            old = totals.get(key, frac(0, 0))
            totals[key] = frac(old['n'] + value['n'], old['of'] + value['of'])
    return totals


def preservation(trials, label, sha, out_dir):
    """E1: preservation_check over the size_only/combined mirror-on trials (mirror.pcap as --relay-pcap)."""
    rows, totals = [], {}
    for t in (t for t in trials if t['arm'] in E1_ARMS):
        out = out_dir / (t['name'] + '.preservation.json')
        argv = ['--relay-pcap', str(t['dir'] / 'mirror.pcap'), '--trial-dir', str(t['dir']), '--build-label', label,
                '--source-sha256', sha, '--out', str(out)] + (['--master-port', str(t['port'])] if t['port'] else [])
        row = dict(trial=t['name'], arm=t['arm'], output=str(out), argv=argv)
        if 'mirror.pcap' in t['missing']:
            rows.append(dict(row, exit_code=None, ok=False, failure='mirror.pcap missing'))
            continue
        err = io.StringIO()
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                code = pc.main(argv)
        except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
            rows.append(dict(row, exit_code=None, ok=False, failure='%s: %s' % (type(error).__name__, error)))
            continue
        result = cap.read_json(out) if code in (0, 1) else None
        rows.append(dict(row, exit_code=code, ok=bool(result and result['ok']), stderr=err.getvalue().strip(),
                         totals=result and result['totals']))
        add(totals, result and result['totals'])
    return dict(tool='scripts/analysis/preservation_check.py', schema=pc.SCHEMA, arms=list(E1_ARMS),
                trials=frac(sum(r['ok'] for r in rows), len(rows)), totals=totals, rows=rows,
                ok=bool(rows) and all(r['ok'] for r in rows))


def first_requests(mirror_on, mirror_off):
    """E2 over every fresh connection: classified where the mirror was on; retransmission only where it was off."""
    rows = [cap.first_request(t) for t in mirror_on] + [cap.first_request(t, mirror=False) for t in mirror_off]
    on = [r for r in rows if r['mirror'] and r['evaluable']]
    every = [r for r in rows if r['evaluable']]
    texts = dict(cap.E2_CLASSES, **cap.OTHER_CLASSES)
    return dict(classes={key: dict(frac(sum(r['class'] == key for r in on), len(on)), text=text)
                         for key, text in texts.items()},
                retransmitted_mirror_on=frac(sum(r['retransmitted'] for r in on), len(on)),
                retransmitted_all_connections=frac(sum(r['retransmitted'] for r in every), len(every)),
                evaluable=frac(len(every), len(rows)), connections=rows, ok=bool(rows) and len(every) == len(rows))


def section(rows, key='ok'):
    good = sum(bool(r[key]) for r in rows)
    return dict(ok=bool(rows) and good == len(rows), trials=frac(good, len(rows)), per_trial=rows)


def analyze(on, off, e2, label, sha, out):
    on_t, off_t, e2_t = ([cap.load(p) for p in group] for group in (on, off, e2))
    d3a = section([mapping(t) for t in on_t], 'mapped')
    d3a['falsified'] = any(r['falsified'] for r in d3a['per_trial'])
    d3c = section([completeness(t) for t in on_t])
    d3c_e2 = section([completeness(t) for t in e2_t])
    d3b = section([cap.fidelity(t, c['uncaptured']) for t, c in zip(on_t, d3c['per_trial']) if t['arm'] == 'off'])
    d3b['totals'] = {d: {} for d in cap.DIRS}
    for row in d3b['per_trial']:
        for d in cap.DIRS:
            add(d3b['totals'][d], row[d])
    d3d = on_off(on_t, off_t)
    e1 = preservation(on_t, label, sha, out.parent / (out.stem + '_e1'))
    e1.update(precondition=dict(D3b=d3b['ok'], D3c=d3c['ok']), usable=d3b['ok'] and d3c['ok'] and e1['ok'])
    e2_result = first_requests(on_t + e2_t, off_t)
    # a missing egress copy can be capture loss, so E2 also needs every capture complete (D3c, E2 block included)
    e2_pre = dict(D3a=d3a['ok'], D3b=d3b['ok'], D3c=d3c['ok'], D3c_e2_block=d3c_e2['ok'] or not e2_t)
    e2_result.update(precondition=e2_pre, usable=all(e2_pre.values()))
    verdicts = dict(D3a=d3a['ok'], D3b=d3b['ok'], D3c=d3c['ok'], D3c_e2_block=e2_pre['D3c_e2_block'],
                    D3d=d3d['ok'], E1=e1['ok'], E2_evaluable=e2_result['ok'])
    return dict(schema=SCHEMA, ok=all(verdicts.values()), verdicts=verdicts,
                build=dict(label=label, source_sha256=sha),
                evidence_label='diagnostic-build evidence (%s, source SHA-256 %s); establishes nothing about the '
                               'exact c72 binary' % (label, sha),
                design=dict(path=str(DESIGN), sha256=pc.pd.sha256(DESIGN) if DESIGN.is_file() else None),
                inputs={name: [dict(dir=str(t['dir']), arm=t['arm'], missing=t['missing']) for t in group]
                        for name, group in (('on', on_t), ('off', off_t), ('e2', e2_t))},
                assumptions=ASSUMPTIONS, D3a=d3a, D3b=d3b, D3c=d3c, D3c_e2_block=d3c_e2, D3d=d3d, E1=e1,
                E2=e2_result)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    for name, help_text in (('--on', 'd3_mirror_on_d20 trial directories'), ('--off', 'd3_mirror_off_d20 trial '
                            'directories'), ('--e2', 'e2_first_request_d20 trial directories')):
        parser.add_argument(name, nargs='*', type=Path, default=[], help=help_text)
    parser.add_argument('--build-label')
    parser.add_argument('--source-sha256')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    _, reason = pc.load(SimpleNamespace(build_label=args.build_label, source_sha256=args.source_sha256,
                                        build_inputs=None))
    if not reason and not (args.on or args.off or args.e2):
        reason = 'no trial directories given'
    if reason:
        print('REFUSED: ' + reason, file=sys.stderr)
        return 2
    result = analyze(args.on, args.off, args.e2, args.build_label, args.source_sha256, args.out)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, default=str) + '\n')
    print(json.dumps(dict(ok=result['ok'], build=result['build'], verdicts=result['verdicts']), indent=2))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""What the outstation's TCP timestamps reveal about the response delay (finding B1). Read-only.

For each outstation exchange in a capture (a pure ACK of a master request, then the outstation's data segment
acknowledging the same request) this records the observed gap between the two at the capture point and the
difference of the TSval values the outstation wrote on them. If the switch delays the response, the observed
gap grows; the TSval difference reflects when the outstation sent each segment. Also reports the outstation's
TSval clock: ticks per second (least-squares fit against capture time) and its step (GCD of TSval changes).

    python3 tsval_exposure.py --json OUT.json PCAP_OR_DIR ...
"""
import argparse
import json
import math
import pathlib
import statistics
import sys

from scapy.all import PcapReader, TCP, IP


def captures(paths):
    for p in map(pathlib.Path, paths):
        yield from (sorted(p.rglob('*.pcap')) if p.is_dir() else [p])


def tsval(t):
    for name, val in t.options:
        if name == 'Timestamp':
            return val[0]
    return None


def scan(path, outstation_port=20000):
    times, vals, exchanges = [], [], []
    pending = {}
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            if IP not in pkt or TCP not in pkt:
                continue
            t = pkt[TCP]
            if t.sport != outstation_port:
                continue
            tv = tsval(t)
            if tv is None:
                continue
            now = float(pkt.time)
            times.append(now); vals.append(tv)
            plen = len(t.payload)
            if plen == 0 and t.flags & 0x10 and not t.flags & 0x07:
                pending[t.ack] = (now, tv)
            elif plen > 0 and t.ack in pending:
                a_time, a_tv = pending.pop(t.ack)
                exchanges.append(dict(gap_ms=(now - a_time) * 1e3, tsval_delta=(tv - a_tv) & 0xFFFFFFFF))
    return times, vals, exchanges


def clock(times, vals):
    if len(times) < 3:
        return None
    t0, v0 = times[0], vals[0]
    xs = [t - t0 for t in times]; ys = [((v - v0) & 0xFFFFFFFF) for v in vals]
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    sxx = sum((x - mx) ** 2 for x in xs)
    rate = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx if sxx else float('nan')
    steps = [b - a for a, b in zip(ys, ys[1:]) if b != a]
    step = 0
    for s in steps:
        step = math.gcd(step, s)
    return dict(ticks_per_s=rate, step_ticks=step)


def arm_of(path):
    name = path.name.lower()
    return 'obfuscated' if 'obfusc' in name else 'native' if 'native' in name or 'off' in name else 'other'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('paths', nargs='+')
    ap.add_argument('--json')
    a = ap.parse_args(argv)
    per_arm, clocks, files = {}, [], 0
    for cap in captures(a.paths):
        files += 1
        times, vals, ex = scan(cap)
        c = clock(times, vals)
        if c:
            clocks.append(c)
        per_arm.setdefault(arm_of(cap), []).extend(ex)
    out = dict(captures=files,
               clock=dict(ticks_per_s_median=statistics.median(c['ticks_per_s'] for c in clocks),
                          step_ticks_values=sorted({c['step_ticks'] for c in clocks})) if clocks else None,
               arms={})
    for arm, ex in sorted(per_arm.items()):
        gaps = [e['gap_ms'] for e in ex]; deltas = [e['tsval_delta'] for e in ex]
        out['arms'][arm] = dict(
            exchanges=len(ex),
            gap_ms_median=statistics.median(gaps) if gaps else None,
            gap_ms_p95=sorted(gaps)[int(0.95 * (len(gaps) - 1))] if gaps else None,
            tsval_delta_counts={str(k): deltas.count(k) for k in sorted(set(deltas))[:12]},
            share_tsval_delta_zero=(deltas.count(0) / len(deltas)) if deltas else None)
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(out, indent=1) + '\n')
    json.dump(out, sys.stdout, indent=1)
    print()
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Size a blocker reservoir from the loopback port's speed and the measured loop latency.

A reservoir keeps its strict-priority queue non-empty, so the held original below it cannot leave,
by circulating K minimum-size tokens through a MAC-near loopback port until the deadline. Two numbers
matter:

  * coverage: K tokens cover a loop of K * t_token. If the loop (egress -> MAC loopback -> ingress ->
    queue) takes longer, the queue drains between laps and the held original leaves early. K must
    satisfy K * t_token >= loop_ns * (1 + margin).
  * load: while a hold lasts, the port is busy at line rate with tokens, which are also ingress
    packets: rate_pps = 1 / t_token, and a hold of D costs D / t_token token passes.

A slower loopback port (10G instead of 25G) makes each token occupy the wire 2.5 times longer, so the
same loop is covered by fewer tokens and every hold costs 2.5 times fewer token passes. Whether a
10G channel can share the dp8/dp9/dp10 quad with the 25G channels, and the loop latency itself, are
hardware facts this file does not establish: measure loop_ns on the switch before choosing K.

    python3 reservoir_sizing.py --loop-ns 1200 [--speed-gbps 25] [--hold-ms 20] [--k 64]
    python3 reservoir_sizing.py --selftest
"""
import argparse
import json
import math
import sys

MIN_FRAME = 64          # bytes on the wire, FCS included: the generator's minimum token
WIRE_OVERHEAD = 20      # preamble + SFD (8) and minimum inter-frame gap (12)
SPEEDS_GBPS = (10, 25, 40, 50, 100)


def token_ns(speed_gbps, frame_bytes=MIN_FRAME):
    return (frame_bytes + WIRE_OVERHEAD) * 8 / speed_gbps   # bits / (Gbit/s) = ns


def size(loop_ns, speed_gbps, hold_ms=None, k=None, margin=0.5, frame_bytes=MIN_FRAME):
    t = token_ns(speed_gbps, frame_bytes)
    k_min = math.ceil(loop_ns * (1 + margin) / t)
    out = dict(speed_gbps=speed_gbps, token_ns=round(t, 3), token_mpps=round(1e3 / t, 3),
               loop_ns=loop_ns, margin=margin, k_min=k_min)
    if k is not None:
        out.update(k=k, covered_loop_ns=round(k * t, 1), k_sufficient=k * t >= loop_ns * (1 + margin))
    if hold_ms is not None:
        out.update(hold_ms=hold_ms, token_passes_per_hold=round(hold_ms * 1e6 / t))
    return out


def selftest():
    # 84 bytes at 25 Gbit/s = 26.88 ns; at 10 Gbit/s = 67.2 ns
    assert abs(token_ns(25) - 26.88) < 1e-9 and abs(token_ns(10) - 67.2) < 1e-9
    # the shipped K = 64 at 25G covers 64 * 26.88 = 1720.32 ns
    r = size(1000, 25, k=64)
    assert r['covered_loop_ns'] == 1720.3 and r['k_sufficient'] and r['k_min'] == 56
    # the same loop at 10G needs 23 tokens, and a 20 ms hold costs 2.5x fewer passes
    r10, r25 = size(1000, 10, hold_ms=20), size(1000, 25, hold_ms=20)
    assert r10['k_min'] == 23
    assert abs(r25['token_passes_per_hold'] / r10['token_passes_per_hold'] - 2.5) < 1e-3
    # a loop longer than K covers is reported, not hidden
    assert size(2000, 25, k=64)['k_sufficient'] is False
    return 'reservoir_sizing selftest: 6 checks pass'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--loop-ns', type=float, help='measured token loop latency on the loopback port')
    ap.add_argument('--speed-gbps', type=float, default=None, help='one speed; default: compare %s' % (SPEEDS_GBPS,))
    ap.add_argument('--hold-ms', type=float, default=None)
    ap.add_argument('--k', type=int, default=None, help='a K to check (the setup uses 64)')
    ap.add_argument('--margin', type=float, default=0.5)
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args(argv)
    if a.selftest:
        print(selftest())
        return 0
    if a.loop_ns is None:
        ap.error('--loop-ns is required (measure it on the switch)')
    speeds = [a.speed_gbps] if a.speed_gbps else SPEEDS_GBPS
    print(json.dumps([size(a.loop_ns, s, a.hold_ms, a.k, a.margin) for s in speeds], indent=1))
    return 0


if __name__ == '__main__':
    sys.exit(main())

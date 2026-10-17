#!/usr/bin/env python3
"""Bounded reset-interleaving check on silicon, plan and judge (Step 4b of the m10 plan; offline only, no host I/O).

Goal: send, from one raw socket on the probe tuple (contention_probe.Endpoints: addresses no Vision interface
owns), a master RST a few microseconds BEFORE the outstation's response, so the response can claim N's work cell
between the RST's stage-0 and stage-1 passes (the m10 restart, count_busy[5]). Each point then reconnects the same
tuple and completes a READ. vision_contention.py injects the plan and captures both directions; this module judges
the captures and the N counter snapshots.

Per point (READ or SELECT, one offset):
  handshake, request, outstation bare ACK, then the master RST at t and the response at t + offset; a settle;
  a same-tuple reconnect (new ISNs), READ request, bare ACK, response; a closing RST.

Verdict of the block (judge_interleave):
  INVALID          a capture or counter snapshot is missing or unreadable
  FAIL             at any point: the first RST was not relayed to the outstation exactly once, the response
                   reached the master more than once, or the reconnect READ was not delivered exactly once with
                   the 61-octet image
  NOT_EXERCISED    no failure, but count_busy[5] (restarts) did not rise: the restart path was not shown
  PASS             no failure and at least one restart
Limits:
  - Every time here is a host-hook timestamp, not switch ingress. The offset actually achieved is measured from the
    out capture, and the requested offset is never assumed.
  - The revised reset contract (no release after T applies the reset) cannot be observed on silicon. Copies of the
    first response at the master are reported, with at most one allowed.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import contention_probe as cp  # noqa: E402

SYN, ACK, PSH, RST = cp.SYN, cp.ACK, cp.PSH, cp.RST
OFFSETS_US = (0, 1, 2, 3, 5)                  # response after the RST; bounded, one block
KINDS = ('READ', 'SELECT')
RESTART_CELL = 5


def _interleave_point(ep, tag, kind, offset_us, client_isn, server_isn, image_len):
    link = cp.Link()
    c, s = client_isn, server_isn
    f = {}
    f['syn'] = ep.m_to_o(c, 0, SYN, mss=1460)
    f['synack'] = ep.o_to_m(s, c + 1, SYN | ACK, mss=1460)
    f['ack'] = ep.m_to_o(c + 1, s + 1, ACK)
    c, s = c + 1, s + 1
    fc, objects, body = (3, cp.crob(200), bytes(2) + cp.crob(200)) if kind == 'SELECT' else \
        (1, cp.READ_OBJECTS, cp.READ_BODY)
    req, app = link.request(fc, objects)
    native = link.response(app, body, kind)
    f['request'] = ep.m_to_o(c, s, PSH | ACK, req)
    f['bare_ack'] = ep.o_to_m(s, c + len(req), ACK)
    f['rst'] = ep.m_to_o(c + len(req), s, RST)
    f['response'] = ep.o_to_m(s, c + len(req), PSH | ACK, native)
    first = dict(client_isn=client_isn, request_seq=c, rst_seq=c + len(req), response_seq=s)
    # the same tuple, a new incarnation
    c2, s2 = client_isn + 0x100000, server_isn + 0x100000
    link2 = cp.Link()
    f['syn2'] = ep.m_to_o(c2, 0, SYN, mss=1460)
    f['synack2'] = ep.o_to_m(s2, c2 + 1, SYN | ACK, mss=1460)
    f['ack2'] = ep.m_to_o(c2 + 1, s2 + 1, ACK)
    c2, s2 = c2 + 1, s2 + 1
    req2, app2 = link2.request(1, cp.READ_OBJECTS)
    native2 = link2.response(app2, cp.READ_BODY, 'READ')
    f['request2'] = ep.m_to_o(c2, s2, PSH | ACK, req2)
    f['bare_ack2'] = ep.o_to_m(s2, c2 + len(req2), ACK)
    f['response2'] = ep.o_to_m(s2, c2 + len(req2), PSH | ACK, native2)
    f['close2'] = ep.m_to_o(c2 + len(req2), s2 + image_len, RST)
    second = dict(client_isn=client_isn + 0x100000, request_seq=c2, response_seq=s2)
    return dict(tag=tag, kind=kind, offset_us=offset_us, first=first, second=second, image_len=image_len,
                frames=f)


def build_interleave_plan(ep, image_len=cp.IMAGE_LEN, offsets_us=OFFSETS_US, kinds=KINDS, isn_stride=0x400000,
                          start_ns=1_000_000, step_us=50, hold_us=5_000, settle_us=300_000):
    """One bounded block: every kind x offset on its own ISN range. hold_us lets T hold the bare ACK before the race;
    settle_us lets the reset finish before the reconnect. The response follows the RST by offset_us."""
    points, client, server = [], 0x20000000, 0x60000000
    i = 0
    for kind in kinds:
        for off in offsets_us:
            points.append(_interleave_point(ep, 'interleave_%s_%dus' % (kind, off), kind, off,
                                            client + i * isn_stride, server + i * isn_stride, image_len))
            i += 1
    schedule, t = [], start_ns

    def emit(p, name, dt_us):
        nonlocal t
        t += int(dt_us * 1000)
        schedule.append(dict(t_ns=t, tag=p['tag'], frame=name, bytes=p['frames'][name].hex()))

    for p in points:
        for name in ('syn', 'synack', 'ack', 'request', 'bare_ack'):
            emit(p, name, step_us)
        emit(p, 'rst', hold_us)
        emit(p, 'response', p['offset_us'])
        t += settle_us * 1000
        for name in ('syn2', 'synack2', 'ack2', 'request2', 'bare_ack2'):
            emit(p, name, step_us)
        emit(p, 'response2', 1_000)
        emit(p, 'close2', settle_us)
        t += settle_us * 1000
    out = [dict({k: v for k, v in p.items() if k != 'frames'}, frames={k: v.hex() for k, v in p['frames'].items()})
           for p in points]
    return dict(kind='reset_interleave', image_len=image_len, points=out, schedule=schedule,
                tuple=[ep.master_ip, ep.outstation_ip, ep.master_port, ep.outstation_port],
                next_hop_mac=ep.next_hop)


def _invalid(reason, **extra):
    return dict(extra, verdict='INVALID', reason=reason)


def judge_interleave(plan, out_pcap, in_pcap, before, after, inject=None, vision_rc=0):
    """See the module docstring. out_pcap: frames injected (offset measured here); in_pcap: frames the switch sent
    back to either probe endpoint (relays to the outstation, deliveries to the master); inject: the injector's
    inject.json; vision_rc: the injector's exit status. Fail-closed (code review of Step 4b): a measurement that did
    not happen as planned is INVALID, never a FAIL blamed on the switch and never a PASS."""
    tup = plan['tuple']
    if vision_rc != 0:
        return _invalid('the injector exited %r' % vision_rc)
    if not isinstance(inject, dict) or inject.get('applied') is not True or inject.get('sent') != len(plan['schedule']):
        return _invalid('inject.json missing, not applied, or sent %r of %d frames'
                        % (inject.get('sent') if isinstance(inject, dict) else inject, len(plan['schedule'])))
    for d in ('out', 'in'):
        stats = ((inject or {}).get('tcpdump') or {}).get(d) or {}
        if 'dropped_kernel' not in stats or stats.get('dropped_kernel') or stats.get('dropped_interface'):
            return _invalid('tcpdump %s statistics missing or show drops: %r' % (d, stats))
    try:
        sent = cp._segs(out_pcap, *tup)
        got = cp._segs(in_pcap, *tup)
    except (OSError, ValueError) as e:
        return _invalid('capture unreadable: %s' % e)
    if len(sent) != len(plan['schedule']):
        return _invalid('out capture holds %d probe frames, the schedule %d' % (len(sent), len(plan['schedule'])))
    if not got:
        return _invalid('in capture holds no probe frame')
    busy = cp._counter_delta(before or {}, after or {}, 'count_busy', 8)
    term = cp._counter_delta(before or {}, after or {}, 'count_term', 1)
    if None in busy or None in term or any(x < 0 for x in busy + term):
        return _invalid('counter snapshot missing a cell or decreasing: count_busy %r count_term %r' % (busy, term))
    out_b, out_a = cp._outcomes(before or {}), cp._outcomes(after or {})
    fallback_keys = (cp.OUT_ACK_FALLBACK, cp.OUT_RESP_FALLBACK)
    if any(not isinstance(out_b.get(k), int) or not isinstance(out_a.get(k), int) for k in fallback_keys):
        return _invalid('T outcome snapshot missing or unreadable fallback counters')
    fallbacks = {k: out_a[k] - out_b[k] for k in fallback_keys}
    relayed_syn = lambda isn: next((x['t_ns'] for x in got if x['probe_dir'] == 'M->O' and x['flags'] & SYN
                                    and not x['flags'] & ACK and x['seq'] == isn), None)
    starts = [relayed_syn(p['first']['client_isn']) for p in plan['points']]
    rows, failures = [], []
    for i, p in enumerate(plan['points']):
        first, second, image_len = p['first'], p['second'], p['image_len']
        t_rst = next((x['t_ns'] for x in sent if x['probe_dir'] == 'M->O' and x['flags'] & RST
                      and x['seq'] == first['rst_seq']), None)
        t_rsp = next((x['t_ns'] for x in sent if x['probe_dir'] == 'O->M' and x['len'] > 0
                      and x['seq'] == first['response_seq']), None)
        problems = []
        t_start, t_syn2 = starts[i], relayed_syn(second['client_isn'])
        later = [t for t in starts[i + 1:] if t is not None]
        t_end = later[0] if later else float('inf')
        if t_start is None or t_syn2 is None:
            problems.append('handshake SYN of the first or the reconnect connection was not relayed')
            window = []
        else:
            window = [x for x in got if t_start <= x['t_ns'] < t_end]
        relayed = [x for x in window if x['probe_dir'] == 'M->O' and x['flags'] & RST and x['seq'] == first['rst_seq']]
        request1 = [x for x in window if x['probe_dir'] == 'M->O' and x['len'] > 0 and x['seq'] == first['request_seq']]
        request2 = [x for x in window if x['probe_dir'] == 'M->O' and x['len'] > 0 and x['seq'] == second['request_seq']]
        to_master = [x for x in window if x['probe_dir'] == 'O->M' and x['len'] > 0]
        copies = [x for x in to_master if x['seq'] == first['response_seq'] and t_syn2 is not None and x['t_ns'] < t_syn2]
        response2 = [x for x in to_master if x['seq'] == second['response_seq'] and x['len'] == image_len]
        unexpected = [x for x in to_master if not any(x is y for y in copies + response2)]
        if len(relayed) != 1:
            problems.append('first RST relayed %d times' % len(relayed))
        if len(copies) > 1:
            problems.append('first response reached the master %d times' % len(copies))
        if any(x['len'] != image_len for x in copies):
            problems.append('first-response copy at the master is %r octets, not the %d-octet image'
                            % ([x['len'] for x in copies], image_len))
        if len(request1) != 1:
            problems.append('first request relayed %d times' % len(request1))
        if unexpected:
            problems.append('%d unexpected master-bound payload frame(s) (a late, rewritten or foreign copy)'
                            % len(unexpected))
        if len(request2) != 1 or len(response2) != 1:
            problems.append('reconnect READ not delivered exactly once (request %d, response %d)'
                            % (len(request2), len(response2)))
        row = dict(tag=p['tag'], kind=p['kind'], requested_offset_us=p['offset_us'],
                   measured_offset_us=None if t_rst is None or t_rsp is None else (t_rsp - t_rst) / 1000.0,
                   request_relayed=len(request1), rst_relayed=len(relayed),
                   first_response_copies_to_master=len(copies), first_copy_lengths=[x['len'] for x in copies],
                   unexpected_to_master=len(unexpected), reconnect_request_relayed=len(request2),
                   reconnect_response_delivered=len(response2), problems=problems)
        failures += ['%s: %s' % (p['tag'], x) for x in problems]
        rows.append(row)
    for cell, name in ((0, 'busy drop'), (3, 'retry exhaustion'), (4, 'stale retry')):
        if busy[cell]:
            failures.append('%s (count_busy[%d]=%d)' % (name, cell, busy[cell]))
    if term[0]:
        failures.append('retried duplicate aborted (count_term[0]=%d)' % term[0])
    if any(fallbacks.values()):
        failures.append('T fell back %r' % fallbacks)
    if failures:
        verdict = 'FAIL'
    elif busy[RESTART_CELL] < 1:
        verdict = 'NOT_EXERCISED'
    else:
        verdict = 'PASS'
    return dict(verdict=verdict, restarts=busy[RESTART_CELL], count_busy_delta=busy, count_term_delta=term,
                t_fallbacks=fallbacks, points=rows, failures=failures, measurement_point=cp.MEASUREMENT_POINT,
                limits='host-hook times; whether a released copy left T before or after T applied the reset is '
                       'not observable on silicon; copies at most once, before the reconnect, are enforced')


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    pl = sub.add_parser('plan')
    pl.add_argument('-o', '--output', required=True)
    for name, default in (('master-ip', '192.0.2.61'), ('outstation-ip', '192.0.2.62'),
                          ('master-mac', '02:00:00:00:00:61'), ('outstation-mac', '02:00:00:00:00:62'),
                          ('next-hop-mac', '02:00:00:00:00:09')):
        pl.add_argument('--' + name, default=default)
    pl.add_argument('--master-port', type=int, default=59400)
    pl.add_argument('--outstation-port', type=int, default=20000)
    pl.add_argument('--image-len', type=int, default=cp.IMAGE_LEN)
    jd = sub.add_parser('judge')
    for name in ('plan', 'out-pcap', 'in-pcap', 'before', 'after', 'output'):
        jd.add_argument('--' + name, required=True)
    a = ap.parse_args(argv)
    if a.cmd == 'plan':
        ep = cp.Endpoints(a.master_ip, a.outstation_ip, a.master_port, a.outstation_port,
                          a.master_mac, a.outstation_mac, a.next_hop_mac)
        plan = build_interleave_plan(ep, image_len=a.image_len)
        Path(a.output).write_text(json.dumps(plan, indent=1) + '\n')
        print('wrote', a.output, len(plan['points']), 'points', len(plan['schedule']), 'frames')
        return 0
    result = judge_interleave(json.loads(Path(a.plan).read_text()), a.out_pcap, a.in_pcap,
                              json.loads(Path(a.before).read_text()), json.loads(Path(a.after).read_text()))
    Path(a.output).write_text(json.dumps(result, indent=1) + '\n')
    print(result['verdict'])
    return 0 if result['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())

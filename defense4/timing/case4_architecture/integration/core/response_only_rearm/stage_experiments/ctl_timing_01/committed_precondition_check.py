"""Precondition of the committed-path judgement, checked from a contention run's model log (option 1, 2026-10-17).

  python3 committed_precondition_check.py RUN_DIR

`<tag>_delivered_once_committed` requires ACK_COMMIT and RESP_RELEASE. The committed path exists only if the response
reaches T before the lane's readiness deadline, t0 + readiness. T keeps no register of the response's arrival, so
the times are read from the model log (reset_application_check.ingress_records; t_units = T's clock,
global_tstamp[39:8], taken by each pipe-1 pass's parser). Two arrivals are separated (code review: in
model_contention_m10_03_05 the OPERATE 090 ms response entered the switch before readiness and reached T after it):
  - switch ingress: the response's first pipe-0 ingress from the wire port. Pipe 0 records no clock, so this
    arrival is bracketed by the T clock of the nearest pipe-1 passes before and after it in the log;
  - T arrival: the first later pipe-1 pass whose frame carries the response (its TCP sequence and first payload
    octets), whatever actions it ran.

Attribution. Every sweep point reuses one TCP port pair. A point's records run from the first pipe-1 record that
carries its server sequence (reset_application_check.server_seq_pattern) to the next point's; the starts must be in
case order. The judged lane is the window's last admit_t0 pass (OPERATE: the same pass runs hold_operate).

Every committed case gets a row. A failed case is excused as `committed_path_not_measured` only when the stimulus was
late: the switch-ingress bracket lies wholly at or after t0 + readiness, the ACK fell back before the T arrival, that
pass ran admit_response, N counted no busy drop or exhaustion (count_busy_delta[0] and [3]), and the original was
delivered once. Other failed cases:
  in_switch_delay   the response entered the switch before readiness and reached T after it (unresolved: dataplane
                    or simulator latency; a failure);
  genuine_failure   the response reached T before readiness and the committed path still did not happen;
  unattributed      the case's lane could not be located;
  undetermined      anything else.
  (in_switch_delay also covers an original dropped inside the switch whose cleanup retransmission reached T.)
A passing case is `measured` with arrival evidence, `measured_unverified` without it (no window of its own, or the
response entered the switch before the lane's T admission), or `inconsistent` if its response reached T after
readiness (an attribution error). Exit 0: all measured; 2: anything else classified; 3: checker error (JSON record).
This only classifies; it changes no case's verdict and so cannot turn a failed attempt into a passing one.
"""
import hashlib
import json
import sys
from pathlib import Path

import reset_application_check as rac

WRAP = 1 << 32                      # t_units is global_tstamp[39:8], 32 bits
WIRE_PORT = 9                       # the master and relay legs share dev port 9 (launch_model.sh); direction by sport
OUTSTATION_SPORT = '4e20'           # 20000
SUFFIX = '_delivered_once_committed'


def acts(record):
    return ' '.join(record['actions'])


def late(t_units, t0_units, readiness):
    """True if t_units is at or after t0 + readiness on the 32-bit clock."""
    return (t_units - t0_units) % WRAP >= readiness


def outstation_payload(frame_hex):
    """(sequence hex, first 8 payload octets hex) of a wire frame from the outstation that carries data, else None."""
    f = bytes.fromhex(frame_hex)
    if len(f) < 54 or f[12:14] != b'\x08\x00' or f[23] != 6:
        return None
    ihl = (f[14] & 0x0f) * 4
    tcp = 14 + ihl
    if f[tcp:tcp + 2].hex() != OUTSTATION_SPORT:
        return None
    payload = f[tcp + (f[tcp + 12] >> 4) * 4:14 + int.from_bytes(f[16:18], 'big')]
    return (f[tcp + 4:tcp + 8].hex(), payload[:8].hex()) if payload else None


def bracket(records, index):
    """T clock of the nearest pipe-1 passes before and after records[index], or None on a side without one."""
    lo = next((r['t_units'] for r in reversed(records[:index]) if r['pipe'] == 1 and r['t_units'] is not None), None)
    hi = next((r['t_units'] for r in records[index + 1:] if r['pipe'] == 1 and r['t_units'] is not None), None)
    return lo, hi


def lane(records, begin, end):
    """Index of the window's last admit_t0 pass (pipe 1), or None."""
    return next((i for i in range(end - 1, begin - 1, -1)
                 if records[i]['pipe'] == 1 and 'admit_t0' in acts(records[i])), None)


def measure(records, begin, end, readiness):
    """Lane timing within records[begin:end]. Pure; unit-tested."""
    i0 = lane(records, begin, end)
    if i0 is None:
        return dict(attributed=False)
    t0 = records[i0]['t_units']
    out = dict(attributed=True, t0_wall=records[i0]['wall'], t0_units=t0)
    ing = next((i for i in range(i0 + 1, end) if records[i]['pipe'] == 0 and records[i]['port'] == WIRE_PORT
                and outstation_payload(records[i]['frame'])), None)
    if ing is None or t0 is None:
        return out
    seq, head = outstation_payload(records[ing]['frame'])
    lo, hi = bracket(records, ing)
    out.update(ingress_wall=records[ing]['wall'], ingress_bracket_units=[lo, hi],
               ingress_late=(None if lo is None or hi is None else
                             True if late(lo, t0, readiness) else False if not late(hi, t0, readiness) else None))
    i_t = next((i for i in range(ing + 1, end) if records[i]['pipe'] == 1 and seq in records[i]['frame']
                and head in records[i]['frame']), None)
    if i_t is None or records[i_t]['t_units'] is None:
        return out
    t_arr = records[i_t]['t_units']
    between = records[i0 + 1:i_t]
    out.update(t_arrival_wall=records[i_t]['wall'], t_arrival_ms_after_t0=(t_arr - t0) % WRAP,
               t_arrival_late=late(t_arr, t0, readiness),
               t_arrival_admitted='admit_response' in acts(records[i_t]),
               ack_fallback_before=any(r['pipe'] == 1 and 'release_ack_fallback' in acts(r) for r in between))
    return out


def classify(case_ok, m, busy_ok, original_ok):
    """Pure; unit-tested. m is measure()'s result."""
    if case_ok:
        if m.get('t_arrival_late'):
            return 'inconsistent'
        return 'measured' if 't_arrival_late' in m else 'measured_unverified'
    if not m.get('attributed'):
        return 'unattributed'
    if 't_arrival_late' not in m:
        return 'undetermined'
    if not m['t_arrival_late']:
        return 'genuine_failure'
    if m.get('ingress_late') is True and m['t_arrival_admitted'] and m['ack_fallback_before'] and busy_ok \
            and original_ok:
        return 'committed_path_not_measured'
    if m.get('ingress_late') is False:
        return 'in_switch_delay'
    return 'undetermined'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check(run_dir):
    run_dir = Path(run_dir)
    results_path, = run_dir.glob('*_results.json')
    log_path, = run_dir.glob('model_*.log')
    results = json.loads(results_path.read_text())
    params = json.loads((run_dir / 't_params_written.json').read_text())
    if len({json.dumps(p['written'], sort_keys=True) for p in params}) != 1:
        raise ValueError('T parameters changed during the run; one readiness cannot be assumed')
    readiness, unit = params[-1]['written']['readiness'], params[-1]['t_time']['unit_ns']
    with open(log_path, errors='replace') as log:
        records = rac.ingress_records(log)
    cases = results['cases']
    names = {c['name']: c for c in cases}
    starts = []                                           # (record index, tag), in case order
    for c in cases:
        if c['name'].endswith('_SYNACK') and any((c.get('received') or {}).values()):
            tag = c['name'][:-len('_SYNACK')]
            pattern = rac.server_seq_pattern(results, tag)
            first = next((i for i, r in enumerate(records) if r['pipe'] == 1 and pattern in r['frame']), None)
            if first is not None:
                starts.append((first, tag))
    if [i for i, _t in starts] != sorted(i for i, _t in starts):
        raise ValueError('connection starts in the log are not in case order; attribution would be unsound')
    window = {tag: (first, starts[k + 1][0] if k + 1 < len(starts) else len(records))
              for k, (first, tag) in enumerate(starts)}
    points = {p.get('tag'): p for p in results['meta'].get('points', [])}
    out = dict(readiness_units=readiness, unit_ns=unit, points={},
               sha256={'checker': sha(__file__), 'reset_application_check': sha(rac.__file__),
                       'results': sha(results_path), 'model_log': sha(log_path)})
    for c in cases:
        if not c['name'].endswith(SUFFIX):
            continue
        tag = c['name'][:-len(SUFFIX)]
        m = measure(records, *window[tag], readiness) if tag in window else dict(attributed=False)
        busy = (points.get(tag) or c).get('count_busy_delta')
        busy_ok = busy is not None and busy[0] == 0 and busy[3] == 0
        original_ok = bool(names.get('%s_original_delivered_once' % tag, {}).get('ok'))
        if 't_arrival_ms_after_t0' in m:
            m['t_arrival_ms_after_t0'] = round(m['t_arrival_ms_after_t0'] * unit / 1e6, 3)
        out['points'][tag] = dict(m, committed_ok=bool(c.get('ok')), busy_ok=busy_ok, original_ok=original_ok,
                                  classification=classify(c.get('ok'), m, busy_ok, original_ok))
    out['readiness_ms'] = round(readiness * unit / 1e6, 3)
    return out


def main(argv):
    try:
        result = check(argv[1])
    except Exception as e:                      # recorded, never an empty file (code review)
        print(json.dumps(dict(error=True, exception=repr(e)), indent=1))
        return 3
    print(json.dumps(result, indent=1))
    return 0 if all(p['classification'] == 'measured' for p in result['points'].values()) else 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))

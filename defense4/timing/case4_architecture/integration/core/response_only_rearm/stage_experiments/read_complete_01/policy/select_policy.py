"""Ditto-inspired READ size-target policy, constrained by coverage of the declared READ profile.

Deterministic: re-decodes the five retained native captures, extracts the size distribution at three
observation layers, seeds 2- and 3-state policies with Ditto's percentile rule (NDSS'22 Sec. V Eq. 2,
P_i = percentile_{(i+1)*100/L}(D)), snaps and adjusts the seeds until every structure class of the
declared profile reaches a target, then selects the lowest added-byte overhead on the retained sample.

This is an ADAPTATION, not Ditto: Ditto pads individual packets on a fixed-rate schedule with chaff and
encryption; here a DNP3 response (one application fragment) is padded at aggregate-response granularity
with synthetic measurement objects, and no chaff, schedule or encryption is added. Ditto's guarantee does
not transfer. Low overhead does not establish effective obfuscation.

  python3 select_policy.py            # writes policy.json next to this file
"""
import collections
import hashlib
import itertools
import json
import math
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / 'software/source/full_read_01'))
import fullread as fr  # noqa: E402
import general_read_padding as gp  # noqa: E402

std = gp.std
# The handoff's retained distribution, tracked here (byte-identical to the handoff copy; their hashes are
# recorded in policy.json input_manifest, which reproduce.sh checks with git diff).
INPUTS = ROOT / 'evidence/m1_software_pinned_01/target_selection/inputs'
INPUT_RUNS = ('native_analog_base', 'native_class0_base', 'native_integrity_base', 'native_integrity_large',
              'native_range_base')

# ---- frozen implementation decisions (recorded in policy.json) -------------------------------------
PAD_START, PAD_STOP = 1024, 4095   # reserved G1V2 index range; fixture DBs hold BI 0..15 only
CAPACITY = 2048                    # OpenDNP3 default max rx fragment size (verified live, see TARGET_POLICY.md)
MAX_NATIVE = 377                   # declared profile: native aggregate encoded length <= 377
MAX_APP = 315                      # implied by <=377 encoded (handoff length argument)
LAYER = 'aggregate solicited-response encoded DNP3 octets (all link frames incl. headers and CRCs)'


def nearest_rank(sorted_values, i, states):
    """Inverse empirical CDF at the ((i+1)*100/states)-th percentile, in exact integer arithmetic
    (smallest value whose cumulative count >= (i+1)*N/states)."""
    k = max(1, -(-(i + 1) * len(sorted_values) // states))
    return sorted_values[k - 1]


def load_retained():
    rows, manifest = [], []
    present = sorted(d.name for d in INPUTS.iterdir()) if INPUTS.is_dir() else []
    if tuple(present) != INPUT_RUNS or not all((INPUTS / r / f).is_file() for r in INPUT_RUNS
                                               for f in ('capture.pcap', 'run.json')):
        raise SystemExit('retained inputs incomplete at %s: found %r' % (INPUTS, present))
    for d in sorted(INPUTS.iterdir()):
        cap = d / 'capture.pcap'
        meta = json.loads((d / 'run.json').read_text())
        ts = fr.transactions(cap)
        recs = [r for r in fr.capture.tcp_records(cap) if r['dst'][1] == 20000]
        reqs = [r['frame'] for r in fr.direction_frames(recs) if std.deframe(r['frame'])[1][2] == 1]
        assert len(ts) == len(reqs) == meta['reads']
        for i, (t, q) in enumerate(zip(ts, reqs)):
            raw = b''.join(bytes.fromhex(f) for f in t['response_frames_hex'])
            _, app = gp.one_fragment(raw)
            rows.append(dict(run=d.name, exchange=i, request=q, response=raw, native=len(raw), app=len(app),
                             frames=list(t['link_frames']), tcp=list(t['tcp_segments'])))
        manifest.append(dict(run=d.name, capture_sha256=hashlib.sha256(cap.read_bytes()).hexdigest(),
                             reads=len(ts), mode=meta['mode'], database=meta['db']))
    return rows, manifest


# ---- declared structural profile --------------------------------------------------------------------
H_RESP = bytes.fromhex('056400c401000a00')
REQ = None  # set below


def encode(app, chunks=None, seq=63, header=H_RESP):
    if chunks is None:
        chunks = [len(app)] if len(app) <= 249 else [len(app) // 2, len(app) - len(app) // 2]
    out, pos = [], 0
    for i, n in enumerate(chunks):
        u = bytes([((seq + i) & 63) | (std.FIR if i == 0 else 0) | (std.FIN if i == len(chunks) - 1 else 0)]) + app[pos:pos + n]
        pos += n
        out.append(std.frame(header[:2] + bytes([5 + len(u)]) + header[3:], u))
    assert pos == len(app)
    return b''.join(out)


REQ = encode(bytes.fromhex('c3013c0106'), header=bytes.fromhex('056400c40a000100'))
APPH = bytes.fromhex('c3810000')
OBJ = {'g1v2': (1, 2, 1), 'g10v2': (10, 2, 1), 'g20v1': (20, 1, 5), 'g20v2': (20, 2, 3), 'g30v1': (30, 1, 5),
       'g30v2': (30, 2, 3), 'g30v3': (30, 3, 4), 'g30v4': (30, 4, 2), 'g30v5': (30, 5, 5)}


def obj_block(name, count, start=0, wide=False):
    g, v, size = OBJ[name]
    last = start + count - 1
    w = 2 if (wide or last > 255) else 1
    hdr = bytes([g, v, 0 if w == 1 else 1]) + start.to_bytes(w, 'little') + last.to_bytes(w, 'little')
    return hdr + bytes(((i * 37 + 1) & 0xFF) if size > 1 else 0x01 for i in range(count * size))


def mix_app(length, primary, filler='g10v2', wide=False):
    """App of exactly `length` octets: as many `primary` points as fit, then 1-octet `filler` points."""
    g, v, size = OBJ[primary]
    hdr_p = 7 if wide else 5
    hdr_f = 7 if wide else 5
    for k in range((length - 4 - hdr_p) // size, -1, -1):
        rest = length - 4 - (hdr_p + k * size if k else 0)
        if rest == 0 and k:
            app = APPH + obj_block(primary, k, wide=wide)
            if len(app) == length:
                return app
            continue
        if rest >= hdr_f + 1:
            fstart = k if OBJ[filler][0] == g else 0  # never duplicate a point index of the same group
            body = (obj_block(primary, k, wide=wide) if k else b'') + obj_block(filler, rest - hdr_f, start=fstart, wide=wide)
            if len(APPH + body) == length:
                return APPH + body
    return None


def profile_cases(retained):
    """(case_id, request, native) for every structure class x length in the declared profile."""
    cases = []
    lengths = [4] + list(range(10, MAX_APP + 1))
    # F1: single-type static family (handoff test_coverage), natural framing
    for a in lengths:
        app = mix_app(a, 'g10v2') if a > 4 else APPH
        if app:
            cases.append(('F1_g10v2_A%d' % a, REQ, encode(app)))
    # F2: multi-type mixes, 8-bit and 16-bit range qualifiers, two framings (half split and max-first split)
    for primary in ('g30v1', 'g20v1', 'g30v2', 'g30v3', 'g30v4', 'g30v5', 'g20v2', 'g1v2'):
        for wide in (False, True):
            for a in lengths[1:]:
                app = mix_app(a, primary, wide=wide)
                if app is None:
                    continue
                for tag, chunks in (('nat', None), ('max1', [min(249, a)] + ([a - 249] if a > 249 else []))):
                    raw = encode(app, chunks)
                    if len(raw) <= MAX_NATIVE:
                        cases.append(('F2_%s_%s_%s_A%d' % (primary, 'q1' if wide else 'q0', tag, a), REQ, raw))
    # F3: every first-frame cut of a 300-octet multi-type app (incl. cuts inside the app header)
    app300 = mix_app(300, 'g30v1')
    for cut in range(1, 250):
        rem, chunks = 300 - cut, [cut]
        while rem:
            n = min(rem, 249)
            chunks.append(n)
            rem -= n
        raw = encode(app300, chunks)
        if len(raw) <= MAX_NATIVE:
            cases.append(('F3_cut%d' % cut, REQ, raw))
    # F4: the retained captured multi-type shapes (one per distinct response structure)
    seen = set()
    for r in retained:
        key = (r['native'], r['app'], tuple(r['frames']))
        if key not in seen:
            seen.add(key)
            cases.append(('F4_%s' % r['run'], r['request'], r['response']))
    return cases


def reach_key(native):
    frames, app = gp.one_fragment(native)
    return (len(native), len(app), len(std.deframe(frames[0])[1]) >= 5)


# ---- exact reachability model of pad_read (mirrors general_read_padding.pad_read; verified below) -------
def reach_model(key):
    L, A, pp = key
    plans = set()
    if pp:
        for n in range(4, min(PAD_STOP - PAD_START + 1, CAPACITY - A) + 1):
            last = PAD_START + n - 1
            w = 1 if last <= 255 else 2
            obj = 3 + 2 * w + n
            if A + obj <= CAPACITY:
                plans.add(L + gp.prefix_size(obj))

    def fallback(T):
        cap = next((n for n in range(A + 6, CAPACITY + 1) if gp.prefix_size(n) == T), None)
        if cap is None:
            return False
        for w in (1, 2):
            count = cap - A - (3 + 2 * w)
            last = PAD_START + count - 1
            if count >= 1 and last <= PAD_STOP and last < 1 << (8 * w):
                return True
        return False
    return L, plans, fallback


def first_target(model, targets):
    """(target, construction) pad_read would choose, or None if unreachable."""
    L, plans, fallback = model
    for t in sorted(targets):
        if t == L:
            return t, 'at_target'
        if t < L:
            continue
        if t in plans:
            return t, 'prefix'
        if fallback(t):
            return t, 'resegment'
    return None


def search(cases, retained, seeds, hi=440, span=60):
    """Rule v3: over all target sets with T_i >= seed_i (seed_i <= T_i <= seed_i+span, top <= hi, strictly
    increasing), keep those where (a) every profile case reaches a target and (b) every retained workload shape
    reaches its target by the prefix construction or is already at it; return the minimum added bytes on the
    retained sample (ties: smaller targets). Exhaustive, so not myopic like the greedy +1 rule."""
    keys = sorted({reach_key(c[2]) for c in cases})
    models = {k: reach_model(k) for k in keys}
    fb_cache = {}
    for k, (L, plans, fb) in models.items():
        models[k] = (L, plans, (lambda T, fb=fb, k=k: fb_cache.setdefault((k, T), fb(T))))
    wl = collections.Counter(reach_key(r['response']) for r in retained)
    ranges = [range(sd, min(sd + span, hi) + 1) for sd in seeds[:-1]] + [range(seeds[-1], hi + 1)]
    best, feasible = None, 0  # feasible counts sets that passed both constraints and were not pruned
    for combo in itertools.product(*ranges):
        if any(a >= b for a, b in zip(combo, combo[1:])):
            continue
        added, ok = 0, True
        for k, n in wl.items():
            ft = first_target(models[k], combo)
            if ft is None or ft[1] == 'resegment':
                ok = False
                break
            added += n * (ft[0] - k[0])
        if not ok or (best and added > best[0]):
            continue
        if any(first_target(models[k], combo) is None for k in keys):
            continue
        feasible += 1
        if best is None or (added, combo) < best[:2]:
            best = (added, combo)
    return list(best[1]), feasible


def coverage(cases, targets, cache):
    fails = []
    for cid, req, raw in cases:
        key = reach_key(raw) + (tuple(targets),)
        if key not in cache:
            r = gp.pad_read(req, raw, list(targets), pad_start=PAD_START, pad_stop=PAD_STOP, max_app_bytes=CAPACITY)
            cache[key] = (r.status, r.target, r.construction, r.padding_points)
        if cache[key][0] == 'unreachable':
            fails.append((cid, len(raw)))
    return fails


def prefix_fails(workload, targets, cache):
    """Rule v2: each retained workload shape must reach its target by the PREFIX construction (the one the
    switch implements: first segment only, native tail verbatim) or already be at a target."""
    fails = []
    for cid, req, raw in workload:
        key = reach_key(raw) + (tuple(targets),)
        if key not in cache:
            r = gp.pad_read(req, raw, list(targets), pad_start=PAD_START, pad_stop=PAD_STOP, max_app_bytes=CAPACITY)
            cache[key] = (r.status, r.target, r.construction, r.padding_points)
        status, _, construction, _ = cache[key]
        if status == 'unreachable' or (status == 'padded' and construction != 'prefix'):
            fails.append((cid, len(raw)))
    return fails


def adjust(cases, seeds, cache, workload=None):
    """Smallest upward moves until every profile case reaches a target (and, rule v2, every workload shape
    reaches it by the prefix construction). Returns (targets, steps)."""
    targets, steps = sorted(set(seeds)), []
    for _ in range(400):
        fails = coverage(cases, targets, cache) + (prefix_fails(workload, targets, cache) if workload else [])
        if not fails:
            return targets, steps
        cid, L = min(fails, key=lambda f: f[1])
        j = next((i for i, t in enumerate(targets) if t >= L), len(targets) - 1)
        old = targets[j]
        targets[j] = old + 1
        targets = sorted(set(targets))
        steps.append(dict(raised=old, to=old + 1, first_unreached_case=cid, native=L, unreached_cases=len(fails)))
    raise SystemExit('adjustment did not converge')


def compress(steps):
    out = []
    for s in steps:
        if out and out[-1]['to'] == s['raised']:
            out[-1]['to'] = s['to']
            out[-1]['moves'] += 1
        else:
            out.append(dict(s, moves=1))
    return out


def evaluate(retained, targets):
    """Exact per-exchange outputs on the retained sample; overhead and residual distinctions."""
    by_native = collections.Counter(r['native'] for r in retained)
    per = {}
    for r in retained:
        key = (r['native'], r['app'], tuple(r['frames']), tuple(r['tcp']))
        if key in per:
            continue
        res = gp.pad_read(r['request'], r['response'], list(targets), pad_start=PAD_START, pad_stop=PAD_STOP,
                          max_app_bytes=CAPACITY)
        out_frames = [len(f) for f in gp.split_frames(res.output)]
        # Master-facing TCP payloads: in-network padding adds bytes to the FIRST native TCP segment only;
        # continuation segments keep their size. (A resegmented output is reported with native cuts too.)
        added = len(res.output) - r['native']
        out_tcp = [r['tcp'][0] + added] + r['tcp'][1:]
        per[key] = dict(native=r['native'], app=r['app'], native_frames=r['frames'], native_tcp=r['tcp'],
                        status=res.status, target=res.target, construction=res.construction if res.status == 'padded' else None,
                        added=added, padding_points=res.padding_points, output_frames=out_frames, output_tcp=out_tcp)
    total_native = sum(r['native'] for r in retained)
    added = 0
    for r in retained:
        added += per[(r['native'], r['app'], tuple(r['frames']), tuple(r['tcp']))]['added']
    out_classes = collections.Counter()
    pkt_classes = collections.Counter()
    for r in retained:
        p = per[(r['native'], r['app'], tuple(r['frames']), tuple(r['tcp']))]
        out_classes[p['target'] if p['target'] else r['native']] += 1
        pkt_classes[tuple(p['output_tcp'])] += 1
    pkts = sum(len(r['tcp']) for r in retained)
    return dict(targets=list(targets), native_total=total_native, added_total=added,
                added_percent=round(100 * added / total_native, 3),
                # assumed 66-octet Ethernet+IPv4+TCP(timestamps) header per payload packet; payload bytes exact
                wire_added_percent_assuming_66B_headers=round(100 * added / (total_native + 66 * pkts), 3),
                shapes=list(per.values()),
                residual_aggregate_classes={str(k): v for k, v in sorted(out_classes.items())},
                residual_tcp_payload_sequences={str(list(k)): v for k, v in sorted(pkt_classes.items())},
                native_aggregate_classes={str(k): v for k, v in sorted(by_native.items())})


def main():
    retained, manifest = load_retained()
    agg = sorted(r['native'] for r in retained)
    tcp = sorted(x for r in retained for x in r['tcp'])
    link = sorted(x for r in retained for x in r['frames'])
    dist = {name: dict(collections.Counter(v)) for name, v in (('aggregate_response', agg), ('tcp_payload', tcp), ('link_frame', link))}
    seeds = {}
    for name, v in (('aggregate_response', agg), ('tcp_payload', tcp), ('link_frame', link)):
        seeds[name] = {str(L): [nearest_rank(v, i, L) for i in range(L)] for L in (2, 3)}
    cases = profile_cases(retained)
    cache = {}
    candidates = []
    workload = [c for c in cases if c[0].startswith('F4_')]
    history = {}
    if '--history' in sys.argv:   # recompute the superseded greedy rules (v1, v2-greedy) for the record
        for L in (2, 3):
            sd = seeds['aggregate_response'][str(L)]
            t1, s1 = adjust(cases, sd, cache)
            t2, s2 = adjust(cases, sd, cache, workload)
            history[L] = dict(v1=dict(targets=t1, adjustments=compress(s1), added_percent=evaluate(retained, t1)['added_percent']),
                              v2_greedy=dict(targets=t2, adjustments=compress(s2), added_percent=evaluate(retained, t2)['added_percent']))
    for L in (2, 3):
        seed = seeds['aggregate_response'][str(L)]
        targets, feasible = search(cases, retained, seed)
        # Verify with the REAL encoder: profile coverage and workload construction.
        if coverage(cases, targets, cache) or prefix_fails(workload, targets, cache):
            raise SystemExit('reachability model disagrees with pad_read for %s' % targets)
        ev = evaluate(retained, targets)
        candidates.append(dict(states=L, seeds=seed, snapped=sorted(set(seed)), feasible_unpruned_sets=feasible,
                               history=history.get(L), targets=targets, covers_profile=True,
                               **{k: ev[k] for k in ev if k != 'targets'}))
    comparator = dict(name='163/269/399 handoff coverage profile (minimum-added-bytes, NOT Ditto)',
                      covers_profile=not coverage(cases, [163, 269, 399], cache), **evaluate(retained, [163, 269, 399]))
    chosen = min(candidates, key=lambda c: (c['added_total'], len(c['targets'])))
    # Capacity and index needs of the chosen construction, over the whole profile.
    max_app_out, max_points = 0, 0
    for cid, req, raw in cases:
        r = gp.pad_read(req, raw, chosen['targets'], pad_start=PAD_START, pad_stop=PAD_STOP, max_app_bytes=CAPACITY)
        if r.status == 'padded':
            max_app_out = max(max_app_out, len(gp.one_fragment(r.output)[1]))
            max_points = max(max_points, r.padding_points)
    result = dict(
        rule=('Ditto-inspired adaptation: seeds = nearest-rank percentiles P_i=percentile_{(i+1)100/L}(D), '
              'L in {2,3}, D = retained aggregate-response distribution; snap to encoder reachability; raise the '
              'target of the first unreached profile case by the smallest upward step until all profile cases '
              'reach a target; choose min added bytes on the retained sample, ties -> fewer states. '
              'AMENDED (recorded, see TARGET_POLICY.md): v1 greedy +1 needed the resegment fallback for the 377 '
              'workload shape (not realizable per-packet in the switch); v2 adds the constraint that every retained '
              'workload shape reaches its target by the prefix construction; the greedy +1 adjustment proved myopic '
              '(39.96%%), so v3 searches exhaustively over upward-adjusted target sets (T_i >= seed_i) for the minimum '
              'added bytes subject to full profile coverage AND the workload prefix constraint'),
        observation_layer=LAYER,
        other_layers_reported=['tcp_payload', 'link_frame'],
        distribution=dist, ditto_seeds=seeds,
        profile=dict(max_native_encoded=MAX_NATIVE, max_app_octets=MAX_APP, single_solicited_fragment=True,
                     objects=sorted(OBJ), qualifiers=['0x00', '0x01'], request_objects='fullread profile (G60 class, range/all-points READs)',
                     reserved_padding_range=[PAD_START, PAD_STOP], endpoint_capacity_assumed=CAPACITY,
                     cases=len(cases), distinct_reachability_keys=len({reach_key(c[2]) for c in cases}),
                     out_of_profile='native >377, multi-fragment, unknown objects, control responses: explicit unreachable/raise'),
        candidates=candidates, comparator=comparator,
        selected=dict(targets=chosen['targets'], states=chosen['states'],
                      required_app_capacity=max_app_out, max_padding_points=max_points,
                      required_index_range=[PAD_START, PAD_START + max_points - 1]),
        input_manifest=manifest,
        encoder_sha256=hashlib.sha256((ROOT / 'software/source/full_read_01/general_read_padding.py').read_bytes()).hexdigest())
    (HERE / 'policy.json').write_text(json.dumps(result, indent=1) + '\n')
    print(json.dumps(dict(selected=result['selected'],
                          candidates=[{k: c[k] for k in ('states', 'seeds', 'targets', 'added_percent',
                                                         'residual_aggregate_classes')} for c in candidates],
                          comparator={k: comparator[k] for k in ('targets', 'added_percent', 'covers_profile')},
                          cases=len(cases)), indent=1))


if __name__ == '__main__':
    main()

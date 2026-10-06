"""Build a provisional request-anchored admission record from retained evidence.

The OFF smoke and TCP_INFO belong to the historical df599 build. Master-facing
captures describe observations, not switch timing or feedback path bounds. No
local arithmetic estimate establishes heartbeat, release or physical drain.
"""
import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'size'))
import rrc  # noqa: E402
from defense4.timing.active_control import delay_admission as da  # noqa: E402

RES = Path(__file__).resolve().parents[1] / 'results'
CONN = 'vision-sel751-20000'
HISTORICAL_BUILD = 'defense4_timing-df5991016285'
SOURCE = Path(__file__).resolve().parents[2] / 'response_ready/src/defense4_response_ready.p4'
BUILD = 'case4-source-' + hashlib.sha256(SOURCE.read_bytes()).hexdigest()
P = da.Provenance


def smoke_cohort(records=None, expected_count=None, main_client_port=None):
    """Identify one main TCP flow by declared count, excluding other precheck flows.

    Ambiguous or incomplete cohorts fail. Matching uses reverse full flow, modulo
    32-bit TCP end, application sequence and READ function. Capture location stays
    master-facing; these rows never become switch-side bounds.
    """
    smoke_dir = RES / 'hw_smoke_20261006/cand_off_30'
    expected_apps = None
    if records is None:
        status = json.loads((smoke_dir / 'status.json').read_text())
        app_rows = [json.loads(x) for x in (smoke_dir / 'read.jsonl').read_text().splitlines() if x]
        expected_count = status['read_count'] if expected_count is None else expected_count
        if len(app_rows) != expected_count or any(x['operation'] != 'READ' for x in app_rows):
            raise ValueError('declared main READ count differs from application record')
        expected_apps = [x['app_seq'] for x in app_rows]
        records = rrc.read_records(smoke_dir / 'traffic.pcapng')
    elif expected_count is None:
        raise ValueError('synthetic cohort requires an explicit expected_count')
    packets = []
    requests = defaultdict(list)
    for t, raw in records:
        p = rrc.parse(raw)
        if p is None:
            continue
        flow = (raw[26:30], raw[30:34], p.sport, p.dport)
        packets.append((t, p, flow))
        if (p.dport == 20000 and len(p.payload) >= 13
                and p.payload[:2] == b'\x05\x64' and p.payload[12] == 1):
            requests[flow].append((t, p))
    candidates = [flow for flow, rows in requests.items()
                  if len(rows) == expected_count and (main_client_port is None or flow[2] == main_client_port)]
    if len(candidates) != 1:
        raise ValueError('main READ cohort is ambiguous or does not match declared count')
    flow = candidates[0]
    reverse = (flow[1], flow[0], flow[3], flow[2])
    reqs = requests[flow]
    if expected_apps is not None and [p.payload[11] & 15 for _, p in reqs] != expected_apps:
        raise ValueError('main capture application sequence differs from application record')
    rows = []
    for ts, rq in reqs:
        end = (rq.seq + len(rq.payload)) & 0xffffffff
        ack = next((t for t, p, f in packets if f == reverse and not p.payload
                    and p.ack == end and t >= ts), None)
        resp = next((t for t, p, f in packets if f == reverse and len(p.payload) >= 13
                     and p.ack == end and t >= ts and p.payload[12] == 129
                     and p.payload[11] & 15 == rq.payload[11] & 15), None)
        if ack is None or resp is None or resp < ack:
            raise ValueError('main READ has no ordered matching ACK/RESPONSE')
        rows.append(((ack-ts)/1e6, (resp-ts)/1e6, (resp-ack)/1e6))
    return dict(rows=rows, main_count=len(rows), main_client_port=flow[2],
                precheck_count=sum(len(v) for f, v in requests.items() if f != flow),
                observation_point='master-facing capture', historical_build=HISTORICAL_BUILD)


def smoke():
    return smoke_cohort()['rows']


def build(hold_ms, gap_ms=1.0, target_build=None, *, operation='READ', operation_profile_sha256=''):
    """hold_ms is proposed request-relative D_A, never a measured hold guarantee."""
    rows = smoke()
    rto = json.loads((RES / 'master_rto_20261006/master_rto_cand_20261006.json').read_text())
    target_build = target_build or BUILD
    ctx = da.PolicyContext(connection_id=CONN, build_id=target_build,
        operation=operation, operation_profile_sha256=operation_profile_sha256)
    obs = '2026-10-06T17:05:00Z'
    applies = da.Applicability(connection_id=CONN, build_id=HISTORICAL_BUILD,
                              direction='master_to_outstation', timer='master_rto')
    def bound(name, value, provenance, source, identity=None):
        return da.Bound(name, value, provenance, source, obs, identity)
    def unavailable(name, source):
        return bound(name, None, P.UNAVAILABLE, source)
    smoke_src = 'cand_off_30: 30 main READs; one separate precheck excluded; historical master-facing capture'
    inp = dict(d_a_ms=hold_ms, clrt_new_ms=gap_ms, anchor='request', context=ctx,
        master_rto_ms=bound('master_rto_ms', rto['tcp_info_idle']['rto_us']/1000,
            P.MEASURED_THIS_CONNECTION if target_build == HISTORICAL_BUILD else P.INHERITED_EARLIER_BUILD,
            'TCP_INFO on historical df599 DNP3 socket; first repeat at 204.4 ms; not a timer measurement on the new candidate', applies),
        outstation_rto_ms=bound('outstation_rto_ms', 3000., P.MEASURED_OTHER_SETTING,
            '2026-09-15 frozen relay setting; not the current candidate'),
        application_deadline_ms=bound('application_deadline_ms', 500., P.OPERATOR_SUPPLIED,
            'driver per-transaction budget (--budget-ms 500)'),
        clrt_original_ms=unavailable('clrt_original_ms', smoke_src+'; no switch observation point'),
        master_feedback_path_ms=unavailable('master_feedback_path_ms',
            'TCP_INFO SRTT+4RTTVAR is an estimator, not a measured feedback path upper bound'),
        outstation_feedback_path_ms=unavailable('outstation_feedback_path_ms', 'no relay-facing measurement'),
        native_request_to_response_ms=bound('native_request_to_response_ms', max(r[1] for r in rows),
            P.INHERITED_EARLIER_BUILD, smoke_src+'; observed application-facing maximum, no future guarantee'),
        ack_latency_bound_ms=unavailable('ack_latency_bound_ms',
            smoke_src+'; request-to-ACK includes paths and does not isolate outstation ACK latency'),
        detect_ms=unavailable('detect_ms', 'no detection measurement for current source'),
        release_tail_ms=unavailable('release_tail_ms', 'no commitment/release measurement for current source'),
        readiness_expiry_ms=bound('readiness_expiry_ms',30.,P.OPERATOR_SUPPLIED,'fixed requested readiness policy'),
        completion_timeout_ms=unavailable('completion_timeout_ms','completion setting not yet admitted'),
        safety_margin_ms=3., policy_cap_ms=40.)
    for name in ('switch_request_to_ack_min_ms','switch_request_to_ack_max_ms',
                 'switch_request_to_response_min_ms','switch_request_to_response_max_ms',
                 'heartbeat_interval_ms','physical_drain_ms'):
        inp[name] = unavailable(name,'no applicable switch/recovery measurement for '+target_build)
    if ctx.requires_sbo:
        inp['sbo'] = da.SBOInputs(
            budget_ms=unavailable('sbo_budget_ms', 'outstation SELECT retention setting/origin is unverified; not the 500 ms application budget'),
            native_cycle_ms=unavailable('sbo_native_cycle_ms', 'no source-current SELECT acceptance to matching OPERATE acceptance observation'),
            operate_added_ms=unavailable('sbo_operate_added_ms', 'no source-current control-domain normal/recovery hold and release measurement'),
            operation_profile_sha256=operation_profile_sha256)
    return da.AdmissionInputs(**inp)


def attach_observations(verdict, path, identity):
    """Attach current internal measurements without filling unavailable physical bounds.

    This is an evidence import, not a promotion from internal completion to wire
    departure, or from configured service periods to measured maxima.
    """
    from observations import load_observations
    context = verdict['policy']['context']
    expected = dict(identity, source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        build_id=context['build_id'], connection_id=context['connection_id'],
        operation_profile_sha256=context['operation_profile_sha256'])
    record = load_observations(path, expected)
    verdict['observation_record'] = record.summary()
    pairs = (('request_ingress', 'ack_ingress'), ('request_ingress', 'response_complete_ingress'),
             ('ack_deadline', 'ack_commit'), ('response_deadline', 'response_commit'),
             ('ack_deadline', 'blocker_termination'), ('ack_commit', 'ack_wire_departure'),
             ('response_commit', 'response_wire_departure'))
    verdict['observation_intervals'] = [{
        'transaction_id': transaction, **record.interval(transaction, start, end)}
        for transaction in sorted({s['transaction_id'] for s in record.samples})
        for start, end in pairs]
    return verdict


def write_record(path, verdict):
    """An admission output is retained evidence; never overwrite an earlier record."""
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(verdict, stream, indent=1, default=str)
        stream.write('\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output')
    parser.add_argument('--da-ms', type=float, default=10.)
    parser.add_argument('--gap-ms', type=float, default=1.)
    parser.add_argument('--target-build', default=None)
    parser.add_argument('--operation', choices=('READ', 'SELECT', 'OPERATE', 'SBO'), default='READ')
    parser.add_argument('--operation-profile-sha256', default='')
    parser.add_argument('--observations', help='current internal observation JSON/JSONL; does not authorize hardware')
    parser.add_argument('--observation-identity', help='expected collector instrument/schema identity JSON')
    args = parser.parse_args()
    if bool(args.observations) != bool(args.observation_identity):
        parser.error('--observations and --observation-identity must be supplied together')
    verdict = da.evaluate(build(args.da_ms, args.gap_ms, args.target_build,
        operation=args.operation, operation_profile_sha256=args.operation_profile_sha256))
    verdict['historical_smoke_cohort'] = smoke_cohort()
    if args.observations:
        attach_observations(verdict, args.observations, json.loads(Path(args.observation_identity).read_text()))
    write_record(args.output, verdict)
    print('verdict:', verdict['verdict'])
    print('unknown inputs:', ', '.join(verdict['unknown_inputs']))

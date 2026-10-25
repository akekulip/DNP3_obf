"""B1 offline discrimination of the two c67 physical failures (retained captures and model results only).

Reads the retained relay_wire.json/master.json/trial.json of the c67 reference and loss blocks (and c52 block 25 for
the loss comparison) plus the c67 control_timing02 model results. Writes b1_offline.json beside this script (refuses
to overwrite). No testbed contact. Observation point: the master NIC only; model times are T-clock units.
"""
import glob
import json
import statistics
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVID = HERE.parent
BLOCKS = EVID / 'hw_blocks'
MODEL = EVID.parents[1] / 'ctl_timing_01/evidence/model_control_timing_m12p_c67_sdk9132_02/control_timing_results.json'


def exchanges(block, arm, trial='t0'):
    return json.loads(Path(glob.glob(str(BLOCKS / block / 'physical_relay' / arm / ('*_' + trial)))[0],
                           ).joinpath('relay_wire.json').read_text())['exchanges']


def tsval(packet):
    options = bytes.fromhex(packet['tcp_options_hex'])
    at = options.find(b'\x08\x0a')
    return int.from_bytes(options[at + 2:at + 6], 'big') if at >= 0 else None


replay = json.loads((EVID / 'c67_reference_replay_20261025.json').read_text())
result = dict(observation='master NIC only (in.pcap/out.pcap); no relay-side or switch-departure timestamp')

# T-a: position of complete CLRT relative to D per D x arm.
cells, errors, pairs = [], [], []
for block, info in replay['blocks'].items():
    d_us = info['D_ns'] / 1000
    for arm in ('timing_only', 'combined'):
        if arm not in info['trials']:
            continue
        err = [e['complete_clrt_us'] - d_us for e in exchanges(block, arm)]
        errors += err
        pairs += list(zip(err, err[1:]))
        cells.append(dict(D_ms=d_us / 1000, arm=arm, n=len(err), below_D_minus_100us=sum(x < -100 for x in err),
                          within_100us=sum(abs(x) <= 100 for x in err), above_D_plus_100us=sum(x > 100 for x in err),
                          median_error_us=statistics.median(err), min_error_us=min(err), max_error_us=max(err)))
result['T_a_error_position'] = cells
result['T_c_abs_error_tail_counts'] = {str(t): sum(abs(x) > t for x in errors) for t in (1500, 1900, 2000, 2100, 2500)}
xs = [(a, b) for a, b in pairs if abs(a) < 5000 and abs(b) < 5000]
mx, my = statistics.mean(a for a, _ in xs), statistics.mean(b for _, b in xs)
cov = sum((a - mx) * (b - my) for a, b in xs)
result['T_c_lag1_error_correlation'] = dict(n=len(xs), r=cov / (sum((a - mx) ** 2 for a, _ in xs) *
                                                                 sum((b - my) ** 2 for _, b in xs)) ** .5)

# T-d: READ request->response by arm (every READ follows an OPERATE in this schedule) and the outlier timeline.
native = {}
for block, arms in (('rc01_hw_c67_20261025_03_reference', ('off', 'size_only', 'timing_only', 'combined')),
                    ('rc01_hw_c67_20261025_04_reference_rest', ('timing_only', 'combined'))):
    for arm in arms:
        rtt = sorted((e['response']['complete_timestamp_ns'] - e['request']['first_timestamp_ns']) / 1e6
                     for i, e in enumerate(exchanges(block, arm)) if i and e['operation'] == 'READ')
        native[block[-20:] + '/' + arm] = dict(n=len(rtt), median_ms=rtt[len(rtt) // 2], max_ms=rtt[-1])
outlier = exchanges('rc01_hw_c67_20261025_04_reference_rest', 'timing_only')[162]
result['T_d'] = dict(read_rtt_after_operate=native, outlier=dict(
    block='rc01_hw_c67_20261025_04_reference_rest', arm='timing_only', exchange_index=162,
    workload=outlier['workload'], complete_clrt_us=outlier['complete_clrt_us'],
    request_to_ack_ms=(outlier['ack_timestamp_ns'] - outlier['request']['first_timestamp_ns']) / 1e6,
    request_to_response_ms=outlier['master_rtt_ns'] / 1e6))

# Model T clock: release - ACK release versus the written gap (units of 256 ns).
model = json.loads(MODEL.read_text())
rows = [dict(case=c['name'], gap_units=c['point']['written_units']['gap'],
             release_minus_ack_units=c['point']['response_release_units'] - c['point']['ack_release_units'])
        for c in model['cases'] if isinstance(c.get('point'), dict) and 'response_release_units' in c['point']]
steps = sorted({r['release_minus_ack_units'] for r in rows})
result['model_T_clock'] = dict(unit_ns=256, cases=len(rows), distinct_release_minus_ack_units=steps,
                               min_excess_units=min(r['release_minus_ack_units'] - r['gap_units'] for r in rows),
                               rows=rows)

# M-a/M-b: the three t3 SELECT-response-loss trials.
loss = {}
for label, pattern in (('c67_loss_mixed_t3', 'rc01_hw_c67_20261025_06_loss_mixed_950/physical_relay/combined/*_t3'),
                       ('c67_loss_full_t3', 'rc01_hw_c67_20261025_07_loss_full_950/physical_relay/combined/*_t3'),
                       ('c52_loss_mixed_t3', 'rc01_hw_c52_20261024_25_loss_mixed_950/physical_relay/combined/*_t3')):
    directory = Path(glob.glob(str(BLOCKS / pattern))[0])
    wire = json.loads((directory / 'relay_wire.json').read_text())
    master = json.loads((directory / 'master.json').read_text())
    trial = json.loads((directory / 'trial.json').read_text())
    packets = sorted([('out', p) for p in wire['packets']['out']] + [('in', p) for p in wire['packets']['in']],
                     key=lambda item: item[1]['timestamp_ns'])
    select = next(p for d, p in packets if d == 'out' and p['payload_len'] == 45)
    at = lambda p: (p['timestamp_ns'] - select['timestamp_ns']) / 1e6
    window = [(d, p) for d, p in packets if 0 <= at(p) < 1300]
    copies = [p for d, p in window if d == 'in' and p['payload_len'] == 60][:2]
    operate = next(p for d, p in window if d == 'out' and p['payload_len'] > 0 and at(p) > 1)
    first_ack = next(p for d, p in window if d == 'in' and p['payload_len'] == 0)
    loss[label] = dict(
        ack_ms=at(first_ack), first_copy_ms=at(copies[0]), second_copy_ms=at(copies[1]),
        copy_gap_ms=at(copies[1]) - at(copies[0]), select_to_operate_sent_ms=at(operate),
        relay_tsval_copy_gap_ticks=tsval(copies[1]) - tsval(copies[0]),
        operate_points=[r.get('points') for r in master['records'] if r['operation'] == 'OPERATE'],
        switch_outcomes={k: v for k, v in trial['observed']['switch']['outcomes'].items() if v},
        loss_rule=dict(chain=trial['loss']['chain'], mode=trial['loss']['mode'], cls=trial['loss']['class']))
result['M_ab_select_response_loss'] = loss
result['notes'] = [
    'master-side intervals are bounds, not the relay select window; relay TSval steps are 10 ms',
    'model T-clock events fall on a ~4882-unit (~1.25 ms) grid; the model proves release >= D only']

out = HERE / 'b1_offline.json'
with out.open('x') as stream:
    json.dump(result, stream, indent=1)
    stream.write('\n')
print(json.dumps({k: v for k, v in result.items() if k not in ('model_T_clock',)}, indent=1)[:6000])
print('model distinct release-ACK units:', steps)

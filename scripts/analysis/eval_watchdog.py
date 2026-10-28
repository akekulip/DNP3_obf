#!/usr/bin/env python3
"""Per-block data-quality watchdog for the evaluation campaign: one line per anomaly, one OK line per clean block.

Each newly completed block is extracted with eval_rows and checked against the pre-registered design
(results/analysis/evaluation/DESIGN.json): planned counts, capture drops, retransmissions, class sizes per arm,
timed-arm CLRT at D, application outcomes, IIN and piggybacking. Exits when the campaign is terminal.

  python3 -u scripts/analysis/eval_watchdog.py CAMPAIGN_DIR
"""
import json
from pathlib import Path
import statistics
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import eval_rows  # noqa: E402

NATIVE = {('READ', 'mixed'): 91, ('READ', 'integrity'): 134, ('SELECT', ''): 49, ('OPERATE', ''): 49}
PADDED = {('READ', 'mixed'): 141, ('READ', 'integrity'): 158, ('SELECT', ''): 60, ('OPERATE', ''): 60}
PADDED_ARMS, TIMED_ARMS = {'size_only', 'combined'}, {'timing_only', 'combined'}
IIN_OK = 128            # IIN1 0x80 = DEVICE_RESTART set (as on every SEL-751 response here), IIN2 0x00;
                        # 0x84 adds class-2 events pending, which changes integrity READ sizes
CLRT_MEDIAN_TOLERANCE_MS = 1.0  # watchdog regime check only, not an evaluation criterion


def block_anomalies(rows, d_ms):
    """Anomalies in one block's rows against the pre-registered expectations."""
    anomalies = []
    for arm in sorted({row['arm'] for row in rows}):
        arm_rows = [row for row in rows if row['arm'] == arm]
        sizes = PADDED if arm in PADDED_ARMS else NATIVE
        wrong = sorted({(row['operation'], row['read_class'], row['resp_len']) for row in arm_rows
                        if sizes.get((row['operation'], row['read_class'])) != row['resp_len']})
        if wrong:
            anomalies.append('%s: response sizes outside the %s images: %s' % (
                arm, 'padded' if arm in PADDED_ARMS else 'native', wrong[:6]))
        bad = [row for row in arm_rows if row['outcome'] != 'OK' or not row['app_ok']
               or (row['operation'] != 'READ' and row['crob'] != '1:SUCCESS;3:SUCCESS')]
        if bad:
            anomalies.append('%s: %d exchanges not OK, first %s seq %s outcome %s crob %s' % (
                arm, len(bad), bad[0]['operation'], bad[0]['seq'], bad[0]['outcome'], bad[0]['crob']))
        iins = sorted({row['iin'] for row in arm_rows if row['iin'] != IIN_OK})
        if iins:
            anomalies.append('%s: IIN other than 0x80 0x00 seen: %s' % (arm, iins))
        piggy = sum(row['piggyback'] for row in arm_rows)
        if piggy:
            anomalies.append('%s: %d piggybacked exchanges' % (arm, piggy))
        if arm in TIMED_ARMS:
            for operation in ('READ', 'SELECT', 'OPERATE'):
                values = [row['clrt_ms'] for row in arm_rows if row['operation'] == operation]
                if values and abs(statistics.median(values) - d_ms) > CLRT_MEDIAN_TOLERANCE_MS:
                    anomalies.append('%s %s: CLRT median %.3f ms, D %d ms' % (
                        arm, operation, statistics.median(values), d_ms))
    return anomalies


def retransmitted_exchanges(wire):
    """Indices of exchanges whose request or response bytes were sent more than once."""
    found = set()
    for direction, span in (('out', 'request'), ('in', 'response')):
        seen = {}
        for packet in wire['packets'][direction]:
            if packet['payload_len']:
                key = (packet['seq'], packet['payload_hex'])
                seen[key] = seen.get(key, 0) + 1
        for (seq, _), count in seen.items():
            if count > 1:
                for index, exchange in enumerate(wire['exchanges']):
                    part = exchange.get(span) or {}
                    if part and part['sequence_start'] <= seq < part['sequence_end']:
                        found.add(index)
    return sorted(found)


def capture_anomalies(run_root):
    anomalies = []
    for wire_path in sorted(Path(run_root).glob('*/*/*/relay_wire.json')):
        wire = json.loads(wire_path.read_text())
        arm = wire_path.parent.parent.name
        drops = {d: (s or {}).get('dropped_kernel') for d, s in (wire.get('capture_drops') or {}).items()}
        if any(v != 0 for v in drops.values()) or len(drops) != 2:
            anomalies.append('%s: capture drops %s' % (arm, drops))
        if any((wire.get('retransmissions') or {}).values()):
            anomalies.append('%s: retransmissions %s at exchange(s) %s' % (
                arm, wire.get('retransmissions'), retransmitted_exchanges(wire)))
        if not wire.get('ok'):
            anomalies.append('%s: relay_wire not ok: %s' % (arm, (wire.get('failures') or [])[:3]))
    return anomalies


def main():
    campaign = Path(sys.argv[1]).resolve()
    manifest = json.loads((campaign / 'manifest.json').read_text())
    steps = {step['id']: step for step in manifest['steps']}
    state = HERE.parents[1] / 'results/analysis/evaluation' / ('watchdog_%s.json' % campaign.name)
    checked = set(json.loads(state.read_text())) if state.is_file() else set()  # survives monitor re-arms
    if checked:
        print('%s DATA WATCHDOG RESUMED: %d blocks already checked' % (time.strftime('%H:%M:%S'), len(checked)), flush=True)
    while True:
        for block_id, step in steps.items():
            terminal = campaign / 'steps' / block_id / 'terminal.json'
            if block_id in checked or not terminal.is_file():
                continue
            status = json.loads(terminal.read_text()).get('status')
            if status != 'completed':
                print('%s DATA SKIP %s: block %s' % (time.strftime('%H:%M:%S'), block_id, status), flush=True)
                checked.add(block_id)
                state.write_text(json.dumps(sorted(checked)) + '\n')
                continue
            config = json.loads(Path(step['argv'][4]).read_text())
            d_ms = config['timing_params_ns']['gap'] // 1000000
            order = [arm['name'] for arm in config['arms']]
            rows, problems = [], []
            for trial in sorted(Path(step['run_root']).glob('*/*/*/relay_wire.json')):
                context = dict(block_id=block_id, d_ms=d_ms, arm=trial.parent.parent.name)
                got, trial_problems, _ = eval_rows.trial_rows(trial.parent, context, eval_rows.EXPECTED)
                rows.extend(got)
                problems.extend(trial_problems)
            arms = sorted({row['arm'] for row in rows})
            if arms != sorted(order):
                problems.append('arms with data %s, planned %s' % (arms, order))
            anomalies = problems + capture_anomalies(step['run_root']) + block_anomalies(rows, d_ms)
            stamp = time.strftime('%H:%M:%S')
            if anomalies:
                for anomaly in anomalies:
                    print('%s DATA ANOMALY %s D%d: %s' % (stamp, block_id, d_ms, anomaly), flush=True)
            else:
                medians = {arm: statistics.median(r['clrt_ms'] for r in rows if r['arm'] == arm) for arm in arms}
                print('%s DATA OK %s D%d: %d rows; CLRT medians %s' % (
                    stamp, block_id, d_ms, len(rows), {a: round(v, 2) for a, v in medians.items()}), flush=True)
            checked.add(block_id)                         # only after the check has been reported
            state.write_text(json.dumps(sorted(checked)) + '\n')
        try:
            out = subprocess.run([sys.executable, str(HERE.parent / 'hardware/evaluation_campaign.py'), 'status',
                                  str(campaign)], capture_output=True, text=True, timeout=60).stdout
            phase = json.loads(out)['phase']
        except (ValueError, KeyError, subprocess.TimeoutExpired):
            phase = 'unknown'
        if phase in ('complete', 'stopped') and all(
                block_id in checked or not (campaign / 'steps' / block_id / 'terminal.json').is_file()
                for block_id in steps):
            print('%s DATA WATCHDOG DONE: campaign %s, %d blocks checked' % (
                time.strftime('%H:%M:%S'), phase, len(checked)), flush=True)
            return 0
        time.sleep(30)


if __name__ == '__main__':
    raise SystemExit(main())

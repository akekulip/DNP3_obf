#!/usr/bin/env python3
"""Tabulate the master-ACK behaviour runs on c72, c74 and c75 against results/analysis/ack_behaviour/DESIGN.json.

  python3 summarize_ack_behaviour.py C72_RUN C74_RUN C75_RUN OUT_JSON

Per case and build: state reached, every probe's disposition on dev64 (with the dev64 ACK/window/TSval), obsolete,
new information, N state unchanged, generation consumed, the rule verdict, the relay reply, and the progress steps;
then per scenario and build the set of verdicts across the four class/T variants, the disposition predicted from the
rows (DESIGN.json predictions_from_rows) against the observed one, the generation check, and the decision gate:
a valid window update or keepalive (window_increase_outstanding, zero_window_outstanding, keepalive_*) whose case
progress failed on c75 or c72. For those scenarios the gate cannot fire in the model (DESIGN.json interpretation_limits:
the scripted relay ignores the advertised window and runs no persist or keepalive timer), so its silence is reported as
not testable there, not as cleared. A forwarded probe must also keep its advertised window on dev64."""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUILDS = ('c72', 'c74', 'c75')
LATE = {'c72': False, 'c74': True, 'c75': False}
ALL_F = {b: False for b in BUILDS}
ALL_T = {b: True for b in BUILDS}
UNKNOWN = {b: None for b in BUILDS}
PREDICTED_FORWARDED = {
    'late_ack_wire_order': {'final_ACK': LATE}, 'late_ack_reverse_order': {'final_ACK': LATE},
    'r1_ack_behind_read': {'old_ACK_of_response1': LATE}, 'r2_offset': {'offset_ACK': LATE},
    'window_increase_outstanding': {'window_update': ALL_F}, 'window_increase_idle': {'window_update': ALL_T},
    'zero_window_outstanding': {'zero_window': ALL_F, 'window_reopen': ALL_F},
    'keepalive_idle': {'keepalive_0': ALL_F, 'keepalive_1': UNKNOWN},
    'keepalive_outstanding': {'keepalive_0': ALL_F, 'keepalive_1': UNKNOWN},
    'duplicate_ack_idle': {'duplicate_ACK_1': ALL_T, 'duplicate_ACK_2': ALL_T},
    'response_ack_control': {'response_ACK': ALL_T}}
GATE_SCENARIOS = ('window_increase_outstanding', 'zero_window_outstanding', 'keepalive_idle', 'keepalive_outstanding')
NOT_TESTABLE = ('the scripted model relay ignores the advertised window and runs no persist or keepalive timer, so '
                'suppressing a window update, zero window, reopening or keepalive cannot change what reaches the master; '
                'only N state was checkable for these scenarios. The real-TCP consequence is not testable in the model.')


def load(run):
    return {p.name[5:-5]: json.loads(p.read_text()) for p in sorted(Path(run).glob('case_*.json'))}


def probe_row(p):
    return dict(forwarded=p['forwarded'], port64_copies=p['port64_copies'], sent={k: p['sent'].get(k) for k in (
                    'seq', 'ack', 'window', 'tsval', 'payload_len', 'order')},
                port64=p['port64'], covered_by=p['covered_by'], obsolete=p['obsolete'],
                new_information=p['new_information'], n_state_unchanged=p['n_state_unchanged'],
                owner_state_before=None if p['n_before'].get('owner') is None else p['n_before']['owner'] >> 16,
                owner_state_after=None if p['n_after'].get('owner') is None else p['n_after']['owner'] >> 16,
                generation_consumed=p['generation_consumed'], t_delta=p['t_delta'],
                first_event=p['passes']['first_event'], busy=p['passes']['busy'], aborts=p['passes']['aborts'],
                relay_reply=p.get('relay_reply'), classification=p['classification'])


def main():
    runs = dict(zip(BUILDS, (Path(p) for p in sys.argv[1:4])))
    out = Path(sys.argv[4])
    data = {b: load(r) for b, r in runs.items()}
    names = sorted(set().union(*[set(v) for v in data.values()]))
    cases, scenarios, prediction_misses, gate_hits, problems, window_changed = {}, {}, [], [], [], []
    generation = {b: dict(suppressed=set(), forwarded=set()) for b in BUILDS}
    for name in names:
        row = {}
        for b in BUILDS:
            rec = data[b].get(name)
            if rec is None:
                problems.append('%s missing on %s' % (name, b))
                continue
            probes = {p['sent']['name']: probe_row(p) for p in rec['probes']}
            row[b] = dict(state_reached=rec['state_reached'], progress_ok=rec['progress_ok'],
                          error=(rec.get('error') or '').strip().splitlines()[-1:] or None,
                          attempts=[{k: a.get(k) for k in ('attempt', 'state_reached', 'read_claimed_first',
                                                            'read_port64')} for a in rec.get('attempts', [])] or None,
                          probes=probes, progress=rec['progress'], next_image_len=rec.get('next_image_len'),
                          consequence=rec['consequence'])
            scenario = rec['scenario']
            agg = scenarios.setdefault(scenario, {}).setdefault(b, dict(verdicts={}, progress_ok=[], state_reached=[]))
            agg['progress_ok'].append(rec['progress_ok'])
            agg['state_reached'].append(rec['state_reached'])
            for probe, p in probes.items():
                agg['verdicts'].setdefault(probe, set()).add(p['classification'])
                want = PREDICTED_FORWARDED.get(scenario, {}).get(probe, UNKNOWN)[b]
                if want is not None and rec['state_reached'] is not False and want != p['forwarded']:
                    prediction_misses.append(dict(case=name, build=b, probe=probe, predicted_forwarded=want,
                                                  observed_forwarded=p['forwarded']))
                if p['forwarded'] and (p['port64'] or {}).get('window') != p['sent']['window']:
                    window_changed.append(dict(case=name, build=b, probe=probe, sent=p['sent']['window'],
                                               port64=(p['port64'] or {}).get('window')))
                if p['generation_consumed'] is not None:
                    generation[b]['forwarded' if p['forwarded'] else 'suppressed'].add(p['generation_consumed'])
            if b in ('c72', 'c75') and scenario in GATE_SCENARIOS and rec['state_reached'] is not False \
                    and not rec['progress_ok']:
                gate_hits.append(dict(case=name, build=b, consequence=rec['consequence']))
        cases[name] = row
    for scenario in scenarios.values():
        for agg in scenario.values():
            agg['verdicts'] = {k: sorted(v) for k, v in agg['verdicts'].items()}
    report = dict(schema='ack-behaviour-summary-v1', runs={b: r.name for b, r in runs.items()},
                  exit_codes={b: json.loads((r / 'launch_command.json').read_text()).get('exit_code')
                              for b, r in runs.items()},
                  driver_sha256={b: json.loads((r / 'launch_command.json').read_text()).get('driver_sha256')
                                 for b, r in runs.items()},
                  source_sha256={b: json.loads((r / 'launch_command.json').read_text()).get('source_sha256')
                                 for b, r in runs.items()},
                  observation='SDK tofino-model functional output; not hardware, not wire timing',
                  design_sha256=hashlib.sha256((HERE / 'DESIGN.json').read_bytes()).hexdigest(),
                  per_scenario=scenarios, prediction_misses=prediction_misses,
                  generation_consumed_by_disposition={b: {k: sorted(v) for k, v in g.items()} for b, g in generation.items()},
                  decision_gate=dict(rule=json.loads((HERE / 'DESIGN.json').read_text())['decision_gate'],
                                     hits=gate_hits, stop=bool(gate_hits), testable_in_model=False,
                                     scenarios=list(GATE_SCENARIOS), status=NOT_TESTABLE),
                  forwarded_window_changed=window_changed,
                  cases=cases, problems=problems,
                  summarizer=dict(sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                  source=Path(__file__).read_text()))
    out.write_text(json.dumps(report, indent=1, default=str) + '\n')
    print(json.dumps(dict(stop=bool(gate_hits), gate_hits=gate_hits, prediction_misses=prediction_misses,
                          problems=problems,
                          per_scenario={s: {b: v['verdicts'] for b, v in x.items()} for s, x in scenarios.items()}),
                     indent=0, default=str))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

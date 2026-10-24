#!/usr/bin/env python3
"""C3 diagnostic poller (C3_DIAGNOSTIC_PLAN_20261016): light, read-only switch samples to JSONL. Runs on the switch.

poll: every --period-s, one JSON line {seq, t_start_ns, t_end_ns (switch time.monotonic_ns), wall_time, outcomes
(all 25 p1.t_Ingress.outcomes cells, summed over pipes as snapshot_counters.py reads them), pktgen (READ app 0 and
OPERATE app 1 counters of tf1.pktgen.app_cfg on pipe 1, as snapshot_lifecycle.py --read-app reads them), n_epoch,
n_owner, n_work_generation, n_work_phase, t_cur_epoch, t_gen_alloc, t_op_gen_alloc (raw register values, the
token_window.AUTHORITY names; masks are applied in analysis)}. A failed read is recorded in that sample's
`errors` and the poll continues. Stops on the stop file, SIGTERM or --max-duration-s, then writes one summary line.
wait-start / stop: harness helpers that wait for the first sample, and stop the poller and check its summary.

Read-only by construction: the BF Runtime client never binds the program or subscribes, and its write() raises.
This file contains no table or register write call.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import sys
import time

ALL_PIPES = 0xffff                       # t_config.ALL_PIPES: snapshot_counters.py sums outcome cells over it
OUTCOME_CELLS = 25                       # split raw-timer layout (snapshot_lifecycle.rejection_layout)
APPS = (('READ', 0), ('OPERATE', 1))     # tf1.pktgen.app_cfg app_id, pipe 1 (snapshot_lifecycle --read-app)
APP_COUNTERS = ('trigger_counter', 'batch_counter', 'pkt_counter')
# (sample key, register, field suffix): names as token_window.AUTHORITY and snapshot_lifecycle read them (index 0)
REGISTERS = (('n_epoch', 'p0.n_Ingress.epoch', '.f1'), ('n_owner', 'p0.n_Ingress.owner', '.f1'),
             ('n_work_generation', 'p0.n_Ingress.work.work', '.generation'),
             ('n_work_phase', 'p0.n_Ingress.work.work', '.phase'),
             ('t_cur_epoch', 'p1.t_Ingress.cur_epoch_reg', '.f1'),
             ('t_gen_alloc', 'p1.t_Ingress.gen_alloc_reg', '.f1'),
             ('t_op_gen_alloc', 'p1.t_Ingress.op_gen_alloc_reg', '.f1'))
MIN_SLEEP_S = 0.05                       # never two samples back to back, even when a sample overruns the period
SAMPLE_KEYS = ('seq', 't_start_ns', 't_end_ns', 'wall_time', 'outcomes', 'pktgen') + \
    tuple(key for key, _, _ in REGISTERS) + ('errors',)


def field(values, suffix):
    """One integer from a register entry: the single field ending in suffix, one lane (pipe-local read)."""
    keys = [key for key in values if key.endswith(suffix)]
    if len(keys) != 1:
        raise ValueError('no single field ending ' + suffix)
    value = values[keys[0]]
    lanes = value if isinstance(value, list) else [value]
    if len(lanes) != 1 or type(lanes[0]) is not int:
        raise ValueError('field %s is not one integer' % keys[0])
    return lanes[0]


def sample(sw, seq, clock=time.monotonic_ns, wall=time.time):
    """One sample. Every read is independent: a failure is recorded under errors and its value is None."""
    out = dict(seq=seq, t_start_ns=clock(), wall_time=wall(), outcomes=[], pktgen={}, errors={})
    for index in range(OUTCOME_CELLS):
        try:
            out['outcomes'].append(sum(sw.register('p1.t_Ingress.outcomes', ALL_PIPES, index)))
        except Exception as error:
            out['outcomes'].append(None)
            out['errors']['outcomes[%d]' % index] = str(error)[:300]
    for role, app_id in APPS:
        try:
            entry = sw.must_get('tf1.pktgen.app_cfg', 1, [('app_id', app_id, None)])
            out['pktgen'][role] = {name: entry.get(name) for name in APP_COUNTERS}
        except Exception as error:
            out['pktgen'][role] = {name: None for name in APP_COUNTERS}
            out['errors']['pktgen.' + role] = str(error)[:300]
    entries = {}
    for key, name, suffix in REGISTERS:
        try:
            if name not in entries:
                entries[name] = sw.must_get(name, 1 if name.startswith('p1.') else 0, [('$REGISTER_INDEX', 0, None)])
            out[key] = field(entries[name], suffix)
        except Exception as error:
            out[key] = None
            out['errors'][key] = str(error)[:300]
    out['t_end_ns'] = clock()
    return out


def summary(samples, failed, durations, stopped_by, period_s, started_wall, error=None):
    return dict(summary=True, samples=samples, samples_with_errors=failed, stopped_by=stopped_by, period_s=period_s,
                max_sample_ns=max(durations) if durations else None,
                mean_sample_ns=(sum(durations) // len(durations)) if durations else None,
                wall_start=started_wall, wall_end=time.time(), error=error)


def read_only_switch(switch_tools, program, client_id):
    """The snapshot_lifecycle.py client: no bind, no subscribe; write() refuses."""
    sys.path.insert(0, str(Path(switch_tools).resolve()))
    from switch import Switch, gc

    class ReadOnlySwitch(Switch):
        def __init__(self):
            self.iface = gc.ClientInterface('localhost:50052', client_id=client_id,
                                            device_id=0, perform_subscribe=False)
            self.bi = self.iface.bfrt_info_get(program)
            if self.bi is None:
                raise ValueError('requested program is not installed')
            self.sw_read = set()

        def close(self):
            self.iface.channel.close()

        def write(self, op):
            raise RuntimeError('diag_poll is read-only')

        def get(self, table, pipe, key, priority=None):
            entry = self.table(table)
            values = list(entry.entry_get(self.target(pipe), [self.key(entry, key, priority)],
                                          {'from_hw': True}, p4_name=program))
            if len(values) != 1:
                raise ValueError('expected exactly one hardware entry')
            return self.as_dict(values[0][0])
    return ReadOnlySwitch()


def poll(args, connect=read_only_switch, clock=time.monotonic_ns, sleep=time.sleep):
    if args.period_s <= 0 or args.max_duration_s <= 0:
        raise ValueError('period and maximum duration must be positive')
    stop = {'signal': False}
    signal.signal(signal.SIGTERM, lambda *_: stop.update(signal=True))
    output, stop_file = Path(args.output), Path(args.stop_file)
    Path(args.pid_file).write_text('%d\n' % os.getpid())
    started_wall, started = time.time(), clock()
    count = failed = 0
    durations = []
    with open(output, 'x') as handle:          # never appends to an earlier run
        def emit(record):
            handle.write(json.dumps(record, sort_keys=True) + '\n')
            handle.flush()
        try:
            sw = connect(args.switch_tools, args.program, args.client_id)
        except Exception as error:
            emit(summary(0, 0, [], 'bind_failed', args.period_s, started_wall, str(error)[:300]))
            return 1
        try:
            stopped_by = 'max_duration'
            while clock() - started < int(args.max_duration_s * 1e9):
                if stop['signal']:
                    stopped_by = 'sigterm'; break
                if stop_file.exists():
                    stopped_by = 'stop_file'; break
                record = sample(sw, count, clock)
                emit(record)
                count += 1
                failed += bool(record['errors'])
                durations.append(record['t_end_ns'] - record['t_start_ns'])
                elapsed = (clock() - record['t_start_ns']) / 1e9
                sleep(max(args.period_s - elapsed, MIN_SLEEP_S))
            emit(summary(count, failed, durations, stopped_by, args.period_s, started_wall))
        finally:
            sw.close()
    return 0


def _lines(path):
    try:
        return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    except (OSError, ValueError):
        return []


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _pid(path):
    try:
        return int(Path(path).read_text().strip())
    except (OSError, ValueError):
        return None


def sample_problems(record):
    """Why a sample is not a complete read: any recorded error, or any None among outcomes, pktgen, registers."""
    problems = ['errors: %s' % sorted(record.get('errors') or {})] if record.get('errors') else []
    outcomes = record.get('outcomes')
    if not isinstance(outcomes, list) or len(outcomes) != OUTCOME_CELLS or any(v is None for v in outcomes):
        problems.append('outcomes incomplete')
    pktgen = record.get('pktgen') or {}
    if any(pktgen.get(role, {}).get(name) is None for role, _ in APPS for name in APP_COUNTERS):
        problems.append('pktgen counters incomplete')
    missing = [key for key, _, _ in REGISTERS if record.get(key) is None]
    if missing:
        problems.append('registers missing: ' + ', '.join(missing))
    return problems


def wait_start(args, sleep=time.sleep):
    """rc 0 once the poller is alive and its first sample is complete (no error, no None value); otherwise rc 1
    and the poller is sent SIGTERM. The first sample's duration (t_end_ns - t_start_ns) is reported."""
    deadline = time.monotonic() + args.timeout_s
    reason, first = 'no first sample before the timeout', None
    while time.monotonic() < deadline:
        lines, pid = _lines(args.output), _pid(args.pid_file)
        if lines and 'seq' in lines[0]:
            first = lines[0]
            problems = sample_problems(first)
            if problems:
                reason = 'first sample incomplete: ' + '; '.join(problems)
                break
            if pid is not None and _alive(pid):
                print(json.dumps(dict(started=True, pid=pid, first_t_start_ns=first['t_start_ns'],
                                      first_sample_ns=first['t_end_ns'] - first['t_start_ns'])))
                return 0
        if lines and lines[-1].get('summary'):
            reason = 'poller ended: %s' % lines[-1].get('stopped_by')
            break
        sleep(0.05)
    pid = _pid(args.pid_file)
    if pid is not None and _alive(pid):
        os.kill(pid, signal.SIGTERM)
    duration = None
    if isinstance(first, dict) and type(first.get('t_end_ns')) is int and type(first.get('t_start_ns')) is int:
        duration = first['t_end_ns'] - first['t_start_ns']
    print(json.dumps(dict(started=False, pid=pid, reason=reason, first_sample_ns=duration,
                          last=(_lines(args.output) or [None])[-1])))
    return 1


def stop_poller(args, sleep=time.sleep):
    """Stop file; after --timeout-s SIGTERM; after a further --timeout-s SIGKILL. Reports which one ended the
    poller (stop_file / sigterm / sigkill / not_running / still_running). rc 0 only if the poller exited and its
    last line is the summary (a SIGKILLed poller has none)."""
    Path(args.stop_file).touch()
    pid = _pid(args.pid_file)
    escalation = ['stop_file', signal.SIGTERM, signal.SIGKILL]
    step, ended_by = 0, 'not_running' if pid is None or not _alive(pid) else None
    deadline = time.monotonic() + args.timeout_s
    while ended_by is None:
        if not _alive(pid):
            ended_by = ('stop_file', 'sigterm', 'sigkill')[step]
            break
        if time.monotonic() >= deadline:
            step += 1
            if step == len(escalation):
                ended_by = 'still_running'
                break
            try:
                os.kill(pid, escalation[step])
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + args.timeout_s
        sleep(0.05)
    lines = _lines(args.output)
    last = lines[-1] if lines else None
    exited = pid is not None and not _alive(pid)
    ok = exited and isinstance(last, dict) and last.get('summary') is True and last.get('stopped_by') != 'bind_failed'
    print(json.dumps(dict(stopped=ok, pid=pid, exited=exited, ended_by=ended_by,
                          samples=sum(1 for line in lines if 'seq' in line), summary=last if ok else None)))
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest='mode', required=True)
    p = sub.add_parser('poll')
    p.add_argument('--build-out', required=True, type=Path)
    p.add_argument('--switch-tools', required=True, type=Path)
    p.add_argument('--program', default='response_only')
    p.add_argument('--client-id', type=int, default=218)
    p.add_argument('--period-s', type=float, default=0.1)
    p.add_argument('--max-duration-s', type=float, default=600.0)
    for mode in ('poll', 'wait-start', 'stop'):
        target = p if mode == 'poll' else sub.add_parser(mode)
        target.add_argument('--output', required=True)
        target.add_argument('--stop-file', required=True)
        target.add_argument('--pid-file', required=True)
        if mode != 'poll':
            target.add_argument('--timeout-s', type=float, default=10.0)
    args = ap.parse_args(argv)
    if args.mode == 'poll':
        schema = args.build_out / 'bfrt.json'
        sizes = {t['name']: t.get('size') for t in json.loads(schema.read_text())['tables']}
        if sizes.get('p1.t_Ingress.outcomes') != OUTCOME_CELLS:
            print('REFUSED: p1.t_Ingress.outcomes is not %d cells in %s' % (OUTCOME_CELLS, schema))
            return 2
        return poll(args)
    return wait_start(args) if args.mode == 'wait-start' else stop_poller(args)


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Fixed three-incarnation isolation sequence on an already installed tuple.

Default prints an offline plan. The hardware owner installs/restores the switch
and observes c2/pre_read_ready.json during its pre-READ pause (10 s by default; the
switch-side harness derives it from the old-token cleanup bound and passes --pre-read-grace-ms):
  sudo env DEFENSE4_HW_AUTHORIZED=1 python3 vision_isolation.py LABEL \
    --master-port PORT --padding 1 --apply

Deploy beside vision_candidate.py and its pinned endpoint helpers. Each leg
issues one READ plus SBO, and the existing observer uses the actual kernel's
ss -K after the OPERATE response. The application, capture, controls and RST
proof gates must pass before the next leg starts. No setup or switch calls are
made here. Runtime requires the isolated pre-READ endpoint binary for c2.

--endpoint isolation_20s (opt-in, the 20 s endpoint_isolation_20s binary only): c2 may pause up to 20000 ms and
its master also gets CASE4_PRE_READ_PERMIT/CASE4_PRE_READ_RUN, so it issues its first READ only after the
switch-side harness grants an endpoint-local permit through the grant-permit subcommand:
  sudo env DEFENSE4_HW_AUTHORIZED=1 python3 vision_isolation.py grant-permit LABEL \
    --ready-ns N --opens 1 --deadline-ns D
grant-permit writes runs/LABEL/c2/pre_read_permit.json atomically only if c2's marker binds to N/opens and
Vision's monotonic clock is still before D (c2's scheduled first READ). The default (barrier_10s) is unchanged.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import vision_candidate as vc
from token_window import PRE_READ_GRACE_MS, ENDPOINT_CAPABILITIES, PERMIT_GRACE_MS

PERMIT_KEYS = ('CASE4_PRE_READ_PERMIT', 'CASE4_PRE_READ_RUN')
# vision_run.run_connection's master timeout for one READ + SBO with read pause 25 ms and close grace 1000 ms:
# reads*4 + 30 + ceil((25 + 1000) / 1000) s. The master's worst case: connect 5 s, pause, permit poll window,
# READ 3 s + 25 ms pause, SBO 3 s, close grace 1 s.
MASTER_BUDGET_S = 1 * 4 + 30 + 2
MASTER_FIXED_WORST_S = 5 + 3 + 0.025 + 3 + 1


def master_budget(pause_ms, permit):
    worst = MASTER_FIXED_WORST_S + pause_ms / 1000.0 + (PERMIT_GRACE_MS / 1000.0 if permit else 0.0)
    return dict(worst_s=worst, budget_s=MASTER_BUDGET_S, ok=worst < MASTER_BUDGET_S)


@contextmanager
def permit_controls(dest, run_label, enabled):
    """Set the permit controls for one master only when enabled; always restore the caller's environment."""
    prior = {key: os.environ.get(key) for key in PERMIT_KEYS}
    for key in PERMIT_KEYS:
        os.environ.pop(key, None)
    if enabled:
        os.environ[PERMIT_KEYS[0]] = str(Path(dest) / 'pre_read_permit.json')
        os.environ[PERMIT_KEYS[1]] = run_label
    try:
        yield
    finally:
        for key, value in prior.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def permit_evidence(dest, run_label, grace):
    """c2's final master JSON must show the permit it accepted, bound to this run and readiness instance."""
    failures = []
    try:
        master = json.loads((Path(dest) / 'master.json').read_text())
        permit = json.loads((Path(dest) / 'pre_read_permit.json').read_text())
    except (OSError, ValueError):
        return ['missing or malformed permit evidence (master.json / pre_read_permit.json)']
    accepted = master.get('pre_read_permit') if isinstance(master, dict) else None
    ready, issued = master.get('pre_read_ready_ns'), master.get('first_read_issued_ns')
    if not isinstance(accepted, dict) or accepted.get('run') != run_label or not isinstance(permit, dict):
        return ['c2 master did not report the accepted permit for ' + run_label]
    granted = accepted.get('granted_ns')
    if any(type(value) is not int for value in (ready, issued, granted, accepted.get('accepted_ns'))) or \
            permit.get('granted_ns') != granted or permit.get('ready_ns') != ready or permit.get('run') != run_label \
            or permit.get('grant') is not True or not ready < granted <= accepted['accepted_ns'] <= issued:
        failures.append('permit evidence does not bind c2 readiness, grant and first READ in order')
    elif granted >= ready + grace * 1_000_000:
        failures.append('permit granted after c2 scheduled first READ')
    return failures


def grant_permit(label, ready_ns, opens, deadline_ns, runs=None, clock=None):
    """Write c2's permit atomically, once, only if its marker binds to ready_ns/opens and Vision's monotonic
    clock is before deadline_ns (the harness passes c2's scheduled first READ, ready + pause)."""
    import time
    clock = clock or time.monotonic_ns
    if not re.fullmatch('[A-Za-z0-9_]+', label):
        raise ValueError('invalid label')
    if any(type(value) is not int or value <= 0 for value in (ready_ns, opens, deadline_ns)) or deadline_ns <= ready_ns:
        raise ValueError('ready_ns, opens and deadline_ns must be positive integers, deadline after readiness')
    c2 = Path(runs or vc.vr.RUNS) / label / 'c2'
    target = c2 / 'pre_read_permit.json'
    report = dict(path=str(target), written=False, ready_ns=ready_ns, opens=opens, deadline_ns=deadline_ns)
    try:
        marker = json.loads((c2 / 'pre_read_ready.json').read_text())
    except (OSError, ValueError):
        return dict(report, reason='c2 marker missing or incomplete')
    if not isinstance(marker, dict) or marker.get('pre_read_ready_ns') != ready_ns or marker.get('opens') != opens \
            or marker.get('first_read_issued_ns') != 0 or marker.get('tcp_open') is not True:
        return dict(report, reason='c2 marker does not bind this readiness instance')
    if os.path.lexists(target):
        return dict(report, reason='permit already exists')
    granted = clock()
    report['granted_ns'] = granted
    if not ready_ns < granted < deadline_ns:
        return dict(report, reason='late or stale: Vision clock %d not inside (ready %d, deadline %d)'
                    % (granted, ready_ns, deadline_ns))
    body = json.dumps(dict(run=label + '_c2', ready_ns=ready_ns, opens=opens, grant=True, granted_ns=granted))
    tmp = c2 / ('.pre_read_permit.%d.tmp' % os.getpid())
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        written = clock()
        if written >= deadline_ns:
            os.unlink(str(tmp))
            return dict(report, reason='late: write finished at %d, deadline %d' % (written, deadline_ns))
        os.link(str(tmp), str(target))       # fails if a permit appeared meanwhile: never overwrite
    finally:
        if os.path.lexists(str(tmp)):
            os.unlink(str(tmp))
    return dict(report, written=True, written_ns=written, reason='granted')


def grant_main(argv):
    parser = argparse.ArgumentParser(prog='vision_isolation.py grant-permit')
    parser.add_argument('label')
    parser.add_argument('--ready-ns', type=int, required=True)
    parser.add_argument('--opens', type=int, required=True)
    parser.add_argument('--deadline-ns', type=int, required=True)
    args = parser.parse_args(argv)
    if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
        raise ValueError('grant-permit requires DEFENSE4_HW_AUTHORIZED=1')
    report = grant_permit(args.label, args.ready_ns, args.opens, args.deadline_ns)
    print(json.dumps(report))
    return 0 if report['written'] else 1


def abort_c2(label, runs=None, proc='/proc', settle_s=1.0):
    """Fail-safe run as root through the permitted sudo Python entry point: SIGKILL every process whose argv
    contains the exact c2 master stop path, then rescan until none remains or settle_s passes. Matching a
    whole argv element (never a regex over this process's own command line) cannot select this process."""
    import os
    import signal
    import time
    if not re.fullmatch('[A-Za-z0-9_]+', label):
        raise ValueError('invalid label')
    target = str(Path(runs or vc.vr.RUNS) / label / 'c2' / 'stop.master').encode()

    def scan():
        found = []
        for entry in Path(proc).iterdir():
            if not entry.name.isdigit() or int(entry.name) == os.getpid():
                continue
            try:
                argv = (entry / 'cmdline').read_bytes().split(b'\0')
            except OSError:
                continue
            if target in argv:
                found.append(int(entry.name))
        return sorted(found)
    matched, killed, errors = scan(), [], []
    for pid in matched:
        try:
            os.kill(pid, signal.SIGKILL)
            killed.append(pid)
        except ProcessLookupError:
            pass
        except OSError as error:
            errors.append('%d: %s' % (pid, error))
    remaining = scan()
    end = time.monotonic() + settle_s
    while remaining and time.monotonic() < end:
        time.sleep(0.05)
        remaining = scan()
    return dict(target=target.decode(), matched=matched, killed=killed, remaining=remaining, errors=errors,
                c2_already_exited=not matched)


def abort_exit_code(result):
    """0 killed and none remains, 1 no c2 master matched (already exited), 3 one remains or a kill failed."""
    if result['remaining'] or result['errors']:
        return 3
    return 1 if result['c2_already_exited'] else 0


def abort_main(argv):
    result = abort_c2(argv[0])
    print(json.dumps(result))
    return abort_exit_code(result)


def source_paths():
    """Every Vision-side file this scenario runs; candidate_isolation.verdict pins exactly these names."""
    return (Path(__file__), Path(vc.__file__), Path(vc.vr.__file__), Path(vc.wc.__file__), Path(vc.clrt.__file__),
            Path(vc.checks.__file__), Path(vc.vr.capture_observation.__file__),
            HERE / 'token_window.py', HERE / 'snapshot_lifecycle.py',
            Path(vc.clrt.__file__).with_name('read_classes.py'))      # deployed beside clrt_check (per-class READ policy)


def scenario(label, port, padding, apply=False, control_padding=1, image_len=58, qualify_capture=False,
             pre_read_grace_ms=PRE_READ_GRACE_MS, endpoint='barrier_10s'):
    vc.guard(port, apply)
    if endpoint not in ENDPOINT_CAPABILITIES:
        raise ValueError('unknown isolation endpoint capability')
    capability = ENDPOINT_CAPABILITIES[endpoint]
    if type(pre_read_grace_ms) is not int or not 1 <= pre_read_grace_ms <= capability['max_pause_ms']:
        raise ValueError('c2 pre-READ pause must be an integer in 1..%d ms' % capability['max_pause_ms'])
    budget = master_budget(pre_read_grace_ms, capability['permit'])
    if not budget['ok']:
        raise ValueError('c2 worst case %.3f s exceeds the master timeout %d s' % (budget['worst_s'], budget['budget_s']))
    graces = (0, pre_read_grace_ms, 0)
    if not re.fullmatch('[A-Za-z0-9_]+', label) or type(padding) is not int or padding not in (0, 1):
        raise ValueError('invalid label or padding')
    if type(qualify_capture) is not bool:
        raise ValueError('qualify_capture must be a boolean')
    parent = Path(vc.vr.RUNS) / label
    plan = [dict(name='c%d' % index, master_port=port, reads=1, start_seed=12344 + index,
                 pre_read_grace_ms=grace,
                 marker_path=str(parent / ('c%d' % index) / 'pre_read_ready.json') if grace else None)
            for index, grace in enumerate(graces, 1)]
    if capability['permit']:                 # only c2, only on the opt-in isolation endpoint
        plan[1].update(permit_path=str(parent / 'c2' / 'pre_read_permit.json'), permit_run=label + '_c2')
    record = dict(scenario='candidate_same_tuple_isolation', label=label, master_port=port,
                  tuple=[vc.MASTER, port, vc.OUTSTATION, vc.SERVER_PORT],
                  namespaces=[vc.NAMESPACE_M, vc.NAMESPACE_O], nic=vc.NIC,
                  padding=padding, reads=1, read_pause_ms=25, close_mode='rst', close_grace_ms=1000,
                  qualify_capture=qualify_capture,
                  switch_mutations=False, applied=apply, plan=plan, connections=[], ok=False)
    if endpoint != 'barrier_10s':            # retained barrier_10s records keep their exact shape
        record.update(endpoint=endpoint, endpoint_capability=dict(capability), master_budget=budget)
    if not apply:
        record['ok'] = True
        return record
    parent.mkdir(parents=True)  # retained evidence must never be reused
    try:
        record['preflight'] = vc.preflight('rst')
        for leg in plan:
            dest = parent / leg['name']
            done, observer = threading.Event(), {}
            connection = dict(leg, ok=False, failures=[])
            record['connections'].append(connection)

            def watch():
                try:
                    observer.update(vc.observe(dest, port, done))
                except Exception as error:
                    observer.update(ok=False, error=str(error))

            worker = threading.Thread(target=watch, daemon=True)
            worker.start()
            try:
                with vc.pre_read_controls(dest, leg['pre_read_grace_ms']), \
                        permit_controls(dest, leg.get('permit_run', ''), 'permit_run' in leg):
                    kwargs = dict(read_pause_ms=25, run_sbo=True, close_grace_ms=1000, capture_immediate=True)
                    if qualify_capture:
                        kwargs['qualify_capture'] = True
                    result = vc.vr.run_connection(str(dest), label + '_' + dest.name, port, 1, 8, 0, 0,
                                                  leg['start_seed'], **kwargs)
                connection['result'] = result
            except Exception as error:
                result = {}
                connection['failures'].append(str(error))
            finally:
                done.set()
                dest.mkdir(exist_ok=True)
                worker.join(timeout=5)
                if worker.is_alive():
                    connection['failures'].append('observer did not stop within 5 seconds')
                connection['observer'] = dict(observer)
                vc.write_json(dest / 'observer.json', observer)
                if observer.get('ok') is not True:
                    connection['failures'].append('kernel RST observer failed')
            connection['failures'] += vc.evaluate(dest, port, 'rst', padding, result,
                                                  rst_grace_ms=1000, reads=1,
                                                  pre_read_grace_ms=leg['pre_read_grace_ms'],
                                                  control_padding=control_padding, image_len=image_len)
            if 'permit_run' in leg:
                connection['failures'] += permit_evidence(dest, leg['permit_run'], leg['pre_read_grace_ms'])
            connection['pre_read_hook'] = vc.pre_read_evidence(dest, leg['pre_read_grace_ms'])[1]
            connection['ok'] = not connection['failures']
            vc.write_json(dest / 'verdict.json', connection)
            if not connection['ok']:
                break
        record['ok'] = len(record['connections']) == 3 and all(c['ok'] for c in record['connections'])
    except Exception as error:
        record['error'] = str(error)
    finally:
        record['source_sha256'] = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in source_paths()}
        record['hashes'] = {str(path.relative_to(parent)): hashlib.sha256(path.read_bytes()).hexdigest()
                            for path in parent.rglob('*') if path.is_file()}
        vc.write_json(parent / 'scenario.json', record)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('label')
    parser.add_argument('--master-port', type=int, required=True)
    parser.add_argument('--padding', type=int, choices=(0, 1), default=1)
    parser.add_argument('--image-len', type=int, default=58)
    parser.add_argument('--control-padding', type=int, choices=(0, 1), default=1,
                        help='0 for strict-response builds: SELECT/OPERATE responses stay native (37 B)')
    parser.add_argument('--qualify-capture', action='store_true',
                        help='opt-in physical packet-boundary qualification evidence for each leg')
    parser.add_argument('--pre-read-grace-ms', type=int, default=PRE_READ_GRACE_MS,
                        help='c2 pre-READ pause, derived by the switch-side harness from the cleanup bound')
    parser.add_argument('--endpoint', choices=sorted(ENDPOINT_CAPABILITIES), default='barrier_10s',
                        help='isolation_20s: opt-in 20 s endpoint whose c2 READ waits for grant-permit')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    result = scenario(args.label, args.master_port, args.padding, args.apply, control_padding=args.control_padding,
                      image_len=args.image_len, qualify_capture=args.qualify_capture,
                      pre_read_grace_ms=args.pre_read_grace_ms, endpoint=args.endpoint)
    print(json.dumps(result, indent=2))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    try:
        if sys.argv[1:2] == ['abort-c2']:
            sys.exit(abort_main(sys.argv[2:]))
        if sys.argv[1:2] == ['grant-permit']:
            sys.exit(grant_main(sys.argv[2:]))
        sys.exit(main())
    except (ValueError, OSError) as error:
        sys.stderr.write('Vision isolation refused: %s\n' % error)
        sys.exit(2)

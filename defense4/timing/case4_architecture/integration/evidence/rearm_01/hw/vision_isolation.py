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
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import threading

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import vision_candidate as vc
from token_window import PRE_READ_GRACE_MS


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
            HERE / 'token_window.py', HERE / 'snapshot_lifecycle.py')


def scenario(label, port, padding, apply=False, control_padding=1, image_len=58, qualify_capture=False,
             pre_read_grace_ms=PRE_READ_GRACE_MS):
    vc.guard(port, apply)
    if type(pre_read_grace_ms) is not int or not 1 <= pre_read_grace_ms <= PRE_READ_GRACE_MS:
        raise ValueError('c2 pre-READ pause must be an integer in 1..%d ms' % PRE_READ_GRACE_MS)
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
    record = dict(scenario='candidate_same_tuple_isolation', label=label, master_port=port,
                  tuple=[vc.MASTER, port, vc.OUTSTATION, vc.SERVER_PORT],
                  namespaces=[vc.NAMESPACE_M, vc.NAMESPACE_O], nic=vc.NIC,
                  padding=padding, reads=1, read_pause_ms=25, close_mode='rst', close_grace_ms=1000,
                  qualify_capture=qualify_capture,
                  switch_mutations=False, applied=apply, plan=plan, connections=[], ok=False)
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
                with vc.pre_read_controls(dest, leg['pre_read_grace_ms']):
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
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    result = scenario(args.label, args.master_port, args.padding, args.apply, control_padding=args.control_padding,
                      image_len=args.image_len, qualify_capture=args.qualify_capture,
                      pre_read_grace_ms=args.pre_read_grace_ms)
    print(json.dumps(result, indent=2))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    try:
        if sys.argv[1:2] == ['abort-c2']:
            sys.exit(abort_main(sys.argv[2:]))
        sys.exit(main())
    except (ValueError, OSError) as error:
        sys.stderr.write('Vision isolation refused: %s\n' % error)
        sys.exit(2)

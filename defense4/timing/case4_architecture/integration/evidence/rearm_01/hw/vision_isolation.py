#!/usr/bin/env python3
"""Fixed three-incarnation isolation sequence on an already installed tuple.

Default prints an offline plan. The hardware owner installs/restores the switch
and observes c2/pre_read_ready.json during its ten-second pre-READ pause:
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

GRACES = (0, PRE_READ_GRACE_MS, 0)


def scenario(label, port, padding, apply=False, control_padding=1):
    vc.guard(port, apply)
    if not re.fullmatch('[A-Za-z0-9_]+', label) or type(padding) is not int or padding not in (0, 1):
        raise ValueError('invalid label or padding')
    parent = Path(vc.vr.RUNS) / label
    plan = [dict(name='c%d' % index, master_port=port, reads=1, start_seed=12344 + index,
                 pre_read_grace_ms=grace,
                 marker_path=str(parent / ('c%d' % index) / 'pre_read_ready.json') if grace else None)
            for index, grace in enumerate(GRACES, 1)]
    record = dict(scenario='candidate_same_tuple_isolation', label=label, master_port=port,
                  tuple=[vc.MASTER, port, vc.OUTSTATION, vc.SERVER_PORT],
                  namespaces=[vc.NAMESPACE_M, vc.NAMESPACE_O], nic=vc.NIC,
                  padding=padding, reads=1, read_pause_ms=25, close_mode='rst', close_grace_ms=1000,
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
                    result = vc.vr.run_connection(str(dest), label + '_' + dest.name, port, 1, 8, 0, 0,
                                                  leg['start_seed'], read_pause_ms=25,
                                                  run_sbo=True, close_grace_ms=1000, capture_immediate=True)
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
                                                  control_padding=control_padding)
            connection['pre_read_hook'] = vc.pre_read_evidence(dest, leg['pre_read_grace_ms'])[1]
            connection['ok'] = not connection['failures']
            vc.write_json(dest / 'verdict.json', connection)
            if not connection['ok']:
                break
        record['ok'] = len(record['connections']) == 3 and all(c['ok'] for c in record['connections'])
    except Exception as error:
        record['error'] = str(error)
    finally:
        record['source_sha256'] = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in
                                  (Path(__file__), Path(vc.__file__), Path(vc.vr.__file__),
                                   Path(vc.wc.__file__), Path(vc.clrt.__file__), Path(vc.checks.__file__),
                                   HERE / 'token_window.py', HERE / 'snapshot_lifecycle.py')}
        record['hashes'] = {str(path.relative_to(parent)): hashlib.sha256(path.read_bytes()).hexdigest()
                            for path in parent.rglob('*') if path.is_file()}
        vc.write_json(parent / 'scenario.json', record)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('label')
    parser.add_argument('--master-port', type=int, required=True)
    parser.add_argument('--padding', type=int, choices=(0, 1), default=1)
    parser.add_argument('--control-padding', type=int, choices=(0, 1), default=1,
                        help='0 for strict-response builds: SELECT/OPERATE responses stay native (37 B)')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    result = scenario(args.label, args.master_port, args.padding, args.apply, control_padding=args.control_padding)
    print(json.dumps(result, indent=2))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError) as error:
        sys.stderr.write('Vision isolation refused: %s\n' % error)
        sys.exit(2)

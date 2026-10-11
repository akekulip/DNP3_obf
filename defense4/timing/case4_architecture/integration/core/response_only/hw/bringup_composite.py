#!/usr/bin/env python3
"""Install the control-plane state of the composed response-only program (N + E in pipe 0, T in pipe 1) on the
physical switch. Dry-run by default: checks the build's sha256s, prints every write, and validates every name
against the compiled bfrt.json and the SDE shared schemas, with no gRPC. --apply (needs
DEFENSE4_HW_AUTHORIZED=1) writes in order: queues, packet generator (apps disabled), mirror, T params, E rows,
N rows, N connection rows last. It reads every write back and stops at the first failure with a manifest of
what was installed.

  python3 bringup_composite.py --build-out <out/> --expect bfrt.json=<sha> --expect p0/tofino.bin=<sha> \
      --expect p1/tofino.bin=<sha> --master-port 54321                       # dry-run
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check_names  # noqa: E402
import readback  # noqa: E402
import rows  # noqa: E402
import t_config as tc  # noqa: E402


def oneline(e):
    return ' | '.join(l.strip() for l in str(e).splitlines() if l.strip())[:400]

REQUIRED_EXPECT = ('bfrt.json', 'p0/tofino.bin', 'p1/tofino.bin')


def parse(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--build-out', required=True, help='the compiled out/ directory the daemon loads')
    ap.add_argument('--expect', action='append', default=[], metavar='REL=SHA256',
                    help='expected sha256 of a file under --build-out; bfrt.json, p0/tofino.bin, p1/tofino.bin required')
    ap.add_argument('--master-ip')   # defaults filled in parse(): the rig's .1 / .7, only when the dev ports differ
    ap.add_argument('--master-port', type=int, required=True, help='the master must bind this fixed TCP source port')
    ap.add_argument('--master-dev', type=int, default=9)
    ap.add_argument('--relay-ip')
    ap.add_argument('--relay-port', type=int, default=20000)
    ap.add_argument('--relay-dev', type=int, default=64)
    for k, v in rows.VECTOR_DECOY.items():
        ap.add_argument('--crob-' + k, type=int, default=v, help='data_connection decoy-object %s, wire byte order (default: vectors.DECOY, index 201)' % k)
    ap.add_argument('--read-dst', type=lambda s: int(s, 0), default=0x0000)
    ap.add_argument('--read-src', type=lambda s: int(s, 0), default=0x0100)
    for k, v in tc.T_PARAM_DEFAULTS.items():
        ap.add_argument('--t-' + k.replace('_', '-'), dest='t_' + k, type=int, default=v)
    ap.add_argument('--k', type=int, default=2, help='2*k generator tokens per trigger (queue_sim default k=2)')
    ap.add_argument('--enable-pktgen', action='store_true', help='enable the two apps last, after clean readback')
    ap.add_argument('--fixed-schema-dir', default=os.environ.get('SDE_INSTALL', '/home/decps/Downloads/bf-sde-9.13.2/install')
                    + '/share/bf_rt_shared')
    ap.add_argument('--program', default='response_only')
    ap.add_argument('--client-id', type=int, default=120)
    ap.add_argument('--manifest-out', default='bringup_manifest.json')
    ap.add_argument('--apply', action='store_true')
    a = ap.parse_args(argv)
    if a.master_dev == a.relay_dev and not (a.master_ip and a.relay_ip):
        ap.error('endpoints sharing dev_port %d are told apart by address: give --master-ip and --relay-ip' % a.master_dev)
    a.master_ip, a.relay_ip = a.master_ip or '192.168.10.1', a.relay_ip or '192.168.10.7'
    return a


def identity(a):
    """Errors if any expected sha256 is missing or differs from the file under --build-out."""
    want = dict(e.split('=', 1) for e in a.expect)
    errs = ['--expect %s=<sha256> is required' % r for r in REQUIRED_EXPECT if r not in want]
    for rel, sha in sorted(want.items()):
        path = Path(a.build_out) / rel
        got = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else 'missing'
        print('    %s %s  %s' % ('OK      ' if got == sha else 'MISMATCH', got, rel))
        if got != sha:
            errs.append('%s: sha256 %s, expected %s' % (rel, got, sha))
    return errs


def source_ports(a):
    """Errors unless the ports COMPILED into the build (out/response_only.p4pp, written by bf-p4c next to
    bfrt.json) are the ones this plan uses. T's forward and relay ports are constants, not table entries: a
    build composed for another port pair would release to the wrong port and bfrt.json cannot show it."""
    path = Path(a.build_out) / 'response_only.p4pp'
    if not path.is_file():
        return ['%s is missing: cannot check the ports compiled into this build' % path]
    text = path.read_text(errors='replace')
    want = dict(t_FORWARD_PORT=a.master_dev, t_RELAY_PORT=a.relay_dev, t_PKTGEN_RETURN=tc.PKTGEN_RETURN,
                t_HB_RETURN=tc.HB_RETURN, t_HELD_RETURN=tc.HELD_RETURN, n_N_ACK_RETURN=rows.cp.N_ACK_RETURN,
                n_RETURN_PORT=rows.cp.RETURN_PORT)
    errs = []
    for name, value in sorted(want.items()):
        found = re.findall(r'const PortId_t %s\s*=\s*9w(\d+)' % name, text)
        if found != [str(value)]:
            errs.append('build has %s = %s, this plan needs %d' % (name, found or 'no such constant', value))
    sid = re.findall(r'const MirrorId_t t_CLONE_SESSION_ID\s*=\s*10w(\d+)', text)
    if sid != [str(tc.CLONE_SESSION_ID)]:
        errs.append('build has t_CLONE_SESSION_ID = %s, this plan writes session %d' % (sid, tc.CLONE_SESSION_ID))
    print('COMPILED PORTS (%s): %s' % (path.name, 'match the plan' if not errs else 'MISMATCH'))
    return errs


def params(a):
    return {k: getattr(a, 't_' + k) for k in tc.T_PARAM_DEFAULTS}


def plan(a):
    """Write order: T-side state first, E next, N last with its connection rows at the very end, so no master
    packet is bound by N before everything it hands to T and E is in place."""
    master, relay = rows.endpoints(a.master_ip, a.master_port, a.master_dev, a.relay_ip, a.relay_port, a.relay_dev)
    decoy = {k: getattr(a, 'crob_' + k) for k in rows.VECTOR_DECOY}
    ne = rows.build(master, relay, decoy, a.read_dst, a.read_src)
    e_rows = [r for r in ne if r['table'].startswith('p0.r_')]
    n_conn = [r for r in ne if r['table'] == 'p0.n_Ingress.connection']
    n_rest = [r for r in ne if r['table'].startswith('p0.n_') and r not in n_conn]
    return (tc.queue_ops() + tc.pktgen_ops(a.k) + [tc.mirror_op(), tc.params_op(params(a))]
            + e_rows + n_rest + n_conn)


def show(op):
    key = op.get('key') or ([('dev_port', op['dev_port'], None), ('qid', op['qid'], None)] if 'qid' in op else [])
    key = ', '.join('%s=%s' % (n, hex(v) if isinstance(v, int) and v > 0xffff else v) + ('&&&%s' % hex(m) if m is not None else '')
                    for n, v, m in key)
    data = ', '.join('%s=%s' % (n, '<%d zero bytes>' % len(v) if isinstance(v, bytes) else v) for n, v in op['data'])
    prio = '' if op.get('priority') is None else ' prio=%d' % op['priority']
    return '%-13s pipe=%-6s %-30s [%s]%s -> %s(%s)' % (op['kind'], hex(op['pipe']), op['table'], key, prio,
                                                        op.get('action') or 'mod', data)


def offline(ops, a):
    tables = check_names.load(Path(a.build_out) / 'bfrt.json', a.fixed_schema_dir)
    errs = check_names.check(ops + tc.enable_ops(), tables)
    errs += check_names.check_registers(['p1.t_Ingress.' + r for r in readback.T_REGISTER_INIT], tables)
    errs += check_names.check_reads(tables)
    return errs


def encode(value):
    if isinstance(value, (bytes, bytearray)):
        return {'hex': bytes(value).hex()}
    return str(value)


def running_conf():
    """--conf-file of the one running bf_switchd, from ps; raises unless exactly one is running."""
    out = subprocess.run(['ps', '-eo', 'args'], stdout=subprocess.PIPE, universal_newlines=True, check=True).stdout
    confs = []
    for line in out.splitlines():
        words = line.split()
        if not words or os.path.basename(words[0]) != 'bf_switchd':
            continue
        for i, w in enumerate(words):
            if w == '--conf-file' and i + 1 < len(words):
                confs.append(words[i + 1])
            elif w.startswith('--conf-file='):
                confs.append(w.split('=', 1)[1])
    if len(confs) != 1:
        raise RuntimeError('expected exactly one running bf_switchd with --conf-file, found %d' % len(confs))
    return confs[0]


def daemon_identity(a):
    """Errors unless the running daemon loaded exactly the files under --build-out as program --program."""
    try:
        conf_path = running_conf()
        prog = json.loads(Path(conf_path).read_text())['p4_devices'][0]['p4_programs'][0]
    except Exception as e:
        return ['running daemon: %s' % e]
    out = Path(a.build_out).resolve()
    want = {'bfrt-config': out / 'bfrt.json'}
    got = {'bfrt-config': prog.get('bfrt-config')}
    for p in prog.get('p4_pipelines', []):
        n = p.get('p4_pipeline_name')
        want.update({n + ' context': out / n / 'context.json', n + ' config': out / n / 'tofino.bin'})
        got.update({n + ' context': p.get('context'), n + ' config': p.get('config')})
    errs = ['daemon conf %s: %s is %s, --build-out has %s' % (conf_path, k, got[k], want[k])
            for k in sorted(want) if got[k] is None or Path(got[k]).resolve() != want[k]]
    if sorted(p.get('p4_pipeline_name') for p in prog.get('p4_pipelines', [])) != ['p0', 'p1']:
        errs.append('daemon conf %s: pipelines are not p0 and p1' % conf_path)
    if prog.get('program-name') != a.program:
        errs.append('daemon conf %s: program %s, expected %s' % (conf_path, prog.get('program-name'), a.program))
    print('RUNNING DAEMON: conf %s -> %s' % (conf_path, 'matches --build-out' if not errs else 'MISMATCH'))
    return errs


def apply(ops, a):
    from switch import Switch
    sw = Switch(a.program, a.client_id)
    done, manifest = [], Path(a.manifest_out)

    def record():
        manifest.write_text(json.dumps(dict(program=a.program, time=time.time(), installed=done), indent=1,
                                       default=encode) + '\n')

    def stop(what):
        if done:                    # nothing written -> no manifest: an empty one would hide an earlier install
            record()
        print('FAIL-CLOSED: %s' % what)
        if done:
            print('%d writes installed before the stop; manifest %s; remove them with bringup_teardown.py '
                  '--manifest %s --apply' % (len(done), manifest, manifest))
        else:
            print('nothing was written; no manifest was created')
        sw.close()
        sys.exit(2)

    def step(op, verify_op=None):
        try:
            if op['kind'] == 'queue':
                pg_id, pgq, _cfg = sw.resolve_queue(op['dev_port'], op['qid'], op['pipe'])
                op['key'] = [('pg_id', pg_id, None), ('pg_queue', pgq, None)]
            undo = sw.write(op)
        except Exception as e:
            stop('write failed: %s: %s' % (show(op), oneline(e)))
        done.append(dict(op, **undo))
        record()
        bad = readback.verify(sw, verify_op or op)
        if bad:
            stop('readback mismatch after %s: %s' % (show(op), bad))
        print('OK  ', show(op))

    try:
        try:
            for table in sorted({op['table'] for op in ops if op['kind'] == 'p4'}):
                if sw.count(table, 0xffff) != 0:
                    stop('%s is not empty before bring-up' % table)
            if sw.get('$mirror.cfg', 0xffff, [('$sid', tc.CLONE_SESSION_ID, None)]) is not None:
                stop('mirror session %d already exists' % tc.CLONE_SESSION_ID)
            bad = readback.register_errors(readback.registers(sw))
        except Exception as e:
            stop('pre-check failed: %s' % e)
        if bad:
            stop('T registers not at their reset values: %s' % bad)
        for op in ops:
            step(op)
        if a.enable_pktgen:
            apps = {o['label']: o for o in ops if o['kind'] == 'pktgen_app'}
            for op in tc.enable_ops():
                step(op, readback.enabled_app_op(apps[op['label']]))   # re-verify the whole app, not just the flag
        try:
            bad = readback.register_errors(readback.registers(sw))
        except Exception as e:
            bad = [str(e)]
        if bad:
            stop('T registers moved during bring-up (was the master quiet?): %s' % bad)
        print('INSTALLED %d writes; manifest %s; pktgen %s' % (len(done), manifest,
                                                                 'ENABLED' if a.enable_pktgen else 'written DISABLED'))
        print('counters', json.dumps(readback.snapshot(sw), indent=1))
    finally:
        sw.close()


def main(argv=None):
    a = parse(argv)
    print('BUILD IDENTITY (%s):' % a.build_out)
    errs = identity(a)
    errs += source_ports(a)
    errs += tc.check_params(params(a))
    ops = plan(a)
    print('PLAN: %d writes (+%d pktgen enables, last, only with --enable-pktgen)' % (len(ops), len(tc.PKTGEN_APPS)))
    for op in ops:
        print('    ', show(op))
    names = offline(ops, a)
    print('NAME CHECK against %s/bfrt.json and %s (shared schemas; the switch runs SDE 9.13.2):'
          % (a.build_out, a.fixed_schema_dir))
    print('    ' + ('\n    '.join(names) if names else 'PASS: every table, key, action, data field and register validated'))
    errs += names
    print('OPEN QUESTIONS: see README.md. The master must stay quiet (no SYN) until INSTALLED is printed.')
    if errs:
        print('REFUSED: %d error(s):\n    %s' % (len(errs), '\n    '.join(errs)))
        return 1
    if not a.apply:
        print('DRY-RUN: nothing written')
        return 0
    if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
        print('REFUSED: --apply needs DEFENSE4_HW_AUTHORIZED=1')
        return 3
    if Path(a.manifest_out).exists():
        print('REFUSED: manifest %s already exists. It records an install; tear that down (or move the file) '
              'first. Nothing was written.' % a.manifest_out)
        return 4
    try:   # the manifest is written right after the first write, so prove its directory is writable before any write
        probe = Path(a.manifest_out).with_name(Path(a.manifest_out).name + '.probe')
        probe.write_text('')
        probe.unlink()
    except OSError as exc:
        print('REFUSED: cannot write next to %s (%s). Nothing was written.' % (a.manifest_out, exc))
        return 4
    errs = daemon_identity(a)
    if errs:
        print('REFUSED: %d error(s):\n    %s' % (len(errs), '\n    '.join(errs)))
        return 1
    apply(ops, a)
    return 0


if __name__ == '__main__':
    sys.exit(main())

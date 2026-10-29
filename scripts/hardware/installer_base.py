#!/usr/bin/env python3
"""Install the control-plane state of the composed response-only program (N + E in pipe 0, T in pipe 1) on the
physical switch. Dry-run by default: checks the build's sha256s, prints every write, and validates every name
against the compiled bfrt.json and the SDE shared schemas, with no gRPC. --apply (needs
DEFENSE4_HW_AUTHORIZED=1) writes in order: MAC loopback of the build's front-panel looping ports, queues, packet generator (apps disabled), mirror, T params, E rows,
N rows, N connection rows last. It reads every write back and stops at the first failure with a manifest of
what was installed.

  python3 bringup_composite.py --build-out <out/> --expect bfrt.json=<sha> --expect p0/tofino.bin=<sha> \
      --expect p1/tofino.bin=<sha> --master-port 54321                       # dry-run
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'model'))     # core/response_only: cp.py, port_map.py, check_mirror_select.py
import check_names  # noqa: E402
import readback  # noqa: E402
import rows  # noqa: E402
import t_config as tc  # noqa: E402
import build_ports  # noqa: E402


def oneline(e):
    return ' | '.join(l.strip() for l in str(e).splitlines() if l.strip())[:400]

# p1/response_only.bfa is the file the mirror guard reads; requiring its hash binds the guarded file to the
# binaries being loaded (a .bfa copied from another build would otherwise be guarded in their place).
TIMING_CONTRACT = None  # candidate entrypoint sets this only after source/artifact profile validation

REQUIRED_EXPECT = ('bfrt.json', 'p0/tofino.bin', 'p1/tofino.bin', 'p1/response_only.bfa')
DIAG_MIRROR_STATES = ('absent', 'off', 'on')


def parse(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False)
    ap.add_argument('--build-out', required=True, help='the compiled out/ directory the daemon loads')
    ap.add_argument('--expect', action='append', default=[], metavar='REL=SHA256',
                    help='expected sha256 of a file under --build-out; bfrt.json, p0/tofino.bin, p1/tofino.bin and '
                         'p1/response_only.bfa (the file the mirror guard reads) are required')
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
    ap.add_argument('--pad-enable', type=int, choices=(0, 1), default=1,
                    help='E padding policy on the fwd_conn row: 1 pads (default), 0 = policy-off control '
                         '(mapper armed and translating, no growth)')
    ap.add_argument('--diag-mirror', choices=DIAG_MIRROR_STATES, default='absent',
                    help='c72_diag_mirror build only: absent (default) plans no diagnostic session; off/on also write '
                         'its two relay-leg copy sessions (diag_mirror_sessions.py) right after the clone session')
    ap.add_argument('--k', type=int, default=2, help='2*k generator tokens per trigger (queue_sim default k=2)')
    for role in ('ack', 'resp'):
        ap.add_argument('--shape-%s-pps' % role, type=int, default=0, dest='shape_%s' % role,
                        help='pace the %s HOLD queue (qid 6/4/2) to this many packets/sec (0 = unshaped)' % role.upper())
        ap.add_argument('--shape-%s-blk-pps' % role, type=int, default=0, dest='block_%s' % role,
                        help='pace the %s BLOCKER queue (qid 7/5/3) to this many packets/sec (0 = unshaped)' % role.upper())
    ap.add_argument('--block-burst', type=int, default=tc.BLOCK_BURST,
                    help='max_burst_size for a shaped blocker queue (>= live blocker count so it stays occupied)')
    ap.add_argument('--enable-pktgen', action='store_true', help='enable app0 last, after clean readback')
    ap.add_argument('--fixed-schema-dir', default=os.environ.get('SDE_INSTALL', '/home/decps/Downloads/bf-sde-9.13.2/install')
                    + '/share/bf_rt_shared')
    ap.add_argument('--program', default='response_only')
    ap.add_argument('--client-id', type=int, default=120)
    ap.add_argument('--manifest-out', default='bringup_manifest.json')
    ap.add_argument('--allow-loopback-port', type=int, action='append', default=[], metavar='DEV_PORT',
                    help='accept this looping port although a module is plugged into its cage (media not UNKNOWN)')
    ap.add_argument('--loopback-wait', type=float, default=10.0, help='seconds to wait for $PORT_UP after the loopback write')
    ap.add_argument('--apply', action='store_true')
    argv = list(sys.argv[1:] if argv is None else argv)
    a = ap.parse_args(argv)
    a.timing_contract = TIMING_CONTRACT
    a.explicit_t_params = {x.split('=')[0] for x in argv if x.startswith('--t-')}
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


def mirror_guard(a):
    """Refuse a build whose compiled T ingress deparser can mirror a non-clone pass (route_ab_01/token_stale_01:
    the mirror_type 0 entry's session id came from a compiler temporary sharing a container with md.cur_gen, so
    every T pass was copied to session cur_gen[9:0]; fixed in mirror_fix_01). Runs Agent 1's
    core/response_only/check_mirror_select.check_out(<build-out>) on <build-out>/p1/*.bfa -- the only file it
    needs. --build-out is used as given: the deploy names it out_<buildname>, the evidence layout names it out.
    Errors (never raises): one per FAIL note, or the read failure."""
    import glob
    import check_mirror_select as cms
    out_dir = Path(a.build_out).resolve()
    bfas = glob.glob(str(out_dir / 'p1' / '*.bfa'))
    try:
        ok, notes = cms.check_out(out_dir)
    except Exception as e:
        ok, notes = False, ['FAIL: the guard could not parse %s: %s' % (bfas or out_dir / 'p1/*.bfa', oneline(e))]
    sha = hashlib.sha256(Path(bfas[0]).read_bytes()).hexdigest() if len(bfas) == 1 else 'absent'
    print('MIRROR GUARD (check_mirror_select on %s, sha256 %s): %s' % (
        bfas[0] if len(bfas) == 1 else Path(a.build_out) / 'p1/*.bfa', sha, 'PASS' if ok else 'FAIL'))
    for n in notes:
        print('    ' + n)
    if ok:
        return []
    return ['mirror guard: %s' % n for n in notes if n.startswith('FAIL') or 'expected one' in n] or \
        ['mirror guard: %s' % notes[-1]]


def build_ports_for(a):
    """(ports read from the build, errors): the build must be composed for --master-dev / --relay-dev."""
    ports, errs = build_ports.read(a.build_out, timing_contract=a.timing_contract)
    if not errs:
        errs = build_ports.check_endpoints(ports, a.master_dev, a.relay_dev, timing_contract=a.timing_contract)
    print('PORTS FROM THE BUILD (response_only.p4pp): %s' % (
        ', '.join('%s=%s' % (k, ports[k]) for k in sorted(ports)) or 'unreadable'))
    loops = build_ports.loopback_ports(ports, timing_contract=a.timing_contract) if not errs else {}
    print('    front-panel ports this bring-up puts in MAC loopback: %s' % (
        ', '.join('%s=%d' % kv for kv in sorted(loops.items(), key=lambda kv: kv[1])) or 'none'))
    return ports, errs


def params(a):
    text = (Path(a.build_out) / 'response_only.p4pp').read_text()
    contract = tc.timing_contract_of_source(text, timing_contract=getattr(a, "timing_contract", None))
    a.timing_contract = contract
    return {key: getattr(a, 't_' + key) for key in tc.RESPONSE_READY_NO_J_KEYS}


def dataplane_params_op(a):
    """T's params write in the build's own time units (directive ba50eac69, C1): the command line is ns, checked by
    tc.check_params; the build's compiled source decides the units (tc.t_time_of_source on response_only.p4pp) and
    tc.t_units converts, rounding up. ns, units and time base are kept on the op, so the manifest records all three."""
    values_ns = params(a)
    t_time = tc.t_time_of_source((Path(a.build_out) / 'response_only.p4pp').read_text())
    op = tc.params_op(tc.t_units(values_ns, **t_time), timing_contract=a.timing_contract)
    op.update(values_ns=values_ns, t_time=t_time)
    return op


def diag_mirror_plan(a, ports):
    """(ops, errors) for --diag-mirror. absent: no ops, nothing read. off/on: the c72_diag_mirror build's two
    $mirror.cfg sessions from its compiled constants (diag_mirror_sessions.load/validate/ops); a build without those
    constants, or any validation error, is an error and plans nothing."""
    state = getattr(a, 'diag_mirror', 'absent')
    if state == 'absent':
        return [], []
    import diag_mirror_sessions
    try:
        constants = diag_mirror_sessions.load(a.build_out)
    except (OSError, ValueError) as e:
        return [], ['--diag-mirror %s: %s' % (state, oneline(e))]
    errs = diag_mirror_sessions.validate(constants)
    if ports.get('clone_session') in (constants['session_rx'], constants['session_tx']):
        errs.append('a diagnostic session is the clone session %d' % ports['clone_session'])
    if errs:
        return [], ['--diag-mirror %s: %s' % (state, e) for e in errs]
    return diag_mirror_sessions.ops(constants, state), []


def diag_sessions(ops, ports):
    """Session ids of the planned diagnostic mirror writes: every mirror write except the clone session."""
    return [op['key'][0][1] for op in ops if op['kind'] == 'mirror' and op['key'][0][1] != ports['clone_session']]


def plan(a, ports):
    """Write order: loopback of the build's front-panel looping ports, then T-side state, E, and N last with
    its connection rows at the very end, so no master packet is bound by N before everything it hands to T
    and E is in place."""
    params(a)  # validate and select the compiled ABI before choosing resources
    master, relay = rows.endpoints(a.master_ip, a.master_port, a.master_dev, a.relay_ip, a.relay_port, a.relay_dev)
    decoy = {k: getattr(a, 'crob_' + k) for k in rows.VECTOR_DECOY}
    ne = rows.build(master, relay, decoy, ports, a.read_dst, a.read_src, pad_enable=a.pad_enable)
    e_rows = [r for r in ne if r['table'].startswith('p0.r_')]
    n_conn = [r for r in ne if r['table'] == 'p0.n_Ingress.connection']
    n_rest = [r for r in ne if r['table'].startswith('p0.n_') and r not in n_conn]
    shape = {r: getattr(a, 'shape_' + r) for r in ('ack', 'resp')}
    block = {r: getattr(a, 'block_' + r) for r in ('ack', 'resp')}
    diag, errs = diag_mirror_plan(a, ports)
    if errs:
        raise ValueError('; '.join(errs))
    return (tc.loopback_ops(ports, timing_contract=a.timing_contract)
            + tc.queue_ops(ports, shape, block, a.block_burst, timing_contract=a.timing_contract)
            + tc.pktgen_ops(a.k, ports, timing_contract=a.timing_contract)
            + [tc.mirror_op(ports)] + diag + [dataplane_params_op(a)] + e_rows + n_rest + n_conn)


def show(op):
    key = op.get('key') or ([('dev_port', op['dev_port'], None), ('qid', op['qid'], None)] if 'qid' in op else [])
    key = ', '.join('%s=%s' % (n, hex(v) if isinstance(v, int) and v > 0xffff else v) + ('&&&%s' % hex(m) if m is not None else '')
                    for n, v, m in key)
    data = ', '.join('%s=%s' % (n, '<%d bytes, [4:6]=%s>' % (len(v), v[4:6].hex()) if isinstance(v, bytes) else v) for n, v in op['data'])
    prio = '' if op.get('priority') is None else ' prio=%d' % op['priority']
    return '%-13s pipe=%-6s %-30s [%s]%s -> %s(%s)' % (op['kind'], hex(op['pipe']), op['table'], key, prio,
                                                        op.get('action') or 'mod', data)


def offline(ops, a, ports):
    tables = check_names.load(Path(a.build_out) / 'bfrt.json', a.fixed_schema_dir)
    errs = check_names.check(ops + tc.enable_ops(ports, timing_contract=a.timing_contract), tables)
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


def loopback_precheck(sw, ops, allow):
    """Read-only. Errors unless every port about to be looped has a $PORT entry, is enabled, has link DOWN
    (a port with link up may be someone's connection) and an empty cage (media UNKNOWN) or is explicitly
    allowed with --allow-loopback-port."""
    errs = []
    for op in ops:
        port = op['key'][0][1]
        got = sw.get('$PORT', op['pipe'], op['key'])
        if got is None:
            errs.append('dev_port %d (%s): no $PORT entry' % (port, op['label']))
            continue
        if got.get('$PORT_ENABLE') is not True:
            errs.append('dev_port %d: $PORT_ENABLE is %r' % (port, got.get('$PORT_ENABLE')))
        if got.get('$PORT_UP') is not False:
            errs.append('dev_port %d: $PORT_UP is %r before bring-up; a port with link up is not ours to loop'
                        % (port, got.get('$PORT_UP')))
        if got.get('$LOOPBACK_MODE') != tc.LOOPBACK_OFF:
            errs.append('dev_port %d: $LOOPBACK_MODE is already %r' % (port, got.get('$LOOPBACK_MODE')))
        if 'UNKNOWN' not in str(got.get('$MEDIA_TYPE')).upper() and port not in allow:
            errs.append('dev_port %d: media is %r (a module is plugged in); pass --allow-loopback-port %d to accept'
                        % (port, got.get('$MEDIA_TYPE'), port))
    return errs


def wait_link_up(sw, op, seconds):
    """True once the looped port reports $PORT_UP (it came up within 3 s on the switch, 2026-10-11)."""
    end = time.time() + seconds
    while True:
        if (sw.get('$PORT', op['pipe'], op['key']) or {}).get('$PORT_UP') is True:
            return True
        if time.time() >= end:
            return False
        time.sleep(0.2)


def apply(ops, a, ports):
    from switch import Switch
    sw = Switch(a.program, a.client_id)
    done, manifest = [], Path(a.manifest_out)

    def record():
        data = dict(program=a.program, time=time.time(), installed=done)
        if getattr(a, 'timing_contract', None) is not None:
            data['timing_contract'] = a.timing_contract
        manifest.write_text(json.dumps(data, indent=1, default=encode) + '\n')

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
            if op['kind'] in ('queue', 'queue_shaping'):
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
        if op['kind'] == 'loopback' and not wait_link_up(sw, op, a.loopback_wait):
            stop('%s: $PORT_UP did not become True within %.1f s of the loopback write' % (op['label'], a.loopback_wait))
        print('OK  ', show(op))

    try:
        try:
            bad = loopback_precheck(sw, [op for op in ops if op['kind'] == 'loopback'], set(a.allow_loopback_port))
            if bad:
                stop('loopback pre-check: %s' % bad)
            for table in sorted({op['table'] for op in ops if op['kind'] == 'p4'}):
                if sw.count(table, 0xffff) != 0:
                    stop('%s is not empty before bring-up' % table)
            if sw.get('$mirror.cfg', 0xffff, [('$sid', ports['clone_session'], None)]) is not None:
                stop('mirror session %d already exists' % ports['clone_session'])
            for sid in diag_sessions(ops, ports):
                if sw.get('$mirror.cfg', 0xffff, [('$sid', sid, None)]) is not None:
                    stop('mirror session %d already exists' % sid)
            bad = readback.register_errors(readback.registers(sw))
        except Exception as e:
            stop('pre-check failed: %s' % e)
        if bad:
            stop('T registers not at their reset values: %s' % bad)
        for op in ops:
            step(op)
        if a.enable_pktgen:
            apps = {o['label']: o for o in ops if o['kind'] == 'pktgen_app'}
            for op in tc.enable_ops(ports, timing_contract=a.timing_contract):
                step(op, readback.enabled_app_op(apps[op['label']]))   # re-verify the whole app, not just the flag
        try:
            bad = readback.register_errors(readback.registers(sw))
        except Exception as e:
            bad = [str(e)]
        if bad:
            stop('T registers moved during bring-up (was the master quiet?): %s' % bad)
        if sw.sw_read:
            print('NOTE: read back from software state, not hardware (no hardware read on this SDE): %s' % ', '.join(sorted(sw.sw_read)))
        print('INSTALLED %d writes; manifest %s; pad_enable=%d; T enabled=%d; pktgen %s' % (len(done), manifest,
                                                                 a.pad_enable, a.t_enabled,
                                                                 'ENABLED' if a.enable_pktgen else 'written DISABLED'))
        shape = {r: getattr(a, 'shape_' + r) for r in ('ack', 'resp')}
        block = {r: getattr(a, 'block_' + r) for r in ('ack', 'resp')}
        print('counters', json.dumps(readback.snapshot(sw, ports, shape, block, timing_contract=a.timing_contract), indent=1))
    finally:
        sw.close()


def main(argv=None):
    a = parse(argv)
    print('BUILD IDENTITY (%s):' % a.build_out)
    errs = identity(a)
    errs += mirror_guard(a)              # before any plan or write, in dry-run and --apply alike
    if errs:                             # wrong build or a defective one: nothing further is worth checking
        print('REFUSED: %d error(s):\n    %s' % (len(errs), '\n    '.join(errs)))
        return 1
    ports, port_errs = build_ports_for(a)
    errs += port_errs + tc.check_params(params(a), timing_contract=a.timing_contract)
    diag_errs = [] if port_errs else diag_mirror_plan(a, ports)[1]
    errs += diag_errs
    if port_errs or diag_errs:   # without the build's ports (or valid diagnostic sessions) there is no plan to print
        print('REFUSED: %d error(s):\n    %s' % (len(errs), '\n    '.join(errs)))
        return 1
    ops = plan(a, ports)
    print('PLAN: %d writes (+%d pktgen enables, last, only with --enable-pktgen) | pad_enable=%d | T enabled=%d'
          % (len(ops), len(tc.pktgen_apps(a.timing_contract)), a.pad_enable, a.t_enabled))
    for op in ops:
        print('    ', show(op))
    names = offline(ops, a, ports)
    print('NAME CHECK against %s/bfrt.json and %s (shared schemas; the switch runs SDE 9.13.2):'
          % (a.build_out, a.fixed_schema_dir))
    print('    ' + ('\n    '.join(names) if names else 'PASS: every table, key, action, data field and register validated'))
    errs += names
    print('The master stays quiet until INSTALLED and successful readback.')
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
    apply(ops, a, ports)
    return 0


if __name__ == '__main__':
    sys.exit(main())

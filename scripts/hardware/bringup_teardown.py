#!/usr/bin/env python3
"""Remove exactly what bringup_composite.py installed, from its manifest. Dry-run by default.

Order:
  1. generator apps disabled (no action, as set_app_enable writes it) and read back        no new tokens
  2. T params rewritten with enabled=0, so T's *_off rows flush held originals and tokens
  3. wait until OUT_HELD_OFF_FLUSH and OUT_TOKEN_OFF stop moving; if they do not settle, STOP: no row is deleted
  4. every write undone in reverse (N connection rows first), each read back:
       delete         P4 rows, mirror session        -> must be absent
       default_reset  T params                       -> must equal the default read before bring-up
       restore        $PORT loopback (back to BF_LPBK_NONE), TM sched_cfg, pktgen port_cfg, pkt_buffer,
                      app_cfg -> must equal the values read before. An app whose prior state was the SDE
                      default (disabled one-shot) is left disabled; any other prior trigger type is reported
                      as NOT restored (exit 1)
This leaves the composite loaded but unconfigured. Going back to the production program is a cold restart:
stop bf_switchd, relaunch ~/Philip_repo/logs/bringup_20261005/launch.sh, replay $PORT with restore_ports.py
(rehearsed 2026-10-06, audit_current/framework_20261005/RESTORATION_REHEARSAL_20261006.md).

  python3 bringup_teardown.py --manifest bringup_manifest.json [--apply]
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import readback  # noqa: E402

COUNTERS = ('trigger_counter', 'batch_counter', 'pkt_counter')
SDE_DEFAULT_TRIGGER = 'trigger_timer_one_shot'
OFF_FLUSH, TOKEN_OFF = 11, 12          # t_OUT_HELD_OFF_FLUSH, t_OUT_TOKEN_OFF (read_queue_timing.p4)


def decode(value):
    """Manifest JSON back to plan values: {'hex': ...} -> bytes, key/data lists -> tuples."""
    if isinstance(value, dict) and set(value) == {'hex'}:
        return bytes.fromhex(value['hex'])
    return value


def as_bytes(value):
    """A bytes-valued field read back or stored in any of the forms seen: {'hex': ...} (our manifest encoding),
    a list of ints (the 9.13.2 software-state read of tf1.pktgen.pkt_buffer, which JSON then keeps as a list),
    bytearray or bytes. Returns bytes, or the value unchanged if it is none of these (e.g. None)."""
    value = decode(value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, list) and all(isinstance(x, int) and 0 <= x <= 255 for x in value):
        return bytes(value)
    return value


def load(path):
    """Read a bring-up manifest back into plan values. The ONE place restore values are normalised: a field
    whose planned (written) value is bytes is a bytes-typed field (only tf1.pktgen.pkt_buffer 'buffer' today),
    so its pre-bring-up value is converted to bytes here, whatever form the switch read and JSON stored it in.
    The real bfrt_grpc DataTuple accepts only int / str / bytearray for such a field and rejects a list."""
    m = json.loads(Path(path).read_text())
    for op in m['installed']:
        op['key'] = [tuple(k) for k in op.get('key', [])]
        op['data'] = [(n, decode(v)) for n, v in op['data']]
        byte_fields = {n for n, v in op['data'] if isinstance(v, (bytes, bytearray))}
        if isinstance(op.get('before'), dict):
            op['before'] = {k: (as_bytes(v) if k in byte_fields else decode(v)) for k, v in op['before'].items()}
    return m


def steps(ops):
    apps = [dict(op, undo='disable') for op in ops if op['kind'] == 'pktgen_app']
    params = [dict(op, undo='t_off') for op in ops if op['kind'] == 'default']
    return apps + params + [op for op in reversed(ops) if op['kind'] != 'pktgen_enable']


# A build without T's outcome counters (c68, write-only measurement state removed) settles on the frames its T loop
# ports have sent instead: T ingress (180), the heartbeat/OPERATE-ladder return (181) and the held return (182) stop
# moving once nothing is held or laddering.
SETTLE_PORTS = (180, 181, 182)


def settle_ports(manifest):
    """Use only installed T loopbacks for no-J; historical manifests keep their settled port set."""
    if manifest.get('timing_contract') != 'response_ready_ack_d_no_j_v3':
        return SETTLE_PORTS
    return tuple(sorted({value for op in manifest['installed'] if op['kind'] == 'loopback'
                         and op.get('label', '').split(' ', 1)[0] in ('t_in', 'held_return')
                         for name, value, _mask in op.get('key', []) if name == '$DEV_PORT'}))


def off_counts(sw, ports=SETTLE_PORTS, timing_contract=None):
    if timing_contract != 'response_ready_ack_d_no_j_v3':
        try:
            return tuple(sum(sw.register('p1.t_Ingress.outcomes', 0xffff, i)) for i in (OFF_FLUSH, TOKEN_OFF))
        except KeyError:                # BF Runtime: the loaded build has no outcomes register
            pass
    return tuple((sw.get('$PORT_STAT', 0xffff, [('$DEV_PORT', port, None)]) or {}).get('$FramesTransmittedAll')
                 for port in ports)


def settle(sw, quiet, timeout, ports=SETTLE_PORTS, timing_contract=None):
    """True once the selected counters are unchanged for `quiet` seconds."""
    start, last, since = time.time(), off_counts(sw, ports, timing_contract), time.time()
    while time.time() - start < timeout:
        time.sleep(0.2)
        now = off_counts(sw, ports, timing_contract)
        if now != last:
            last, since = now, time.time()
        elif time.time() - since >= quiet and None not in now:     # an unreadable counter never settles
            print('settled: %r' % (last,))
            return True
    print('NOT settled after %.1f s: %r' % (timeout, last))
    return False


def undo(sw, op):
    """Undo one write and read it back; returns mismatch strings."""
    t, tgt, kind = sw.table(op['table']), sw.target(op['pipe']), op['undo']
    key = op['key']
    if kind == 'delete':
        t.entry_del(tgt, [sw.key(t, key, op.get('priority'))])
        return [] if sw.get(op['table'], op['pipe'], key, op.get('priority')) is None else ['still present']
    if kind == 'default_reset':
        t.default_entry_reset(tgt)
        got = sw.default_get(op['table'], op['pipe'])
        return [] if got == op['before'] else ['default reads %r, before bring-up %r' % (got, op['before'])]
    if kind == 't_off':
        data = [(n, 0 if n == 'enabled' else v) for n, v in op['data']]
        t.default_entry_set(tgt, sw.data(t, data, op['action']))
        return readback.verify(sw, dict(op, data=data))
    if kind == 'disable':
        back = [('app_enable', False)]
        t.entry_mod(tgt, [sw.key(t, key)], [sw.data(t, back)])
    else:                                   # restore
        before = dict(op.get('before') or {})
        prior_action = before.pop('action_name', None)
        back = [(n, v) for n, v in before.items() if n not in COUNTERS]
        if op['kind'] == 'pktgen_app' and prior_action != op['action']:
            # The app held another trigger type before; its fields are not all in the manifest, so it cannot be
            # put back. Leave it disabled and read that back.
            t.entry_mod(tgt, [sw.key(t, key)], [sw.data(t, [('app_enable', False)])])
            if sw.must_get(op['table'], op['pipe'], key).get('app_enable') is not False:
                return ['app_enable did not read back False']
            if prior_action == SDE_DEFAULT_TRIGGER and before.get('app_enable') is False:
                # The SDE's untouched default: a disabled one-shot timer never fires, and neither does a disabled
                # recirc-pattern app. Disabled is the state it was in (measured on the switch, 2026-10-11).
                return ['NOTE: left disabled (default was a disabled one-shot)']
            return ['NOT restored: was %s (app_enable %r) before bring-up; left DISABLED as trigger_recirc_pattern '
                    'with pattern 0x%08x' % (prior_action, before.get('app_enable'), dict(op['data'])['pattern_value'])]
        if not back or any(v is None for _n, v in back):
            return ['manifest has no pre-write value for %s; NOT restored, left as bring-up wrote it'
                    % sorted(n for n, v in before.items() if v is None)]
        if op['kind'] == 'pktgen_app':
            back = [(n, v) for n, v in back if n != 'app_enable'] + [('app_enable', False)]
        t.entry_mod(tgt, [sw.key(t, key)], [sw.data(t, back, op.get('action'))])
    got = sw.must_get(op['table'], op['pipe'], key)
    return ['%s reads %r, want %r' % (n, got.get(n), v) for n, v in back if not readback.same(n, got.get(n), v)]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--manifest', required=True)
    ap.add_argument('--client-id', type=int, default=121)
    ap.add_argument('--quiet', type=float, default=1.0, help='seconds the off counters must hold still')
    ap.add_argument('--settle-timeout', type=float, default=15.0)
    ap.add_argument('--apply', action='store_true')
    a = ap.parse_args(argv)
    m = load(a.manifest)
    order = steps(m['installed'])
    for op in order:
        print('%-13s %s %s' % (op['undo'], op['table'], op.get('label') or [k[1] for k in op['key']]))
    if not a.apply:
        print('DRY-RUN: %d steps, nothing written' % len(order))
        return 0
    if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
        print('REFUSED: --apply needs DEFENSE4_HW_AUTHORIZED=1')
        return 3
    from switch import Switch
    sw = Switch(m['program'], a.client_id)
    failed, n_pre = [], sum(1 for op in order if op['undo'] in ('disable', 't_off'))
    try:
        for i, op in enumerate(order):
            if i == n_pre:                  # generator off and T off are written; now wait for the flush
                if failed or not settle(sw, a.quiet, a.settle_timeout, ports=settle_ports(m),
                                        timing_contract=m.get('timing_contract')):
                    print('STOPPED before deleting any row: %s' % (failed or 'T did not settle'))
                    return 2
            try:
                bad = undo(sw, op)
            except Exception as e:          # keep going: report every step that could not be undone
                bad = [' | '.join(l.strip() for l in str(e).splitlines() if l.strip())[:400]]
            for note in [b for b in bad if b.startswith('NOTE: ')]:
                print('%s %s: %s' % (op['table'], op.get('label') or '', note[6:]))
            bad = [b for b in bad if not b.startswith('NOTE: ')]
            if bad:
                failed.append('%s %s %s: %s' % (op['undo'], op['table'], op.get('label') or '', bad))
    finally:
        sw.close()
    print('UNDONE and read back %d of %d' % (len(order) - len(failed), len(order)))
    for f in failed:
        print('FAILED', f)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())

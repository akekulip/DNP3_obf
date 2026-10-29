#!/usr/bin/env python3
"""Mirror sessions for the c72_diag_mirror diagnostic build only: both relay-leg copies to one port, untruncated.

  python3 diag_mirror_sessions.py OUT --plan on|off            print the validated $mirror.cfg operations (offline)
  python3 diag_mirror_sessions.py OUT --apply on|off|absent    write them through switch.Switch (switch host only)

OUT is the compiled output directory (response_only.p4pp beside bfrt.json) or a build directory holding
compile_local/out. Every value comes from that compiled source: the ingress session (frames arriving from the
relay), the egress session (frames leaving toward the relay) and the copy port. Nothing else is written.

States of the same binary:
  on      both sessions present and enabled: each relay-leg frame is copied to the copy port;
  off     both sessions present with $session_enable False: the dataplane still names them, no copy is made;
  absent  both sessions deleted (the state in which the c72 model drivers run on this build).
T's clone session (t_CLONE_SESSION_ID, 7 in c72) is never written and t_config.py is not used.
Applying is a switch write: it needs the existing ownership controls and is not part of any offline check.
"""
import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ALL_PIPES = 0xffff
TABLE = '$mirror.cfg'
MAX_PKT_LEN = 16384            # TF1 maximum; jumbo frames are 9216, so no copy is truncated
STATES = ('on', 'off', 'absent')
SOURCE_CONSTANTS = dict(session_rx='n_DIAG_SESSION_RX', session_tx='r_DIAG_SESSION_TX', copy_port='r_DIAG_COPY_PORT',
                        relay_in='n_DIAG_RELAY_PORT', relay_out='r_DIAG_RELAY_PORT', t_clone='t_CLONE_SESSION_ID')
INTERNAL_CONSTANTS = ('n_RETURN_PORT', 'n_N_ACK_RETURN', 'n_READ_HANDOFF_PORT', 't_PKTGEN_RETURN', 't_T_IN',
                      't_HELD_RETURN', 't_N_RETURN', 't_FORWARD_PORT', 't_RELAY_PORT')


def source_of(path):
    path = Path(path)
    for candidate in (path / 'response_only.p4pp', path / 'compile_local/out/response_only.p4pp'):
        if candidate.is_file():
            return candidate
    raise FileNotFoundError('no compiled response_only.p4pp under %s' % path)


def _const(text, name):
    found = re.findall(r'const\s+\w+\s+%s\s*=\s*(?:\d+w)?(\d+)\s*;' % name, text)
    if len(found) != 1:
        raise ValueError('compiled source declares %s %d times' % (name, len(found)))
    return int(found[0])


def load(path):
    """The diagnostic constants and every port the program sends to internally, from the compiled source."""
    text = source_of(path).read_text(errors='replace')
    values = {key: _const(text, name) for key, name in SOURCE_CONSTANTS.items()}
    values['internal_ports'] = {name: _const(text, name) for name in INTERNAL_CONSTANTS}
    dispatch = re.search(r'parser r_EgParser\b.*?transition select\(eg\.egress_port\)\s*\{([^}]*)\}', text, re.S)
    if not dispatch:
        raise ValueError('compiled source has no r_EgParser egress-port dispatch')
    values['egress_parsed_ports'] = sorted(int(p) for p in re.findall(r'9w(\d+)\s*:', dispatch.group(1)))
    return values


def validate(c):
    """Errors that make the configuration unsafe or not diagnostic; empty when it may be written."""
    errors = []
    sessions = (c['session_rx'], c['session_tx'])
    for name in ('session_rx', 'session_tx'):
        if not 1 <= c[name] <= 1015:
            errors.append('%s %d is not a TF1 normal session (1-1015)' % (name, c[name]))
        if c[name] == c['t_clone']:
            errors.append("%s %d is T's clone session" % (name, c[name]))
    if len(set(sessions)) != 2:
        errors.append('the two diagnostic sessions must differ')
    port = c['copy_port']
    if port >> 7 != 0 or port % 128 >= 64:
        errors.append('copy port %d is not a pipe-0 front-panel port (pipe-0 egress is r_EgParser)' % port)
    if port in c['egress_parsed_ports']:
        errors.append('copy port %d is parsed by r_EgParser %s: copies would be transformed' % (port, c['egress_parsed_ports']))
    if port in (c['relay_in'], c['relay_out']) or port in c['internal_ports'].values() or port % 128 == 68:
        errors.append('copy port %d is the relay port, a loop/recirculation port or a forwarding target' % port)
    if c['relay_in'] != c['relay_out'] or c['relay_in'] != c['internal_ports']['t_RELAY_PORT']:
        errors.append('mirrored relay ports disagree: %d / %d / t_RELAY_PORT %d'
                      % (c['relay_in'], c['relay_out'], c['internal_ports']['t_RELAY_PORT']))
    return errors


def ops(c, state):
    """$mirror.cfg operations in t_config.mirror_op's format (switch.Switch.write applies kind 'mirror')."""
    if state not in ('on', 'off'):
        raise ValueError('only on/off have entries to write')
    return [dict(kind='mirror', table=TABLE, pipe=ALL_PIPES, label=label, key=[('$sid', sid, None)], action='$normal',
                 data=[('$direction', direction), ('$ucast_egress_port', c['copy_port']),
                       ('$ucast_egress_port_valid', True), ('$session_enable', state == 'on'),
                       ('$max_pkt_len', MAX_PKT_LEN)])
            for label, sid, direction in (('relay_rx_ingress_copy', c['session_rx'], 'INGRESS'),
                                          ('relay_tx_egress_copy', c['session_tx'], 'EGRESS'))]


def apply(switch, c, state):
    """Delete both diagnostic sessions if present, then write the requested state; read each entry back.
    `switch` is a switch.Switch (or any object with its table/target/key/get/write methods)."""
    errors = validate(c)
    if errors or state not in STATES:
        raise ValueError('refusing to write: %s' % (errors or ['unknown state %r' % state]))
    for sid in (c['session_rx'], c['session_tx']):
        key = [('$sid', sid, None)]
        if switch.get(TABLE, ALL_PIPES, key) is not None:
            table = switch.table(TABLE)
            table.entry_del(switch.target(ALL_PIPES), [switch.key(table, key)])
    planned = ops(c, state) if state != 'absent' else []
    for op in planned:
        switch.write(op)
    readback = {}
    for sid in (c['session_rx'], c['session_tx']):
        readback[sid] = switch.get(TABLE, ALL_PIPES, [('$sid', sid, None)])
    for op in planned:
        got, sid = readback[op['key'][0][1]] or {}, op['key'][0][1]
        wrong = {name: (value, got.get(name)) for name, value in op['data'] if got.get(name) != value}
        if wrong:
            raise RuntimeError('session %d read back differently: %s' % (sid, wrong))
    if state == 'absent' and any(v is not None for v in readback.values()):
        raise RuntimeError('a diagnostic session is still present: %s' % readback)
    return dict(state=state, ops=planned, readback=readback)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('out', type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--plan', choices=('on', 'off'))
    group.add_argument('--apply', choices=STATES)
    parser.add_argument('--program', default='response_only')
    parser.add_argument('--client-id', type=int, default=9)
    args = parser.parse_args()
    c = load(args.out)
    errors = validate(c)
    if errors:
        print(json.dumps(dict(errors=errors), indent=1))
        return 1
    if args.plan:
        print(json.dumps(dict(constants=c, ops=ops(c, args.plan)), indent=1))
        return 0
    sys.path.insert(0, str(HERE))
    import switch as switch_module                 # BF Runtime gRPC: imported only on an explicit --apply
    sw = switch_module.Switch(args.program, args.client_id)
    try:
        print(json.dumps(apply(sw, c, args.apply), indent=1, default=str))
    finally:
        sw.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())

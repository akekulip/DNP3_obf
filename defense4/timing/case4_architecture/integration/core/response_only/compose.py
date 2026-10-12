#!/usr/bin/env python3
"""Compose the response-only target (B' profile, M / E cache / final emitter retired):

  p0 = response-only N ingress (make_n.py, from connection/binding/generate.py's response_only profile,
       which reads integration/handshake.p4 and connection/selected.p4; native_binding.p4 is NOT an input)
       + role E egress (make_e.py, from protocol/case4_response_path.p4: padder + transport mapper,
       egress_port-dispatched parser, conn bound to egress_port)
  p1 = T (read/read_queue_timing.p4), on its two-pipe ports (read/ports.p4: 196-199)

Two pipelines only: the switch has two physical pipes (a Switch(p0,p1,p2,p3) load failed with "only 2
pipe(s) available"; BFRT $PORT shows 324-327 absent). 2cb6ecf9d's Switch(p0, p1, p2) with T in pipe 2 could
not load on it. M is retired, so T takes pipe 1.

Role prefixes n_, r_, t_ as in core/ordinary/compose.py; nothing else is changed. The response path's own
1-stage forwarding ingress is not used (N routes), so p0's ingress is N's and its egress is the response
path's. N and E are regenerated from their real inputs, which inputs.json hashes.

  python3 compose.py <out.p4> [--relay-port=N] [--n-ack-return=N] [--t-in=N] [--hb-return=N] [--held-return=N]

The five ports are build parameters (port_map.py holds their defaults and checks them): T's outstation-side
release port (64), N's ACK lap port (70) and T's three looping inputs (197, 198, 199). With no flag the output
is the model build, byte for byte as before. On the switch only pipe-local 68 recirculates, so the hardware
build names front-panel ports in MAC loopback instead (port_map.HARDWARE_SHARED_PORT). The map is written to
<out>.inputs.json; cp.py's rows take the same map (port_map.load), so rows and build cannot disagree.
"""
import hashlib
import re
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
INTEG = HERE.parent.parent
sys.path.insert(0, str(INTEG / 'read'))
import compose_t_response as ct  # noqa: E402  (inline, strip_main, role, T/R sources)
import make_e  # noqa: E402
import make_n  # noqa: E402
import port_map as pm  # noqa: E402

BINDING = INTEG / 'connection' / 'binding'


RELAY_DECL = re.compile(r'(const\s+PortId_t\s+RELAY_PORT\s*=\s*9w)(\d+)(\s*;)')


def set_port(text, name, value, default):
    """Rewrite the one `const PortId_t <name> = 9w<default>;` declaration in text to 9w<value>. Every use of a
    port in N and T goes through its named constant (parser selects, table keys and const entries, apply-block
    port tests, release and keep_blocking targets), so the declaration is the only place to change. Refuses a
    text where the declaration is missing, repeated, or no longer holds the default it is expected to replace."""
    decl = re.compile(r'(const\s+PortId_t\s+%s\s*=\s*9w)(\d+)(\s*;)' % name)
    found = decl.findall(text)
    assert len(found) == 1, '%s declaration found %d times, expected exactly once' % (name, len(found))
    assert int(found[0][1]) == default, '%s is declared %s, expected the default %d' % (name, found[0][1], default)
    return decl.sub(lambda m: '%s%d%s /* compose.py port override (was %s) */' % (m[1], value, m[3], m[2]), text)


def set_e_lap_port(text, value):
    """E's egress parser dispatches on two literal ports, the master's and N's ACK lap (make_e.py); rewrite the
    lap one. make_e.py is not edited: its own constants locate the line, so a change there fails here."""
    old = '9w%d: eth; 9w%d: eth; default: accept;' % (make_e.MASTER_PORT, make_e.N_ACK_RETURN)
    assert text.count(old) == 1, "E's egress-port dispatch found %d times, expected exactly once" % text.count(old)
    return text.replace(old, '9w%d: eth; 9w%d: eth; default: accept;' % (make_e.MASTER_PORT, value))


def check_reset_kind(n_text, t_text):
    """N hands a close to T as an event whose kind/stage are wire bytes 12-13 on T_IN, a front-panel MAC-loopback
    port on the hardware map. N's emit_reset kind must equal T's KIND_RESET, and be >= 6 so the pair is in the
    EtherType range (an 802.3 length below 0x0600 was counted received-not-good on silicon, p2_production_01)."""
    n = re.findall(r'hdr\.event\.event=8w(\d+)\+\+m\.direction', n_text)
    t = re.findall(r'const\s+bit<8>\s+KIND_RESET\s*=\s*(\d+)\s*;', t_text)
    assert len(n) == 1 and len(t) == 1, 'RESET kind found %d times in N and %d in T' % (len(n), len(t))
    assert int(n[0]) == int(t[0]), "N's emit_reset kind %s differs from T's KIND_RESET %s" % (n[0], t[0])
    assert int(n[0]) >= 6, 'RESET kind %s puts an 802.3 length in wire bytes 12-13' % n[0]


def generate(relay_port=None, ports=None):
    """relay_port: the device port T releases toward the OUTSTATION (requests, OPERATEs, client closes).
    Default: read/ports.p4's RELAY_PORT (64). When both endpoints share one switch port (the reflected
    hardware setup, master and outstation both on 9) pass that port: T's RELAY_PORT is a compile-time
    constant, and with 64 those frames would leave on a port the outstation is not on.

    ports: a port_map.PortMap; overrides relay_port and names N's ACK lap port and T's three looping inputs.
    A port left at its default is not touched, so the default build's text does not change."""
    if ports is None:
        ports = pm.DEFAULT if relay_port is None else pm.DEFAULT._replace(relay_port=relay_port)
    elif ports.relay_port != pm.DEFAULT.relay_port:
        relay_port = ports.relay_port
    pm.check(ports)
    n_text = make_n.generate()
    if ports.n_ack_return != pm.DEFAULT.n_ack_return:
        n_text = set_port(n_text, 'N_ACK_RETURN', ports.n_ack_return, pm.DEFAULT.n_ack_return)
    if ports.t_in != pm.DEFAULT.t_in:
        n_text = set_port(n_text, 'READ_HANDOFF_PORT', ports.t_in, pm.DEFAULT.t_in)
    n_text = n_text.split('#ifndef NATIVE_BINDING_NO_MAIN')[0]
    n_text = ct.strip_main(ct.inline(n_text, BINDING))
    n_out, n_names = ct.role(n_text, 'n')
    e_text = make_e.generate()
    if ports.n_ack_return != pm.DEFAULT.n_ack_return:
        e_text = set_e_lap_port(e_text, ports.n_ack_return)
    r_out, r_names = ct.role(ct.strip_main(e_text), 'r')
    t_text = ct.inline(ct.T_SRC.read_text(), ct.HERE)
    if relay_port is not None:
        assert len(RELAY_DECL.findall(t_text)) == 1, 'RELAY_PORT declaration not found exactly once'
        t_text = RELAY_DECL.sub(lambda m: '%s%d%s /* compose.py relay_port override (was %s) */' % (m[1], relay_port, m[3], m[2]), t_text)
    for name, field in (('T_IN', 't_in'), ('HB_RETURN', 'hb_return'), ('HELD_RETURN', 'held_return')):
        if getattr(ports, field) != getattr(pm.DEFAULT, field):
            t_text = set_port(t_text, name, getattr(ports, field), getattr(pm.DEFAULT, field))
    check_reset_kind(n_text, t_text)
    for name, fixed in (('PKTGEN_RETURN', pm.PKTGEN_RETURN), ('N_RETURN', pm.RETURN_PORT)):
        assert re.search(r'const\s+PortId_t\s+%s\s*=\s*9w%d\s*;' % (name, fixed), t_text), name + ' moved'
    t_out, t_names = ct.role(ct.strip_main(t_text), 't')
    source = ('/* GENERATED by core/response_only/compose.py -- do not edit. Response-only target on the two-pipe\n'
              '   switch: N + B\' egress in pipe 0, T in pipe 1 (M retired). */\n#include <core.p4>\n#include <tna.p4>\n'
              + n_out + '\n' + r_out + '\n' + t_out +
              '\nPipeline(n_IgParser(), n_Ingress(), n_IgDeparser(), r_EgParser(), r_Egress(), r_EgDeparser()) p0;\n'
              'Pipeline(t_IngressParser(), t_Ingress(), t_IngressDeparser(), t_EmptyEgressParser(), t_EmptyEgress(),'
              ' t_EmptyEgressDeparser()) p1;\nSwitch(p0, p1) main;\n')
    files = [INTEG / 'handshake.p4', INTEG / 'connection' / 'selected.p4', BINDING / 'generate.py',
             BINDING / 'work_record.p4', make_e.SOURCE, ct.T_SRC, ct.HERE / 'ports.p4', ct.HERE / 'probe_shell.p4',
             HERE / 'make_n.py', HERE / 'make_e.py', HERE / 'port_map.py']
    meta = dict(inputs={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
                relay_port=relay_port, port_map=dict(ports._asdict()),
                source_sha256=hashlib.sha256(source.encode()).hexdigest(),
                renamed=dict(n=len(n_names), r=len(r_names), t=len(t_names)),
                collisions_before_prefixing=sorted((set(n_names) & set(r_names)) | (set(n_names) & set(t_names))
                                                   | (set(r_names) & set(t_names))))
    return source, meta


if __name__ == '__main__':
    args, ports = pm.parse_args(sys.argv[1:])
    assert len(args) == 1 and not args[0].startswith('--'), 'usage: compose.py <out.p4> [--relay-port=N] ...: %r' % args
    out = Path(args[0])
    src, meta = generate(ports=ports) if ports != pm.DEFAULT else generate()
    out.write_text(src)
    out.with_suffix('.inputs.json').write_text(json.dumps(meta, indent=2) + '\n')
    print('wrote', out, meta['renamed'], 'collisions before prefixing:', meta['collisions_before_prefixing'])

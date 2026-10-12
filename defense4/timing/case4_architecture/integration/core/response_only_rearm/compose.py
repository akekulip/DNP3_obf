#!/usr/bin/env python3
"""Isolated protected-reconnect composition; two physical pipelines."""
import hashlib
import argparse
import json
import sys
from pathlib import Path
import baseline
import make_n
import make_e
import make_t


def generate(ports=None):
    pm, ct = baseline.ports, baseline.composition.ct
    ports = pm.DEFAULT if ports is None else ports
    pm.check(ports)
    n = make_n.generate().split('#ifndef NATIVE_BINDING_NO_MAIN')[0]
    e, t = make_e.generate(), make_t.generate()
    for name, field, default in (('N_ACK_RETURN', 'n_ack_return', pm.DEFAULT.n_ack_return),
                                 ('READ_HANDOFF_PORT', 't_in', pm.DEFAULT.t_in)):
        if getattr(ports, field) != default:
            n = baseline.composition.set_port(n, name, getattr(ports, field), default)
    t = ct.inline(t, baseline.INTEG / 'read')
    for name, field in (('RELAY_PORT', 'relay_port'), ('T_IN', 't_in'),
                        ('HB_RETURN', 'hb_return'), ('HELD_RETURN', 'held_return')):
        default = getattr(pm.DEFAULT, field)
        if getattr(ports, field) != default:
            t = baseline.composition.set_port(t, name, getattr(ports, field), default)
    if ports.n_ack_return != pm.DEFAULT.n_ack_return:
        e = e.replace('9w70: provenance;', '9w%d: provenance;' % ports.n_ack_return)
    if ports.relay_port != pm.DEFAULT.relay_port:
        old = '9w64: provenance;'
        e = e.replace(old, '' if ports.relay_port == 9 else '9w%d: provenance;' % ports.relay_port)
    n, _ = ct.role(ct.strip_main(ct.inline(n, baseline.INTEG / 'connection' / 'binding')), 'n')
    e, _ = ct.role(ct.strip_main(e), 'r')
    t, _ = ct.role(ct.strip_main(t), 't')
    text = ('/* Isolated protected same-tuple reconnect candidate. */\n#include <core.p4>\n#include <tna.p4>\n'
            + n + '\n' + e + '\n' + t + '\n'
            'Pipeline(n_IgParser(), n_Ingress(), n_IgDeparser(), r_EgParser(), r_Egress(), r_EgDeparser()) p0;\n'
            'Pipeline(t_IngressParser(), t_Ingress(), t_IngressDeparser(), t_EmptyEgressParser(), '
            't_EmptyEgress(), t_EmptyEgressDeparser()) p1;\nSwitch(p0, p1) main;\n')
    return text, {'candidate': 'protected_rearm', 'port_map': dict(ports._asdict()),
                  'source_sha256': hashlib.sha256(text.encode()).hexdigest()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    for field in baseline.ports.FIELDS:
        parser.add_argument('--' + field.replace('_', '-'), type=int,
                            default=getattr(baseline.ports.DEFAULT, field))
    args = parser.parse_args()
    ports = baseline.ports.check(baseline.ports.PortMap(**{
        field: getattr(args, field) for field in baseline.ports.FIELDS}))
    out = args.output
    text, metadata = generate(ports)
    out.write_text(text)
    out.with_suffix('.inputs.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print('wrote', out)

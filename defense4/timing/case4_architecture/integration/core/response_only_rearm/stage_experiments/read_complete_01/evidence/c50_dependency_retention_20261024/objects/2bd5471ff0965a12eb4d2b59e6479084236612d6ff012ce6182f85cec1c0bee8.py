"""The response-only target's internal ports, as ONE value shared by the build (compose.py) and the rows
(cp.py), so they cannot disagree.

Measured on the switch (integration/evidence/recirc_ports_01/STATUS.md): each pipe has exactly ONE
recirculating internal port, dev 68 (pipe 0) and dev 196 (pipe 1). 69/70/71 and 197/198/199 have $PORT
entries but frames sent to them never re-enter. Free front-panel ports in MAC loopback do loop: 48 in pipe 0;
180, 181, 182 in pipe 1. The defaults below are the model's ports (the model loops every pipe-local 68-71);
the hardware map replaces the four that do not recirculate on silicon.

  compose.py out.p4 --relay-port=9 --n-ack-return=48 --t-in=180 --hb-return=181 --held-return=182
writes the map into out.inputs.json; installers and drivers load it back with load(path).
"""
import json
from collections import namedtuple
from pathlib import Path

FIELDS = ('relay_port', 'n_ack_return', 't_in', 'hb_return', 'held_return')
PortMap = namedtuple('PortMap', FIELDS)
DEFAULT = PortMap(relay_port=64, n_ack_return=70, t_in=197, hb_return=198, held_return=199)
HARDWARE_SHARED_PORT = PortMap(relay_port=9, n_ack_return=48, t_in=180, hb_return=181, held_return=182)
RETURN_PORT = 68        # N's own recirculation: pipe 0's one recirculating internal port
PKTGEN_RETURN = 196     # T's mirror-clone return and generator port: pipe 1's one recirculating internal port
FLAGS = {'--' + f.replace('_', '-') + '=': f for f in FIELDS}


def parse_args(argv):
    """Split argv into (other arguments, PortMap) taking --relay-port= --n-ack-return= --t-in= --hb-return=
    --held-return=."""
    values, rest = DEFAULT._asdict(), []
    for arg in argv:
        for flag, field in FLAGS.items():
            if arg.startswith(flag):
                values[field] = int(arg[len(flag):])
                break
        else:
            rest.append(arg)
    return rest, check(PortMap(**values))


def check(pm):
    """The four hop ports and the two fixed recirculation ports must all be different device ports, and the
    pipes must be right: N's lap port in pipe 0, T's three in pipe 1 (device port = pipe * 128 + local)."""
    hops = (pm.n_ack_return, pm.t_in, pm.hb_return, pm.held_return, RETURN_PORT, PKTGEN_RETURN)
    if len(set(hops)) != len(hops):
        raise ValueError('internal ports collide: %r' % (pm,))
    if pm.n_ack_return >> 7 != 0:
        raise ValueError('N_ACK_RETURN %d is not a pipe-0 port' % pm.n_ack_return)
    for name in ('t_in', 'hb_return', 'held_return'):
        if getattr(pm, name) >> 7 != 1:
            raise ValueError('%s %d is not a pipe-1 port' % (name, getattr(pm, name)))
    if pm.relay_port in hops:
        raise ValueError('relay port %d is an internal hop port' % pm.relay_port)
    return pm


def load(inputs_json):
    """The port map a build was composed with (compose.py's <out>.inputs.json). Builds composed before the
    map was recorded used the defaults, with relay_port as recorded."""
    meta = json.loads(Path(inputs_json).read_text())
    values = DEFAULT._asdict()
    if meta.get('relay_port') is not None:
        values['relay_port'] = meta['relay_port']
    values.update(meta.get('port_map') or {})
    return check(PortMap(**values))


# A real MAC reads wire bytes 12-13 as EtherType/length. Below 0x0600 it is an 802.3 length (silicon
# p2_production_01: the 76-byte RESET event, bytes 12-13 0x0401, counted on port 180 as received but not good);
# these types are consumed or re-parsed by a MAC/bridge: MAC control (PAUSE), slow protocols (LACP/OAM), the
# VLAN tag types, LLDP, EAPOL, PTP, CFM. Every frame on a front-panel loop port must avoid both.
RESERVED_TYPES = {0x8808: 'MAC control', 0x8809: 'slow protocols', 0x8100: 'VLAN', 0x88a8: 'S-VLAN',
                  0x9100: 'VLAN (legacy)', 0x9200: 'VLAN (legacy)', 0x88cc: 'LLDP', 0x888e: 'EAPOL',
                  0x88f7: 'PTP', 0x8902: 'CFM'}


def type_violation(value):
    """None if `value` (wire bytes 12-13) is a usable EtherType, else why not."""
    if value < 0x0600:
        return '802.3 length'
    return RESERVED_TYPES.get(value)

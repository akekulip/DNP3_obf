"""Current source-profile port map shared by the model and installer row builders."""
import json
from collections import namedtuple
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

FIELDS = ('relay_port', 'n_ack_return', 't_in', 'hb_return', 'held_return')
PortMap = namedtuple('PortMap', FIELDS)
DEFAULT = PortMap(relay_port=64, n_ack_return=48, t_in=180, hb_return=None, held_return=182)
RETURN_PORT = 68        # N's own recirculation: pipe 0's one recirculating internal port
PKTGEN_RETURN = 196     # T's mirror-clone return and generator port: pipe 1's one recirculating internal port
FLAGS = {'--' + f.replace('_', '-') + '=': f for f in FIELDS}


def check(pm):
    """The four hop ports and the two fixed recirculation ports must all be different device ports, and the
    pipes must be right: N's lap port in pipe 0, T's three in pipe 1 (device port = pipe * 128 + local)."""
    hops = (pm.n_ack_return, pm.t_in, pm.held_return, RETURN_PORT, PKTGEN_RETURN)
    if len(set(hops)) != len(hops):
        raise ValueError('internal ports collide: %r' % (pm,))
    if pm.n_ack_return >> 7 != 0:
        raise ValueError('N_ACK_RETURN %d is not a pipe-0 port' % pm.n_ack_return)
    for name in ('t_in', 'held_return'):
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

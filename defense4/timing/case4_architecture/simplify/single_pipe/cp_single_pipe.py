"""Control-plane rows for the single-pipe target's egress (role E, prefixed r_ in the composed program).

Same row plan as protocol/response_path_cp.py, with conn bound to eg.egress_port as in
core/response_only/cp.e_conn_rows, except that the reverse row sits at the RELAY port: there is no N and
no N_ACK_RETURN pass here, so the master's segments are reverse-mapped (and the master's SYN scrubbed) on
their one departure toward the outstation. The timing ingress keeps its own setup
(stage_reduction/control/defense4_timing_setup.py); nothing here touches it.

Rows are (table, key, action, data, priority) like cp.py. Source-level only: no BF Runtime client.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / 'protocol'))
import response_path_cp as rp  # noqa: E402

MASTER_PORT, RELAY_PORT = 9, 64     # keep equal to make_single_pipe.py
CONN_ORDER = ('hdr.ip.src', 'hdr.ip.dst', 'hdr.tcp.sport', 'hdr.tcp.dport')


def e_conn_rows(slot, outstation, master, pad_enable=True, master_port=MASTER_PORT, relay_port=RELAY_PORT):
    """fwd_conn (outstation -> master: the response padded, the SYN-ACK that arms) only at master_port;
    rev_conn (master -> outstation: ACK reverse-mapped, SYN scrubbed) only at relay_port."""
    if master_port == relay_port:
        raise ValueError('one shared port needs the address-qualified rows of cp.n_ports_rows; not supported here')
    out = []
    for table, key, action, data in rp.connection_entries(slot, outstation, master, pad_enable):
        if table == 'Egress.conn':
            port = master_port if action == 'Egress.fwd_conn' else relay_port
            out.append((table, tuple((f, key[f]) for f in CONN_ORDER) + (('eg.egress_port', port),), action,
                        tuple(sorted(data.items())), None))
        elif table == 'Egress.odd_ip_t':
            out.append((table, (('hdr.ip.src', key['hdr.ip.src']), ('hdr.ip.dst', key['hdr.ip.dst'])), action,
                        tuple(sorted(data.items())), None))
        # Ingress.forwarding rows are not used: the timing ingress routes
    return out

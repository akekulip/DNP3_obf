"""Control-plane rows for the response-only target (N in pipe 0 ingress, E in pipe 0 egress).

Rows are (table, key, action, data, priority). `key` is an ORDERED tuple of (field, value) in the P4 key
order; a value is an int (exact) or a (value, mask) pair (ternary). `priority` is BF Runtime
$MATCH_PRIORITY, where the LOWEST value wins: SDE 9.13.1 pkgsrc/p4-examples/p4_16_programs/
tna_ternary_match/test.py, findHit(), `if priorities[y] < priorities[hit_index]`. Every ternary row carries
one, so correctness never depends on install order (review finding W1). Exact rows carry None.

Table names are the unprefixed control names; the composed program prefixes them (p0.n_Ingress.ports,
p0.r_Egress.conn). Source-level only: no BF Runtime client here.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent / 'protocol'))
import response_path_cp as rp  # noqa: E402

N_ACK_RETURN = 70           # keep equal to make_n.py / make_e.py; G-PORTS unconfirmed
RETURN_PORT = 68
TCP = 6
ANY = (0, 0)
PRIO_NORMALIZE = 1          # wins over the plain route on the master port
PRIO_ROUTE = 100


def n_ports_rows(master_dev, outstation_dev):
    """Every master-side IPv4 TCP packet takes the N_ACK_RETURN lap; everything else routes plainly."""
    def key(port, ip_valid=ANY, proto=ANY):
        return (('ig.ingress_port', port), ('hdr.ip.$valid', ip_valid), ('hdr.ip.proto', proto))
    return check_no_loop([
        ('Ingress.ports', key(master_dev, (1, 1), (TCP, 0xff)), 'Ingress.normalize_ack', (), PRIO_NORMALIZE),
        ('Ingress.ports', key(master_dev), 'Ingress.route', (('port', outstation_dev),), PRIO_ROUTE),
        ('Ingress.ports', key(outstation_dev), 'Ingress.route', (('port', master_dev),), PRIO_ROUTE),
        ('Ingress.ports', key(N_ACK_RETURN), 'Ingress.route', (('port', outstation_dev),), PRIO_ROUTE),
        ('Ingress.ports', key(RETURN_PORT), 'Ingress.route', (('port', RETURN_PORT),), PRIO_ROUTE),
    ])


def n_connection_rows(outstation, master, master_ingress=N_ACK_RETURN):
    """Direction is granted only with port provenance on a packet's FIRST pass: master->outstation only on
    N_ACK_RETURN (where every master packet re-enters after the lap), outstation->master only on the
    outstation's own port. N's later passes arrive on RETURN_PORT and look the direction up again, so both
    directions also have a RETURN_PORT row; RETURN_PORT is reached only by N's own recirculation, which
    starts only after a first pass that matched with provenance (no direction -> guard starts no work).
    master_ingress is N_ACK_RETURN on the target; source-level tests that inject the master's packets as
    already normalized pass the master's own port."""
    f4 = (('hdr.ip.src', master.ip_int), ('hdr.ip.dst', outstation.ip_int), ('hdr.tcp.sport', master.port),
          ('hdr.tcp.dport', outstation.port))
    r4 = (('hdr.ip.src', outstation.ip_int), ('hdr.ip.dst', master.ip_int), ('hdr.tcp.sport', outstation.port),
          ('hdr.tcp.dport', master.port))
    fwd = ('Ingress.forward_flow', (('port', outstation.dev_port),))
    rev = ('Ingress.reverse_flow', (('port', master.dev_port),))
    return check_no_loop(
        [('Ingress.connection', f4 + (('ig.ingress_port', port),)) + fwd + (None,)
         for port in (master_ingress, RETURN_PORT)] +
        [('Ingress.connection', r4 + (('ig.ingress_port', port),)) + rev + (None,)
         for port in (outstation.dev_port, RETURN_PORT)])


def e_conn_rows(slot, outstation, master, pad_enable=True):
    """response_path_cp's E rows with conn bound to egress_port: fwd_conn (outstation -> master, the
    response being padded) only at the master's port, rev_conn (master -> outstation, the ACK being
    reverse-mapped) only at N_ACK_RETURN. odd_ip_t is unchanged."""
    out = []
    for table, key, action, data in rp.connection_entries(slot, outstation, master, pad_enable):
        if table == 'Egress.conn':
            order = ('hdr.ip.src', 'hdr.ip.dst', 'hdr.tcp.sport', 'hdr.tcp.dport')
            port = master.dev_port if action == 'Egress.fwd_conn' else N_ACK_RETURN
            out.append((table, tuple((f, key[f]) for f in order) + (('eg.egress_port', port),), action,
                        tuple(sorted(data.items())), None))
        elif table == 'Egress.odd_ip_t':
            out.append((table, (('hdr.ip.src', key['hdr.ip.src']), ('hdr.ip.dst', key['hdr.ip.dst'])), action,
                        tuple(sorted(data.items())), None))
        # the response path's own Ingress.forwarding rows are not used: N routes pipe 0
    return out


def check_no_loop(rows):
    """Control-plane half of the loop guard (make_n.py edit group 7 is the P4 half): no N row may send a
    packet to N_ACK_RETURN except the master's normalize_ack row, and RETURN_PORT's route must stay on
    RETURN_PORT. Raises ValueError; called by every builder here."""
    for table, key, action, data, _ in rows:
        target = dict(data).get('port')
        if target == N_ACK_RETURN:
            raise ValueError('%s %s targets N_ACK_RETURN' % (table, action))
        port = dict(key).get('ig.ingress_port')
        if table == 'Ingress.ports' and port == RETURN_PORT and target not in (None, RETURN_PORT):
            raise ValueError('RETURN_PORT row must route to RETURN_PORT, not %r' % target)
        if action == 'Ingress.normalize_ack' and port in (N_ACK_RETURN, RETURN_PORT):
            raise ValueError('normalize_ack on a recirculation port')
    return rows


def install_ingress(src, rows):
    """Install N rows into a source-level ExtSource (harness), values in key order."""
    for table, key, action, data, priority in rows:
        src.install(table.split('.', 1)[1], tuple(v for _, v in key), action.split('.', 1)[1],
                    tuple(v for _, v in data), priority=priority)

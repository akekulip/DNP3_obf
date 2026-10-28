"""N and E rows for the physical switch, slot 0 only, built by cp.py (nothing re-derived here).

Each row is a dict: table (full bfrt name), key [(field, value, mask-or-None)], priority, action, data
[(field, value)]. Prefixing follows model_drive_composite.py: 'p0.n_' for N, 'p0.r_' for E.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'model'))
import cp  # noqa: E402  (puts protocol/ on sys.path)
import response_path_cp as rp  # noqa: E402

# vectors.decoy_config() (core/harness/vectors.py): the inert DECOY object (vectors.DECOY, index 201), not the
# real CROB, in the byte order the P4 compares (index 201 = bytes c9 00 = 0xC900).
VECTOR_DECOY = dict(index=51456, code=1, repeat=1, on=0, off=0)


def endpoints(master_ip, master_port, master_dev, relay_ip, relay_port, relay_dev):
    if (master_ip,master_dev,relay_ip,relay_port,relay_dev) != (
            '192.168.10.1',9,'192.168.10.7',20000,64):
        raise ValueError('current installer requires the fixed reciprocal SEL-751 IP pair on dev9/dev64')
    for dev in (master_dev, relay_dev):
        if dev // 128 != 0:
            raise ValueError('dev_port %d is not in pipe 0; N and E run in pipe 0 only' % dev)
    return rp.Endpoint(master_ip, master_port, master_dev), rp.Endpoint(relay_ip, relay_port, relay_dev)


def _convert(prefix, cp_rows):
    out = []
    for table, key, action, data, priority in cp_rows:
        out.append(dict(
            kind='p4', pipe=0xffff, table='p0.%s_%s' % (prefix, table), priority=priority, action='%s_%s' % (prefix, action),
            key=[(f, v[0], v[1]) if isinstance(v, tuple) else (f, v, None) for f, v in key],
            data=list(data)))
    return out


def _uses(rows, port):
    return any(port in (v[0] if isinstance(v, tuple) else v for _f, v in key) or port in dict(data).values()
               for _t, key, _a, data, _p in rows)


def build(master, outstation, decoy, ports, read_dst=0x0000, read_src=0x0100, pad_enable=True):
    """Every N/E row the model driver installs for connection A, with these endpoints and the BUILD's ports.

    N's ACK lap port goes to every cp.py builder as n_ack_return= (cp.py's interface since port_map.py).
    RETURN_PORT is not a parameter of cp.py, so the build must use cp.py's. The rows are then checked to
    really use the build's lap port, so a cp.py that stops honouring the argument fails here instead of
    installing rows for another port."""
    # One reciprocal IP pair while N state is retained. The campaign cold-starts
    # the program before a fresh binding; arbitrary live BFRT rebinding is unsupported.
    endpoints(master.ip,master.port,master.dev_port,outstation.ip,outstation.port,outstation.dev_port)
    ack = ports['n_ack_return']
    if ports['return_port'] != cp.RETURN_PORT:
        raise ValueError("build's RETURN_PORT %d is not cp.py's %d" % (ports['return_port'], cp.RETURN_PORT))
    n_rows = (cp.n_ports_rows(master.dev_port, outstation.dev_port, master.ip_int, outstation.ip_int, n_ack_return=ack)
              + cp.n_connection_rows(outstation, master, n_ack_return=ack)
              + cp.n_read_rows(outstation, master, read_dst, read_src))
    fwd4 = (('hdr.ip.src', master.ip_int), ('hdr.ip.dst', outstation.ip_int),
            ('hdr.tcp.sport', master.port), ('hdr.tcp.dport', outstation.port))
    rev4 = (('hdr.ip.src', outstation.ip_int), ('hdr.ip.dst', master.ip_int),
            ('hdr.tcp.sport', outstation.port), ('hdr.tcp.dport', master.port))
    dc = tuple((k, decoy[k]) for k in ('index', 'code', 'repeat', 'on', 'off'))
    n_rows += [('Ingress.data_connection', k, 'Ingress.configure', dc, None) for k in (fwd4, rev4)]
    # pad_enable -> the Egress.conn fwd_conn row's `enable`: 0 keeps the mapper armed and translating but
    # grows nothing (the policy-off control); 1 pads (the default, unchanged).
    e_rows = cp.e_conn_rows(0, outstation, master, pad_enable=bool(pad_enable), n_ack_return=ack)
    cp.check_no_loop(n_rows + e_rows, n_ack_return=ack)          # the control-plane loop guard, over every row
    default = cp.N_ACK_RETURN
    stale = default not in (ack, master.dev_port, outstation.dev_port, cp.RETURN_PORT) and _uses(n_rows + e_rows, default)
    if stale or not _uses(n_rows, ack) or not _uses(e_rows, ack):
        raise ValueError("cp.py's rows do not use the build's N_ACK_RETURN %d (default %d still used: %s): "
                         'rows.py must follow cp.py' % (ack, default, stale))
    return _convert('n', n_rows) + _convert('r', e_rows)

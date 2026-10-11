"""N and E rows for the physical switch, slot 0 only, built by cp.py (nothing re-derived here).

Each row is a dict: table (full bfrt name), key [(field, value, mask-or-None)], priority, action, data
[(field, value)]. Prefixing follows model_drive_composite.py: 'p0.n_' for N, 'p0.r_' for E.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import cp  # noqa: E402  (puts protocol/ on sys.path)
import response_path_cp as rp  # noqa: E402

# vectors.decoy_config() (core/harness/vectors.py): the inert DECOY object (vectors.DECOY, index 201), not the
# real CROB, in the byte order the P4 compares (index 201 = bytes c9 00 = 0xC900).
VECTOR_DECOY = dict(index=51456, code=1, repeat=1, on=0, off=0)


def endpoints(master_ip, master_port, master_dev, relay_ip, relay_port, relay_dev):
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


def build(master, outstation, decoy, read_dst=0x0000, read_src=0x0100):
    """Every N/E row the model driver installs for connection A, with these endpoints."""
    n_rows = (cp.n_ports_rows(master.dev_port, outstation.dev_port, master.ip_int, outstation.ip_int)
              + cp.n_connection_rows(outstation, master)
              + cp.n_read_rows(outstation, master, read_dst, read_src))
    fwd4 = (('hdr.ip.src', master.ip_int), ('hdr.ip.dst', outstation.ip_int),
            ('hdr.tcp.sport', master.port), ('hdr.tcp.dport', outstation.port))
    rev4 = (('hdr.ip.src', outstation.ip_int), ('hdr.ip.dst', master.ip_int),
            ('hdr.tcp.sport', outstation.port), ('hdr.tcp.dport', master.port))
    dc = tuple((k, decoy[k]) for k in ('index', 'code', 'repeat', 'on', 'off'))
    n_rows += [('Ingress.data_connection', k, 'Ingress.configure', dc, None) for k in (fwd4, rev4)]
    e_rows = cp.e_conn_rows(0, outstation, master)
    cp.check_no_loop(n_rows + e_rows)          # the control-plane loop guard, over every row
    return _convert('n', n_rows) + _convert('r', e_rows)

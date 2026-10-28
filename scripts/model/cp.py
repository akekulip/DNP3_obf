"""Candidate rows: baseline N rows plus qualified reverse commits at relay E."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

_path = Path(__file__).resolve().parent / 'cp_base.py'
_spec = importlib.util.spec_from_file_location('rearm_baseline_cp', _path)
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

# Preserve all baseline exports for installer and driver compatibility.
for _name in dir(base):
    if not _name.startswith('_'):
        globals()[_name] = getattr(base, _name)

def e_conn_rows(slot, outstation, master, pad_enable=True, n_ack_return=None):
    rows = base.e_conn_rows(slot, outstation, master, pad_enable, n_ack_return)
    reverse = next(row for row in rows if row[2] == 'Egress.rev_conn')
    table, keys, action, data, priority = reverse
    commit = (table, tuple((name, outstation.dev_port if name == 'eg.egress_port' else value)
                          for name, value in keys), action, data, priority)
    if commit not in rows:
        rows.append(commit)
    return rows


def p1_pad_rows(outstation, master, pad_enable=True):
    """Pipe-1 egress size enable for builds with the read_complete_01 pipe-1 READ padder (their inputs.json
    declares policy.p1_read_pad_conn_table): one p1_conn row for the outstation -> master connection, installed
    exactly when E's fwd_conn row enables padding (pad_enable), so a size-off arm or a native connection is
    never padded in pipe 1. Fully qualified (pipe-1 table), unlike e_conn_rows."""
    if not pad_enable:
        return []
    key = (('hdr.ip.src', outstation.ip_int), ('hdr.ip.dst', master.ip_int),
           ('hdr.tcp.sport', outstation.port), ('hdr.tcp.dport', master.port))
    return [('p1.x_Egress.p1_conn', key, 'x_Egress.p1_pad_ok', (), None)]

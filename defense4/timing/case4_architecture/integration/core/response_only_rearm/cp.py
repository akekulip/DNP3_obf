"""Candidate rows: baseline N rows plus qualified reverse commits at relay E."""
import importlib.util
from pathlib import Path

_path = Path(__file__).resolve().parent.parent / 'response_only' / 'cp.py'
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

"""BFRT adapter implementing the active_control `Device` protocol (write, read).

Handles are injected: `gc` (bfrt_grpc.client), `bfrt_info`, `target`. That keeps the module importable and
testable anywhere; on the switch host `connect()` builds the handles through the repository's own loader.
Writes are refused unless the caller says hardware writes are authorised, and every write is validated
against the compiled schema first. Reads never write. Nothing here can touch a table the schema lacks.
"""
import os

from schema import Schema, SchemaError

AUTH_ENV = "DEFENSE4_HW_AUTHORIZED"       # same variable latency_search/configure.py enforces


class WriteRefused(RuntimeError):
    pass


class BfrtDevice:
    def __init__(self, schema, gc, bfrt_info, target, *, authorized=None):
        self.schema, self.gc, self.info, self.target = schema, gc, bfrt_info, target
        self.authorized = (os.environ.get(AUTH_ENV) == "1") if authorized is None else bool(authorized)
        self.log = []                                       # every call, in order, for the run record

    def _table(self, name):
        return self.info.table_get(self.schema.full_name(name))

    def write(self, table, fields):
        if not self.authorized:
            raise WriteRefused("refusing a hardware write without %s=1" % AUTH_ENV)
        full, action, data = self.schema.check_write(table, fields)      # raises before any device call
        t = self.info.table_get(full)
        t.default_entry_set(self.target, t.make_data([self.gc.DataTuple(k, v) for k, v in data.items()], action))
        self.log.append(("write", full, action, dict(data)))

    def read(self, table):
        """The default entry as {action_name, field: int}; empty dict if the device returns nothing."""
        full = self.schema.full_name(table)
        t = self.info.table_get(full)
        got = None
        for item in t.default_entry_get(self.target, {"from_hw": True}):
            data = item[0] if isinstance(item, tuple) else item
            if data is not None:
                got = data.to_dict()
        out = dict(got or {})
        out.pop("is_default_entry", None)
        self.log.append(("read", full))
        return out


def connect(control_dir, schema_path):
    """On the switch host only: build the injected handles with the repository's own loader."""
    from pathlib import Path
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "latency_search"))
    import configure                                          # noqa: WPS433  (same checkout, not a copy)
    gc, interface, bfrt_info, target = configure._load_bfrt(Path(control_dir))
    return BfrtDevice(Schema.from_file(schema_path), gc, bfrt_info, target), interface

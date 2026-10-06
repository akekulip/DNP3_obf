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
    def __init__(self, schema, gc, bfrt_info, target, *, authorized=None, loaded_identity=None):
        self.schema, self.gc, self.info, self.target = schema, gc, bfrt_info, target
        self.authorized = (os.environ.get(AUTH_ENV) == "1") if authorized is None else bool(authorized)
        # A schema file alone cannot establish which source/artifacts are loaded.
        # Only the separately verified loader may supply this identity. Historical
        # three-default paths keep their existing interface; joint activation
        # refuses absent current loaded-program evidence.
        self.loaded_identity = dict(loaded_identity or {})
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

    def _key(self, operation):
        return self._table(operation.table).make_key([
            self.gc.KeyTuple(name, value['value'], **{k:v for k,v in value.items() if k != 'value'})
            if isinstance(value, dict) else self.gc.KeyTuple(name, value)
            for name, value in operation.key.items()])

    def read_operation(self, operation):
        operation = self.schema.check_operation(operation)
        if operation.kind == 'default':
            return self.read(operation.table) or None
        table = self._table(operation.table)
        rows = list(table.entry_get(self.target, [self._key(operation)], {'from_hw': True}))
        if not rows:
            return None
        if len(rows) != 1:
            raise SchemaError('operation read returned multiple entries; refusing ambiguous state')
        data = rows[0][0].to_dict()
        data.pop('is_default_entry', None)
        # Register reads may contain one value per pipe. Only identical banks
        # can be represented by this target's scalar write; never pick a pipe.
        for name, value in list(data.items()):
            if isinstance(value, list):
                if not value or any(item != value[0] for item in value):
                    raise SchemaError('per-pipe register values differ; an explicit pipe mapping is required')
                data[name] = value[0]
        self.log.append(('read_entry', operation.table, dict(operation.key)))
        return data

    def write_operation(self, operation):
        if not self.authorized:
            raise WriteRefused('refusing a hardware mutation without %s=1' % AUTH_ENV)
        operation = self.schema.check_operation(operation)
        if operation.kind == 'default':
            self.write(operation.table, operation.fields)
            return
        table = self._table(operation.table)
        fields = dict(operation.fields)
        action = fields.pop('action_name', None)
        tuples = [self.gc.DataTuple(name, bool_val=value) if isinstance(value, bool) else
                  self.gc.DataTuple(name, str_val=value) if isinstance(value, str) else
                  self.gc.DataTuple(name, value) for name, value in fields.items()]
        data = table.make_data(tuples, action) if action is not None else table.make_data(tuples)
        exists = self.read_operation(operation) is not None
        method = table.entry_mod if exists else table.entry_add
        method(self.target, [self._key(operation)], [data])
        self.log.append(('write_entry', operation.table, dict(operation.key), dict(operation.fields)))

    def delete_operation(self, operation):
        if not self.authorized:
            raise WriteRefused('refusing a hardware deletion without %s=1' % AUTH_ENV)
        operation = self.schema.check_operation(operation)
        if operation.kind != 'entry':
            raise SchemaError('only a formerly absent keyed entry may be removed during restoration')
        self._table(operation.table).entry_del(self.target, [self._key(operation)])
        self.log.append(('delete_entry', operation.table, dict(operation.key)))


def connect(control_dir, schema_path):
    """On the switch host only: build the injected handles with the repository's own loader."""
    from pathlib import Path
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "latency_search"))
    import configure                                          # noqa: WPS433  (same checkout, not a copy)
    gc, interface, bfrt_info, target = configure._load_bfrt(Path(control_dir))
    return BfrtDevice(Schema.from_file(schema_path), gc, bfrt_info, target), interface

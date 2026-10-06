"""Schema index over a compiled bfrt.json. Every adapter write is checked against the build's own schema,
never against a field list copied from another build (the frozen build's tbl_params differs)."""
from __future__ import annotations
import json
import hashlib
from dataclasses import dataclass, replace
from pathlib import Path


class SchemaError(ValueError):
    pass


@dataclass(frozen=True)
class WriteOperation:
    table: str
    fields: dict
    key: dict | None = None
    kind: str = 'default'
    phase: str = 'configure'
    role: str = ''


def _width(spec):
    t = spec.get("type", {})
    if t.get("width") is not None:
        return int(t["width"])
    kind = t.get("type", "")
    if kind.startswith("uint"):
        return int(kind[4:])
    if kind == 'bool':
        return 1
    raise SchemaError("field %r has no usable width: %r" % (spec.get("name"), t))


class Schema:
    PREFIX = "pipe.Ingress."

    def __init__(self, doc, *, sha256=None):
        self.tables = {t["name"]: t for t in doc["tables"]}
        self.sha256 = sha256 or hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    @classmethod
    def from_file(cls, path):
        raw = Path(path).read_bytes()
        return cls(json.loads(raw), sha256=hashlib.sha256(raw).hexdigest())

    def full_name(self, table):
        name = table if table in self.tables or table.startswith("pipe.") else self.PREFIX + table
        if name not in self.tables:
            raise SchemaError("table %r is not in the compiled schema" % table)
        return name

    def actions(self, table):
        return {a["name"]: {(d.get("singleton", d))["name"]: _width(d.get("singleton", d)) for d in a.get("data", [])}
                for a in self.tables[self.full_name(table)].get("action_specs", [])}

    def has_field(self, table, name):
        return any(name in fields for fields in self.actions(table).values())

    def check_write(self, table, fields):
        """Return (full table name, action, data) or raise. Exactly the action's fields, in range."""
        fields = dict(fields)
        action = fields.pop("action_name", None)
        if action is None:
            raise SchemaError("write to %s names no action" % table)
        spec = self.actions(table)
        if action not in spec:
            raise SchemaError("%s has no action %r (has %s)" % (table, action, sorted(spec)))
        want = spec[action]
        if set(fields) != set(want):
            raise SchemaError("%s.%s fields %s differ from the schema's %s"
                              % (table, action, sorted(fields), sorted(want)))
        for k, v in fields.items():
            if isinstance(v, bool) or not isinstance(v, int) or not (0 <= v < (1 << want[k])):
                raise SchemaError("%s.%s.%s = %r does not fit %d bits" % (table, action, k, v, want[k]))
        return self.full_name(table), action, fields

    @staticmethod
    def _value(name, value, spec):
        kind = spec.get('type', {}).get('type', '')
        if kind == 'bool':
            if not isinstance(value, bool):
                raise SchemaError(name + ' requires a boolean')
        elif kind == 'string':
            if not isinstance(value, str) or not value:
                raise SchemaError(name + ' requires a nonempty string')
            choices = spec.get('type', {}).get('choices')
            if choices is not None and value not in choices:
                raise SchemaError(name + ' is outside the schema enum')
        elif isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << _width(spec):
            raise SchemaError(name + ' is outside the schema width')

    def check_operation(self, operation):
        """Validate one whole default/keyed/register mutation against this schema."""
        if not isinstance(operation, WriteOperation):
            raise SchemaError('mutation must be a WriteOperation')
        if operation.kind not in ('default', 'entry', 'register'):
            raise SchemaError('unsupported mutation kind')
        full = self.full_name(operation.table)
        table = self.tables[full]
        fields = dict(operation.fields)
        if (operation.kind == 'register') != (table.get('table_type') == 'Register'):
            if operation.kind == 'register' or table.get('table_type') == 'Register':
                raise SchemaError('register mutation kind must match the compiled Register table')
        if operation.kind == 'default':
            if operation.key is not None:
                raise SchemaError('default mutation must not supply an entry key')
            self.check_write(full, fields)
            return replace(operation, table=full, fields=fields)
        want_keys = {s['name']: s for s in table.get('key', [])}
        key = dict(operation.key or {})
        if not want_keys or set(key) != set(want_keys):
            raise SchemaError(full + ' mutation keys differ from the compiled schema')
        for name, spec in want_keys.items():
            match = spec.get('match_type', 'Exact').lower()
            value = key[name]
            if match == 'exact':
                self._value(name, value, spec)
            elif match in ('ternary', 'lpm'):
                expected = {'value', 'mask' if match == 'ternary' else 'prefix_len'}
                if not isinstance(value, dict) or set(value) != expected:
                    raise SchemaError(name + ' requires its explicit match parameters')
                self._value(name, value['value'], spec)
                if match == 'ternary':
                    self._value(name, value['mask'], spec)
                elif (isinstance(value['prefix_len'], bool) or not isinstance(value['prefix_len'], int)
                      or not 0 <= value['prefix_len'] <= _width(spec)):
                    raise SchemaError(name + ' has an invalid prefix length')
            else:
                raise SchemaError('unsupported key match kind: ' + match)
        if table.get('action_specs'):
            if operation.kind == 'register':
                raise SchemaError('register mutation cannot write an action table')
            self.check_write(full, fields)
        else:
            specs = {s['name']: s for field in table.get('data', [])
                     for s in [field.get('singleton', field)] if not s.get('read_only', False)}
            if not fields or not set(fields) <= set(specs):
                raise SchemaError(full + ' fields differ from the compiled writable data')
            required = set(specs) if operation.kind == 'register' else {
                name for name, spec in specs.items() if spec.get('mandatory', False)}
            if not required <= set(fields):
                raise SchemaError(full + ' mutation omits required data')
            for name, value in fields.items():
                self._value(name, value, specs[name])
        return replace(operation, table=full, key=key, fields=fields)

    def check_operations(self, operations):
        """Validate the complete inventory before a caller touches the device."""
        return tuple(self.check_operation(operation) for operation in operations)

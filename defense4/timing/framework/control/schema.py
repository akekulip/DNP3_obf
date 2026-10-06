"""Schema index over a compiled bfrt.json. Every adapter write is checked against the build's own schema,
never against a field list copied from another build (the frozen build's tbl_params differs)."""
import json
from pathlib import Path


class SchemaError(ValueError):
    pass


def _width(spec):
    t = spec.get("type", {})
    if t.get("width") is not None:
        return int(t["width"])
    kind = t.get("type", "")
    if kind.startswith("uint"):
        return int(kind[4:])
    raise SchemaError("field %r has no usable width: %r" % (spec.get("name"), t))


class Schema:
    PREFIX = "pipe.Ingress."

    def __init__(self, doc):
        self.tables = {t["name"]: t for t in doc["tables"]}

    @classmethod
    def from_file(cls, path):
        return cls(json.loads(Path(path).read_text()))

    def full_name(self, table):
        name = table if table.startswith("pipe.") else self.PREFIX + table
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

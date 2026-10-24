"""Read N's const profiles after normal smoke setup and before its first packet.

Run through record_closure.py in launch_model.sh. No table writes are added:
the only writes are the unmodified smoke driver's ordinary setup.
"""
import hashlib
import importlib.util
import json
import os
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
CTL = HERE.parents[1]
TABLES = ('p0.n_Ingress.profile', 'p0.n_Ingress.response_profile')


def json_value(value):
    if isinstance(value, bytes):
        return dict(bytes_hex=value.hex())
    return str(value)


def dump_profiles(model):
    build = Path(os.environ['PORT_MAP']).resolve().parent
    context_path = build / 'compile_local/out/p0/context.json'
    schema_path = build / 'compile_local/out/bfrt.json'
    context = json.loads(context_path.read_text())
    schema = json.loads(schema_path.read_text())
    record = dict(stage='after_normal_smoke_setup_before_first_packet', readonly_diagnostic=True,
                  model_grpc=model.grpc, program=model.prog, pipe_id=model.target.pipe_id_,
                  setup_calls=model.diagnostic_setup_calls, tables={}, errors=[])
    record['artifact_sha256'] = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                                 for path in (context_path, schema_path, build / 'response_only.p4')}
    for name in TABLES:
        short = name.split('.', 1)[1]
        expected = next(table for table in context['tables'] if table['name'] == short)
        descriptor = next(table for table in schema['tables'] if table['name'] == name)
        item = dict(expected_match_fields=expected['match_key_fields'],
                    expected_static_entries=expected['static_entries'],
                    expected_actions=[dict(name=action['name'], handle=action['handle'])
                                      for action in expected['actions']],
                    bfrt_schema=descriptor, reads={})
        record['tables'][name] = item
        for from_hw in (False, True):
            read = dict(from_hw=from_hw, entries=[])
            item['reads']['hardware' if from_hw else 'software'] = read
            try:
                table = model.table(name)
                # SDK entry_get documents an empty key list as a wildcard read.
                for data, key in table.entry_get(model.target, [], {'from_hw': from_hw}):
                    read['entries'].append(dict(key=key.to_dict(), data=data.to_dict()))
                read['entry_count'] = len(read['entries'])
            except Exception as error:
                read['error'] = dict(type=type(error).__name__, message=str(error),
                                     traceback=traceback.format_exc())
                record['errors'].append(dict(table=name, from_hw=from_hw, **read['error']))
                print('PROFILE_DIAGNOSTIC_READ_ERROR %s from_hw=%s: %s' % (name, from_hw, error),
                      file=sys.stderr, flush=True)
    destination = Path(os.environ['OUT']) / 'profile_table_readback.json'
    destination.write_text(json.dumps(record, indent=1, default=json_value) + '\n')
    print('PROFILE_DIAGNOSTIC_RETAINED %s (%d read errors)' % (destination, len(record['errors'])), flush=True)
    return record


def main():
    if Path(os.environ['PORT_MAP']).resolve().parent != HERE:
        raise ValueError('this retained diagnostic requires the unchanged c48 build')
    target = CTL.parent / 'seg61_02/model_smoke.py'
    spec = importlib.util.spec_from_file_location('_c48_exact_smoke', target)
    smoke = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = smoke
    spec.loader.exec_module(smoke)
    original_load = smoke.load
    observations = []

    def load(name, path):
        module = original_load(name, path)
        if name == '_seg61_helpers':
            original_model = module.Model

            class DiagnosticModel(original_model):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.diagnostic_setup_calls = []
                    self.diagnostic_read_done = False

                def add(self, table, *args, **kwargs):
                    self.diagnostic_setup_calls.append(dict(operation='add', table=table, args=args, kwargs=kwargs))
                    return super().add(table, *args, **kwargs)

                def set_default(self, table, *args, **kwargs):
                    self.diagnostic_setup_calls.append(dict(operation='set_default', table=table, args=args, kwargs=kwargs))
                    return super().set_default(table, *args, **kwargs)

                def clear(self, table):
                    self.diagnostic_setup_calls.append(dict(operation='clear', table=table))
                    return super().clear(table)

                def exchange(self, *args, **kwargs):
                    if not self.diagnostic_read_done:
                        self.diagnostic_read_done = True
                        observations.append(dump_profiles(self))
                    return super().exchange(*args, **kwargs)

            module.Model = DiagnosticModel
        return module

    smoke.load = load
    result = smoke.main()
    return result or int(not observations or bool(observations[0]['errors']))


if __name__ == '__main__':
    raise SystemExit(main())

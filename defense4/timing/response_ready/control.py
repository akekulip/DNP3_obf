#!/usr/bin/env python3
"""Candidate-only configuration. Planning and file auditing never contact hardware."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from defense4.timing.latency_search import configure, policy

PARAMS = configure.PARAMS_TABLE
BOR = configure.BOR_PARAMS_TABLE
RANDOM = configure.CODEBOOK_TABLE
RELEASE = 'pipe.Ingress.tbl_read_release_params'


def build_plan(da_ms, enabled=1):
    if da_ms not in (5, 10, 15, 20) or type(enabled) is not int or enabled not in (0, 1):
        raise ValueError('expected DA 5/10/15/20 and enabled 0/1')
    a, g = policy.quantize_ms(da_ms), policy.quantize_ms(1)
    return {'da_ms': da_ms, 'requested_gap_ms': 1, 'realized_gap_ms': g.realized_ms,
            'random_entries': [], 'defaults': {
                PARAMS: dict(action_name='Ingress.set_params', mode=4, d_ticks=a.word,
                             da_dr=a.word + g.word, budget=18000, read_len=0),
                BOR: dict(action_name='Ingress.set_bor_params', a_ticks=a.word,
                          r_ticks=a.word + g.word, anchor_req=1),
                RELEASE: dict(action_name='Ingress.set_read_release', enabled=enabled, gap_ticks=g.word)}}


def validate_schema(schema):
    tables = [t for t in schema['tables'] if t['name'] == RELEASE]
    if len(tables) != 1:
        raise ValueError('candidate release table missing or duplicated')
    actions = tables[0].get('action_specs', [])
    actions = [a for a in actions if a['name'] == 'Ingress.set_read_release']
    if len(actions) != 1:
        raise ValueError('candidate release action missing or duplicated')
    fields = actions[0].get('data', [])
    widths = {}
    for raw in fields:
        f = raw.get('singleton', raw)
        typ = f.get('type', {})
        if f['name'] in widths:
            raise ValueError('duplicate release field')
        width = typ.get('width')
        # BFRT emits uint types both with and without an explicit width.
        if width is None and typ.get('type', '').startswith('uint'):
            width = int(typ['type'][4:])
        if typ.get('type') not in ('uint8', 'uint32', 'bytes'):
            raise ValueError('unexpected release field type')
        widths[f['name']] = width
    if widths != {'enabled': 8, 'gap_ticks': 32}:
        raise ValueError('release field names/widths do not match candidate')


def validate_plan(plan):
    try:
        expected = build_plan(plan['da_ms'], plan['defaults'][RELEASE]['enabled'])
    except (KeyError, TypeError) as exc:
        raise ValueError('malformed plan') from exc
    if plan != expected:
        raise ValueError('plan differs from fixed approved candidate configuration')


def audit_readback(snapshot, plan):
    validate_plan(plan)
    tables = snapshot.get('tables', {})
    if tables.get(RANDOM, {}).get('entries') != []:
        raise ValueError('random override entries must be explicitly empty')
    for name, expected in plan['defaults'].items():
        raw = tables.get(name, {}).get('default')
        if isinstance(raw, list):
            if len(raw) != 1:
                raise ValueError('expected exactly one default for ' + name)
            raw = raw[0]
        if isinstance(raw, dict) and 'data' in raw:
            raw = raw['data']
        if not isinstance(raw, dict):
            raise ValueError('missing default for ' + name)
        if raw.get('action_name') != expected['action_name']:
            raise ValueError('wrong/missing action for ' + name)
        if set(raw) - {'is_default_entry'} != set(expected):
            raise ValueError('unexpected/missing fields for ' + name)
        for field, val in expected.items():
            if raw[field] != val or (field != 'action_name' and type(raw[field]) is not int):
                raise ValueError('readback mismatch: ' + name + '.' + field)
    return {'verified': True, 'da_ms': plan['da_ms'], 'random_override_entries': 0}


def apply_live(plan, drained_trial_signoff, backup, control_dir=configure.DEFAULT_CONTROL_DIR):
    configure._require_authorized()
    if not drained_trial_signoff:
        raise RuntimeError('drained-trial signoff is required before configuration changes')
    validate_plan(plan)
    if backup is None:
        raise ValueError('fresh backup path required')
    backup = Path(backup)
    if backup.exists():
        raise FileExistsError(backup)
    gc, interface, info, target = configure._load_bfrt(Path(control_dir))
    try:
        tables = {n: info.table_get(n) for n in (*plan['defaults'], RANDOM)}
        release_info = tables[RELEASE].info
        action = 'Ingress.set_read_release'
        if release_info.name_get() != RELEASE or action not in release_info.action_name_list_get():
            raise ValueError('live pipeline lacks exact candidate release table/action')
        if set(release_info.data_field_name_list_get(action)) != {'enabled', 'gap_ticks'}:
            raise ValueError('live candidate release fields mismatch')
        for field, bits in (('enabled', 8), ('gap_ticks', 32)):
            if release_info.data_field_size_get(field, action) != ((bits + 7)//8, bits):
                raise ValueError('live candidate release field width mismatch')
        def snapshot():
            result = {'tables': {}}
            for n, t in tables.items():
                if n == RANDOM:
                    result['tables'][n] = {'entries': [{'data': d.to_dict(), 'key': k.to_dict()} for d,k in t.entry_get(target, flags={'from_hw': True})]}
                else:
                    result['tables'][n] = {'default': [configure._read_default_dict(t, target)]}
            return result
        before = snapshot()
        with backup.open('x', encoding='utf-8') as stream:
            json.dump(before, stream, indent=2)
        # The caller has stopped traffic and confirmed that token state is drained.
        # Disarm candidate first; re-enable only after all legacy settings are installed.
        release = tables[RELEASE]
        release.default_entry_set(target, release.make_data([gc.DataTuple('enabled', 0), gc.DataTuple('gap_ticks', plan['defaults'][RELEASE]['gap_ticks'])], 'Ingress.set_read_release'))
        keys = [k for _, k in tables[RANDOM].entry_get(target, flags={'from_hw': True})]
        if keys:
            tables[RANDOM].entry_del(target, keys)
        for name, values in plan['defaults'].items():
            tables[name].default_entry_set(target, tables[name].make_data([gc.DataTuple(k,v) for k,v in values.items() if k != 'action_name'], values['action_name']))
        after = snapshot()
        audit_readback(after, plan)
        return after
    finally:
        interface.tear_down_stream()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--da-ms', type=int, choices=(5,10,15,20), required=True)
    ap.add_argument('--enabled', type=int, choices=(0,1), default=1)
    ap.add_argument('--schema', type=Path)
    ap.add_argument('--readback', type=Path)
    ap.add_argument('--apply', action='store_true')
    ap.add_argument('--drained-trial-signoff', action='store_true')
    ap.add_argument('--backup', type=Path)
    ap.add_argument('--control-dir', type=Path, default=configure.DEFAULT_CONTROL_DIR)
    ap.add_argument('--output', type=Path)
    args = ap.parse_args(argv)
    plan = build_plan(args.da_ms, args.enabled)
    if args.schema:
        validate_schema(json.loads(args.schema.read_text()))
    result = plan
    if args.readback:
        result = audit_readback(json.loads(args.readback.read_text()), plan)
    if args.apply:
        result = apply_live(plan, args.drained_trial_signoff, args.backup, args.control_dir)
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end='')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

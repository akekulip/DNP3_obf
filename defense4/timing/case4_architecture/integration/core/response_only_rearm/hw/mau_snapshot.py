"""Diagnostic MAU snapshot of N ingress (BF Runtime p0.snapshot.* fixed tables). No forwarding change.

Spec "start=0,end=10,m.packet_kind=9/0xff,m.lap=1/1,m.stage=0/3": stage range and stage-start trigger
fields (value/mask). Field names are checked against the loaded build's p0.snapshot.ingress_trigger schema.
Measured on the 9.13.2 model (model_mau_probe): ig.ingress_port is live in no stage and cannot trigger;
m.lap marks N's post-lap parse. The snapshot is deleted through the all-pipes target only.
arm() creates the snapshot and enables the trigger; read() records its state and every stage's data, then
deletes the snapshot so nothing is left configured.
"""
import json
from pathlib import Path

CFG, TRIGGER, DATA = 'p0.snapshot.cfg', 'p0.snapshot.ingress_trigger', 'p0.snapshot.ingress_data'


def parse(spec):
    out = dict(start=None, end=None, trigger={})
    for part in filter(None, spec.split(',')):
        name, _, value = part.partition('=')
        if name in ('start', 'end'):
            out[name] = int(value, 0)
            continue
        if '/' not in value:
            raise ValueError('trigger %s needs value/mask' % name)
        val, mask = (int(v, 0) for v in value.split('/'))
        if val & ~mask:
            raise ValueError('trigger %s value has bits outside its mask' % name)
        out['trigger'][name] = (val, mask)
    if out['start'] is None or out['end'] is None or not 0 <= out['start'] <= out['end'] <= 11 or not out['trigger']:
        raise ValueError('spec needs start<=end in 0..11 and at least one trigger field: %r' % spec)
    return out


def trigger_widths(bfrt_json):
    """{field: bit width} of the build's ingress trigger fields."""
    tables = {t['name']: t for t in json.loads(Path(bfrt_json).read_text())['tables']}
    widths = {}
    for item in tables[TRIGGER]['data']:
        field = item.get('singleton', item)
        if field['name'].startswith('trig.') and not field['name'].endswith('_mask'):
            widths[field['name'][5:]] = field['type']['width']
    return widths


def encode(value, width):
    return bytearray(value.to_bytes((width + 7) // 8, 'big'))


def arm(sw, spec, bfrt_json):
    widths = trigger_widths(bfrt_json)
    unknown = sorted(set(spec['trigger']) - set(widths))
    if unknown:
        raise ValueError('not snapshot trigger fields of this build: %s' % unknown)
    for name, (value, mask) in spec['trigger'].items():
        if mask >> widths[name]:
            raise ValueError('trigger %s mask wider than %d bits' % (name, widths[name]))
    cfg, trigger = sw.table(CFG), sw.table(TRIGGER)
    target = sw.target(0)
    cfg.entry_add(target, [sw.key(cfg, [('start_stage', spec['start'], None), ('end_stage', spec['end'], None)])],
                  [sw.data(cfg, [('thread', 'INGRESS')])])
    fields = [('enable', True)]
    for name, (value, mask) in sorted(spec['trigger'].items()):
        fields += [('trig.' + name, encode(value, widths[name])), ('trig.%s_mask' % name, encode(mask, widths[name]))]
    trigger.entry_mod(target, [sw.key(trigger, [('stage', spec['start'], None)])], [sw.data(trigger, fields)])
    return dict(armed=True, state=trigger_state(sw, spec))


def trigger_state(sw, spec):
    got = sw.get(TRIGGER, 0, [('stage', spec['start'], None)])
    return None if got is None else got.get('trigger_state')


def read(sw, spec):
    """Snapshot state and per-stage data; the snapshot is deleted afterwards whatever happens."""
    out = dict(state=None, stages={})
    try:
        out['state'] = trigger_state(sw, spec)
        for stage in range(spec['start'], spec['end'] + 1):
            out['stages'][stage] = sw.get(DATA, 0, [('stage', stage, None)])
    finally:
        trigger, cfg = sw.table(TRIGGER), sw.table(CFG)
        try:
            trigger.entry_mod(sw.target(0), [sw.key(trigger, [('stage', spec['start'], None)])],
                              [sw.data(trigger, [('enable', False)])])
        finally:
            cfg.entry_del(sw.target(0xffff), [sw.key(cfg, [('start_stage', spec['start'], None),
                                                           ('end_stage', spec['end'], None)])])
            out['deleted'] = True
    return out

"""RELAY two-READ-target templates from the real SEL-751 captures (Python >= 3.10).

Writes two_read_templates_relay.json in the SAME structure as two_read_templates.json, but sourced from the
physical relay captures (evidence/relay_native_20261024/native_20261024.json) and padded to the relay targets
[141, 158] -- the relay integrity poll answers 134 B (not the software outstation's 247 B). The software
two_read_templates.json is NOT touched; the model driver selects whichever file matches the build's padded
shapes (read_policy_expect.SHAPES).

One relay capture set was taken (mixed + integrity, one admitted connection), so both variants carry the same
bytes (variants_differ all False); a two-variant set would need a second relay capture.

  $RESEARCH_PYTHON make_two_read_templates_relay.py
"""
import hashlib
import importlib.util
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
# reuse derive.py's bound general_read_padding (gp) / dnp3_std (std), exactly as derive_two_read_relay.py does
_spec = importlib.util.spec_from_file_location('_derive_base_tpl', HERE / 'derive.py')
derive = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(derive)
gp, std = derive.gp, derive.std

TARGETS = [141, 158]
PAD_START, PAD_STOP = 1024, 4095
CAPTURES = ROOT / 'evidence/relay_native_20261024/native_20261024.json'
VARIANTS = ('v0', 'v1')


def template(req, native):
    r = gp.pad_read(req, native, TARGETS, pad_start=PAD_START, pad_stop=PAD_STOP)
    return dict(request=req.hex(), request_len=len(req), native=native.hex(), native_len=len(native),
                native_frames=[len(f) for f in gp.split_frames(native)],
                native_tcp=[len(native)],                    # relay response arrives as one TCP segment (capture)
                expected=r.output.hex(), expected_len=len(r.output),
                expected_frames=[len(f) for f in gp.split_frames(r.output)], status=r.status,
                target=r.target, construction=r.construction, padding_points=r.padding_points)


def classes():
    cap = json.loads(CAPTURES.read_text())
    out = {}
    for cls in ('mixed', 'integrity'):
        oks = [t for t in cap['transactions'] if t['workload'] == cls and t['outcome'] == 'OK']
        if not oks:
            raise ValueError('no OK %s transaction in %s' % (cls, CAPTURES))
        t = oks[0]
        out[cls] = template(bytes.fromhex(t['request_hex']), bytes.fromhex(t['response_wire_hex']))
    return out, hashlib.sha256(CAPTURES.read_bytes()).hexdigest()


def main():
    cls, cap_sha = classes()
    doc = dict(source='physical SEL-751 captures (evidence/relay_native_20261024/native_20261024.json)',
               pad_read_sha256=hashlib.sha256((ROOT / 'software/source/full_read_01/general_read_padding.py')
                                              .read_bytes()).hexdigest(),
               targets=TARGETS, reserved=[PAD_START, PAD_STOP], variants={})
    for v in VARIANTS:
        doc['variants'][v] = dict(capture_sha256=cap_sha, classes=cls)
    a, b = (doc['variants'][v]['classes'] for v in VARIANTS)
    doc['variants_differ'] = {c: a[c]['native'] != b[c]['native'] for c in a}
    (HERE / 'two_read_templates_relay.json').write_text(json.dumps(doc, indent=1) + '\n')
    for c, t in cls.items():
        print(c, dict(native_len=t['native_len'], target=t['target'], points=t['padding_points'],
                      expected_frames=t['expected_frames'], construction=t['construction']))
    print('variants_differ', doc['variants_differ'])


if __name__ == '__main__':
    main()

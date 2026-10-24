"""Switch constants for the RELAY two-READ-target profile (mixed 91 -> 141, integrity 134 -> 158), proved
against the reference encoder AND the real relay captures (evidence/relay_native_20261024/native_20261024.json).

The relay is the outstation (SEL-751, DNP3 addr 0; master addr 1). Its integrity (all-classes) poll answers
134 B, not the software outstation's 247 B, so the full-READ target is 134 -> 158, not 247 -> 271. The mixed
READ is identical to the software profile (91 -> 141). Both natives are single link frames that start with the
same g1v2 q00 [0,15] object header, so the padder discriminates them by link LEN (76 vs 115), exactly as the
software profile discriminates mixed (76) from full (214).

Same construction as derive_two_read.py: general_read_padding.pad_read with reserved indices 1024..4095, the
switch mirror derive.construct must reproduce it byte for byte, and every declared constant must be identical
across 512 natives with every live field varied -- so no constant can depend on a measurement. The derivation
is then tied to the three real relay captures (object layout, request bytes, padded image).

Writes constants_two_read_relay.json. The software constants_two_read.json is not touched.
  $RESEARCH_PYTHON derive_two_read_relay.py
"""
import hashlib
import importlib.util
import json
import pathlib
import random

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('_derive_base', HERE / 'derive.py')
derive = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(derive)
gp, std = derive.gp, derive.std

TARGETS = [141, 158]
PAD_START, PAD_STOP = 1024, 4095
SEED = 0x2ead
N = 512
CAPTURES = (HERE.parent / 'evidence/relay_native_20261024/native_20261024.json')

# (group, variation, start, stop, octets-per-point) in response order, as the master decoded them.
MIXED_OBJECTS = [(1, 2, 0, 15, 1), (30, 1, 0, 7, 5)]
MIXED_REQ_OBJS = bytes.fromhex('010200000f' '1e01000007')            # g1v2 q00 0..15, g30v1 q00 0..7
RELAY_INT_OBJECTS = [(1, 2, 0, 15, 1), (10, 2, 0, 31, 1), (30, 4, 0, 20, 2)]   # relay integrity DB, 134 B
RELAY_INT_REQ_OBJS = bytes.fromhex('3c02063c03063c04063c0106')       # integrity: g60 v2/v3/v4/v1 q06
OSZ = {(1, 2): 1, (10, 2): 1, (30, 1): 5, (20, 1): 5, (30, 4): 2}


def sampler(rng, objects, req_objs, native_len):
    def make():
        seq, appseq = rng.randrange(64), rng.randrange(16)
        iin = bytes([rng.randrange(256), rng.randrange(256)])
        dst, src = rng.randrange(1, 0xfff0), rng.randrange(1, 0xfff0)
        body = b''
        for g, v, lo, hi, osz in objects:
            body += bytes([g, v, 0x00, lo, hi]) + bytes(rng.randrange(256) for _ in range((hi - lo + 1) * osz))
        app = bytes([0xc0 | appseq, 0x81]) + iin + body
        native = std.frame(bytes([0x05, 0x64, 5 + 1 + len(app), 0x44]) + dst.to_bytes(2, 'little') +
                           src.to_bytes(2, 'little'), bytes([std.FIR | std.FIN | seq]) + app)
        assert len(native) == native_len, (len(native), native_len)
        req_user = bytes([0xc0 | ((seq - 1) & 63), 0xc0 | appseq, 0x01]) + req_objs
        req = std.frame(bytes([0x05, 0x64, 5 + len(req_user), 0xc4]) + src.to_bytes(2, 'little') +
                        dst.to_bytes(2, 'little'), req_user)
        return req, native
    return make


def object_headers(app):
    """(g, v, q, start, stop) of every q00 range header in a response APDU."""
    out, p, body = [], 0, app[4:]
    while p < len(body):
        g, v, q, lo, hi = body[p:p + 5]
        assert q == 0x00, q
        n = hi - lo + 1
        out.append((g, v, q, lo, hi)); p += 5 + n * OSZ[(g, v)]
    return out


def derive_shape(name, sample):
    req, native = sample()
    r = gp.pad_read(req, native, TARGETS, pad_start=PAD_START, pad_stop=PAD_STOP)
    assert r.status == 'padded' and r.construction == 'prefix' and r.prefix_frames == 1, (name, vars(r))
    out = gp.split_frames(r.output)
    prefix = out[0]
    _, pu = std.deframe(prefix)
    nhdr, nuser = std.deframe(native)
    added = len(r.output) - len(native)
    c = dict(shape=name, native_total=len(native), native_link_len=native[2], native_ip_len=40 + len(native),
             target=r.target, added=added, padding_points=r.padding_points,
             padding_indices=[PAD_START, PAD_START + r.padding_points - 1],
             padding_object='g1v2 q0x01 (16-bit start/stop), every point octet 0x00 = state 0, flags 0x00',
             frames_out=[len(f) for f in out], prefix_frame_len=len(prefix), prefix_link_len=prefix[2],
             prefix_link_ctrl=prefix[3], prefix_user_len=len(pu),
             padobj_head=pu[5:].hex(), padobj_header=pu[5:12].hex(), block0_tail=pu[5:16].hex(),
             rest=prefix[28:].hex(),
             link_crc_delta=derive.crc_be(prefix, 8) ^ derive.crc_be(native, 8),
             request_len=len(req), request_link_len=req[2], request_ip_len=40 + len(req),
             request_objects=std.deframe(req)[1][3:].hex(),
             response_headers=object_headers(nuser[1:]))
    return c, r


def prove(name, sample):
    c, _ = derive_shape(name, sample)
    for _ in range(N):
        req, native = sample()
        r = gp.pad_read(req, native, TARGETS, pad_start=PAD_START, pad_stop=PAD_STOP)
        assert derive.construct(native, c) == r.output, (name, 'construct differs from pad_read')
        again, _ = derive_shape(name, lambda: (req, native))
        for k in ('prefix_link_len', 'prefix_link_ctrl', 'padobj_head', 'block0_tail', 'rest', 'link_crc_delta',
                  'added', 'padding_points', 'frames_out', 'target', 'native_link_len', 'request_link_len',
                  'request_objects', 'response_headers'):
            assert again[k] == c[k], (name, 'constant depends on live bytes', k, again[k], c[k])
    c['verified_samples'] = N
    return c


def main():
    rng = random.Random(SEED)
    shapes = {
        'mixed_g1v2_g30v1_91': prove('mixed_g1v2_g30v1_91', sampler(rng, MIXED_OBJECTS, MIXED_REQ_OBJS, 91)),
        'integrity_134': prove('integrity_134', sampler(rng, RELAY_INT_OBJECTS, RELAY_INT_REQ_OBJS, 134)),
    }
    # Tie the derivation to the REAL relay captures: object layout, request bytes, and padded image.
    doc_cap = json.loads(CAPTURES.read_text())
    live = {}
    for cls, shape in (('mixed', 'mixed_g1v2_g30v1_91'), ('integrity', 'integrity_134')):
        c = shapes[shape]
        for t in [x for x in doc_cap['transactions'] if x['workload'] == cls and x['outcome'] == 'OK']:
            native = bytes.fromhex(t['response_wire_hex']); req = bytes.fromhex(t['request_hex'])
            assert len(native) == c['native_total'] and native[2] == c['native_link_len'], (cls, 'len/LEN')
            assert std.deframe(req)[1][3:].hex() == c['request_objects'], (cls, 'request objects')
            assert object_headers(std.deframe(native)[1][1:]) == [tuple(h) for h in c['response_headers']], \
                (cls, 'response object layout')
            r = gp.pad_read(req, native, TARGETS, pad_start=PAD_START, pad_stop=PAD_STOP)
            assert derive.construct(native, c) == r.output, (cls, 'construct != captured pad_read')
            assert len(r.output) == c['target'], (cls, 'target')
            live.setdefault('%s' % cls, []).append(hashlib.sha256(native).hexdigest())
    doc = dict(profile='relay two-READ-target (mixed 91 -> 141, integrity 134 -> 158); SEL-751 outstation',
               policy_targets=TARGETS, reserved_range=[PAD_START, PAD_STOP], seed=SEED,
               encoder_sha256=hashlib.sha256((derive.ROOT / 'software/source/full_read_01/general_read_padding.py')
                                             .read_bytes()).hexdigest(),
               captures=str(CAPTURES.relative_to(HERE.parent.parent)),
               captures_sha256=hashlib.sha256(CAPTURES.read_bytes()).hexdigest(),
               note=('Relay integrity answers 134 B (G1V2 0..15 + G10V2 0..31 + G30V4 0..20), not the software '
                     '247 B; 158 is the prefix floor (134 + 24). Derived from real relay captures 2026-10-24.'),
               live_checks={k: {'n': len(v), 'native_sha256': v} for k, v in live.items()}, shapes=shapes)
    (HERE / 'constants_two_read_relay.json').write_text(json.dumps(doc, indent=1) + '\n')
    for name, c in shapes.items():
        print(name, dict(frames_out=c['frames_out'], target=c['target'], points=c['padding_points'],
                         prefix_link_len=hex(c['prefix_link_len']), link_crc_delta=c['link_crc_delta'],
                         rest_len=len(c['rest']) // 2, verified=c['verified_samples']))
    print('live relay captures matched:', {k: len(v) for k, v in live.items()})


if __name__ == '__main__':
    main()

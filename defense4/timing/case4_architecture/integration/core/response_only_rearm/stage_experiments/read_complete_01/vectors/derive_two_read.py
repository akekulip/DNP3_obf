"""Switch constants for the two-READ-target profile (91 -> 141, 247 -> 271), proved against the reference encoder.

Shapes (both single-link-frame natives, both padded by the existing prefix construction):
  mixed_g1v2_g30v1_91   one READ with g1v2 q00 0..15 + g30v1 q00 0..7; native 91 B -> [50, 91] = 141, 26 points
  integrity_247         base-database integrity poll; native 247 B -> [24, 247] = 271, 4 points

For each shape this samples natives with EVERY live field varied (link addresses, transport and application sequence,
IIN, every measurement value and flag octet), pads each with general_read_padding.pad_read(targets=[141, 271],
reserved 1024..4095), and asserts on 512 samples that derive.construct (the P4 action's mirror) reproduces pad_read
byte for byte and that every declared constant is identical across samples -- so no constant can depend on a
measurement. The object layouts are taken from the live captures (two_read_templates.json); the derived construction
is then checked against those captured natives too (both fixture variants).

Writes constants_two_read.json. constants.json and constants_segmented.json are not touched (derive.py is not run).
  $RESEARCH_PYTHON derive_two_read.py
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

TARGETS = [141, 271]
PAD_START, PAD_STOP = 1024, 4095
SEED = 0x2ead
N = 512
TEMPLATES = json.loads((HERE / 'two_read_templates.json').read_text())

# (group, variation, start, stop, object octets) in response order, as the live master decoded them
MIXED_OBJECTS = [(1, 2, 0, 15, 1), (30, 1, 0, 7, 5)]
MIXED_REQ_OBJS = bytes.fromhex('010200000f' '1e01000007')            # g1v2 q00 0..15, g30v1 q00 0..7
FULL_OBJECTS = [(1, 2, 0, 15, 1), (30, 1, 0, 20, 5), (20, 1, 0, 7, 5), (10, 2, 0, 22, 1)]
FULL_REQ_OBJS = bytes.fromhex('3c02063c03063c04063c0106')           # integrity: g60 v2/v3/v4/v1 q06


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
    """(g, v, q, start, stop) of every range header in a response APDU (q00 only, as both shapes use)."""
    out, p, body = [], 0, app[4:]
    while p < len(body):
        g, v, q, lo, hi = body[p:p + 5]
        assert q == 0x00, q
        n = hi - lo + 1
        osz = {(1, 2): 1, (10, 2): 1, (30, 1): 5, (20, 1): 5}[(g, v)]
        out.append((g, v, q, lo, hi)); p += 5 + n * osz
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
             padobj_head=pu[5:].hex(),                      # every prefix user octet after the moved app header
             padobj_header=pu[5:12].hex(),                  # the 7-octet g1v2 q01 start/stop object header
             block0_tail=pu[5:16].hex(),                    # prefix block-0 octets after tp+app (<= 11)
             rest=prefix[28:].hex(),                        # prefix data blocks after block 0, with their CRCs
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
        'integrity_247': prove('integrity_247', sampler(rng, FULL_OBJECTS, FULL_REQ_OBJS, 247)),
    }
    # Tie the derivation to the LIVE captures: object layout, request bytes and padded image of each captured native.
    live = {}
    for variant, rec in TEMPLATES['variants'].items():
        for cls, shape in (('mixed', 'mixed_g1v2_g30v1_91'), ('integrity', 'integrity_247')):
            t, c = rec['classes'][cls], shapes[shape]
            native, req = bytes.fromhex(t['native']), bytes.fromhex(t['request'])
            assert len(native) == c['native_total'] and native[2] == c['native_link_len'], (variant, cls)
            assert std.deframe(req)[1][3:].hex() == c['request_objects'], (variant, cls, 'request objects')
            assert object_headers(std.deframe(native)[1][1:]) == [tuple(h) for h in c['response_headers']], \
                (variant, cls, 'response object layout')
            assert derive.construct(native, c).hex() == t['expected'], (variant, cls, 'construct != captured pad_read')
            live['%s/%s' % (variant, cls)] = dict(native_sha256=hashlib.sha256(native).hexdigest(),
                                                  construct_equals_pad_read=True)
    doc = dict(profile='two-READ-target (mixed 91 -> 141, integrity 247 -> 271)', policy_targets=TARGETS,
               reserved_range=[PAD_START, PAD_STOP], seed=SEED,
               encoder_sha256=hashlib.sha256((derive.ROOT / 'software/source/full_read_01/general_read_padding.py')
                                             .read_bytes()).hexdigest(),
               templates_sha256=hashlib.sha256((HERE / 'two_read_templates.json').read_bytes()).hexdigest(),
               note=('271 is NOT a target of the frozen policy (policy.json: 141/247/401, under which a 247 native is '
                     'already_at_target); this profile declares targets [141, 271] for these two workloads only.'),
               live_checks=live, shapes=shapes)
    (HERE / 'constants_two_read.json').write_text(json.dumps(doc, indent=1) + '\n')
    for name, c in shapes.items():
        print(name, dict(frames_out=c['frames_out'], target=c['target'], points=c['padding_points'],
                         prefix_link_len=hex(c['prefix_link_len']), link_crc_delta=c['link_crc_delta'],
                         rest_len=len(c['rest']) // 2, verified=c['verified_samples']))
    print('live captures matched:', sorted(live))


if __name__ == '__main__':
    main()

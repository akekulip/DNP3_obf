"""Derive the switch's per-shape READ prefix constants from the reference encoder (Python >= 3.10).

For each hardware READ shape of the frozen policy (policy/policy.json) this computes the constants the P4
prefix padder needs, then PROVES on many varied native responses (every transport sequence, varied app
sequence, IIN, point values and link addresses) that the constant-based construction equals
general_read_padding.pad_read byte for byte. Output: constants.json, consumed by make_m12.py (P4 constants)
and by the Python-3.8 model drivers (expected bytes). Nothing here is capture-specific: only the frame
structure (link LEN of the native first frame, application/object layout) selects a shape.

  python3 derive.py            # writes constants.json next to this file
"""
import hashlib
import json
import pathlib
import random
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / 'software/source/full_read_01'))
import general_read_padding as gp  # noqa: E402

std = gp.std
POLICY = json.loads((ROOT / 'policy/policy.json').read_text())
TARGETS = POLICY['selected']['targets']
PAD_START, PAD_STOP = POLICY['profile']['reserved_padding_range']


def crc_be(frame, offset):
    """P4-space value of a wire CRC (P4 reads the little-endian wire octets as a big-endian bit<16>)."""
    return int.from_bytes(frame[offset:offset + 2], 'big')


def construct(native, c):
    """The switch construction from constants only (mirrors the P4 action). native = first link frame
    (+ any further frames, passed through except for the transport octet renumber, which the P4 handles
    per continuation shape)."""
    frames = gp.split_frames(native)
    first = frames[0]
    hdr, user = std.deframe(first)
    tp = user[0]
    seq = tp & 63
    prefix_user = bytes([0x40 | seq]) + user[1:5] + bytes.fromhex(c['padobj_head'])
    prefix = std.frame(hdr[:2] + bytes([c['prefix_link_len']]) + hdr[3:], prefix_user)
    out = [prefix]
    for i, f in enumerate(frames):
        h, u = std.deframe(f)
        th = (u[0] & std.FIN) | (((u[0] & 63) + 1) & 63)
        body = bytes(4) + u[5:] if i == 0 else u[1:]
        out.append(std.frame(h, bytes([th]) + body))
    return b''.join(out)


def derive(shape, sample):
    req, native = sample()
    r = gp.pad_read(req, native, TARGETS, pad_start=PAD_START, pad_stop=PAD_STOP)
    assert r.status == 'padded' and r.construction == 'prefix' and r.prefix_frames == 1, r
    out = gp.split_frames(r.output)
    prefix, cont = out[0], out[1]
    _, pu = std.deframe(prefix)
    c = dict(shape=shape['name'], native_first_link_len=native[2], native_total=len(native), target=r.target,
             added=len(r.output) - len(native), padding_points=r.padding_points,
             prefix_link_len=prefix[2], prefix_frame_len=len(prefix), padobj_head=pu[5:].hex(),
             block0_tail=pu[5:16].hex(),                      # bytes 6..16 of the prefix block 0 (after tp+app)
             rest=prefix[28:].hex(),                          # constant data blocks + their CRCs after block 0
             link_crc_delta=crc_be(prefix, 8) ^ crc_be(native, 8),
             reserved_first_index=PAD_START, frames_out=[len(f) for f in out])
    return c


def range_sample(rng):
    def make():
        seq = rng.randrange(64); appseq = rng.randrange(16)
        iin = bytes([rng.randrange(256) & 0xfe, rng.randrange(256) & 0x3f])
        dst, src = rng.randrange(1, 0xfff0), rng.randrange(1, 0xfff0)
        statuses = bytes(rng.randrange(256) for _ in range(23))
        user = bytes([0xc0 | seq, 0xc0 | appseq, 0x81]) + iin + bytes.fromhex('0a02000016') + statuses
        native = std.frame(bytes([0x05, 0x64, 5 + len(user), 0x44]) + dst.to_bytes(2, 'little') + src.to_bytes(2, 'little'), user)
        req_user = bytes([0xc0 | ((seq - 1) & 63), 0xc0 | appseq, 0x01]) + bytes.fromhex('0a02000016')
        req = std.frame(bytes([0x05, 0x64, 5 + len(req_user), 0xc4]) + src.to_bytes(2, 'little') + dst.to_bytes(2, 'little'), req_user)
        return req, native
    return make


SHAPES = [dict(name='range_g10v2_23', native=49, sampler=range_sample)]


def main():
    rng = random.Random(20261020)
    result = dict(policy_targets=TARGETS, reserved_range=[PAD_START, PAD_STOP],
                  encoder_sha256=hashlib.sha256((ROOT / 'software/source/full_read_01/general_read_padding.py').read_bytes()).hexdigest(),
                  policy_sha256=hashlib.sha256((ROOT / 'policy/policy.json').read_bytes()).hexdigest(), shapes={})
    for shape in SHAPES:
        sample = shape['sampler'](rng)
        c = derive(shape, sample)
        checked = 0
        for _ in range(512):
            req, native = sample()
            r = gp.pad_read(req, native, TARGETS, pad_start=PAD_START, pad_stop=PAD_STOP)
            assert construct(native, c) == r.output, 'constant construction differs from pad_read'
            again = derive(shape, lambda: (req, native))
            for k in ('prefix_link_len', 'padobj_head', 'rest', 'link_crc_delta', 'block0_tail'):
                assert again[k] == c[k], ('constant depends on live bytes', k)
            checked += 1
        c['verified_samples'] = checked
        result['shapes'][shape['name']] = c
    (HERE / 'constants.json').write_text(json.dumps(result, indent=1) + '\n')
    print(json.dumps(result, indent=1))


if __name__ == '__main__':
    main()

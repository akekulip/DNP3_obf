"""Expected READ image for the build under test (Python 3.8; shared by the model drivers).

A build whose response_only.inputs.json (PORT_MAP) declares a read_complete_01 policy pads the range READ
by the derived prefix construction (read_complete_01/vectors/constants.json, proven equal to the reference
encoder by derive.py); every other build keeps its own encoder (passed in as `fallback`, e.g. encode61.read61).
The constants file must match the hash the build recorded, so a driver can never compare against constants
the build was not generated from.

A two-READ-target build (policy.constants_file = constants_two_read.json) pads TWO READ shapes, each by its own
derived constants: SHAPES maps the native response length to its shape (91 -> mixed 141, 247 -> full 271). Every
other build has one shape, SHAPES = {49: range}, so its behaviour here is unchanged. A READ native that is not a
declared shape is not padded (it is not this build's traffic); expectations never fall back to another shape's size.
"""
import hashlib
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONSTANTS = HERE.parent / 'read_complete_01/vectors/constants.json'
REPO_STAGE = HERE.parent


def _shapes():
    """{native response length: shape constants} for the build under test, or {} for a non-policy build."""
    path = os.environ.get('PORT_MAP')
    if not path:
        return {}
    inputs = json.loads(Path(path).read_text())
    pol = inputs.get('policy')
    if not pol:
        return {}
    source = REPO_STAGE / pol['constants_file'] if pol.get('constants_file') else CONSTANTS
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pol['constants_sha256']:
        raise ValueError('READ policy constants differ from the ones this build was generated from')
    shapes = json.loads(raw)['shapes']
    if pol.get('constants_file'):
        return {s['native_total']: s for s in shapes.values()}
    return {shapes['range_g10v2_23']['native_total']: shapes['range_g10v2_23']}


SHAPES = _shapes()
TWO_READ = len(SHAPES) > 1
# the first (smallest-native) shape stands for the build's READ policy where one scalar is still needed
POLICY = SHAPES[min(SHAPES)] if SHAPES else None


def _first_index(c):
    return c['reserved_first_index'] if 'reserved_first_index' in c else c['padding_indices'][0]


def _passthrough_lengths():
    """Native (= output) lengths of the pass-through READ classes the build declares (inputs.json
    passthrough_reads): those responses leave the switch unchanged."""
    path = os.environ.get('PORT_MAP')
    if not path or not POLICY:
        return frozenset()
    reads = json.loads(Path(path).read_text()).get('passthrough_reads') or {}
    return frozenset(v['output_octets'] for v in reads.values() if v['output_octets'] == v['response_octets'])


PASSTHROUGH_LENS = _passthrough_lengths()


def _read_boundary():
    """The reverse-ACK boundary the build implements: 'cimg' (per committed image, stale beyond the image) or
    'max_image_ladder' (b08: the SBO pre-start region is withheld, a documented limitation)."""
    path = os.environ.get('PORT_MAP')
    return json.loads(Path(path).read_text()).get('read_boundary', 'max_image_ladder') if path and POLICY else None


READ_BOUNDARY = _read_boundary()


def construct(native, c=None):
    import dnp3_std as std
    if c is None and len(native) in PASSTHROUGH_LENS:
        return native                                     # already at a policy target: unchanged
    if c is None and TWO_READ:
        if len(native) not in SHAPES:
            return native                                 # not a declared shape of this build: not padded
        c = SHAPES[len(native)]
    c = c or POLICY
    hdr, user = std.deframe(native)
    seq = user[0] & 63
    prefix = std.frame(hdr[:2] + bytes([c['prefix_link_len']]) + hdr[3:],
                       bytes([0x40 | seq]) + user[1:5] + bytes.fromhex(c['padobj_head']))
    return prefix + std.frame(hdr, bytes([(user[0] & std.FIN) | ((seq + 1) & 63)]) + bytes(4) + user[5:])


def read_image_fn(fallback):
    """The build's READ encoder: the policy construction, or the build's own (fallback)."""
    return construct if POLICY else fallback


def read_image_len(default):
    """The image of the drivers' default READ (the range READ). A two-READ build does not pad the range READ: its
    image is its native length, never another shape's target."""
    if TWO_READ:
        return READ_NATIVE_LEN
    return POLICY['target'] if POLICY else default


READ_NATIVE_LEN = 49


def install(encode61):
    """Make encode61.read61 the build's READ encoder (no-op unless the build declares a READ policy)."""
    if POLICY and getattr(encode61, '_policy_installed', False) is False:
        encode61._read61_native_build = encode61.read61
        encode61.read61 = construct
        encode61._policy_installed = True
    return encode61


def image_len_of(native, default):
    """Wire image length for a native response: the policy READ image for the READ shape, else the build's."""
    if len(native) in PASSTHROUGH_LENS:
        return len(native)
    if TWO_READ:
        if len(native) in SHAPES:
            return SHAPES[len(native)]['target']
        return len(native) if len(native) == READ_NATIVE_LEN else default   # range READ: admitted, not padded
    return read_image_len(default) if len(native) == READ_NATIVE_LEN else default


def growth(native, default):
    return image_len_of(native, default) - len(native)


def split_frames(stream):
    import dnp3_std as std
    out, p = [], 0
    while p < len(stream):
        n = std.frame_length(stream[p + 2] - 5)
        out.append(stream[p:p + n])
        p += n
    return out


def _std():
    """dnp3_std with the static measurement objects and their response qualifiers (0x00/0x01) registered, as
    the reference encoder's fullread module does (IEEE 1815 Clause 12); the reserved padding indices >= 1024
    need the 16-bit range qualifier 0x01."""
    import sys
    path = str(HERE.parent / 'full_read_01')
    if path not in sys.path:
        sys.path.insert(0, path)
    import fullread  # noqa: F401  (registers the objects/qualifiers in dnp3_std)
    import dnp3_std as std
    return std


def check_read_image(native, image, expected_statuses=None):
    """Independent decode of a policy READ image (any number of link frames): one reassembled fragment, the
    native application header/IIN unchanged, the native points as the suffix (values and flags), exactly the
    synthetic reserved-range G1V2 points (flags/value 0) as the prefix, every CRC valid, the policy length."""
    std = _std()
    c = SHAPES.get(len(native), POLICY) if TWO_READ else POLICY
    if TWO_READ and len(native) not in SHAPES:
        # not a declared shape of this build (e.g. the range READ): it must leave the switch exactly as it came
        if image != native:
            raise AssertionError('READ of undeclared native length %d was altered (%d octets out)' % (len(native), len(image)))
        return {'native_len': len(native), 'image_len': len(image), 'padding_points': 0, 'unpadded': True}
    if len(image) != c['target']:
        raise AssertionError('READ length %d != policy target %d' % (len(image), c['target']))
    frames = split_frames(image)
    for f in frames:
        std.deframe(f)                                    # verifies every block CRC
    frags, events = std.reassemble(frames)
    if events or len(frags) != 1:
        raise AssertionError('READ image does not reassemble into one fragment: %r %r' % (frags, events))
    app = frags[0][0]
    native_user = std.deframe(native)[1]
    if app[:4] != native_user[1:5]:
        raise AssertionError('READ application header/IIN changed')
    _, native_points = std.check_read_response(native_user)
    _, points = std.check_read_response(std.fragment_user(app))
    n = c['padding_points']
    if points[n:] != native_points:
        raise AssertionError('original READ points not preserved as the suffix')
    if [(g, v, i, d) for g, v, i, d in points[:n]] != [(1, 2, _first_index(c) + k, b'\x00') for k in range(n)]:
        raise AssertionError('padding is not exactly the reserved synthetic prefix')
    if expected_statuses is not None and [obj[3][0] for obj in points[n:]] != list(expected_statuses):
        raise AssertionError('READ statuses changed')
    return {'native_len': len(native), 'image_len': len(image), 'points': len(points), 'padding_points': n,
            'frames': [len(f) for f in frames], 'iin': app[2:4].hex()}

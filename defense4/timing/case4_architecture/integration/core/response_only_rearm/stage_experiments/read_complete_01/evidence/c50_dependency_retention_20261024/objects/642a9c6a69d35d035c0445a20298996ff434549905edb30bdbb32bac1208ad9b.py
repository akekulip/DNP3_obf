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
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONSTANTS = HERE.parent / 'read_complete_01/vectors/constants.json'
REPO_STAGE = HERE.parent


def _inputs():
    path = os.environ.get('PORT_MAP')
    return json.loads(Path(path).read_text()) if path else {}


_BUILD_INPUTS = _inputs()
SEL751 = (_BUILD_INPUTS.get('endpoint_profile') or
          (_BUILD_INPUTS.get('supported_profile') or {}).get('endpoint_profile')) == 'sel751'
CONTROL_REQUEST_LEN = 45 if SEL751 else 35
CONTROL_NATIVE_LEN = 49 if SEL751 else 37
CONTROL_IMAGE_LEN = 60 if SEL751 else 61
TCP_TIMESTAMPS = (_BUILD_INPUTS.get('supported_profile') or {}).get('tcp_profile') == 'sel751_ts'
_timestamp_tick = 1_000_000
_latest_timestamp = {False: 0, True: 0}


def advance_timestamp():
    """Advance after constructing a sent/expected pair, preserving options across coordinate mapping."""
    global _timestamp_tick
    if TCP_TIMESTAMPS:
        _timestamp_tick = (_timestamp_tick + 1) & 0xffffffff


def tcp_payload_offset(frame):
    tcp = 14 + (frame[14] & 15) * 4
    return tcp + (frame[tcp + 12] >> 4) * 4


def timestamp_values(frame):
    tcp = 14 + (frame[14] & 15) * 4
    options = frame[tcp + 20:tcp_payload_offset(frame)]
    position = options.find(b'\x08\x0a')
    return struct.unpack('!II', options[position + 2:position + 10]) if position >= 0 else None


def timestamp_order_ok(frames):
    """Bounded PAWS sanity: delivered timestamps never regress within one direction/connection."""
    latest = {}
    for frame in frames:
        value = timestamp_values(frame)
        if value is None:
            continue
        key = frame[26:38]
        tcp = 14 + (frame[14] & 15) * 4
        if frame[tcp + 13] & 2:
            latest.pop(key, None)
        previous = latest.get(key)
        if previous is not None and ((value[0] - previous) & 0xffffffff) >= 0x80000000:
            return False
        latest[key] = value[0]
    return True


def preserve_options(sent, expected):
    """Expected mapper output retains the exact input TCP options, including old/new retransmission TS."""
    if not TCP_TIMESTAMPS or expected is None:
        return expected
    src_tcp = 14 + (sent[14] & 15) * 4
    dst_tcp = 14 + (expected[14] & 15) * 4
    options = sent[src_tcp + 20:tcp_payload_offset(sent)]
    frame = bytearray(expected)
    if len(options) != tcp_payload_offset(frame) - dst_tcp - 20:
        raise ValueError('mapping changed the TCP option capsule length')
    frame[dst_tcp + 20:tcp_payload_offset(frame)] = options
    frame[dst_tcp + 16:dst_tcp + 18] = b'\0\0'
    end = 14 + int.from_bytes(frame[16:18], 'big')
    data = frame[26:34] + struct.pack('!BBH', 0, 6, end - dst_tcp) + frame[dst_tcp:end]
    if len(data) & 1:
        data += b'\0'
    value = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    frame[dst_tcp + 16:dst_tcp + 18] = struct.pack('!H', (~value) & 65535)
    return bytes(frame)


def reverse_window(window, distance, native):
    """Normalize the master's advertised receive window in its negotiated scale units."""
    scale = 128 if TCP_TIMESTAMPS else 1
    available = window * scale
    return 0 if available < distance else min((native + available - distance) // scale, 65535)


def abort_reference_len(kind):
    return (READ_NATIVE_LEN if kind == 'READ' else CONTROL_NATIVE_LEN) if SEL751 else (49 if kind == 'READ' else 37)


def read_frames(transport=0, app=0, cls='mixed', variant=0):
    """Complete captured relay READ, retaining actual link addresses and objects."""
    from two_read_templates import select_templates
    std = _std()
    templates, _path = select_templates(HERE.parent / 'read_complete_01/vectors', SHAPES)
    item = templates['v%d' % (variant % 2)]['classes'][cls]
    result = []
    for key in ('request', 'native'):
        head, user = std.deframe(bytes.fromhex(item[key]))
        result.append(std.frame(head, bytes([(user[0] & 0xc0) | (transport & 63),
                                             (user[1] & 0xf0) | (app & 15)]) + user[2:]))
    return tuple(result)


def configure_helpers(helpers):
    """Bind existing packet builders to the selected endpoint without changing legacy fixtures."""
    if not SEL751:
        return helpers
    vectors, rs = helpers.vectors, helpers.rs
    vectors.CLIENT, vectors.SERVER = 0xc0a80a01, 0xc0a80a07
    vectors.CLIENT_PORT, vectors.SERVER_PORT = 59410, 20000
    vectors.FLOW_PORTS = (vectors.CLIENT_PORT, vectors.SERVER_PORT)
    if not hasattr(vectors, '_physical_packet_base'):
        vectors._physical_packet_base = vectors.packet

    def packet(flags, seq, ack=0, reverse=False, timestamps=None, **kwargs):
        raw = vectors._physical_packet_base(flags, seq, ack, reverse=reverse, **kwargs)
        master_mac, relay_mac = bytes.fromhex('3cfdfecc5dc0'), bytes.fromhex('0030a7024ca2')
        raw = (master_mac + relay_mac if reverse else relay_mac + master_mac) + raw[12:]
        if not TCP_TIMESTAMPS:
            if timestamps is not None:
                raise ValueError('timestamps require the explicit sel751_ts profile')
            return raw
        values = timestamps or (_timestamp_tick + (10_000 if reverse else 0),
                                0 if flags & 2 and not reverse else _latest_timestamp[not reverse])
        _latest_timestamp[reverse] = values[0]
        ts = struct.pack('!II', *values)
        if flags & 2:
            options = (bytes.fromhex('020405b401030300010104020101080a') + ts if reverse else
                       bytes.fromhex('020405b40402080a') + ts + bytes.fromhex('01030307'))
        else:
            options = bytes.fromhex('0101080a') + ts
        old_tcp_end = tcp_payload_offset(raw)
        frame = bytearray(raw[:54] + options + raw[old_tcp_end:])
        frame[46] = ((20 + len(options)) // 4) << 4
        frame[16:18] = struct.pack('!H', len(frame) - 14)
        frame[24:26] = b'\0\0'
        frame[24:26] = struct.pack('!H', vectors.checksum(frame[14:34]))
        frame[50:52] = b'\0\0'
        pseudo = frame[26:34] + struct.pack('!BBH', 0, 6, len(frame) - 34)
        frame[50:52] = struct.pack('!H', vectors.checksum(pseudo + frame[34:]))
        return bytes(frame)

    vectors.packet = packet
    helpers.MASTER = helpers.rp.Endpoint('192.168.10.1', vectors.CLIENT_PORT, 9)
    helpers.OUTSTATION = helpers.rp.Endpoint('192.168.10.7', vectors.SERVER_PORT, 64)
    vectors.native_select = lambda app=0, fc=3: relay_control_frame(0, app, fc)
    helpers.native_response37 = lambda app, fc, status=0, iin1=0: relay_control_frame(
        0, app, fc, response=True, statuses=(status, status), iin=bytes((iin1, 0)))
    rs.request_frame = lambda app=0xc0: read_frames(0, app & 15)[0]
    rs.response_frame = lambda: read_frames()[1]
    rs.request_packet = lambda seq=101, ack=901, app=0xc0: vectors.packet(
        24, seq, ack, payload=rs.request_frame(app))
    rs.response_packet = lambda seq=901, ack=126: vectors.packet(
        24, seq, ack, reverse=True, payload=rs.response_frame())
    return helpers


def report_endpoint(report):
    """Record physical wire identities and the intentional alternate-port negative fixture."""
    if SEL751:
        report.record['meta']['endpoint_profile'] = dict(
            name='sel751', master_ip='192.168.10.1', relay_ip='192.168.10.7',
            master_mac='3c:fd:fe:cc:5d:c0', relay_mac='00:30:a7:02:4c:a2',
            master_dev=9, relay_dev=64, master_tcp_port=59410, relay_tcp_port=20000,
            dnp_master=1, dnp_relay=0,
            alternate_tcp_port_fixture='Unconfigured-connection probes use master source port 59411')
        report.record['meta']['endpoint_profile']['tcp_profile'] = 'sel751_ts' if TCP_TIMESTAMPS else 'clean_fixture'
        if TCP_TIMESTAMPS:
            report.record['meta']['endpoint_profile'].update(tcp_header_octets=32, syn_tcp_header_octets=40,
                synack_tcp_header_octets=44, master_window_scale=7, relay_window_scale=0,
                timestamp_policy='monotonic logical steps; exact options retained across seq/ack mapping')


def relay_control_frame(seq=0, app=0, fc=3, response=False, statuses=(0, 0), iin=b'\x00\x00'):
    """Use the shared, independently checked two-CROB relay vectors."""
    import sys
    path = str(HERE.parent / 'ctl_timing_01')
    if path not in sys.path:
        sys.path.insert(0, path)
    import relay_sbo_vectors as relay
    native = relay.control_frame(seq, app, fc, response=response, statuses=statuses)
    head, user = _std().deframe(native)
    if response:
        user = user[:3] + iin + user[5:]
    return _std().frame(head, user)


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
            return None if SEL751 else native             # relay profile admits only the two captured READs
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
    if SEL751:
        return SHAPES[91]['target']
    if TWO_READ:
        return READ_NATIVE_LEN
    return POLICY['target'] if POLICY else default


READ_NATIVE_LEN = 91 if SEL751 else 49


def install(encode61):
    """Make encode61.read61 the build's READ encoder (no-op unless the build declares a READ policy)."""
    if POLICY and getattr(encode61, '_policy_installed', False) is False:
        encode61._read61_native_build = encode61.read61
        encode61.read61 = construct
        encode61._policy_installed = True
    if SEL751 and not getattr(encode61, '_relay_installed', False):
        import sys
        sys.path.insert(0, str(HERE.parent / 'ctl_timing_01'))
        import relay_sbo_vectors as relay
        def control_image(native):
            try:
                _head, user = relay.std.deframe(native)
                if user[1] & 0x20:
                    return None
                objects = bytearray(user[5:])
                objects[15] = objects[27] = 0
                if bytes(objects) != relay.OBJECTS:
                    return None
                return relay.control_image(native)
            except (ValueError, IndexError):
                return None
        encode61.ctl61 = control_image
        encode61._relay_installed = True
    return encode61


def image_len_of(native, default):
    """Wire image length for a native response: the policy READ image for the READ shape, else the build's."""
    if SEL751 and len(native) == CONTROL_NATIVE_LEN:
        return CONTROL_IMAGE_LEN
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

"""Per-class READ expectations for the READ-class schedule endpoint (stdlib only).

The endpoint (rearm_01/repeat_sbo_endpoint, binary case4_socket_gate_read_schedule) issues, under
CASE4_READ_SCHEDULE=rotate4, the READ classes range, analog, class0 and integrity in a fixed slot order, against the
fixture database CASE4_DB=base|large. This module is the one place the harness turns a configuration into what
each READ must look like at the master:

  builds[b].read_images        {class: image length | null}; null or absent: the class is not supported in
                               hardware on this build, and a padded arm refuses to run it. An image means the
                               read_complete_01 prefix construction (general_read_padding.pad_read, prefix path):
                               either the native length (already at target) or at least native + 24, the
                               smallest prefix frame (a G1V2 q0x01 block of 4 zero flags); anything in between is
                               refused as unreachable
  builds[b].read_images_by_db  {db: {class: image length | null}}, overriding read_images on that database
  traffic.read_schedule        'rotate4' (absent: the existing range READ in every slot)
  traffic.db                   'base' | 'large' (required with a schedule); a trial may override both

A build declaring neither read_images nor read_images_by_db keeps every legacy behaviour; expectations() then
returns None, and a READ schedule on such a build is refused. Requests are classified from their bytes
(classify_request), never from their position.

ASSUMPTION (packet level, fails closed): for a natively segmented class (large DB class0/integrity, 292 + 85) the
switch is assumed to emit the prefix frame in the same TCP segment as the renumbered native first frame (316 + 85
for a 401 image). Only clrt_check's per-packet pairing and checks.first_packet_len depend on it; if the hardware
segments otherwise, those responses do not pair and the per-class timing check fails, never passes.
profile_check and check_capture compare the reassembled aggregate and accept any segmentation.
"""
import struct

CLASSES = ('range', 'analog', 'class0', 'integrity')
SCHEDULES = {'rotate4': CLASSES}
DBS = ('base', 'large')
# Native aggregate response link octets and their TCP segments, measured on loopback 2026-10-21
# (repeat_sbo_endpoint/README.md, loopback_evidence_20261021/b_rotate4_{base,large}). No database: the existing
# 23-point BOS fixture, range only.
NATIVE_SEGMENTS = {
    None: {'range': (49,)},
    'base': {'range': (49,), 'analog': (141,), 'class0': (247,), 'integrity': (247,)},
    'large': {'range': (49,), 'analog': (141,), 'class0': (292, 85), 'integrity': (292, 85)},
}
INTEGRITY = {(60, 1), (60, 2), (60, 3), (60, 4)}
PREFIX_MIN_GROWTH = 24      # smallest prefix frame: 10 header + (1 transport + 4 app/IIN + 7 obj head) + 2 CRC


class ReadClassError(ValueError):
    """A per-class READ declaration or schedule the harness refuses to run."""


def classify_request(app):
    """READ class of one application request fragment (app control, function, object headers), or None.

    range: one G10 header with a start-stop range (q0x00/q0x01); analog: one G30 header with a range;
    class0: G60V1 q0x06 alone; integrity: G60V2, G60V3, G60V4 and G60V1, each q0x06 once."""
    if len(app) < 3 or app[1] != 1:
        return None
    headers, p = [], 2
    while p < len(app):
        if len(app) - p < 3:
            return None
        g, v, q = app[p:p + 3]
        width = {0x00: 1, 0x01: 2, 0x06: 0}.get(q)
        if width is None or len(app) - p < 3 + 2 * width:
            return None
        if width:
            fmt = '<B' if width == 1 else '<H'
            start = struct.unpack(fmt, app[p + 3:p + 3 + width])[0]
            stop = struct.unpack(fmt, app[p + 3 + width:p + 3 + 2 * width])[0]
            if stop < start:
                return None
        headers.append((g, v, q))
        p += 3 + 2 * width
    if len(headers) == 1 and headers[0][2] in (0x00, 0x01):
        return {10: 'range', 30: 'analog'}.get(headers[0][0])
    if headers == [(60, 1, 0x06)]:
        return 'class0'
    if len(headers) == 4 and all(q == 0x06 for _g, _v, q in headers) and \
            {(g, v) for g, v, _q in headers} == INTEGRITY:
        return 'integrity'
    return None


def _crc(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA6BC if c & 1 else c >> 1
    return (~c) & 0xFFFF


def _users(payload):
    """CRC-checked transport+application user octets of each link frame; None when any frame is invalid."""
    users, base = [], 0
    while base < len(payload):
        if len(payload) - base < 10 or payload[base:base + 2] != b'\x05\x64' or payload[base + 2] < 5 or \
                _crc(payload[base:base + 8]) != int.from_bytes(payload[base + 8:base + 10], 'little'):
            return None
        remaining, p, user = payload[base + 2] - 5, base + 10, bytearray()
        while remaining:
            k = min(16, remaining)
            block, crc = payload[p:p + k], payload[p + k:p + k + 2]
            if len(block) != k or len(crc) != 2 or _crc(block) != int.from_bytes(crc, 'little'):
                return None
            user.extend(block)
            p, remaining = p + k + 2, remaining - k
        users.append(bytes(user))
        base = p
    return users


def classify_request_frames(payload):
    """READ class of a request carried as link frames (one transport series FIR..FIN), or None."""
    users = _users(payload)
    if not users or any(not u for u in users):
        return None
    if not users[0][0] & 0x40 or not users[-1][0] & 0x80 or any(u[0] & 0x40 for u in users[1:]):
        return None
    return classify_request(b''.join(u[1:] for u in users))


def class_counts(classes, reads):
    """Slot k issues classes[k mod len]: class j is issued floor(T/n) + (1 if j < T mod n else 0) times."""
    n = len(classes)
    return {c: reads // n + (1 if j < reads % n else 0) for j, c in enumerate(classes)}


def schedule_and_db(config, trial=None):
    """(schedule name or None, classes, db or None) from the trial, else the traffic section."""
    traffic = (config or {}).get('traffic') or {}
    trial = trial or {}
    name = trial.get('read_schedule', traffic.get('read_schedule'))
    db = trial.get('db', traffic.get('db'))
    if name is not None and name not in SCHEDULES:
        raise ReadClassError('read_schedule %r is not one of %s' % (name, sorted(SCHEDULES)))
    if db is not None and db not in DBS:
        raise ReadClassError('db %r is not one of %s' % (db, list(DBS)))
    if name is not None and db is None:
        raise ReadClassError('read_schedule %r needs db (base or large) on both endpoints' % name)
    return name, (SCHEDULES[name] if name else ('range',)), db


def declared(build):
    """The build declares per-class READ images (read_images, read_images_by_db, or both)."""
    return isinstance(build, dict) and ('read_images' in build or 'read_images_by_db' in build)


def build_images(build, db):
    """{class: declared image or None} on this database (read_images, overridden by read_images_by_db[db])."""
    images = dict(build.get('read_images') or {})
    images.update(((build.get('read_images_by_db') or {}).get(db) or {}) if db else {})
    for cls, value in images.items():
        if cls not in CLASSES:
            raise ReadClassError('read_images declares unknown class %r' % cls)
        if value is not None and (type(value) is not int or not 10 <= value <= 2048):
            raise ReadClassError('read_images[%s] must be an integer image length or null, got %r' % (cls, value))
        native = sum(NATIVE_SEGMENTS.get(db, {}).get(cls, ())) or None
        if value is not None and native is not None and native < value < native + PREFIX_MIN_GROWTH:
            raise ReadClassError('read_images[%s]=%d on db %r is unreachable by the prefix construction: it adds 0 or '
                                 'at least %d octets to the native %d' % (cls, value, db, PREFIX_MIN_GROWTH, native))
    return images


def range_image_len(build, default=None):
    """The range READ image of a build that runs only the range READ: read_images['range'] when declared (and
    then read_image_len, if also present, must agree), else read_image_len, else default."""
    build = build or {}
    if declared(build):
        image = build_images(build, None).get('range')
        if image is None:
            raise ReadClassError('READ class range is not supported in hardware on this build (read_images)')
        if 'read_image_len' in build and int(build['read_image_len']) != image:
            raise ReadClassError('read_image_len %r disagrees with read_images range %d'
                                 % (build['read_image_len'], image))
        return image
    return build.get('read_image_len', default)


def expectations(config, arm, trial=None, padded=True):
    """Per-class READ expectation of one trial on one arm, or None when the arm's build declares no read_images.

    padded: the arm transforms READ responses (standards.expected_lengths decides). Returns
      {'schedule', 'db', 'padded', 'order': [slot order], 'classes': {class: {'native', 'image', 'count',
                                                                                'native_segments'}}}
    with every scheduled class issued at least once. A padded arm whose build does not support a scheduled class
    (null or absent image), or declares an image below the native, raises ReadClassError."""
    build = ((config or {}).get('builds') or {}).get((arm or {}).get('build')) or {}
    name, classes, db = schedule_and_db(config, trial)
    if not declared(build):
        if name is not None:
            raise ReadClassError('read_schedule %r needs per-class READ images: build %s declares neither read_images '
                                 'nor read_images_by_db' % (name, (arm or {}).get('build')))
        return None
    reads = int((trial or {}).get('reads', 0))
    images = build_images(build, db)
    out = {}
    for cls, count in class_counts(classes, reads).items():
        if not count:
            continue
        segments = NATIVE_SEGMENTS[db].get(cls)
        if segments is None:
            raise ReadClassError('READ class %s has no native shape on db %r' % (cls, db))
        native = sum(segments)
        image = images.get(cls) if padded else native
        if image is None:
            raise ReadClassError('READ class %s is not supported in hardware on build %s (db %s): refusing to run it'
                                 % (cls, arm.get('build'), db))
        if image < native:
            raise ReadClassError('READ class %s image %d is below its native %d (db %s)' % (cls, image, native, db))
        out[cls] = {'native': native, 'image': image, 'count': count, 'native_segments': list(segments)}
    return {'schedule': name, 'db': db, 'padded': bool(padded), 'order': list(classes), 'classes': out}

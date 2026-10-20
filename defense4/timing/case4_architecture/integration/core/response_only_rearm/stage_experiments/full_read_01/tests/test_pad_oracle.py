"""Offline tests for the measurement-object padding oracle and target selection.

Each padded response is re-checked with the independent IEEE 1815-2012 oracle (dnp3_std): every link
CRC valid, one reassembled fragment, the original points preserved as the prefix, the added points
legal, and the total exactly the target.
"""
from pathlib import Path
import sys

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / 'read_reencode_01'))
import dnp3_std as std  # noqa: E402
import pad_oracle as po  # noqa: E402
import fullread as fr  # noqa: E402


def make_response(points):
    """A one-frame READ response carrying `points` binary-output-status points (g10v2), FIR+FIN."""
    objs = bytes([0x0A, 0x02, 0x00, 0x00, points - 1]) + bytes(range(points))
    app = bytes([0x81, 0x00, 0x00, 0x00]) + objs            # appctrl, func, iin(2) ... wait order below
    app = bytes([0xC0, 0x81, 0x00, 0x00]) + objs            # appctrl=0xC0, func=0x81, iin=0x0000
    user = bytes([std.FIR | std.FIN | 0]) + app
    return std.frame(bytes([0x05, 0x64, 5 + len(user), 0x44, 0x0A, 0x00, 0x01, 0x00]), user)


def test_frame_length_matches_standard():
    assert std.frame_length(33) == 49            # native range READ (user 33 octets)
    assert std.frame_length(209) == 247          # full integrity READ, base DB
    assert po.frame_octets(31) == 45


def test_plan_padding_is_exact_or_none():
    for add in range(0, 60):
        plan = po.plan_padding(add)
        if plan is not None:
            points, qual = plan
            assert po.frame_octets(po.padding_user(points, qual)) == add
    assert po.plan_padding(45) == (25, 0)
    assert po.plan_padding(5) is None            # below the smallest padding frame


def test_pad_reaches_target_and_preserves_points():
    native = make_response(23)
    target = po.choose_target(len(native), [73, 141, 292])
    padded, info = po.pad_response(native, target, first_pad_index=16)
    assert len(padded) == target
    # independent re-check
    frames = po._split_frames(padded)
    frags, events = std.reassemble(frames)
    assert events == [] and len(frags) == 1
    pts = std.points(std.parse_objects(std.response(std.fragment_user(frags[0][0]))['objects'], response=True))
    native_pts = std.points(std.parse_objects(std.response(std.fragment_user(
        std.reassemble(po._split_frames(native))[0][0][0]))['objects'], response=True))
    assert pts[:len(native_pts)] == native_pts            # original points are the prefix, unchanged
    added = pts[len(native_pts):]
    assert all(g == 1 and v == 2 and d == b'\x00' for g, v, _i, d in added)   # padding = g1v2, flags 0x00
    assert [i for _g, _v, i, _d in added] == list(range(16, 16 + info['points']))


def test_every_native_size_reaches_its_target():
    for native_points in (5, 23, 40):
        native = make_response(native_points)
        t = po.choose_target(len(native), [73, 141, 292])
        if t == len(native):
            continue
        padded, info = po.pad_response(native, t, 16)
        assert len(padded) == t
        std.reassemble(po._split_frames(padded))          # raises on any CRC/transport error


def test_ineligible_without_fin_stays_native():
    native = bytearray(make_response(23))
    # clear FIN on the only transport segment -> not a complete response -> untouched
    native[10] &= ~std.FIN & 0xFF
    native[26:28] = std.crc(bytes(native[10:26])).to_bytes(2, 'little')
    out, info = po.pad_response(bytes(native), 292, 16)
    assert info is None and out == bytes(native)


def test_target_rule_requires_a_merge():
    sel = po.select_targets([49, 141, 247], 292)
    assert sel['selected'] == [141, 292]
    assert any(len(v) >= 2 for v in po.buckets([49, 141, 247], sel['selected']).values())


def test_expand_request_adds_real_ranges_within_fragment():
    # native range READ request: g10v2 0..22
    user = bytes([std.FIR | std.FIN, 0xC0, 0x01, 0x0A, 0x02, 0x00, 0x00, 0x16])
    frame = std.frame(bytes([0x05, 0x64, 5 + len(user), 0x01, 0x00, 0x0A, 0x00, 0x01]), user)
    extra = [po.range_header(30, 1, 0, 20), po.range_header(20, 1, 0, 7)]
    out = po.expand_request(frame, extra)
    _, u = std.deframe(out)
    headers = fr.request_headers(u[3:])
    assert [(h['group'], h['variation']) for h in headers] == [(10, 2), (30, 1), (20, 1)]


def test_expand_request_refuses_over_fragment():
    user = bytes([std.FIR | std.FIN, 0xC0, 0x01, 0x0A, 0x02, 0x00, 0x00, 0x16])
    frame = std.frame(bytes([0x05, 0x64, 5 + len(user), 0x01, 0x00, 0x0A, 0x00, 0x01]), user)
    with pytest.raises(std.StdError):
        po.expand_request(frame, [po.range_header(30, 1, 0, 60)] * 50)

"""Tests for the prefix padding construction (prepend.py), the encoding reference for the P4 padder.

Every padded output is re-checked with the independent IEEE 1815-2012 oracle: all CRCs valid, one
reassembled fragment, the original points preserved as the SUFFIX (padding is a prefix), and only the
first 28 octets touched.
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
import prepend as pp  # noqa: E402


def make_read(points, seq=0, dst=10, src=1):
    """A single-frame READ response: g10v2 `points` binary-output-status points, FIR+FIN."""
    objs = bytes([0x0A, 0x02, 0x00, 0x00, points - 1]) + bytes(range(points))
    user = bytes([std.FIR | std.FIN | seq]) + bytes([0xC0, 0x81, 0x00, 0x00]) + objs
    return std.frame(bytes([0x05, 0x64, 5 + len(user), 0x44]) + dst.to_bytes(2, 'little') + src.to_bytes(2, 'little'), user)


def check_padded(native, out, info):
    frames = po._split_frames(out)
    frags, events = std.reassemble(frames)
    assert events == [] and len(frags) == 1
    app = frags[0][0]
    _, pts = std.check_read_response(std.fragment_user(app))
    _, orig = std.check_read_response(std.deframe(native)[1])
    assert pts[info['padding_points']:] == orig          # originals are the SUFFIX (padding prefixed)
    added = pts[:info['padding_points']]
    assert all(g == 1 and v == 2 and d == b'\x00' for g, v, _i, d in added)
    assert out[-info['original_tail_bytes_unchanged']:] == native[-info['original_tail_bytes_unchanged']:]


def test_full_read_cheap_prefix():
    native = make_read(23)                                # range READ 49 B
    # emulate a 247-B full READ by padding the range READ's point count up; use the real 247 size via target math
    out, info = pp.prepend_padding(native, target=269)
    assert info['total_bytes'] == 269
    check_padded(native, out, info)


def test_leading_frame_is_fir_not_fin():
    native = make_read(23)
    out, _ = pp.prepend_padding(native, target=269)
    frames = po._split_frames(out)
    lead_tp = std.deframe(frames[0])[1][0]
    cont_tp = std.deframe(frames[1])[1][0]
    assert lead_tp & 0x40 and not lead_tp & 0x80          # leading: FIR=1, FIN=0
    assert cont_tp & 0x80 and not cont_tp & 0x40          # continuation: FIR=0, FIN=1
    assert (cont_tp & 0x3f) == ((native[10] & 0x3f) + 1) & 0x3f   # next sequence


def test_crc_recomputed_across_seq_and_addr():
    for seq in (0, 1, 31, 62, 63):
        for dst, src in ((10, 1), (123, 456)):
            native = make_read(23, seq=seq, dst=dst, src=src)
            out, info = pp.prepend_padding(native, target=269)
            std.reassemble(po._split_frames(out))         # raises on any CRC/transport error
            check_padded(native, out, info)


def test_only_first_28_octets_change():
    native = make_read(23)
    out, info = pp.prepend_padding(native, target=269)
    # the continuation frame (out after the prefix) must end with native[28:] verbatim
    prefix_len = info['prefix_bytes']
    continuation = out[prefix_len:]
    assert continuation[28:] == native[28:]


def test_rejects_non_response_or_bad_crc():
    native = bytearray(make_read(23))
    native[27] ^= 0xFF                                    # corrupt first-block CRC
    with pytest.raises(ValueError):
        pp.prepend_padding(bytes(native), target=269)


def test_unattainable_target_rejected():
    native = make_read(23)
    with pytest.raises(ValueError):
        pp.prepend_padding(native, target=49 + 5)         # below the smallest reachable padding

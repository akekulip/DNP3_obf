"""Prefix padding construction for a supported single-frame READ response (encoding reference only).

This resolves the two blockers of appending padding after the native response: the egress parser's
160-byte depth limit (the 247-byte full READ cannot be fully parsed) and the fact that Tofino emits
parsed headers *before* the unparsed payload (a partial-parse append lands inside the frame). Instead,
the padding is a PREFIX and the native tail is reused verbatim, so only the first 28 octets are read or
modified:

  - a NEW leading link frame: transport FIR=1, FIN=0, carrying the live application header (b[1:5]) then
    the padding object header and most of its synthetic g1 points;
  - the ORIGINAL frame becomes a continuation: same link header, but its first block's transport octet is
    FIR=0, FIN=1 at the next sequence number, its former application-header byte positions now hold the
    last four padding-point bytes, and the original first-block object bytes (b[5:]) follow; the
    first-block CRC is recomputed over all of this;
  - the original tail bytes 28.. are copied verbatim.

The reassembled fragment is `app header + padding object (all points) + original objects`; DNP3 object
order is free, so the master delivers the originals plus the synthetic padding points.

This module is the ENCODING reference (what the P4 must reproduce). It is not a P4/ASIC claim and has not
been checked against a live master; those are proven by the model gate and the hardware run.
"""
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'read_reencode_01'))
import dnp3_std as std  # noqa: E402
import pad_oracle as po  # noqa: E402


def prepend_padding(native, target=269, first_index=16):
    """Return (padded_bytes, info) for a supported single-frame READ response. Reads/modifies only the
    first 28 octets; copies native[28:] verbatim."""
    h = native[:8]
    b = native[10:26]
    if len(b) != 16 or len(native) != std.frame_length(h[2] - 5):
        raise ValueError('unsupported or incomplete single link frame')
    if std.crc(h) != int.from_bytes(native[8:10], 'little'):
        raise ValueError('bad link header CRC')
    if std.crc(b) != int.from_bytes(native[26:28], 'little'):
        raise ValueError('bad first-block CRC')
    if b[0] & 0xc0 != 0xc0 or b[2] != 0x81:
        raise ValueError('requires one complete native response transport segment')
    plan = po.plan_padding(target - len(native))
    if plan is None:
        raise ValueError('unattainable target')
    points, qualifier = plan
    if points < 4 or qualifier != 0 or first_index + points > 256:
        raise ValueError('outside this bounded construction')
    # g1v2 padding object (all-zero points), qualifier 0x00 range [first_index, first_index+points-1]
    obj = bytes([1, 2, 0, first_index, first_index + points - 1]) + bytes(points)
    seq = b[0] & 63
    # leading frame: FIR=1, FIN=0; live app header b[1:5]; padding object minus its last four points
    prefix_user = bytes([std.FIR | seq]) + b[1:5] + obj[:-4]
    prefix_header = h[:2] + bytes([5 + len(prefix_user)]) + h[3:]
    prefix = std.frame(prefix_header, prefix_user)
    # continuation first block: FIR=0, FIN=1, seq+1; the last four padding points occupy the former
    # app-header byte positions; then the original first-block object bytes b[5:]
    continuation_first = bytes([std.FIN | ((seq + 1) & 63)]) + obj[-4:] + b[5:]
    continuation = (native[:10] + continuation_first
                    + std.crc(continuation_first).to_bytes(2, 'little') + native[28:])
    out = prefix + continuation
    assert len(out) == target and continuation[28:] == native[28:]
    return out, {'native_bytes': len(native), 'prefix_bytes': len(prefix),
                 'total_bytes': len(out), 'padding_points': points, 'target': target,
                 'original_tail_bytes_unchanged': len(native) - 28}


if __name__ == '__main__':
    import json
    import fullread as fr
    evidence = HERE / 'evidence'
    cases, checks = [], 0
    for directory in ('native_range_base', 'native_integrity_base'):
        t = fr.transactions(evidence / directory / 'capture.pcap')[0]
        captured = bytes.fromhex(t['response_frames_hex'][0])
        header, user = std.deframe(captured)
        for seq in (0, 62, 63):
            for dst, src in ((10, 1), (123, 456)):
                h = header[:4] + dst.to_bytes(2, 'little') + src.to_bytes(2, 'little')
                native = std.frame(h, bytes([0xc0 | seq]) + user[1:])
                out, info = prepend_padding(native)
                fragments, events = std.reassemble(po._split_frames(out))
                assert not events and len(fragments) == 1
                app = fragments[0][0]
                added = bytes([1, 2, 0, 16, 16 + info['padding_points'] - 1]) + bytes(info['padding_points'])
                assert app == user[1:5] + added + user[5:]
                _, points = std.check_read_response(std.fragment_user(app))
                original_points = std.check_read_response(user)[1]
                assert points[info['padding_points']:] == original_points
                checks += 1
        cases.append(info)
    print(json.dumps({'status': 'encoding checks only; uncompiled and not tested against a live master',
                      'checks_passed': checks, 'cases': cases}, indent=2))

"""Software oracle for the 61-octet equal-size profile (bounded experiment, Philip 2026-10-13).

READ (native 49): one link frame, the same 23 G10V2 points as three start/stop ranges:
    block 1  H | 0a 02 00 00 05 | P0..P5                         (the native first block; only the stop index changes)
    block 2  0a 02 00 06 09 | P6..P9 | 0a 02 01 0a 00 16 00      (qualifier 0x00, 0x00, then 0x01)
    block 3  P10..P22
  45 user octets -> 10 + 45 + 3*2 = 61.

SELECT/OPERATE response (native 37 = th + 22 application octets): the same application octets in three transport
segments (Clause 8.2.2 Rule 1: varying segment sizes; 8.2.1 Rule 4: a FIR segment may carry any sequence):
    frame 1  [FIR, seq s]   + app[0:15]   LEN 0x15  -> 28 octets (user = the native first 16-octet block)
    frame 2  [seq s+1]      + app[15:21]  LEN 0x0c  -> 19
    frame 3  [FIN, seq s+2] + app[21:22]  LEN 0x07  -> 14       total 61, all in one TCP segment.
The application octets, hence the Rule 8 echo, are byte-identical. Any other shape stays native.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'read_reencode_01'))
import dnp3_std as std  # noqa: E402

READ_NATIVE_HEADER = bytes.fromhex('0a02000016')
READ_HDR_A = bytes.fromhex('0a02000005')
READ_HDR_B = bytes.fromhex('0a02000609')
READ_HDR_C = bytes.fromhex('0a02010a001600')
CTL_PARTS = (15, 6, 1)
SIZE = 61


def read_eligible(user):
    return (len(user) == 33 and user[0] & 0xC0 == 0xC0 and user[1] & 0xF0 == 0xC0 and user[2] == 0x81
            and user[5:10] == READ_NATIVE_HEADER)


def read61(frame):
    header8, user = std.deframe(frame)
    if not read_eligible(user):
        return None
    h, p = user[:5], user[10:]
    new = h + READ_HDR_A + p[:6] + READ_HDR_B + p[6:10] + READ_HDR_C + p[10:]
    return std.frame(header8[:2] + bytes([5 + len(new)]) + header8[3:], new)


def ctl_eligible(user):
    """A single-segment SELECT/OPERATE response echoing one CROB (G12V1, qualifier 0x28, count 1), as the P4
    control profile admits: 23 user octets, FIR|FIN, function 0x81."""
    return (len(user) == 23 and user[0] & 0xC0 == 0xC0 and user[1] & 0xF0 == 0xC0 and user[2] == 0x81
            and user[5:10] == bytes.fromhex('0c01280100') and user[-1] == 0)


def ctl61(frame):
    """Native control response frame -> the three transport segments as one octet string (one TCP payload)."""
    header8, user = std.deframe(frame)
    if not ctl_eligible(user):
        return None
    seq, app = user[0] & 0x3F, user[1:]
    out, at = b'', 0
    for i, n in enumerate(CTL_PARTS):
        th = ((seq + i) & 0x3F) | (std.FIR if i == 0 else 0) | (std.FIN if i == len(CTL_PARTS) - 1 else 0)
        seg = bytes([th]) + app[at:at + n]
        out += std.frame(header8[:2] + bytes([5 + len(seg)]) + header8[3:], seg)
        at += n
    assert at == len(app)
    return out


def split_frames(stream):
    """Cut an octet string holding back-to-back link frames into frames (LEN-driven)."""
    frames, p = [], 0
    while p < len(stream):
        if stream[p:p + 2] != b'\x05\x64':
            raise std.StdError('stream not aligned on a link frame at %d' % p)
        n = std.frame_length(stream[p + 2] - 5)
        frames.append(stream[p:p + n])
        p += n
    return frames


def encode(frame):
    """Any response frame -> its 61-octet image, or None when it is not an eligible shape (stays native)."""
    return read61(frame) or ctl61(frame)

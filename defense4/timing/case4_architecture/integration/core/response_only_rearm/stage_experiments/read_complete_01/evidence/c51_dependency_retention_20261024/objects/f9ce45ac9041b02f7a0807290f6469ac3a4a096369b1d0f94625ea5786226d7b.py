"""Pure SEL-751 whole49 builders and independent faithful 15+17 reframing.

No model, PacketGate, network, hardware, or generator imports.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'read_reencode_01'))
import dnp3_std as std

OBJECTS = bytes.fromhex('0c011702010101c80000000000000000030101c80000000000000000')


def frame(header, user):
    return std.frame(header[:2] + bytes([5 + len(user)]) + header[3:8], user)


def control_frame(seq, app, fc=3, response=False, statuses=(0, 0)):
    objects = bytearray(OBJECTS)
    objects[15], objects[27] = statuses
    user = bytes([0xc0 | (seq & 63), 0xc0 | (app & 15), 0x81 if response else fc])
    if response:
        user += b'\x80\x00'
    return frame(bytes.fromhex('0564004401000000' if response else '056400c400000100'), user + objects)


def control_image(native):
    header, user = std.deframe(native)
    if len(native) != 49 or len(user) != 33 or user[0] & 0xc0 != 0xc0 or user[2] != 0x81 or user[5:9] != bytes.fromhex('0c011702'):
        raise ValueError('expected whole49 two-CROB q17 response')
    seq = user[0] & 63
    return (frame(header, bytes([0x40 | seq]) + user[1:16]) +
            frame(header, bytes([0x80 | ((seq + 1) & 63)]) + user[16:]))

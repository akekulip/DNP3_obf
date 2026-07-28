"""
CRC-16/DNP (IEEE 1815) checksum helpers for DNP3 link/transport blocks.

Provides the bitwise CRC computation plus helpers to append and verify the 2-byte
CRC that terminates every DNP3 block (the 8-byte link header and each <=16-byte
user-data block). Used by the field map and CRC-aware tooling to confirm that
captured frames carry intact CRCs. No CRC is recomputed on the replay path; this
module only computes and checks them.
"""

import logging
import struct
import sys

stdout_stream = logging.StreamHandler(sys.stdout)
stdout_stream.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))

_log = logging.getLogger(__name__)
_log.addHandler(stdout_stream)
_log.setLevel(logging.DEBUG)

# CRC-16/DNP parameters (IEEE 1815 / DNP3):
#   polynomial 0x3D65, reflected input/output, init 0x0000, final XOR 0xFFFF.
# The reflected form of 0x3D65 used by the bitwise loop below is 0xA6BC.
_REFLECTED_POLY = 0xA6BC


def dnp3_crc16(data):
    """
        Compute the CRC-16/DNP of ``data`` (one DNP3 block, e.g. the 8-byte link
        header or a <=16-byte user-data block).

        NOTE: this CRC implementation is validated against captured DNP3 frames
        (see the module self-test) but is labeled experimental until exercised
        against your own captures.

    :param data: bytes to checksum.
    :return: 16-bit CRC as an int.
    """
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ _REFLECTED_POLY
            else:
                crc >>= 1
    # Final complement per the DNP3 specification.
    return (~crc) & 0xFFFF


def append_crc(data):
    """
        Return ``data`` followed by its 2 CRC bytes in DNP3 transmission order
        (low byte first / little-endian).

    :param data: bytes of a single block.
    :return: data + 2 CRC bytes.
    """
    crc = dnp3_crc16(data)
    return data + struct.pack('<H', crc)


def verify_crc(data, crc_bytes):
    """
        Verify that ``crc_bytes`` (2 bytes, little-endian as transmitted) match
        the CRC-16/DNP of ``data``.

    :param data: the block bytes the CRC covers.
    :param crc_bytes: the 2 received CRC bytes (low byte first).
    :return: True if the CRC matches.
    """
    if len(crc_bytes) != 2:
        _log.warning('verify_crc expected 2 CRC bytes, got %s', len(crc_bytes))
        return False
    received = struct.unpack('<H', bytes(crc_bytes))[0]
    computed = dnp3_crc16(data)
    return received == computed


def _self_test():
    """
        Validate the CRC against a known DNP3 link header.

        The link header is the first 8 bytes of a DNP3 frame; the following 2
        bytes are its CRC (transmitted low byte first).
    """
    # Real captured response link header + CRC (start 0x0564, dest 1, src 10).
    header = bytes.fromhex('05642b4401000a00')
    crc_bytes = bytes.fromhex('0b61')  # transmitted low byte first -> 0x610b
    computed = dnp3_crc16(header)
    expected = struct.unpack('<H', crc_bytes)[0]
    _log.info('Self-test header CRC computed=0x%04x expected=0x%04x match=%s',
              computed, expected, computed == expected)
    assert verify_crc(header, crc_bytes), 'CRC self-test failed'
    # append_crc round-trip.
    assert append_crc(header) == header + crc_bytes, 'append_crc self-test failed'
    _log.info('CRC self-test passed (experimental implementation).')


if __name__ == '__main__':
    _self_test()

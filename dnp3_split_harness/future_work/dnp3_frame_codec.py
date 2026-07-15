"""
EXPERIMENTAL (future_work): encode/decode DNP3 link frames with CRC recompute.

Archived 2026-06-18 and NOT used by the current replay path. Parses a DNP3 byte
stream into link frames and rebuilds frames while recomputing per-block CRCs --
the recompute-based line that the chosen byte-preserving CRC-boundary split
(dnp3_crc_splitter.py) deliberately avoids. Kept for the later
DNP3-aware modification phase; do not wire it into the no-byte-modification
experiments.
"""

import argparse
import logging
import os
import sys

# Archived under future_work/; reuse the CRC helpers that now live in the
# flattened harness root (one directory up from future_work/).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dnp3_crc import dnp3_crc16, append_crc, verify_crc

stdout_stream = logging.StreamHandler(sys.stdout)
stdout_stream.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))

_log = logging.getLogger(__name__)
_log.addHandler(stdout_stream)
_log.setLevel(logging.DEBUG)

# DNP3 link-frame structure (IEEE 1815):
#   [0:2]  start 0x05 0x64
#   [2]    LEN  = octet count of control+dest+src+user data, EXCLUDING CRCs (5..255)
#   [3]    control
#   [4:6]  destination (little-endian)
#   [6:8]  source (little-endian)
#   [8:10] header CRC (over bytes 0..7), little-endian
#   then user data in blocks of <=16 bytes, each followed by its own 2-byte CRC.
START = b'\x05\x64'
HEADER_LEN = 8            # bytes 0..7 covered by the header CRC
HEADER_CRC_LEN = 2
BLOCK_DATA = 16          # max user-data bytes per CRC block
BLOCK_CRC_LEN = 2
LEN_FIXED = 5            # control(1) + dest(2) + src(2) counted by LEN
MAX_USER = 250          # LEN max 255 => 250 user bytes max per frame


class DNP3Frame(object):
    """
        A parsed DNP3 link frame.

        Holds the link-layer header fields and the CRC-stripped user data (the
        transport byte followed by the application bytes). ``valid`` is True when
        the header CRC and every block CRC verified during parsing.
    """

    def __init__(self, control, destination, source, user_data, valid=True):
        self.control = control
        self.destination = destination
        self.source = source
        self.user_data = user_data      # transport + application bytes, CRCs removed
        self.valid = valid

    def __repr__(self):
        return ('DNP3Frame(control=0x{:02x} dest={} src={} user={}B valid={})'
                .format(self.control, self.destination, self.source,
                        len(self.user_data), self.valid))


class DNP3FrameCodec(object):
    """
        Parse and build DNP3 link frames with correct header and per-block CRCs.

        This is the keystone for DNP3-aware re-framing: ``parse_frame`` strips a
        frame to its transport payload (validating all CRCs), and ``build_frame``
        reconstructs a wire-valid frame from header fields + transport payload,
        recomputing every CRC. ``build_frame(*parse_frame(x)) == x`` for any valid
        frame (round-trip identity).
    """

    @staticmethod
    def wire_length(user_len):
        """Return the on-wire byte length of a frame carrying ``user_len`` user bytes."""
        nblocks = (user_len + BLOCK_DATA - 1) // BLOCK_DATA if user_len > 0 else 0
        return HEADER_LEN + HEADER_CRC_LEN + user_len + nblocks * BLOCK_CRC_LEN

    def parse_frame(self, data, offset=0):
        """
            Parse one DNP3 link frame from ``data`` starting at ``offset``.

        :param data: bytes containing at least one frame at ``offset``.
        :param offset: index of the frame's start bytes.
        :return: (DNP3Frame, next_offset) where next_offset is just past this frame.
        :raises ValueError: on a malformed/short frame or bad start bytes.
        """
        if data[offset:offset + 2] != START:
            raise ValueError('No DNP3 start bytes (0x0564) at offset {}'.format(offset))
        if offset + HEADER_LEN + HEADER_CRC_LEN > len(data):
            raise ValueError('Truncated frame header at offset {}'.format(offset))

        length = data[offset + 2]
        control = data[offset + 3]
        destination = int.from_bytes(data[offset + 4:offset + 6], 'little')
        source = int.from_bytes(data[offset + 6:offset + 8], 'little')

        valid = True
        header = data[offset:offset + HEADER_LEN]
        header_crc = data[offset + HEADER_LEN:offset + HEADER_LEN + HEADER_CRC_LEN]
        if not verify_crc(header, header_crc):
            _log.warning('Header CRC mismatch at offset %s', offset)
            valid = False

        user_total = length - LEN_FIXED          # user-data bytes carried by this frame
        if user_total < 0:
            raise ValueError('Invalid LEN={} at offset {}'.format(length, offset))

        pos = offset + HEADER_LEN + HEADER_CRC_LEN
        user_data = bytearray()
        remaining = user_total
        while remaining > 0:
            chunk_len = min(BLOCK_DATA, remaining)
            if pos + chunk_len + BLOCK_CRC_LEN > len(data):
                raise ValueError('Truncated data block at offset {}'.format(pos))
            chunk = data[pos:pos + chunk_len]
            block_crc = data[pos + chunk_len:pos + chunk_len + BLOCK_CRC_LEN]
            if not verify_crc(chunk, block_crc):
                _log.warning('Block CRC mismatch at offset %s', pos)
                valid = False
            user_data.extend(chunk)
            pos += chunk_len + BLOCK_CRC_LEN
            remaining -= chunk_len

        return DNP3Frame(control, destination, source, bytes(user_data), valid), pos

    def parse_stream(self, data):
        """Parse every consecutive DNP3 frame in ``data``; return a list of DNP3Frame."""
        frames = []
        offset = 0
        while offset < len(data) - 1:
            if data[offset:offset + 2] != START:
                offset += 1
                continue
            frame, offset = self.parse_frame(data, offset)
            frames.append(frame)
        return frames

    def build_frame(self, control, destination, source, user_data):
        """
            Build a wire-valid DNP3 link frame from header fields + user data.

            Recomputes the header CRC and a CRC for each <=16-byte user block.

        :param control: link control byte (int).
        :param destination: destination link address (int).
        :param source: source link address (int).
        :param user_data: transport + application bytes (<= 250).
        :return: the complete frame bytes.
        """
        if len(user_data) > MAX_USER:
            raise ValueError('user_data {} > {} bytes; split across frames first'
                             .format(len(user_data), MAX_USER))
        length = LEN_FIXED + len(user_data)
        header = bytearray()
        header += START
        header.append(length)
        header.append(control)
        header += int(destination).to_bytes(2, 'little')
        header += int(source).to_bytes(2, 'little')
        frame = bytearray(append_crc(bytes(header)))      # header + header CRC
        for i in range(0, len(user_data), BLOCK_DATA):
            frame += append_crc(user_data[i:i + BLOCK_DATA])   # data block + its CRC
        return bytes(frame)


def _self_test(payload_path):
    """Round-trip check: parse each frame in ``payload_path`` and rebuild it identically."""
    codec = DNP3FrameCodec()
    with open(payload_path, 'rb') as fh:
        data = fh.read()
    frames = codec.parse_stream(data)
    _log.info('Parsed %s frame(s) from %s', len(frames), payload_path)
    ok = True
    # Round-trip each frame from its own start to its computed wire length.
    offset = 0
    idx = 0
    while offset < len(data) - 1:
        if data[offset:offset + 2] != START:
            offset += 1
            continue
        frame, nxt = codec.parse_frame(data, offset)
        rebuilt = codec.build_frame(frame.control, frame.destination, frame.source, frame.user_data)
        original = data[offset:nxt]
        same = rebuilt == original
        ok = ok and same and frame.valid
        _log.info('frame %s: %s  crc_valid=%s  rebuild_identical=%s',
                  idx, frame, frame.valid, same)
        idx += 1
        offset = nxt
    _log.info('Round-trip %s for all frames.', 'PASSED' if ok else 'FAILED')
    return ok


def build_parser():
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        description='DNP3 link-frame codec: round-trip self-test on a raw payload .bin.')
    parser.add_argument('--payload', required=True, help='Raw DNP3 byte stream to parse + rebuild.')
    return parser


def main():
    args = build_parser().parse_args()
    if not os.path.exists(args.payload):
        _log.error('Payload not found: %s', args.payload)
        sys.exit(1)
    sys.exit(0 if _self_test(args.payload) else 1)


if __name__ == '__main__':
    main()

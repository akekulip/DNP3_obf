"""
Split a captured DNP3 byte stream at its existing CRC boundaries.

Defines ``DNP3CRCSplitter``: it locates the offsets that follow each already-valid
CRC block (the header block and each <=16-byte data block) and cuts the stream
only there, so every chunk ends on a CRC already present in the capture. No byte
is altered and no CRC is recomputed -- the concatenation of the chunks is
byte-identical to the input. This is the structure-aware variant of TCP-level
split replay and the harness's byte-preserving obfuscation primitive.
"""

import argparse
import logging
import os
import sys

stdout_stream = logging.StreamHandler(sys.stdout)
stdout_stream.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))

_log = logging.getLogger(__name__)
_log.addHandler(stdout_stream)
_log.setLevel(logging.DEBUG)

# DNP3 on-wire block layout used to locate CRC boundaries:
#   header block = 8 header bytes + 2 CRC
#   data block   = up to 16 data bytes + 2 CRC
START = b'\x05\x64'
HEADER_BLOCK = 8
CRC_LEN = 2
DATA_BLOCK = 16
LEN_FIXED = 5            # LEN counts control+dest+src; user bytes = LEN - 5


class DNP3CRCSplitter(object):
    """
        Split a captured DNP3 byte stream at its existing CRC boundaries — without
        recomputing any CRC.

        Every DNP3 block (the header block and each <=16-byte data block) already
        ends with its own 2-byte CRC. This splitter locates those boundaries and
        cuts the byte stream so each piece ends exactly on a CRC that is already
        present in the capture. No bytes are altered and no CRC is recalculated:
        the concatenation of the pieces is byte-identical to the input.

        This is a structure-aware variant of TCP-level split replay (Phase 7):
        the cut points line up with DNP3 CRC blocks instead of arbitrary offsets.
        (A piece here is a CRC block, not yet a standalone link frame — frame
        wrapping is a later step.)
    """

    def crc_boundaries(self, data):
        """
            Return the byte offsets that immediately follow each CRC in ``data``.

            These are exactly the positions where the stream can be cut so every
            piece ends on an existing CRC.

        :param data: a DNP3 byte stream (one or more concatenated frames).
        :return: sorted list of cut offsets (1..len(data)).
        """
        bounds = []
        offset = 0
        n = len(data)
        while offset < n - 1:
            if data[offset:offset + 2] != START:
                offset += 1
                continue
            length = data[offset + 2]
            user_total = length - LEN_FIXED
            if user_total < 0:
                _log.warning('Invalid LEN=%s at offset %s; stopping scan.', length, offset)
                break
            # boundary after the header block's CRC
            pos = offset + HEADER_BLOCK + CRC_LEN
            bounds.append(pos)
            remaining = user_total
            while remaining > 0:
                chunk = min(DATA_BLOCK, remaining)
                pos += chunk + CRC_LEN          # boundary after this data block's CRC
                bounds.append(pos)
                remaining -= chunk
            offset = pos
        return [b for b in bounds if 0 < b <= n]

    def split(self, data, blocks_per_chunk=1):
        """
            Split ``data`` into chunks of ``blocks_per_chunk`` whole CRC blocks.

            Each chunk ends on an existing CRC; no CRC is recomputed. The
            concatenation of the returned chunks equals ``data`` exactly.

        :param data: the DNP3 byte stream to split.
        :param blocks_per_chunk: how many CRC blocks per emitted chunk (>=1).
        :return: list of chunk bytes.
        """
        if blocks_per_chunk < 1:
            raise ValueError('blocks_per_chunk must be >= 1')
        bounds = self.crc_boundaries(data)
        # keep every Nth boundary as a cut point
        cuts = bounds[blocks_per_chunk - 1::blocks_per_chunk]
        chunks = []
        prev = 0
        for cut in cuts:
            if cut > prev:
                chunks.append(data[prev:cut])
                prev = cut
        if prev < len(data):                    # trailing bytes (shouldn't happen on clean input)
            chunks.append(data[prev:])
        if b''.join(chunks) != data:
            raise ValueError('CRC split did not reconstruct the original stream')
        return chunks


def build_parser():
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        description='Split a captured DNP3 stream at existing CRC boundaries (no recompute).')
    parser.add_argument('--response', required=True, help='Captured DNP3 byte stream (.bin).')
    parser.add_argument('--blocks-per-chunk', type=int, default=1,
                        help='Number of whole CRC blocks per chunk (default 1).')
    parser.add_argument('--output-dir', default=None,
                        help='Optional: write each chunk as chunk_NNNN.bin here.')
    return parser


def main():
    args = build_parser().parse_args()
    if not os.path.exists(args.response):
        _log.error('Response not found: %s', args.response)
        sys.exit(1)

    with open(args.response, 'rb') as fh:
        data = fh.read()

    splitter = DNP3CRCSplitter()
    chunks = splitter.split(data, args.blocks_per_chunk)
    _log.info('Split %s bytes into %s chunk(s) at CRC boundaries (blocks_per_chunk=%s).',
              len(data), len(chunks), args.blocks_per_chunk)
    _log.info('Chunk sizes: %s', [len(c) for c in chunks])
    _log.info('Reconstruction byte-identical: %s', b''.join(chunks) == data)

    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        for i, chunk in enumerate(chunks):
            with open(os.path.join(args.output_dir, 'chunk_{:04d}.bin'.format(i + 1)), 'wb') as fh:
                fh.write(chunk)
        _log.info('Wrote %s chunk file(s) to %s', len(chunks), args.output_dir)


if __name__ == '__main__':
    main()

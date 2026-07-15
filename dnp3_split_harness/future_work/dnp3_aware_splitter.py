"""
Experimental future work. NOT used by the current byte-preserving replay path.

This re-segmenter rebuilds DNP3 link frames and RECOMPUTES CRCs, so it changes the
on-wire bytes. The validated replay path is the opposite -- captured bytes are cut
only on existing CRC boundaries and never modified (see dnp3_crc_splitter.py and
tcp_split_replay_server.py). Keep this file out of the current replay server; it
belongs to a later phase (true DNP3-aware modification).
"""

import argparse
import logging
import os
import sys

# Archived under future_work/; dnp3_frame_codec.py is its sibling here.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dnp3_frame_codec import DNP3FrameCodec

stdout_stream = logging.StreamHandler(sys.stdout)
stdout_stream.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))

_log = logging.getLogger(__name__)
_log.addHandler(stdout_stream)
_log.setLevel(logging.DEBUG)

# Transport header bits (first user byte of every link frame).
T_FIN = 0x80
T_FIR = 0x40
T_SEQ_MASK = 0x3F
MAX_SEG_DATA = 249       # frame user max 250 = 1 transport byte + 249 data


class DNP3AwareSplitter(object):
    """
        Semantics-preserving DNP3 re-framing by transport re-segmentation.

        A DNP3 application response (APDU) is carried as a run of transport
        segments — one per link frame, FIR on the first, FIN on the last, sequence
        incrementing. This splitter reassembles each APDU (stripping the per-frame
        transport header), re-divides the application payload into a different
        number of segments of a chosen size, reassigns valid transport headers,
        and rebuilds each segment as a wire-valid frame (CRCs recomputed by the
        codec). The application payload and the link control/addresses are
        preserved exactly, so the master reassembles the identical APDU — only the
        number and size of DNP3 frames on the wire change.

        Pure link-level re-blocking is intentionally NOT done: each link frame is
        one transport segment, so splitting a segment across frames would corrupt
        transport reassembly.
    """

    def __init__(self):
        self.codec = DNP3FrameCodec()

    def group_apdus(self, frames):
        """
            Group a flat list of DNP3Frame into APDUs using transport FIR/FIN.

        :return: list of APDUs, each a list of DNP3Frame from FIR to FIN.
        """
        apdus = []
        current = []
        for frame in frames:
            transport = frame.user_data[0]
            fir = bool(transport & T_FIR)
            fin = bool(transport & T_FIN)
            if fir:
                current = [frame]
            else:
                current.append(frame)
            if fin:
                apdus.append(current)
                current = []
        if current:
            apdus.append(current)
        return apdus

    @staticmethod
    def reassemble_apdu(apdu_frames):
        """Concatenate the application payload of an APDU (strip each transport header)."""
        return b''.join(frame.user_data[1:] for frame in apdu_frames)

    def resegment_apdu(self, apdu_frames, max_seg_data):
        """
            Re-segment one APDU into frames whose application payload is chunked
            into pieces of at most ``max_seg_data`` bytes.

        :return: bytes of the rebuilt frames for this APDU.
        """
        if not 1 <= max_seg_data <= MAX_SEG_DATA:
            raise ValueError('max_seg_data must be 1..{}'.format(MAX_SEG_DATA))
        head = apdu_frames[0]
        control, dest, src = head.control, head.destination, head.source
        first_seq = head.user_data[0] & T_SEQ_MASK
        app_payload = self.reassemble_apdu(apdu_frames)

        chunks = [app_payload[i:i + max_seg_data]
                  for i in range(0, len(app_payload), max_seg_data)] or [b'']
        out = bytearray()
        last = len(chunks) - 1
        for i, chunk in enumerate(chunks):
            fir = T_FIR if i == 0 else 0
            fin = T_FIN if i == last else 0
            seq = (first_seq + i) & T_SEQ_MASK
            transport = fin | fir | seq
            out += self.codec.build_frame(control, dest, src, bytes([transport]) + chunk)
        return bytes(out)

    def split_stream(self, data, max_seg_data):
        """
            Re-frame a whole captured response stream by transport re-segmentation.

        :return: (new_stream_bytes, stats_dict)
        """
        frames = self.codec.parse_stream(data)
        apdus = self.group_apdus(frames)
        out = bytearray()
        for apdu in apdus:
            out += self.resegment_apdu(apdu, max_seg_data)
        stats = {
            'apdus': len(apdus),
            'frames_in': len(frames),
            'frames_out': len(self.codec.parse_stream(bytes(out))),
            'bytes_in': len(data),
            'bytes_out': len(out),
        }
        return bytes(out), stats

    def verify_equivalence(self, original, reframed):
        """
            Confirm the reframed stream is semantically identical to the original:
            same APDU application payloads, in order, with all CRCs valid.

        :return: True if equivalent and every reframed frame's CRCs verify.
        """
        orig_apdus = [self.reassemble_apdu(a)
                      for a in self.group_apdus(self.codec.parse_stream(original))]
        new_frames = self.codec.parse_stream(reframed)
        new_apdus = [self.reassemble_apdu(a) for a in self.group_apdus(new_frames)]
        crc_ok = all(frame.valid for frame in new_frames)
        equal = orig_apdus == new_apdus
        if not crc_ok:
            _log.error('Reframed stream has invalid CRC(s).')
        if not equal:
            _log.error('Reframed APDU payload(s) differ from the original.')
        return crc_ok and equal


def build_parser():
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        description='DNP3-aware splitter: re-frame a captured response by transport '
                    're-segmentation, preserving the application payload.')
    parser.add_argument('--response', required=True, help='Captured response byte stream (.bin).')
    parser.add_argument('--max-seg-data', type=int, default=40,
                        help='Max application-payload bytes per transport segment (1..249).')
    parser.add_argument('--output', required=True, help='Path to write the re-framed stream.')
    return parser


def main():
    args = build_parser().parse_args()
    if not os.path.exists(args.response):
        _log.error('Response not found: %s', args.response)
        sys.exit(1)

    with open(args.response, 'rb') as fh:
        original = fh.read()

    splitter = DNP3AwareSplitter()
    reframed, stats = splitter.split_stream(original, args.max_seg_data)
    equivalent = splitter.verify_equivalence(original, reframed)

    if not equivalent:
        _log.error('Aborting: reframed stream is not semantically equivalent.')
        sys.exit(1)

    out_dir = os.path.dirname(os.path.abspath(args.output))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.output, 'wb') as fh:
        fh.write(reframed)

    _log.info('APDUs=%s  frames %s -> %s  bytes %s -> %s  (max_seg_data=%s)  equivalent=%s',
              stats['apdus'], stats['frames_in'], stats['frames_out'],
              stats['bytes_in'], stats['bytes_out'], args.max_seg_data, equivalent)
    _log.info('Wrote re-framed, CRC-valid, payload-identical stream to %s', args.output)


if __name__ == '__main__':
    main()

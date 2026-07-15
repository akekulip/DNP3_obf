"""
Legacy single-shot byte-split replay server.

Earlier phase of the experiment: serve ONE captured response file to the first
connection, split across multiple TCP writes by a chosen split mode (full / half
/ byte / fixed / offsets / crc). It does not parse the master request or match it
to a response -- it just dumps the one response after the first read. Kept for the
TCP-robustness tests (e.g. scripts/run_split_replay_test.sh).

The current, request-aware path lives in tcp_split_replay_server.py +
captured_exchange.py (driven by dnp3_split_replay_server.py / split_server.py).
Prefer that for new work; this file is here so the legacy tests still run.

All modes are byte-preserving: b"".join(chunks) == response.
"""

import argparse
import logging
import os
import socket
import sys
import time
from datetime import datetime

from dnp3_crc_splitter import DNP3CRCSplitter

stdout_stream = logging.StreamHandler(sys.stdout)
stdout_stream.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))
_log = logging.getLogger(__name__)
_log.addHandler(stdout_stream)
_log.setLevel(logging.DEBUG)

RECV_BUFSIZE = 65535
SPLIT_MODES = ['full', 'half', 'byte', 'fixed', 'offsets', 'crc', 'crc-boundary']


def split_payload(payload, mode, fixed_size=40, offsets_str='', blocks_per_chunk=1):
    """Split ``payload`` into chunks by ``mode`` (concatenation always equals payload).

    Modes:
      full    -> one chunk (the whole payload).
      half    -> two chunks split at the midpoint.
      byte    -> one chunk per byte.
      fixed   -> chunks of ``fixed_size`` bytes (last may be shorter).
      offsets -> chunks split at the given comma-separated byte offsets.
      crc     -> chunks of ``blocks_per_chunk`` whole DNP3 CRC blocks; each chunk
                 ends on an existing CRC and no CRC is recomputed.
    """
    if mode in ('crc', 'crc-boundary'):
        return DNP3CRCSplitter().split(payload, blocks_per_chunk)

    if mode == 'full':
        return [payload]

    if mode == 'half':
        mid = len(payload) // 2
        return [c for c in (payload[:mid], payload[mid:]) if c]

    if mode == 'byte':
        return [payload[i:i + 1] for i in range(len(payload))]

    if mode == 'fixed':
        if fixed_size < 1:
            raise ValueError('--fixed-size must be >= 1')
        return [payload[i:i + fixed_size] for i in range(0, len(payload), fixed_size)]

    if mode == 'offsets':
        cuts = sorted({int(x) for x in offsets_str.split(',') if x.strip() != ''})
        cuts = [c for c in cuts if 0 < c < len(payload)]
        chunks = []
        prev = 0
        for cut in cuts:
            chunks.append(payload[prev:cut])
            prev = cut
        chunks.append(payload[prev:])
        return [c for c in chunks if c]

    raise ValueError('Unknown split mode: {}'.format(mode))


class LegacySingleResponseServer:
    """Replay one captured response across multiple TCP writes (no request matching)."""

    def __init__(self, host, port, response_path, split_mode='half',
                 fixed_size=40, offsets_str='', blocks_per_chunk=1,
                 delay_between_chunks_ms=0, hold_after_response_sec=5.0, log_dir=None):
        self.host = host
        self.port = port
        self.response_path = response_path
        self.split_mode = split_mode
        self.delay_between_chunks_ms = delay_between_chunks_ms
        self.hold_after_response_sec = hold_after_response_sec
        self.log_dir = log_dir

        with open(response_path, 'rb') as fh:
            self.response_bytes = fh.read()
        self.chunks = split_payload(self.response_bytes, split_mode, fixed_size,
                                    offsets_str, blocks_per_chunk)
        if b''.join(self.chunks) != self.response_bytes:
            raise ValueError('split produced bytes that do not reconstruct the original payload')

        _log.info('Loaded response payload: %s bytes', len(self.response_bytes))
        _log.info('Split mode: %s', split_mode)
        _log.info('Chunk count: %s', len(self.chunks))
        _log.info('Chunk sizes: %s', [len(c) for c in self.chunks])
        _log.info('Byte-preservation check: PASS')

        if self.log_dir:
            os.makedirs(self.log_dir, exist_ok=True)

    def _dump(self, name, data):
        if not self.log_dir:
            return
        with open(os.path.join(self.log_dir, name), 'wb') as fh:
            fh.write(data)

    def serve_once(self):
        """Accept one connection, send the response in chunks, then hold for a CONFIRM."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(1)
            _log.info('Listening on %s:%s (single connection).', self.host, self.port)

            conn, addr = srv.accept()
            _log.info('Connection from %s at %s', addr, datetime.now().isoformat())
            with conn:
                conn.settimeout(5.0)
                try:
                    request = conn.recv(RECV_BUFSIZE)
                except socket.timeout:
                    request = b''
                    _log.warning('No request received within timeout; responding anyway.')
                _log.info('Received %s request byte(s).', len(request))
                self._dump('received_request.bin', request)

                for idx, chunk in enumerate(self.chunks):
                    conn.sendall(chunk)
                    _log.info('Sent chunk %s/%s: %s byte(s)', idx + 1, len(self.chunks), len(chunk))
                    self._dump('chunk_{:04d}.bin'.format(idx + 1), chunk)
                    if self.delay_between_chunks_ms > 0 and idx < len(self.chunks) - 1:
                        time.sleep(self.delay_between_chunks_ms / 1000.0)

                self._receive_follow_up(conn)
            _log.info('Connection closed cleanly.')

    def _receive_follow_up(self, conn):
        """Hold the socket open and log any follow-up bytes (e.g. a DNP3 CONFIRM)."""
        if self.hold_after_response_sec <= 0:
            return
        _log.info('Waiting for follow-up data / DNP3 CONFIRM (up to %ss).',
                  self.hold_after_response_sec)
        deadline = time.time() + self.hold_after_response_sec
        follow_up = bytearray()
        conn.settimeout(0.5)
        while time.time() < deadline:
            try:
                data = conn.recv(RECV_BUFSIZE)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                _log.info('Master closed the connection.')
                break
            follow_up += data
            _log.info('Received follow-up bytes: %s', len(data))
        if follow_up:
            self._dump('follow_up.bin', bytes(follow_up))
            _log.info('Total follow-up bytes received: %s (saved to follow_up.bin)', len(follow_up))
        else:
            _log.info('No follow-up bytes received within the hold window.')


def build_parser():
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        description='Legacy single-shot replay: serve one captured response across multiple '
                    'TCP writes (byte-preserving). Tests TCP-stream robustness, not DNP3 '
                    'request matching.')
    parser.add_argument('--host', default='0.0.0.0', help='Local interface address to bind.')
    parser.add_argument('--port', type=int, default=20000, help='TCP port (default 20000).')
    parser.add_argument('--response', required=True, help='Path to the response .bin to replay.')
    parser.add_argument('--split-mode', choices=SPLIT_MODES, default='half',
                        help='How to chunk the response across sendall() calls.')
    parser.add_argument('--fixed-size', type=int, default=40,
                        help='Chunk size in bytes for --split-mode fixed.')
    parser.add_argument('--offsets', default='',
                        help='Comma-separated byte offsets for --split-mode offsets.')
    parser.add_argument('--blocks-per-chunk', type=int, default=1,
                        help='CRC blocks per chunk for --split-mode crc (default 1).')
    parser.add_argument('--delay-between-chunks-ms', type=int, default=0,
                        help='Milliseconds to sleep between chunk writes.')
    parser.add_argument('--hold-after-response-sec', type=float, default=5.0,
                        help='Seconds to keep the connection open after the last chunk.')
    parser.add_argument('--log-dir', default=None,
                        help='Directory to write per-chunk dumps and a run log.')
    return parser


def main():
    args = build_parser().parse_args()
    if args.log_dir:
        os.makedirs(args.log_dir, exist_ok=True)
        file_handler = logging.FileHandler(
            os.path.join(args.log_dir, 'legacy_single_response_server_{}.log'.format(int(time.time()))))
        file_handler.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))
        logging.getLogger().addHandler(file_handler)
        logging.getLogger().setLevel(logging.DEBUG)

    if not os.path.exists(args.response):
        _log.error('Response file not found: %s', args.response)
        sys.exit(1)

    server = LegacySingleResponseServer(
        host=args.host, port=args.port, response_path=args.response,
        split_mode=args.split_mode, fixed_size=args.fixed_size, offsets_str=args.offsets,
        blocks_per_chunk=args.blocks_per_chunk,
        delay_between_chunks_ms=args.delay_between_chunks_ms,
        hold_after_response_sec=args.hold_after_response_sec, log_dir=args.log_dir)
    server.serve_once()


if __name__ == '__main__':
    main()

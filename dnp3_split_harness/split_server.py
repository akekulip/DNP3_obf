"""
split_server.py -- the one canonical TCP replay/split server (no pydnp3 needed).

Run it with no arguments:

    python split_server.py                 # crc-boundary split (default)
    python split_server.py --delivery full # exact replay, one write per response

It stands in for the outstation on 0.0.0.0:20000 (settings from lab_config.py),
and for each master request it:

  - reassembles whole DNP3 link frames from the TCP stream (TCP gives no message
    boundaries, so one recv() may carry a partial frame, one frame, or several),
  - parses the DNP3 function code + application sequence,
  - selects the matching captured response (request->response map built from the
    baseline capture's payloads/replay/*.bin + metadata.json),
  - in crc-boundary mode, splits every data-bearing RESPONSE -- the READ response
    AND its CONFIRM-triggered continuation fragment -- on existing DNP3 CRC
    boundaries (no byte altered, no CRC recomputed, so b"".join(chunks) ==
    response); in full mode, sends each response group as a single write,
  - sends the chunks with socket.sendall() over a TCP_NODELAY socket, holds the
    connection open, and logs the master's DNP3 CONFIRM.

It refuses to serve a captured response to a request it cannot match (no blind
byte dumping). This single server replaces the former trio of replay servers:
``--delivery full`` is the exact verbatim replay; ``--delivery crc-boundary`` is
the byte-preserving split. (The earlier standalone variants are kept for
reference under archive_experiments/.)

Everything it needs -- frame reassembler, request parser, CRC-boundary splitter,
captured-exchange map, and the TCP server -- lives in this one file; the only
harness import is lab_config.py. This is a plain TCP socket server, so it does
NOT require pydnp3.

Stop the real outstation first -- both need port 20000:

    sudo fuser -k 20000/tcp
"""

import argparse
import json
import logging
import os
import socket
import sys
import time

from datetime import datetime

HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HARNESS_DIR)  # so 'lab_config' imports regardless of cwd

import lab_config as cfg
import timing_policy as tpol

# Single source of truth: all lab settings come from lab_config.py.
BIND_IP = cfg.BIND_IP
DNP3_PORT = cfg.DNP3_PORT
DEFAULT_SPLIT_MODE = cfg.DEFAULT_SPLIT_MODE
DEFAULT_BLOCKS_PER_CHUNK = cfg.DEFAULT_BLOCKS_PER_CHUNK
DEFAULT_CHUNK_DELAY_MS = cfg.DEFAULT_CHUNK_DELAY_MS
DEFAULT_HOLD_AFTER_RESPONSE_SEC = cfg.DEFAULT_HOLD_AFTER_RESPONSE_SEC
DEFAULT_REPLAY_DIR = cfg.DEFAULT_REPLAY_DIR
LOG_DIR = cfg.LOG_DIR

stdout_stream = logging.StreamHandler(sys.stdout)
stdout_stream.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))
logging.getLogger().addHandler(stdout_stream)
logging.getLogger().setLevel(logging.DEBUG)
_log = logging.getLogger(__name__)

# --- DNP3 framing constants -------------------------------------------------
START_BYTES = b"\x05\x64"        # DNP3 link-frame start octets
CONFIRM_FUNCTION_CODE = 0x00
READ_FUNCTION_CODE = 0x01
RESPONSE_FUNCTION_CODE = 0x81
RECV_BUFSIZE = 65535
# Delivery modes: "full" = exact replay (one write/group); the CRC-split aliases
# cut data responses on existing CRC boundaries.
CRC_SPLIT_MODES = ("crc", "crc-boundary")
FULL_DELIVERY = "full"

# Application function codes, enough to identify a master request.
FUNCTION_CODES = {
    0x00: "CONFIRM",
    0x01: "READ",
    0x02: "WRITE",
    0x14: "ENABLE_UNSOLICITED",
    0x15: "DISABLE_UNSOLICITED",
    0x81: "RESPONSE",
}
# A frame must reach at least the application function code (offset 12) to parse.
_MIN_FRAME_LEN = 13

# DNP3 control function codes. This harness serves READ responses + handshake
# replies only and issues no controls (SELECT/OPERATE live in the multi-CROB
# harness), so none of these should appear here -- but if a control-bearing
# request ever did, the timing policy bypasses it (critical traffic is never held).
CRITICAL_FUNCTION_CODES = frozenset({0x03, 0x04, 0x05, 0x06, 0x0d, 0x0e})

# On-wire DNP3 block layout used to locate CRC boundaries:
#   header block = 8 header bytes + 2 CRC ; data block = up to 16 bytes + 2 CRC
HEADER_BLOCK = 8
CRC_LEN = 2
DATA_BLOCK = 16
LEN_FIXED = 5            # LEN counts control+dest+src; user bytes = LEN - 5


# ------------------------------------------------------------------ #
# Minimal DNP3 request parsing (function code + application sequence)
# ------------------------------------------------------------------ #

def parse_dnp3_request(data):
    """Identify a master request from the first link frame of ``data``.

    DNP3 frame byte offsets used here:
        0-1 start (0x05 0x64); 2 length; 3 link control; 4-5 dest (LE);
        6-7 src (LE); 8-9 header CRC; 10 transport byte; 11 application
        control (sequence in low nibble); 12 application function code.

    Returns a dict with ``valid`` plus the decoded fields. ``valid`` is False
    (fields None) when the bytes are too short or lack the DNP3 start bytes.
    """
    if len(data) < _MIN_FRAME_LEN or data[0:2] != START_BYTES:
        return {
            "valid": False,
            "src": None,
            "dst": None,
            "transport_seq": None,
            "transport_fir": None,
            "transport_fin": None,
            "app_seq": None,
            "function_code": None,
            "function_name": None,
            "payload_len": len(data),
        }

    dst = data[4] | (data[5] << 8)
    src = data[6] | (data[7] << 8)
    transport = data[10]
    app_control = data[11]
    function_code = data[12]
    return {
        "valid": True,
        "src": src,
        "dst": dst,
        "transport_seq": transport & 0x3F,
        "transport_fir": bool(transport & 0x40),
        "transport_fin": bool(transport & 0x80),
        "app_seq": app_control & 0x0F,
        "function_code": function_code,
        "function_name": FUNCTION_CODES.get(function_code, "UNKNOWN"),
        "payload_len": len(data),
    }


def describe_request(parsed):
    """Render a parsed request as a one-line string for logs."""
    if not parsed["valid"]:
        return "non-DNP3/short ({} bytes)".format(parsed["payload_len"])
    return "{} (0x{:02x}) app_seq={} src={} dst={}".format(
        parsed["function_name"], parsed["function_code"],
        parsed["app_seq"], parsed["src"], parsed["dst"])


def dnp3_frame_length(buf, offset=0):
    """Wire length of the DNP3 link frame starting at ``offset`` in ``buf``.

    The link header carries LEN, which counts control+dest+src plus the user
    payload (transport + application bytes) but not the CRCs. The on-wire frame
    is the 10-byte header block (8 header bytes + 2 CRC) followed by the payload
    split into <=16-byte data blocks, each with its own 2-byte CRC.

    Returns the full frame length in bytes, ``None`` if ``buf`` is too short to
    determine it yet, or ``-1`` if the LEN field is invalid (caller should
    resynchronize).
    """
    if len(buf) - offset < 3:
        return None
    if buf[offset:offset + 2] != START_BYTES:
        return None
    length = buf[offset + 2]
    payload_len = length - LEN_FIXED
    if payload_len < 0:
        return -1
    n_blocks = (payload_len + DATA_BLOCK - 1) // DATA_BLOCK
    return HEADER_BLOCK + CRC_LEN + payload_len + n_blocks * CRC_LEN


# ------------------------------------------------------------------ #
# TCP -> DNP3 frame reassembly (TCP has no message boundaries)
# ------------------------------------------------------------------ #

class FrameReader:
    """Buffered reader that emits exactly one complete DNP3 link frame per call.

    TCP gives no message boundaries: a single recv() may hold half a frame, one
    frame, several frames, or a frame plus part of the next. This buffers bytes,
    locates the 0x05 0x64 start, computes the full wire-frame length from the LEN
    field, and returns one whole frame -- retaining any remainder for the next
    call. This makes the server a valid TCP implementation rather than relying on
    each request arriving in its own recv().
    """

    def __init__(self, conn):
        self._conn = conn
        self._buf = bytearray()

    def next_frame(self, timeout_sec):
        """Return one complete DNP3 frame, or b'' on timeout / closed connection."""
        self._conn.settimeout(timeout_sec)
        while True:
            frame = self._take_buffered_frame()
            if frame is not None:
                return frame
            try:
                data = self._conn.recv(RECV_BUFSIZE)
            except (socket.timeout, OSError):
                return b""
            if not data:
                return b""          # peer closed and no complete frame buffered
            self._buf += data

    def _take_buffered_frame(self):
        """Pop one complete frame from the buffer, or None if not yet complete."""
        buf = self._buf
        start = buf.find(START_BYTES)
        if start == -1:
            # No start bytes yet; keep only a trailing lone 0x05 in case the
            # 0x64 arrives on the next read.
            if len(buf) > 1:
                del buf[:-1]
            return None
        if start > 0:
            _log.debug("Discarding %s byte(s) before DNP3 start octets.", start)
            del buf[:start]
        frame_len = dnp3_frame_length(buf, 0)
        if frame_len is None:
            return None             # need more bytes to read LEN / complete frame
        if frame_len < 0:
            del buf[:2]             # invalid LEN: drop start octets and resync
            return self._take_buffered_frame()
        if len(buf) < frame_len:
            return None             # frame has not fully arrived yet
        frame = bytes(buf[:frame_len])
        del buf[:frame_len]
        return frame


# ------------------------------------------------------------------ #
# CRC-boundary splitter (reuse existing CRCs, recompute nothing)
# ------------------------------------------------------------------ #

class DNP3CRCSplitter(object):
    """
        Split a captured DNP3 byte stream at its existing CRC boundaries -- without
        recomputing any CRC.

        Every DNP3 block (the header block and each <=16-byte data block) already
        ends with its own 2-byte CRC. This splitter locates those boundaries and
        cuts the byte stream so each piece ends exactly on a CRC that is already
        present in the capture. No bytes are altered and no CRC is recalculated:
        the concatenation of the pieces is byte-identical to the input.
    """

    def crc_boundaries(self, data):
        """
            Return the byte offsets that immediately follow each CRC in ``data``.

            These are exactly the positions where the stream can be cut so every
            piece ends on an existing CRC.
        """
        bounds = []
        offset = 0
        n = len(data)
        while offset < n - 1:
            if data[offset:offset + 2] != START_BYTES:
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


def response_is_data_response(response_bytes):
    """True if a captured response begins with a DNP3 application RESPONSE (0x81)."""
    parsed = parse_dnp3_request(response_bytes)
    return parsed["valid"] and parsed["function_code"] == RESPONSE_FUNCTION_CODE


# ------------------------------------------------------------------ #
# Captured request -> response map
# ------------------------------------------------------------------ #

class CapturedExchange:
    """The captured request->response entries, with request matching.

    A baseline capture is extracted into orig_*.bin (master requests), resp_*.bin
    (outstation responses) and metadata.json (an ordered list of packet records).
    In capture order, each request is followed by the run of responses it
    produced; that run, concatenated, is the captured reply to that request. This
    refuses to serve a captured response to a request it cannot match -- the
    safety rule that keeps the server from being a blind byte dumper.

    A multi-fragment READ answer spans two captured groups: the READ produces the
    first RESPONSE fragment (FIR=1, FIN=0, confirm requested); after the master's
    CONFIRM the outstation sends the continuation RESPONSE fragment. Both groups
    are flagged ``is_splittable`` -- a READ, or a CONFIRM whose captured response
    is itself a data RESPONSE -- so the continuation is split too, not just the
    first fragment.
    """

    def __init__(self, payload_dir):
        self.payload_dir = payload_dir
        self.entries = self._load_entries(payload_dir)
        self._used = [False] * len(self.entries)

        _log.info("Loaded %s captured request->response entr(ies) from %s.",
                  len(self.entries), payload_dir)
        for i, entry in enumerate(self.entries):
            _log.info("  entry %s: %s (0x%02x) app_seq=%s -> %s (%s bytes)%s",
                      i + 1, entry["function_name"], entry["function_code"],
                      entry["app_seq"], "+".join(entry["response_files"]),
                      len(entry["response_bytes"]),
                      " [data RESPONSE -- will be split]" if entry["is_splittable"] else "")

    def has_pending_responses(self):
        """True while at least one captured response has not been served yet."""
        return not all(self._used)

    def match_response(self, parsed_request):
        """Return the captured entry for ``parsed_request``, or None.

        Match priority:
          1. same function code AND application sequence,
          2. otherwise the next unused entry with the same function code.

        On a match the entry is marked used so it is not served twice. A request
        that matches nothing returns None -- a captured response is never served
        to a request that does not match one.
        """
        if not parsed_request["valid"]:
            return None

        index = self._find(parsed_request, require_app_seq=True)
        if index is None:
            index = self._find(parsed_request, require_app_seq=False)
        if index is None:
            _log.warning("No captured response matches function code %s app_seq %s; "
                         "serving nothing.",
                         "0x{:02x}".format(parsed_request["function_code"]),
                         parsed_request["app_seq"])
            return None

        self._used[index] = True
        return self.entries[index]

    def _find(self, parsed_request, require_app_seq):
        """Index of the first unused entry matching the request, or None."""
        for i, entry in enumerate(self.entries):
            if self._used[i]:
                continue
            if entry["function_code"] != parsed_request["function_code"]:
                continue
            if require_app_seq and entry["app_seq"] != parsed_request["app_seq"]:
                continue
            return i
        return None

    def _load_entries(self, payload_dir):
        """Read metadata.json and build the ordered request->response entries."""
        with open(os.path.join(payload_dir, "metadata.json")) as fh:
            events = json.load(fh)

        # Group each request ('orig') with the consecutive responses ('resp')
        # that follow it before the next request, in capture order.
        groups = []
        request_file = None
        response_files = []
        for event in events:
            if event["direction"] == "orig":
                if request_file is not None:
                    groups.append((request_file, response_files))
                request_file = event["filename"]
                response_files = []
            else:
                response_files.append(event["filename"])
        if request_file is not None:
            groups.append((request_file, response_files))

        entries = []
        for request_file, response_files in groups:
            with open(os.path.join(payload_dir, request_file), "rb") as fh:
                parsed = parse_dnp3_request(fh.read())
            response_bytes = bytearray()
            for name in response_files:
                with open(os.path.join(payload_dir, name), "rb") as fh:
                    response_bytes += fh.read()
            response_bytes = bytes(response_bytes)
            # Split a READ response and any CONFIRM-triggered continuation that is
            # itself a data RESPONSE; leave handshake replies (ENABLE_UNSOL/WRITE)
            # whole.
            is_read = parsed["function_code"] == READ_FUNCTION_CODE
            is_continuation = (parsed["function_code"] == CONFIRM_FUNCTION_CODE
                               and response_is_data_response(response_bytes))
            entries.append({
                "request_file": request_file,
                "response_files": response_files,
                "response_bytes": response_bytes,
                "function_code": parsed["function_code"],
                "function_name": parsed["function_name"],
                "app_seq": parsed["app_seq"],
                "is_read": is_read,
                "is_splittable": is_read or is_continuation,
            })
        return entries


# ------------------------------------------------------------------ #
# Single-connection TCP replay/split server
# ------------------------------------------------------------------ #

class TCPSplitReplayServer:
    """Single-connection TCP server that replays matched captured responses.

    It opens a plain TCP server on the outstation's port, accepts the master's
    connection (TCP_NODELAY so write boundaries are not coalesced by Nagle),
    reassembles whole DNP3 frames from the stream, and for each master request
    selects the matching captured response. In ``crc-boundary`` delivery it splits
    every data-bearing RESPONSE (the READ fragment and its CONFIRM-triggered
    continuation) on existing DNP3 CRC boundaries (no byte altered, no CRC
    recomputed, so b"".join(chunks) == response); in ``full`` delivery it sends
    each response group in one write (exact verbatim replay). The single
    connection is held open so the master's DNP3 CONFIRM arrives on the same
    socket.
    """

    def __init__(self, host, port, exchange, delivery="crc-boundary",
                 blocks_per_chunk=1, delay_between_chunks_ms=0,
                 request_timeout_sec=10.0, hold_after_response_sec=10.0,
                 log_dir=None, scheduler=None, rto_safe_ms=None):
        self.host = host
        self.port = port
        self.exchange = exchange
        self.delivery = delivery
        self.blocks_per_chunk = blocks_per_chunk
        self.delay_between_chunks_ms = delay_between_chunks_ms
        self.request_timeout_sec = request_timeout_sec
        self.hold_after_response_sec = hold_after_response_sec
        self.log_dir = log_dir
        # Response-time normalization (Phase 1). In native mode the scheduler
        # returns hold=0, so the wire behavior is identical to before; it only
        # adds a per-transaction timing log.
        self.scheduler = scheduler
        self.rto_safe_ms = rto_safe_ms

        self._splitter = DNP3CRCSplitter()
        self._request_count = 0
        self._timing_log_path = (os.path.join(log_dir, "timing_decisions.jsonl")
                                 if log_dir else None)
        if self.log_dir:
            os.makedirs(self.log_dir, exist_ok=True)

    def serve_once(self):
        """Accept one master connection and replay the matched responses."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(1)
            _log.info("Listening on %s:%s (delivery=%s)", self.host, self.port, self.delivery)

            conn, addr = server.accept()
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            _log.info("Accepted connection from %s at %s (TCP_NODELAY set)",
                      addr, datetime.now().isoformat())
            flow_id = "{}:{}".format(addr[0], addr[1])

            with conn:
                reader = FrameReader(conn)
                while self.exchange.has_pending_responses():
                    request = reader.next_frame(self.request_timeout_sec)
                    if not request:
                        _log.warning("No further master request (idle or closed); stopping.")
                        break

                    # Timestamp request arrival before any work, so the timing
                    # target is measured from arrival (not from response-ready).
                    request_received_ns = time.monotonic_ns()
                    self._request_count += 1
                    self._dump("request_{:02d}.bin".format(self._request_count), request)
                    parsed = parse_dnp3_request(request)
                    _log.info("Received request: %s [%s byte(s)]",
                              describe_request(parsed), len(request))
                    if parsed["valid"] and parsed["function_name"] == "CONFIRM":
                        _log.info("Received CONFIRM (app_seq=%s).", parsed["app_seq"])

                    entry = self.exchange.match_response(parsed)
                    if entry is None:
                        # Safety: never fire a captured response at a request we
                        # cannot match. Wait for the next master message.
                        continue

                    chunks = self._make_chunks(entry)
                    if b"".join(chunks) != entry["response_bytes"]:
                        raise ValueError("split did not reconstruct the response for {}".format(
                            entry["request_file"]))

                    will_split = self.delivery != FULL_DELIVERY and entry["is_splittable"]
                    _log.info("Matched response file(s): %s", "+".join(entry["response_files"]))
                    _log.info("Delivery: %s",
                              self.delivery if will_split else "full (single write)")
                    _log.info("Chunk count: %s", len(chunks))
                    _log.info("Chunk sizes: %s", [len(c) for c in chunks])
                    _log.info("Byte-preservation check: PASS")
                    decision = self._apply_timing(
                        flow_id, request, parsed, entry, request_received_ns)
                    send_start_ns = time.monotonic_ns()
                    self._send_chunks(conn, chunks)
                    send_complete_ns = time.monotonic_ns()
                    if decision is not None:
                        decision.send_start_ns = send_start_ns
                        decision.send_complete_ns = send_complete_ns
                        self._log_timing(decision)
                    if entry["is_splittable"]:
                        _log.info("Data RESPONSE sent; waiting for the master CONFIRM.")

                if not self.exchange.has_pending_responses():
                    _log.info("All captured responses replayed.")
                self._receive_trailing_data(reader)

            _log.info("Connection closed cleanly.")

    def _make_chunks(self, entry):
        """Split a data RESPONSE on CRC boundaries; otherwise send it as one write.

        ``full`` delivery never splits (exact verbatim replay). ``crc-boundary``
        delivery splits the READ fragment AND its CONFIRM-triggered continuation
        (entries flagged ``is_splittable``), leaving handshake replies whole.
        """
        response_bytes = entry["response_bytes"]
        if self.delivery != FULL_DELIVERY and entry["is_splittable"]:
            return self._splitter.split(response_bytes, self.blocks_per_chunk)
        return [response_bytes]

    @staticmethod
    def _is_critical(parsed):
        """True for a control-bearing request (never held). None occur in this
        harness; the hook keeps timing fail-open if one ever appeared."""
        return bool(parsed["valid"]) and parsed["function_code"] in CRITICAL_FUNCTION_CODES

    def _apply_timing(self, flow_id, request, parsed, entry, request_received_ns):
        """Hold the already-prepared response until its scheduled release (Phase 1).

        Bytes are never touched -- only *when* the first chunk leaves. In native
        mode the scheduled release is the response-ready instant, so this is a
        no-op wait and the wire behavior is unchanged.

        Returns the TimingDecision (so the caller can stamp send_start/complete
        and log one complete row after the write), or None when timing is off.
        """
        if self.scheduler is None:
            return None
        response_ready_ns = time.monotonic_ns()
        decision = self.scheduler.decide(
            flow_id=flow_id,
            transaction_id=self._request_count,
            request_received_ns=request_received_ns,
            response_ready_ns=response_ready_ns,
            request_size=len(request),
            response_size=len(entry["response_bytes"]),
            packet_role=tpol.COMBINED_RESPONSE,
            is_critical=self._is_critical(parsed),
            is_supported=bool(parsed["valid"]),
            rto_safe_ms=self.rto_safe_ms,
        )
        if decision.bypassed:
            _log.info("Timing: bypass (%s) -- sending immediately.", decision.bypass_reason)
        elif decision.deadline_missed:
            _log.info("Timing: target missed (response ready after target) -- sending when ready.")
        elif decision.hold_delay_ns > 0:
            _log.info("Timing: holding %.2f ms (mode=%s, target=%.2f ms -> visible %.2f ms).",
                      decision.hold_delay_ns * tpol.NS_TO_MS, decision.timing_mode,
                      decision.selected_target_delay_ns * tpol.NS_TO_MS,
                      decision.visible_delay_ns * tpol.NS_TO_MS)
        # Absolute-deadline wait; a no-op when the release instant is already past.
        tpol.wait_until(decision.actual_release_ns)
        return decision

    def _log_timing(self, decision):
        """Append one timing decision as a JSON line under log_dir."""
        if not self._timing_log_path:
            return
        with open(self._timing_log_path, "a") as fh:
            fh.write(json.dumps(decision.to_log_dict()) + "\n")

    def _send_chunks(self, conn, chunks):
        """Write each chunk with sendall(), optionally pausing between writes."""
        for index, chunk in enumerate(chunks):
            conn.sendall(chunk)
            _log.info("Sent chunk %s/%s: %s byte(s)", index + 1, len(chunks), len(chunk))
            if self.delay_between_chunks_ms > 0 and index < len(chunks) - 1:
                time.sleep(self.delay_between_chunks_ms / 1000.0)

    def _receive_trailing_data(self, reader):
        """Hold the socket open briefly and log any trailing frames (e.g. a CONFIRM)."""
        if self.hold_after_response_sec <= 0:
            return
        _log.info("Holding connection for trailing data / final CONFIRM (up to %ss).",
                  self.hold_after_response_sec)
        deadline = time.time() + self.hold_after_response_sec
        trailing = bytearray()
        while time.time() < deadline:
            remaining = deadline - time.time()
            frame = reader.next_frame(min(0.5, max(0.0, remaining)))
            if not frame:
                continue
            trailing += frame
            parsed = parse_dnp3_request(frame)
            if parsed["valid"] and parsed["function_name"] == "CONFIRM":
                _log.info("Received CONFIRM (app_seq=%s).", parsed["app_seq"])
            else:
                _log.info("Trailing frame received: %s (%s)", len(frame), describe_request(parsed))
        if trailing:
            self._dump("trailing.bin", bytes(trailing))

    def _dump(self, name, data):
        """Save a byte buffer under log_dir, if logging to a directory."""
        if not self.log_dir:
            return
        with open(os.path.join(self.log_dir, name), "wb") as fh:
            fh.write(data)


# ------------------------------------------------------------------ #
# Command-line entry point (defaults sourced from lab_config.py)
# ------------------------------------------------------------------ #

def build_parser():
    """Build the argument parser; every default comes from lab_config.py."""
    default_delivery = (FULL_DELIVERY if DEFAULT_SPLIT_MODE == FULL_DELIVERY
                        else "crc-boundary")
    parser = argparse.ArgumentParser(
        description='Canonical DNP3 replay/split server (full or CRC-boundary delivery).')
    parser.add_argument('--host', default=BIND_IP,
                        help='Local interface to bind (default from lab_config).')
    parser.add_argument('--port', type=int, default=DNP3_PORT,
                        help='TCP port (DNP3 default 20000).')
    parser.add_argument('--delivery', choices=[FULL_DELIVERY, 'crc-boundary'],
                        default=default_delivery,
                        help='full = exact verbatim replay (one write/response); '
                             'crc-boundary = split data responses on CRC boundaries (default).')
    parser.add_argument('--blocks-per-chunk', type=int, default=DEFAULT_BLOCKS_PER_CHUNK,
                        help='CRC blocks per chunk in crc-boundary delivery (1 = maximum split).')
    parser.add_argument('--chunk-delay-ms', type=int, default=DEFAULT_CHUNK_DELAY_MS,
                        help='Milliseconds to pause between chunk writes.')
    parser.add_argument('--request-timeout-sec', type=float, default=10.0,
                        help='Seconds to wait for each master request frame.')
    parser.add_argument('--hold-after-response-sec', type=float,
                        default=DEFAULT_HOLD_AFTER_RESPONSE_SEC,
                        help='Seconds to hold the socket for a trailing CONFIRM.')
    parser.add_argument('--replay-dir', default=DEFAULT_REPLAY_DIR,
                        help='Directory of captured payloads + metadata.json.')
    parser.add_argument('--log-dir', default=os.path.join(LOG_DIR, 'replay'),
                        help='Directory for per-run logs and byte dumps.')
    tpol.add_timing_arguments(parser)
    return parser


def main():
    """Stand in for the outstation and replay captured responses (full or split)."""
    args = build_parser().parse_args()

    payload_dir = (args.replay_dir if os.path.isabs(args.replay_dir)
                   else os.path.join(HARNESS_DIR, args.replay_dir))
    if not os.path.exists(os.path.join(payload_dir, "metadata.json")):
        _log.error("Missing %s/metadata.json. Run the baseline capture and "
                   "extract_payloads.py first.", args.replay_dir)
        sys.exit(1)

    log_dir = args.log_dir if os.path.isabs(args.log_dir) else os.path.join(HARNESS_DIR, args.log_dir)
    os.makedirs(log_dir, exist_ok=True)
    file_handler = logging.FileHandler(
        os.path.join(log_dir, "split_replay_server_{}.log".format(int(time.time()))))
    file_handler.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))
    logging.getLogger().addHandler(file_handler)

    _log.info("Split server replacing the outstation on %s:%s (delivery=%s).",
              args.host, args.port, args.delivery)
    _log.info("Reminder: stop the real outstation first -- sudo fuser -k %s/tcp", args.port)

    profile = tpol.profile_from_args(args)
    scheduler = tpol.ReleaseScheduler(profile)
    _log.info("Timing policy: mode=%s%s", profile.mode,
              "" if profile.mode == tpol.NATIVE else
              (" target=%.1fms" % args.target_delay_ms if profile.mode == tpol.FIXED
               else " bounds=[%.1f,%.1f]ms seed=%s" % (
                   args.target_min_ms, args.target_max_ms, args.timing_seed)))

    exchange = CapturedExchange(payload_dir)
    server = TCPSplitReplayServer(
        host=args.host,
        port=args.port,
        exchange=exchange,
        delivery=args.delivery,
        blocks_per_chunk=args.blocks_per_chunk,
        delay_between_chunks_ms=args.chunk_delay_ms,
        request_timeout_sec=args.request_timeout_sec,
        hold_after_response_sec=args.hold_after_response_sec,
        log_dir=log_dir,
        scheduler=scheduler,
        rto_safe_ms=args.rto_safe_ms,
    )
    server.serve_once()


if __name__ == "__main__":
    main()

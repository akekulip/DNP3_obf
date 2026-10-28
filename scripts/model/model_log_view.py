"""The running model's own log, read by the contention driver while it runs (harness fixes, 2026-10-17).

The model writes every pass to $OUT/model_*.log as it processes it. The driver uses that state observation in two
places where host time cannot decide:
  - the READ/SELECT abort order: whether T's release pass for the response came before or after T's reset-application
    pass (reset_application_check.classify), when the pre-send register read cannot decide;
  - the targeted restart: the response is sent when the master RST's stage-0 pass (n_Ingress.first_close) appears.
Reading never changes what the model does.
"""
import os
import re
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

import reset_application_check as rac


def log_path(out=None):
    """The run's model log, or None (no log yet, or more than one)."""
    logs = sorted(Path(out or os.environ.get('OUT', '.')).glob('model_*.log'))
    return logs[0] if len(logs) == 1 else None


def size(path):
    return path.stat().st_size if path is not None and path.exists() else None


def lines_since(path, offset):
    """Complete lines appended since a byte offset (a partial first line is dropped)."""
    with open(path, 'rb') as log:
        log.seek(offset)
        data = log.read()
    text = data.decode(errors='replace')
    if offset and not text.startswith(':'):
        text = text.split('\n', 1)[1] if '\n' in text else ''
    return text.splitlines(True)


def records_since(path, offset):
    return rac.ingress_records(lines_since(path, offset))


def wait_idle(path, quiet=0.05, timeout=2.0, poll=0.005):
    """Wait until the log has not grown for `quiet` seconds (the model has finished its pending passes). Returns
    (size, idle_reached): the size then, or the size at the timeout with idle_reached False. (Diagnostic 02: a cleanup RST's first_close was logged after the next
    try had taken its offset, and triggered that try early.)"""
    start, last, since = time.monotonic(), size(path), time.monotonic()
    while time.monotonic() - start < timeout:
        time.sleep(poll)
        now = size(path)
        if now != last:
            last, since = now, time.monotonic()
        elif time.monotonic() - since >= quiet:
            return last, True
    return last, False


def wait_for(path, offset, pattern, timeout, poll=0.001):
    """Poll the log from offset until a line matches pattern. Returns (matched line or None, seconds waited, byte
    offset just after the matched line or None)."""
    rx, start, pos, tail = re.compile(pattern), time.monotonic(), offset, b''
    while time.monotonic() - start < timeout:
        with open(path, 'rb') as log:
            log.seek(pos)
            chunk = log.read()
        if chunk:
            cursor = pos - len(tail)                         # file offset where `tail + chunk` begins
            pos += len(chunk)
            lines = (tail + chunk).split(b'\n')
            tail = lines.pop()
            for line in lines:
                cursor += len(line) + 1
                if rx.search(line.decode(errors='replace')):
                    return line.decode(errors='replace'), time.monotonic() - start, cursor
        else:
            time.sleep(poll)
    return None, time.monotonic() - start, None


def connection_order(records, pattern, t_release_count, copies_to_master):
    """reset_application_check.classify over the pipe-1 (T) records whose frame carries pattern."""
    return rac.classify([r for r in records if r['pipe'] == 1 and pattern in r['frame']], t_release_count,
                        copies_to_master)

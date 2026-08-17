"""Startup-readiness helpers shared by the S4 software CLIs and the runner.

A component writes a ready file only after its capture/inject sockets are open,
so the orchestrator can wait for every process to be listening before it starts
traffic. This removes startup races without a fixed, guessed sleep.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Sequence


def write_ready_file(path: Path) -> None:
    """Atomically publish a ready file containing this process id."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text("%d\n" % os.getpid(), encoding="utf-8")
    os.replace(tmp, path)


def wait_for_ready_files(
    paths: Sequence[Path], *, timeout_s: float, poll_s: float = 0.02
) -> bool:
    """Block until every path exists or the timeout elapses.

    Returns ``True`` when all ready files have appeared, ``False`` on timeout.
    Uses a monotonic deadline and a bounded poll so the caller never spins
    unbounded.
    """

    if timeout_s <= 0:
        raise ValueError("timeout_s must be positive")
    targets = [Path(item) for item in paths]
    deadline = time.monotonic() + timeout_s
    while True:
        if all(target.exists() for target in targets):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll_s)

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from defense4.size.real_size_normalization.software.runner_support import (
    wait_for_ready_files,
    write_ready_file,
)


def test_write_ready_file_is_atomic_and_holds_pid(tmp_path: Path) -> None:
    ready = tmp_path / "sub" / "shim.ready"
    write_ready_file(ready)
    assert ready.exists()
    assert ready.read_text(encoding="utf-8").strip().isdigit()
    assert not (tmp_path / "sub" / "shim.ready.tmp").exists()


def test_wait_returns_true_when_all_files_present(tmp_path: Path) -> None:
    a = tmp_path / "a.ready"
    b = tmp_path / "b.ready"
    write_ready_file(a)
    write_ready_file(b)
    assert wait_for_ready_files([a, b], timeout_s=1.0)


def test_wait_times_out_when_a_file_never_appears(tmp_path: Path) -> None:
    present = tmp_path / "present.ready"
    missing = tmp_path / "missing.ready"
    write_ready_file(present)
    start = time.monotonic()
    assert not wait_for_ready_files([present, missing], timeout_s=0.1, poll_s=0.01)
    assert time.monotonic() - start >= 0.1


def test_wait_unblocks_when_file_appears_late(tmp_path: Path) -> None:
    late = tmp_path / "late.ready"

    def _create() -> None:
        time.sleep(0.05)
        write_ready_file(late)

    worker = threading.Thread(target=_create)
    worker.start()
    try:
        assert wait_for_ready_files([late], timeout_s=1.0, poll_s=0.01)
    finally:
        worker.join()


def test_wait_rejects_nonpositive_timeout(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        wait_for_ready_files([tmp_path / "x"], timeout_s=0)

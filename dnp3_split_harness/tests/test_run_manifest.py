"""Unit tests for run_manifest.py (Phase 01 run-directory + manifest support).

Pure filesystem behavior; no network, no rig. Runs on Python 3.8.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

import pytest

# make the harness root importable when pytest is invoked from elsewhere
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import run_manifest  # noqa: E402


REQUIRED_MANIFEST_KEYS = {
    "run_id", "phase", "created_utc", "start_utc", "end_utc", "exit_status",
    "git", "host", "python_version", "tool_versions", "inputs", "command", "config",
}


def _make_input(tmp_path, name="in.bin", data=b"dnp3-bytes"):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_sha256_file_matches_hashlib(tmp_path):
    data = b"the quick brown fox" * 100
    p = _make_input(tmp_path, data=data)
    assert run_manifest.sha256_file(p) == hashlib.sha256(data).hexdigest()


def test_hash_inputs_structure(tmp_path):
    p = _make_input(tmp_path, "AB1400.pcap", b"abc")
    h = run_manifest.hash_inputs([p])
    assert set(h) == {"AB1400.pcap"}
    entry = h["AB1400.pcap"]
    assert entry["size_bytes"] == 3
    assert entry["sha256"] == hashlib.sha256(b"abc").hexdigest()
    assert os.path.isabs(entry["path"])


def test_start_creates_dir_and_manifest(tmp_path):
    inp = _make_input(tmp_path)
    run_dir = str(tmp_path / "runs" / "r1")
    ctx = run_manifest.RunContext.start(
        phase="phase_01", short_name="smoke", inputs=[inp],
        argv=["prog", "--x"], run_dir=run_dir, base_dir=str(tmp_path),
        config={"k": "v"},
    )
    assert os.path.isdir(ctx.run_dir)
    assert os.path.isfile(ctx.manifest_path)
    assert os.path.isfile(os.path.join(ctx.run_dir, "config.json"))
    man = json.loads(open(ctx.manifest_path).read())
    assert REQUIRED_MANIFEST_KEYS.issubset(man)
    assert man["phase"] == "phase_01"
    assert man["command"] == ["prog", "--x"]
    assert man["config"] == {"k": "v"}
    assert os.path.basename(inp) in man["inputs"]
    assert "tshark" in man["tool_versions"]        # key present (value may be None)
    assert man["python_version"]                    # non-empty
    assert man["exit_status"] is None               # not finished yet


def test_refuses_populated_directory(tmp_path):
    inp = _make_input(tmp_path)
    run_dir = tmp_path / "runs" / "already"
    run_dir.mkdir(parents=True)
    (run_dir / "leftover.txt").write_text("stale")
    with pytest.raises(run_manifest.RunDirectoryError):
        run_manifest.RunContext.start(
            phase="phase_01", short_name="smoke", inputs=[inp],
            run_dir=str(run_dir), base_dir=str(tmp_path),
        )


def test_empty_preexisting_directory_is_allowed(tmp_path):
    inp = _make_input(tmp_path)
    run_dir = tmp_path / "runs" / "empty"
    run_dir.mkdir(parents=True)  # exists but empty
    ctx = run_manifest.RunContext.start(
        phase="phase_01", short_name="smoke", inputs=[inp],
        run_dir=str(run_dir), base_dir=str(tmp_path),
    )
    assert os.path.isfile(ctx.manifest_path)


def test_path_and_subdir_are_fresh(tmp_path):
    inp = _make_input(tmp_path)
    ctx = run_manifest.RunContext.start(
        phase="phase_01", short_name="smoke", inputs=[inp],
        run_dir=str(tmp_path / "runs" / "r2"), base_dir=str(tmp_path),
    )
    tables = ctx.subdir("tables")
    assert os.path.isdir(tables)
    csv_path = ctx.path("tables", "out.csv")
    assert csv_path.startswith(ctx.run_dir)
    assert os.path.isdir(os.path.dirname(csv_path))
    assert not os.path.exists(csv_path)  # fresh: not created until written


def test_finish_stamps_exit_and_end(tmp_path):
    inp = _make_input(tmp_path)
    ctx = run_manifest.RunContext.start(
        phase="phase_01", short_name="smoke", inputs=[inp],
        run_dir=str(tmp_path / "runs" / "r3"), base_dir=str(tmp_path),
    )
    ctx.finish(exit_status=0)
    man = json.loads(open(ctx.manifest_path).read())
    assert man["exit_status"] == 0
    assert man["end_utc"] is not None
    assert "duration_ms" in man


def test_mint_run_dir_format(tmp_path):
    d = run_manifest.mint_run_dir(str(tmp_path), "phase_01", "ack")
    base = os.path.basename(d)
    assert base.endswith("_phase_01_ack")
    assert os.path.dirname(d).endswith("runs")
    assert base[8] == "T" and base.endswith("ack")  # UTC stamp shape YYYYmmddTHHMMSSZ_...

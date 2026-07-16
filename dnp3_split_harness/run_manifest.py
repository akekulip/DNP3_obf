"""run_manifest.py -- minimal, reusable run-directory + manifest support.

Phase 01 run isolation (the Phase-01 slice of migration item M9). A run directory
is created once, refuses to write into an already-populated directory, records
immutable input hashes and full environment provenance in ``manifest.json``, and
hands out fresh output paths. Nothing here appends to an existing file or overwrites
a fixed ``reports/*`` path -- that is the whole point.

Design goals (kept deliberately small this phase):
  * unique run id (UTC-stamped) or an explicit caller-supplied run directory;
  * immutable SHA-256 of every input, recorded before any output is written;
  * refusal when the target run directory already exists and is non-empty;
  * a manifest capturing git commit/branch/dirty-tree, Python + tshark versions,
    input hashes, the exact command, start/end timestamps, and exit status;
  * fresh, run-scoped output paths (``tables/``, ``figures/``, ``report/`` ...).

Python 3.8 compatible (``from __future__ import annotations``; ``typing`` generics).
Only the standard library is used, so it adds no dependency.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence

_HASH_BUFSIZE = 1 << 20  # 1 MiB


class RunDirectoryError(RuntimeError):
    """Raised when a run directory cannot be created safely (e.g. already populated)."""


# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #

def sha256_file(path: str) -> str:
    """Return the SHA-256 hex digest of a file, read in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_HASH_BUFSIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_inputs(paths: Sequence[str]) -> Dict[str, dict]:
    """Map each input's basename -> {path, size_bytes, sha256}. Inputs are immutable."""
    out: Dict[str, dict] = {}
    for p in paths:
        ap = os.path.abspath(p)
        out[os.path.basename(p)] = {
            "path": ap,
            "size_bytes": os.path.getsize(ap),
            "sha256": sha256_file(ap),
        }
    return out


# --------------------------------------------------------------------------- #
# Environment provenance
# --------------------------------------------------------------------------- #

def _run_cmd(cmd: List[str], cwd: Optional[str] = None) -> Optional[str]:
    try:
        r = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return r.stdout.decode("utf-8", "replace").strip()


def git_provenance(cwd: str) -> Dict[str, object]:
    """Best-effort git commit/branch/dirty status. Fields are None if git is absent."""
    commit = _run_cmd(["git", "rev-parse", "HEAD"], cwd)
    branch = _run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd)
    status = _run_cmd(["git", "status", "--porcelain"], cwd)
    dirty: Optional[bool]
    dirty_files: List[str]
    if status is None:
        dirty, dirty_files = None, []
    else:
        lines = [ln for ln in status.splitlines() if ln.strip()]
        dirty = bool(lines)
        dirty_files = [ln[3:] for ln in lines]
    return {"commit": commit, "branch": branch,
            "dirty_tree": dirty, "dirty_files": dirty_files}


def tshark_version() -> Optional[str]:
    """First line of ``tshark --version``, or None if tshark is not on PATH."""
    if shutil.which("tshark") is None:
        return None
    out = _run_cmd(["tshark", "--version"])
    if not out:
        return None
    return out.splitlines()[0].strip()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def mint_run_dir(base_dir: str, phase: str, short_name: str) -> str:
    """Return a fresh ``<base>/runs/<UTC>_<phase>_<short_name>`` path (not yet created)."""
    return os.path.join(base_dir, "runs", "{}_{}_{}".format(utc_stamp(), phase, short_name))


def _is_populated(path: str) -> bool:
    if not os.path.isdir(path):
        return False
    with os.scandir(path) as it:
        return any(True for _ in it)


# --------------------------------------------------------------------------- #
# Run context
# --------------------------------------------------------------------------- #

@dataclass
class RunContext:
    """An open run directory plus its manifest. Use :meth:`start` / :meth:`finish`."""
    run_dir: str
    run_id: str
    phase: str
    manifest_path: str
    _start_ns: int = field(repr=False)
    _manifest: dict = field(repr=False)

    @classmethod
    def start(
        cls,
        phase: str,
        short_name: str,
        inputs: Sequence[str],
        argv: Optional[Sequence[str]] = None,
        run_dir: Optional[str] = None,
        base_dir: Optional[str] = None,
        config: Optional[dict] = None,
        extra_tool_versions: Optional[Dict[str, Optional[str]]] = None,
        repo_dir: Optional[str] = None,
    ) -> "RunContext":
        """Create the run directory (refusing a populated one) and write the manifest.

        ``run_dir`` explicit -> use it; else mint ``base_dir/runs/<UTC>_<phase>_<name>``.
        Raises :class:`RunDirectoryError` if the target already holds files.
        """
        base_dir = os.path.abspath(base_dir or os.getcwd())
        if run_dir is None:
            run_dir = mint_run_dir(base_dir, phase, short_name)
        run_dir = os.path.abspath(run_dir)

        if _is_populated(run_dir):
            raise RunDirectoryError(
                "refusing to write into a populated run directory: {}".format(run_dir))
        os.makedirs(run_dir, exist_ok=True)

        run_id = os.path.basename(run_dir.rstrip(os.sep))
        repo_dir = repo_dir or base_dir
        tool_versions: Dict[str, Optional[str]] = {"tshark": tshark_version()}
        if extra_tool_versions:
            tool_versions.update(extra_tool_versions)

        now = utc_now_iso()
        manifest = {
            "run_id": run_id,
            "phase": phase,
            "created_utc": now,
            "start_utc": now,
            "end_utc": None,
            "exit_status": None,
            "git": git_provenance(repo_dir),
            "host": {
                "hostname": socket.gethostname(),
                "os": platform.platform(),
                "kernel": platform.release(),
            },
            "python_version": platform.python_version(),
            "tool_versions": tool_versions,
            "inputs": hash_inputs(list(inputs)),
            "command": list(argv) if argv is not None else list(sys.argv),
            "config": dict(config) if config else {},
        }

        ctx = cls(
            run_dir=run_dir,
            run_id=run_id,
            phase=phase,
            manifest_path=os.path.join(run_dir, "manifest.json"),
            _start_ns=time.monotonic_ns(),
            _manifest=manifest,
        )
        ctx._write_manifest()
        with open(os.path.join(run_dir, "config.json"), "w") as fh:
            json.dump(manifest["config"], fh, indent=2, sort_keys=True)
        return ctx

    def subdir(self, name: str) -> str:
        """Return (creating) a subdirectory of the run directory."""
        d = os.path.join(self.run_dir, name)
        os.makedirs(d, exist_ok=True)
        return d

    def path(self, *parts: str) -> str:
        """Return a fresh path inside the run directory, creating parent dirs."""
        p = os.path.join(self.run_dir, *parts)
        parent = os.path.dirname(p)
        if parent:
            os.makedirs(parent, exist_ok=True)
        return p

    def _write_manifest(self) -> None:
        with open(self.manifest_path, "w") as fh:
            json.dump(self._manifest, fh, indent=2, sort_keys=True)

    def finish(self, exit_status: int) -> str:
        """Stamp end timestamp + exit status and rewrite the manifest. Returns its path."""
        self._manifest["exit_status"] = int(exit_status)
        self._manifest["end_utc"] = utc_now_iso()
        self._manifest["duration_ms"] = round(
            (time.monotonic_ns() - self._start_ns) * 1e-6, 3)
        self._write_manifest()
        return self.manifest_path

"""Repo-root discovery, sha256, and relative-path resolution.

No absolute host paths are baked in: the repo root is discovered at runtime by
walking up from a starting directory until a ``.git`` marker is found. In a git
worktree ``.git`` is a *file* (a ``gitdir:`` pointer), not a directory, so both
forms are accepted.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def find_repo_root(start: Path | None = None) -> Path:
    """Walk up from ``start`` (default: this file) until a ``.git`` marker.

    Accepts ``.git`` as either a directory (normal clone) or a file (worktree).

    Raises:
        FileNotFoundError: if no ``.git`` marker is found up to the filesystem root.
    """
    here = (start or Path(__file__)).resolve()
    for cand in [here, *here.parents]:
        if (cand / ".git").exists():
            return cand
    raise FileNotFoundError(f"no .git marker found walking up from {here}")


def sha256_file(path: Path, chunk: int = 1 << 16) -> str:
    """Return the hex SHA-256 of a file, streamed in ``chunk``-byte reads."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def resolve(repo_root: Path, rel: str) -> Path:
    """Resolve a repo-relative path against ``repo_root``.

    Raises:
        ValueError: if ``rel`` is absolute (registries must stay portable).
    """
    p = Path(rel)
    if p.is_absolute():
        raise ValueError(f"registry path must be repo-relative, got absolute: {rel}")
    return (repo_root / p).resolve()

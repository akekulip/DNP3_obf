#!/usr/bin/env python3
"""Scenario adapter for the frozen c72 replay (audit 2026-10-28, section 4.6).

The frozen scripts/checks/replay.py always reads <trial>/result.json. Three-connection persistence and reconnect
trials record their endpoint result once, for all connections, in <trial>/scenario.json, which is byte-for-byte the
Vision output the live campaign used. This adapter redirects only that one read; every other read, the checker code
and the verdict logic stay frozen. Results produced with it carry this file's SHA-256 and are reported apart from
the unadapted replay.
"""
from pathlib import Path


def endpoint_path(path):
    path = Path(path)
    if path.name == 'result.json' and not path.exists() and (path.parent / 'scenario.json').exists():
        return path.parent / 'scenario.json'
    return path


def install(replay_module):
    """Wrap the frozen module's read() so a missing result.json falls back to scenario.json."""
    frozen_read = replay_module.read

    def read(path):
        return frozen_read(endpoint_path(path))

    replay_module.read = read
    return replay_module

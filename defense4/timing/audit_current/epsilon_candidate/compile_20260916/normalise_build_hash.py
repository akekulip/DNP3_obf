#!/usr/bin/env python3
"""Normalised build identity for a Tofino `tofino.bin`.

    normalise_build_hash.py <path to pipe/tofino.bin> ...

`bf-p4c` stamps a fresh random 16-hex-character `run_id` into every binary it emits, so the raw
sha256 of `tofino.bin` identifies a compile event and not a program: the same source compiled
twice gives two different hashes. Zeroing that one field makes the hash a function of the input,
which is what a build identity has to be.

Both hashes are printed. The raw hash remains the exact identifier of a particular artefact and is
not replaced by this; the normalised hash is the additional comparison that can be reproduced.
"""
from __future__ import annotations

import hashlib
import re
import sys

RUN_ID_KEY = rb"run_id\x00\x11\x00\x00\x00"
RUN_ID_LEN = 16


def normalised(path: str) -> tuple[str, str, int]:
    raw = open(path, "rb").read()
    b = bytearray(raw)
    n = 0
    for m in re.finditer(re.escape(b"run_id") + rb"\x00\x11\x00\x00\x00", bytes(b)):
        s = m.end()
        b[s:s + RUN_ID_LEN] = b"0" * RUN_ID_LEN
        n += 1
    return (hashlib.sha256(raw).hexdigest(),
            hashlib.sha256(bytes(b)).hexdigest(), n)


if __name__ == "__main__":
    for p in sys.argv[1:]:
        raw, norm, n = normalised(p)
        print("%s\n  raw        %s\n  normalised %s  (%d run_id field(s) zeroed)" % (p, raw, norm, n))

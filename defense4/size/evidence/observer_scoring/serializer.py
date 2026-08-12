#!/usr/bin/env python3
"""Faithful DNP3 serializer for the observer time-series, PROVEN against the emitted C++ vectors.

The static structural evidence is EMITTED by the real opendnp3 build (decoy_gate/out/vectors/*.json).
The repeated-read observer experiment needs many reads with process-value dynamics that do not exist
in that static evidence, so we SYNTHESISE the reads here. To keep the synthesis honest, this module's
class-0 serializer is byte-for-byte cross-checked against every emitted C++ read vector in selftest();
only after that check passes do we use it to render synthetic time-series reads. Value dynamics are a
declared model input (labelled synthetic); the SERIALIZATION is the real wire format.

No git, no hardware, no absolute home paths.
"""
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))


def repo_root(start=HERE):
    d = start
    for _ in range(9):
        # .git is a FILE in this worktree, so test path existence, not isdir
        if os.path.exists(os.path.join(d, ".git")) or os.path.isdir(os.path.join(d, "defense4")):
            return d
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return start


ROOT = repo_root()
READ_VECTORS = os.path.join(ROOT, "defense4/size/evidence/decoy_gate/out/vectors/read_vectors.json")

# Application header the real opendnp3 outstation emits for a class-0 integrity RESPONSE of
# Group30Var1 objects (confirmed byte-exact by selftest against the emitted vectors):
#   C0            application control (FIR|FIN|seq0)
#   81            function RESPONSE
#   80 00         IIN (IIN1.7 device restart set)
#   1E 01         Group 30 Var 1 (32-bit analog input with flag)
#   00            qualifier 0x00 = 1-byte start/stop index range
APP_HEADER = ["C0", "81", "80", "00", "1E", "01", "00"]
FLAG_ONLINE = 0x01


def _obj5(value_i32, flag=FLAG_ONLINE):
    """One Group30Var1 object: 1 flag byte + 4-byte signed LE value -> list of 5 hex tokens."""
    vb = struct.pack("<i", int(value_i32))
    return ["%02X" % flag] + ["%02X" % b for b in vb]


def serialize_class0(values, flags=None):
    """values: dict {index -> int32} over a CONTIGUOUS range [min..max]. Returns hex-token string.

    This is the wire form a class-0 integrity poll returns: header + one 5-byte object per index in
    the inclusive range. Missing indices in the range are not allowed (the real outstation packs a
    contiguous range)."""
    idxs = sorted(values)
    start, stop = idxs[0], idxs[-1]
    assert idxs == list(range(start, stop + 1)), "class-0 range must be contiguous"
    flags = flags or {}
    toks = list(APP_HEADER) + ["%02X" % start, "%02X" % stop]
    for i in range(start, stop + 1):
        toks += _obj5(values[i], flags.get(i, FLAG_ONLINE))
    return " ".join(toks)


def app_bytes(hexstr):
    return len(hexstr.split())


def selftest():
    """Reproduce EVERY emitted C++ read vector byte-for-byte. Raises on any mismatch."""
    doc = json.load(open(READ_VECTORS))
    checked = 0
    for v in doc["vectors"]:
        # rebuild the value map from the ground-truth (reals valued real_base+i, decoys 50000+i)
        vals = {}
        for o in v["objects"]:
            vals[o["index"]] = o["value_i32"]
        got = serialize_class0(vals)
        exp = v["response_hex"]
        if got != exp:
            raise AssertionError(
                "serializer mismatch for kind=%s profile=%s total=%s\n  exp %s\n  got %s"
                % (v["kind"], v.get("profile"), v["total_points"], exp, got))
        assert app_bytes(got) == v["app_bytes"]
        checked += 1
    return checked


if __name__ == "__main__":
    n = selftest()
    print("serializer selftest: %d/%d emitted read vectors reproduced byte-for-byte" % (n, n))

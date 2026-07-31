#!/usr/bin/env python3
"""Verify (or refresh) the SHA-256 provenance hashes in MANIFEST.yaml
(CORRECTIONS.md §9 / §6.2).

The manifest binds each claim to a source, an assembly and a resource report. Those hashes
must track the files: after the P4 source changed for the §5.5 seq-zero fix, the manifest's
`p4_sha256` had to change too, and a manually-edited manifest is exactly where such a
provenance hash goes stale. This tool computes the hashes from the files and:

    --check   (default)  exit non-zero if ANY committed hash no longer matches its file
    --write              rewrite the manifest's hashes from the current files

Hashed fields:
    canonical_program.p4_sha256                 <- p4/case_a_defense3.p4
    builds[].assembly_sha256                    <- artifacts/final/<...>.bfa
    builds[].resource_report_sha256             <- artifacts/final/<...>.table_summary.log
    commit                                      <- `git rev-parse HEAD` (informational tree
                                                   state; the manifest is committed just after)

Run from defense3/. STDLIB + pyyaml only.
"""
from __future__ import annotations
import argparse
import hashlib
import os
import subprocess
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)               # defense3/
MANIFEST = os.path.join(ROOT, "MANIFEST.yaml")


def sha256(path):
    p = os.path.join(ROOT, path)
    if not os.path.exists(p):
        return None
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def head_commit():
    try:
        return subprocess.check_output(
            ["git", "-C", ROOT, "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return None


def planned_hashes(man):
    """Return {label: (recorded_or_None, actual_or_None, path)} for every hashed field."""
    out = {}
    cp = man.get("canonical_program", {})
    src = cp.get("p4_source")
    if src:
        out["canonical_program.p4_sha256"] = (cp.get("p4_sha256"), sha256(src), src)
    for b in man.get("builds", []):
        name = b.get("name", "?")
        for field, key in (("assembly", "assembly_sha256"),
                           ("resource_report", "resource_report_sha256")):
            path = b.get(field)
            if path:
                out["builds[%s].%s" % (name, key)] = (b.get(key), sha256(path), path)
    return out


def check(man):
    bad = 0
    for label, (recorded, actual, path) in planned_hashes(man).items():
        if actual is None:
            print("  MISSING FILE  %-48s (%s)" % (label, path)); bad += 1
        elif recorded is None:
            print("  NO HASH       %-48s -> %s..." % (label, actual[:12])); bad += 1
        elif recorded != actual:
            print("  MISMATCH      %-48s recorded %s... != actual %s..."
                  % (label, str(recorded)[:12], actual[:12])); bad += 1
        else:
            print("  OK            %-48s %s..." % (label, actual[:12]))
    print("%d provenance mismatch(es)" % bad)
    return bad


def write(man):
    cp = man.setdefault("canonical_program", {})
    if cp.get("p4_source"):
        cp["p4_sha256"] = sha256(cp["p4_source"])
    for b in man.get("builds", []):
        if b.get("assembly"):
            b["assembly_sha256"] = sha256(b["assembly"])
        if b.get("resource_report"):
            b["resource_report_sha256"] = sha256(b["resource_report"])
    c = head_commit()
    if c:
        man["commit"] = c
    with open(MANIFEST, "w") as f:
        yaml.safe_dump(man, f, default_flow_style=False, sort_keys=False, width=100)
    print("MANIFEST.yaml hashes refreshed (commit %s)" % (c[:12] if c else "?"))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--write", action="store_true", help="rewrite hashes from the files")
    a = ap.parse_args(argv)
    with open(MANIFEST) as f:
        man = yaml.safe_load(f)
    if a.write:
        return write(man)
    return 1 if check(man) else 0


if __name__ == "__main__":
    sys.exit(main())

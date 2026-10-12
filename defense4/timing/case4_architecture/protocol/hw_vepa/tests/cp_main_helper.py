"""Run campaign.main(plan ...) against an in-memory config written to a cleaned temp dir; returns (rc, stdout)."""
import contextlib
import io
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import campaign as cp  # noqa: E402


def plan(cfg, _unused, argv):
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, 'cfg.json')
        open(path, 'w').write(json.dumps(cfg))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rc = cp.main(['plan', '--config', path] + argv)
        return rc, buf.getvalue()

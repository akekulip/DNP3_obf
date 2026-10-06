"""Master for the BMv2 artifact: the repository's own corrected Session and frozen READ builder (not pydnp3)."""
import argparse
import json
import sys
import time
from pathlib import Path

HARNESS = Path(__file__).resolve().parents[3] / "active_harness"
sys.path.insert(0, str(HARNESS))
from dnp3_codec import FUNC_READ          # noqa: E402
from frozen_builders import read_frame     # noqa: E402
from session import Session               # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--host", default="10.0.0.2")
ap.add_argument("--count", type=int, default=5)
ap.add_argument("--gap-ms", type=float, default=50.0)
ap.add_argument("--budget-ms", type=float, default=500.0)
a = ap.parse_args()
rows = []
with Session(a.host, 20000) as s:
    for i in range(a.count):
        seq = i & 0x0F
        out = s.transaction(operation="READ", frame=read_frame(seq), function=FUNC_READ, app_seq=seq, budget_ms=a.budget_ms)
        rows.append(out.as_dict())
        time.sleep(a.gap_ms / 1e3)
print(json.dumps(rows))

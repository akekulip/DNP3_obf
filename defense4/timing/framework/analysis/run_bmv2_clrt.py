"""Collect the BMv2 CLRT population for two matched arms (same seeded device-latency sequence) and save the raw run JSON.
Software data: BMv2 timing, not Tofino line-rate evidence. Usage: run_bmv2_clrt.py OUTDIR [COUNT]"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

LAB = Path(__file__).resolve().parents[1] / "bmv2" / "lab" / "run_lab.py"
COMMON = dict(latency_ms=2.0, jitter_ms=10.0, seed=20261006, gap_ms=40, budget_ms=2000, budget=1000, loop_pps=20000)
ARMS = {"timing_off": dict(mode=0, da_us=0, gap_us=0), "response_ready": dict(mode=4, da_us=10000, gap_us=1000)}


def run(arm, count):
    kw = dict(COMMON, **ARMS[arm], count=count)
    d = tempfile.mkdtemp(prefix="clrt_")
    r = subprocess.run([sys.executable, "-B", str(LAB), "step5", d, json.dumps(kw)], capture_output=True, text=True, timeout=900)
    if r.returncode:
        raise RuntimeError(r.stderr[-1500:])
    out = json.loads(r.stdout.strip().splitlines()[-1])
    out["arm"], out["declared"] = arm, kw
    return out


if __name__ == "__main__":
    outdir, count = Path(sys.argv[1]), int(sys.argv[2]) if len(sys.argv) > 2 else 120
    outdir.mkdir(parents=True, exist_ok=True)
    for arm in ARMS:
        (outdir / (arm + ".json")).write_text(json.dumps(run(arm, count), indent=1) + "\n")
        print("wrote", arm)

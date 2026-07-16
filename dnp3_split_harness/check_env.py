"""check_env.py -- environment / dependency check for the DNP3 obfuscation harness.

Reports the interpreter, the required and optional Python packages, and the external
tshark binary, then exits non-zero if a REQUIRED dependency is missing. Optional
dependencies produce a warning, never a failure. Run before an experiment:

    python3 check_env.py            # human-readable report; exit 1 if a required dep is missing
    python3 check_env.py --json     # machine-readable

Python 3.8 compatible; standard library only.
"""

from __future__ import annotations

import argparse
import importlib
import json
import platform
import shutil
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

# (module, import_name, why, tier)  tier in {"required", "optional", "runtime"}
_PACKAGES: List[Tuple[str, str, str]] = [
    ("scapy", "required", "PCAP parsing (analyze_ack.py, extract_payloads.py)"),
    ("numpy", "required", "numerics (characterize/attacker/fingerprint)"),
    ("pandas", "required", "dataframes (attacker_eval.py, ack_fingerprint_eval.py)"),
    ("sklearn", "optional", "ML attacker eval (attacker_eval.py, ack_fingerprint_eval.py)"),
    ("matplotlib", "optional", "figure rendering"),
    ("pydnp3", "runtime", "live DNP3 master/outstation only (run_master/run_outstation)"),
]

_SUPPORTED_PY = (3, 8)


def _pkg_version(mod_name: str) -> Optional[str]:
    try:
        mod = importlib.import_module(mod_name)
    except Exception:  # noqa: BLE001 - any import failure means "not usable"
        return None
    return getattr(mod, "__version__", "present")


def _tshark() -> Optional[str]:
    if shutil.which("tshark") is None:
        return None
    try:
        out = subprocess.run(["tshark", "--version"], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    line = out.stdout.decode("utf-8", "replace").splitlines()
    return line[0].strip() if line else "present"


def gather() -> Dict[str, object]:
    py = platform.python_version()
    py_ok = sys.version_info[:2] == _SUPPORTED_PY
    packages = {}
    for mod_name, tier, why in _PACKAGES:
        packages[mod_name] = {
            "tier": tier, "why": why, "version": _pkg_version(mod_name),
        }
    tshark = _tshark()
    missing_required = [m for m, meta in packages.items()
                        if meta["tier"] == "required" and meta["version"] is None]
    if tshark is None:
        missing_required.append("tshark(binary)")
    return {
        "python_version": py,
        "python_supported": py_ok,
        "supported_python": "%d.%d" % _SUPPORTED_PY,
        "packages": packages,
        "tshark": tshark,
        "missing_required": missing_required,
        "ok": not missing_required,
    }


def _print_report(info: Dict[str, object]) -> None:
    print("=" * 64)
    print("DNP3 obfuscation harness -- environment check")
    print("=" * 64)
    mark = "OK " if info["python_supported"] else "WARN"
    print("[%s] Python %s (supported: %s)" %
          (mark, info["python_version"], info["supported_python"]))
    if not info["python_supported"]:
        print("       ! not the supported interpreter; pydnp3 and the tests target 3.8")
    print("-" * 64)
    for mod_name, meta in info["packages"].items():  # type: ignore[union-attr]
        ver = meta["version"]
        if ver is not None:
            status = "OK "
        elif meta["tier"] == "required":
            status = "MISS"
        else:
            status = "opt "
        print("[%s] %-12s %-9s %s" %
              (status, mod_name, ("" if ver is None else str(ver)), meta["why"]))
    ts = info["tshark"]
    print("[%s] %-12s %s" % ("OK " if ts else "MISS", "tshark",
                             ts if ts else "NOT FOUND on PATH (apt-get install tshark)"))
    print("-" * 64)
    if info["ok"]:
        print("RESULT: OK -- all required dependencies present.")
    else:
        print("RESULT: MISSING REQUIRED -> %s" % ", ".join(info["missing_required"]))
    print("=" * 64)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()
    info = gather()
    if args.json:
        print(json.dumps(info, indent=2, sort_keys=True))
    else:
        _print_report(info)
    return 0 if info["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

"""plan / execute / verify / restore for the framework profiles.

plan runs anywhere and touches nothing. execute, verify and restore need the switch host (bfrt_grpc) and,
for anything that writes, DEFENSE4_HW_AUTHORIZED=1. execute refuses without a drained-trial signoff, writes the
backup before its first write and refuses to overwrite one, and requires an admission record for any case that holds.
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "control"))
sys.path.insert(0, str(HERE.parents[1] / "response_ready" / "tests"))
import bfrt_device as bd      # noqa: E402
import profiles as pf         # noqa: E402
from test_p4_release import SOURCE, sem   # noqa: E402


def consts(source=None):
    return sem.extract_consts((Path(source) if source else SOURCE).read_text())


def profile_from(a):
    return pf.Profile(a.case, a.d_a_ms, a.gap_ms, a.budget, connection_id=a.connection_id, build_id=a.build_id)


def run(argv, device_factory=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command", choices=("plan", "execute", "verify", "restore"))
    ap.add_argument("--case", choices=pf.CASES, default="combined")
    ap.add_argument("--d-a-ms", type=float, default=0.0)
    ap.add_argument("--gap-ms", type=float, default=1.0)
    ap.add_argument("--budget", type=int, default=18000)
    ap.add_argument("--connection-id", default="")
    ap.add_argument("--build-id", default="")
    ap.add_argument("--source", help="P4 source whose constants give the mode numbers")
    ap.add_argument("--schema", help="bfrt.json of the loaded build")
    ap.add_argument("--control-dir")
    ap.add_argument("--backup")
    ap.add_argument("--admission")
    ap.add_argument("--drained-trial-signoff", action="store_true")
    a = ap.parse_args(argv)
    c = consts(a.source)
    if a.command == "plan":
        p = profile_from(a)
        out = {"problems": pf.problems(p, c)}
        if not out["problems"]:
            pl = pf.plan(p, c)
            out["plan"] = {k: v for k, v in pl.items()}
        print(json.dumps(out, indent=2, sort_keys=True, default=list))
        return 1 if out["problems"] else 0
    factory = device_factory or (lambda: bd.connect(a.control_dir, a.schema))
    device, interface = factory()
    try:
        if a.command == "verify":
            pl = pf.plan(profile_from(a), c)
            got = {t: device.read(t) for t in pl["expect"]}
            ok = all(got[t] == pl["expect"][t] for t in pl["expect"])
            print(json.dumps({"verified": ok, "read": got}, indent=2, sort_keys=True))
            return 0 if ok else 1
        if not (a.backup):
            raise SystemExit("--backup is required")
        if a.command == "restore":
            saved = json.loads(Path(a.backup).read_text())
            print(json.dumps(pf.restore(device, saved), indent=2, sort_keys=True))
            return 0
        if not a.drained_trial_signoff:
            raise SystemExit("execute needs --drained-trial-signoff: traffic stopped and token state drained")
        adm = json.loads(Path(a.admission).read_text()) if a.admission else None
        rec = pf.activate(device, profile_from(a), c, mock=False, admission=adm, backup_path=a.backup)
        print(json.dumps(rec, indent=2, sort_keys=True, default=list))
        return 0
    finally:
        if interface is not None and hasattr(interface, "tear_down_stream"):
            interface.tear_down_stream()


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))

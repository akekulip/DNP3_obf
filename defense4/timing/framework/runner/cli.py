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
import declaration as decl    # noqa: E402
from test_p4_release import SOURCE, sem   # noqa: E402


def consts(source=None):
    return sem.extract_consts((Path(source) if source else SOURCE).read_text())


def profile_from(a):
    return pf.Profile(a.case, a.d_a_ms, a.gap_ms, a.budget, connection_id=a.connection_id, build_id=a.build_id,
        readiness_expiry_ms=a.readiness_expiry_ms, heartbeat_request_us=a.heartbeat_request_us,
        completion_deadline_ms=a.completion_deadline_ms, measured_heartbeat_max_us=a.measured_heartbeat_max_us,
        measured_drain_max_ms=a.measured_drain_max_ms, measured_release_max_us=a.measured_release_max_us,
        padding_profile=a.padding_profile, split_profile=a.split_profile, translation_capacity=a.translation_capacity)


def run(argv, device_factory=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command", choices=("plan", "execute", "verify", "restore"))
    ap.add_argument("--case", choices=pf.CASES, default="combined")
    ap.add_argument("--d-a-ms", type=float, default=0.0)
    ap.add_argument("--gap-ms", type=float, default=1.0)
    ap.add_argument("--budget", type=int, default=18000)
    ap.add_argument("--readiness-expiry-ms", type=float, default=30.0)
    ap.add_argument("--heartbeat-request-us", type=float, default=100.0)
    ap.add_argument("--completion-deadline-ms", type=float)
    ap.add_argument("--measured-heartbeat-max-us", type=float)
    ap.add_argument("--measured-drain-max-ms", type=float)
    ap.add_argument("--measured-release-max-us", type=float)
    ap.add_argument("--padding-profile", choices=pf.PADDING_PROFILES, default=pf.PADDING_PROFILES[0])
    ap.add_argument("--split-profile", choices=pf.SPLIT_PROFILES, default=pf.SPLIT_PROFILES[0])
    ap.add_argument("--translation-capacity", type=int, default=2)
    ap.add_argument("--declaration", action="append", help="offline budget plan for each declared run list")
    ap.add_argument("--campaign", help="offline campaign manifest referencing declarations relative to its directory")
    ap.add_argument("--connection-id", default="")
    ap.add_argument("--build-id", default="")
    ap.add_argument("--source", help="P4 source whose constants give the mode numbers")
    ap.add_argument("--schema", help="bfrt.json of the loaded build")
    ap.add_argument("--control-dir")
    ap.add_argument("--backup")
    ap.add_argument("--admission")
    ap.add_argument("--drained-trial-signoff", action="store_true")
    a = ap.parse_args(argv)
    if a.declaration or a.campaign:
        if a.command != "plan":
            ap.error("--declaration and --campaign are offline plan inputs; they do not authorize collection")
        if a.declaration and a.campaign:
            ap.error("choose --declaration or --campaign")
        campaign = decl.load(a.campaign) if a.campaign else {}
        paths = a.declaration or [Path(a.campaign).resolve().parent / p for p in campaign.get("declarations", [])]
        declarations = [decl.load(path) for path in paths]
        problems = decl.validate_campaign(declarations,
            max_total_attempts=campaign.get("max_total_attempts", decl.MAX_TOTAL_ATTEMPTS),
            max_duration_ms=campaign.get("max_duration_ms"))
        out = {"problems": problems, "hardware_authorized": False}
        if not problems:
            summaries = [decl.budget_summary(d) for d in declarations]
            out["declarations"] = [{"id": d["id"], "sha256": decl.digest(d), "budget": s}
                                   for d, s in zip(declarations, summaries)]
            out["campaign_budget"] = {key: sum(s[key] for s in summaries) for key in summaries[0]}
        print(json.dumps(out, indent=2, sort_keys=True))
        return 1 if problems else 0
    c = consts(a.source)
    if a.command == "plan":
        p = profile_from(a)
        out = {"problems": pf.problems(p, c)}
        if not out["problems"]:
            pl = pf.plan(p, c)
            out["plan"] = {k: v for k, v in pl.items()}
        print(json.dumps(out, indent=2, sort_keys=True, default=list))
        return 1 if out["problems"] else 0
    if a.command in ("execute", "verify"):
        offline = pf.plan(profile_from(a), c)
        if offline.get("activation_blockers"):
            print(json.dumps({"verified": False, "problems": offline["activation_blockers"]}, indent=2))
            return 1
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

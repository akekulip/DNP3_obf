#!/usr/bin/env python3
"""Bring-up of the response-ready candidate on the switch host, after it has been cold-started with its own conf.

This is `defense4_timing_setup.hw_configure_all` (the sequence that passed strict readback on hardware on 2026-09-25) with exactly the steps that do not
fit the candidate removed, and the candidate's own steps added:

  removed  hw_config_codebook         the candidate's contract needs tbl_bor_codebook EMPTY (no random deadlines)
  removed  hw_verify_tbl_commit       verifies the old commit map; the candidate adds OUT_ACK_FWD_ARM (44)
  removed  verify_commit_map          offline totality of that same old map
  removed  caseA.config_params_d4     frozen writer of tbl_params; the candidate's schema differs (no shape_enable)
  removed  hw_config_tbl_bor_params   replaced by the schema-checked adapter below
  added    tbl_bor_codebook is read back EMPTY
  added    the three parameter tables through framework/control/profiles.py (schema-checked, readback after every write, backup first)
  kept     pktgen enabled LAST, and only if every check passed

Nothing here loads a program or restarts anything; it needs a running bf_switchd that already holds the candidate. Writes need DEFENSE4_HW_AUTHORIZED=1.
`--list` prints the sequence and touches nothing.
"""
import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SETUP_DIR = os.environ.get("SETUP_DIR", "/home/decps/dnp3_timing7_20260925/control")     # the modules used on 2026-09-25
SDE_INSTALL = os.environ.get("SDE_INSTALL", "/home/decps/Downloads/bf-sde-9.13.2/install")
sys.path.insert(0, SDE_INSTALL + "/lib/python3.8/site-packages/tofino")      # bfrt_grpc, as live_snapshot.py does
sys.path.insert(0, SETUP_DIR)
sys.path.insert(0, str(HERE))

#: the proven steps, in order, as hw_configure_all runs them; the test compares this list with that function's source
PROVEN_STEPS = [
    "d3.assert_dp8_speed", "d3.config_ports", "hw_config_bor_loopback", "d3.disarm_port_shaper", "hw_init_registers",
    "hw_config_queues_on_port(RRC)", "hw_config_queues_on_port(BOR)", "hw_config_pktgen_two_apps(disabled)",
    "d3.config_mirror", "d3.config_session",
]
CANDIDATE_STEPS = ["tbl_bor_codebook empty", "adapter: tbl_params / tbl_bor_params / tbl_read_release_params", "hw_config_pktgen_two_apps(enabled)"]
REMOVED = ["verify_commit_map", "caseA.config_params_d4", "hw_config_tbl_bor_params", "hw_config_codebook", "hw_verify_tbl_commit"]


def identity(build_out, manifest):
    """The files the daemon was told to load must be the ones the compiler produced."""
    want = json.loads(Path(manifest).read_text())["artifact_sha256"]
    got = {k: hashlib.sha256((Path(build_out) / k).read_bytes()).hexdigest() for k in want}
    return {"match": got == want, "want": want, "got": got}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--list", action="store_true", help="print the sequence and exit; touches nothing")
    ap.add_argument("--case", default="off", choices=("off", "combined", "ack_focused", "response_focused"))
    ap.add_argument("--d-a-ms", type=float, default=0.0)
    ap.add_argument("--gap-ms", type=float, default=1.0)
    ap.add_argument("--build-out", default="/home/decps/framework_build_20261006c/sde_9_13_2_build/out")
    ap.add_argument("--manifest", default="/home/decps/framework_build_20261006c/sde_9_13_2_build/manifest.json")
    ap.add_argument("--consts", default=str(HERE / "consts.json"), help="mode numbers extracted from the P4 source, with its hash")
    ap.add_argument("--program", default="defense4_timing")
    ap.add_argument("--admission", help="admission record (JSON) for any case that holds")
    ap.add_argument("--connection-id", default="vision-sel751-20000")
    ap.add_argument("--build-id", default="")
    ap.add_argument("--backup", help="path for the pre-write snapshot of the three parameter tables (must not exist)")
    ap.add_argument("--record", help="path for the activation record (JSON)")
    ap.add_argument("--no-pktgen-enable", action="store_true")
    args = ap.parse_args(argv)

    print("PROVEN steps kept:", *PROVEN_STEPS, sep="\n  ")
    print("REMOVED (do not fit the candidate):", *REMOVED, sep="\n  ")
    print("CANDIDATE steps:", *CANDIDATE_STEPS, sep="\n  ")
    if args.list:
        return 0

    ident = identity(args.build_out, args.manifest)
    print("build identity:", "MATCH" if ident["match"] else "MISMATCH")
    if not ident["match"]:
        print(json.dumps(ident, indent=1))
        return 2
    consts = json.loads(Path(args.consts).read_text())
    man = json.loads(Path(args.manifest).read_text())
    if consts.get("_source_sha256") != man["source_sha256"]:
        print("REFUSED: mode constants were extracted from a different source than the build's")
        return 2

    import defense4_timing_setup as m                # the 2026-09-25 module, unchanged
    import bfrt_grpc.client as gc
    import profiles as pf
    from bfrt_device import BfrtDevice
    from schema import Schema

    a = m.build_argparser().parse_args(["configure-all", "--read-len", "0", "--anchor-req", "1", "--mode", "OFF"])
    if not m._require_hw("candidate-bringup"):
        return 2
    chk = m.Checks()
    iface, bi, tgt, tdev = m._connect(a)
    out, record = {}, {}
    try:
        d3 = m.d3
        d3.assert_dp8_speed(bi, tdev, tgt, a, out, chk, pre=True)
        d3.config_ports(bi, tdev, a, out, chk, write=True)
        m.hw_config_bor_loopback(bi, tdev, a, out, chk)
        d3.disarm_port_shaper(bi, [("pipe0", tgt), ("device", tdev)], a, out, chk, write=True)
        m.hw_init_registers(bi, tgt, chk)
        m.hw_config_queues_on_port(bi, tgt, a, a.port_l, m.QUEUE_PLAN_RRC, out, chk)
        m.hw_config_queues_on_port(bi, tgt, a, a.port_bor_l, m.QUEUE_PLAN_BOR, out, chk)
        m.hw_config_pktgen_two_apps(bi, tgt, a, out, chk, enable=False)
        d3.config_mirror(bi, tgt, a, out, chk, write=True)
        d3.config_session(bi, tdev, a, out, chk, write=True)
        # candidate: no random deadlines
        cb = bi.table_get("pipe.Ingress.tbl_bor_codebook")
        n = sum(1 for _ in cb.entry_get(tdev, flags={"from_hw": False}))
        (chk.ok if n == 0 else chk.fail)("tbl_bor_codebook is empty (no random deadlines)", "entries=%d" % n)
        # candidate: the three parameter tables, schema-checked, readback after every write
        schema = Schema.from_file(Path(args.build_out) / "bfrt.json")
        dev = BfrtDevice(schema, gc, bi, tdev, authorized=True)
        adm = json.loads(Path(args.admission).read_text()) if args.admission else None
        prof = pf.Profile(args.case, args.d_a_ms, args.gap_ms, 18000, connection_id=args.connection_id, build_id=args.build_id)
        try:
            record = pf.activate(dev, prof, consts, mock=False, admission=adm, backup_path=args.backup)
            chk.ok("parameter tables written and read back", "case=%s" % args.case)
        except pf.ActivationError as exc:
            record = exc.record
            chk.fail("parameter activation", str(exc))
        if not chk.blocked() and not args.no_pktgen_enable:
            m.hw_config_pktgen_two_apps(bi, tgt, a, out, chk, enable=True)
            chk.ok("pktgen apps ENABLED (all prerequisites passed)", "")
        else:
            chk.warn("pktgen LEFT DISABLED", "n_fail=%d n_warn=%d" % (chk.n_fail, chk.n_warn))
    finally:
        try:
            iface._tear_down_stream()
        except Exception:
            pass
    print("==== candidate bring-up readback ====")
    print(chk.render())
    print("RESULT: %s (n_fail=%d n_warn=%d)" % ("PASS" if not chk.blocked() else "FAIL", chk.n_fail, chk.n_warn))
    if args.record:
        Path(args.record).write_text(json.dumps({"time_ns": time.time_ns(), "identity": ident, "activation": record,
                                                 "pass": not chk.blocked()}, indent=1, default=str))
    return 0 if not chk.blocked() else 2


if __name__ == "__main__":
    sys.exit(main())

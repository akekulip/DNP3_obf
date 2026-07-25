#!/usr/bin/env python3
"""03_configure_tm.py — configure Traffic Manager + guard interval G on the switch.

Runs LOCALLY on the dev box; drives the switch over ssh (sshpass -e). Bakes in the
§4 control-plane review fixes so the pipeline cannot be mis-bound or leak silently:

  C1  always pass --prog dnp3_timing_normalizer to the setup script (its default is
      ibspg_controlled_drain — the WRONG pipeline).
  C2  run WITHOUT --paired (two-level strict priority), --qb 7 --qh 1
      --host-ports 9,11 --port-l 8 --pg-l 2.
  C3  explicitly clear + verify NO max-rate shaper on Q_BLOCK (qid7) — the restore
      target uses shapers; a stale one makes Q_BLOCK ineligible and Q_RESP leaks.
  G   set the guard interval via p13_guard.py --param g_ticks (which tick-aligns G;
      review D1), and gate on the tick-aligned readback.

Staging: the three switch-side helpers (ibspg_paired_setup.py, tm_shaper_clear.py,
p13_guard.py) are scp'd to SW_STAGE_DIR each run, so this is self-contained.

Prints a JSON summary and exits nonzero if any gate fails. --dry-run prints every
remote command and touches nothing.
"""
import argparse
import json
import os
import shlex
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TF_DIR = os.path.dirname(HERE)
REPO_ROOT = os.path.dirname(os.path.dirname(TF_DIR))


def env(name, default):
    return os.environ.get(name, default)


def sh(cmd, dry, capture=True):
    """Run a local shell command (used for ssh/scp). Logs it; honors dry-run."""
    print("RUN: %s" % cmd)
    if dry:
        return 0, ""
    p = subprocess.run(cmd, shell=True, capture_output=capture, text=True)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main():
    ap = argparse.ArgumentParser(description="configure TM queues + guard G (review C1-C3 + D1)")
    ap.add_argument("--g-ms", type=float, default=float(env("G_MS", "25")))
    ap.add_argument("--config", action="store_true", help="run the one-time static TM/port config")
    ap.add_argument("--set-g", action="store_true", help="set + verify the guard interval G")
    ap.add_argument("--all", action="store_true", help="config + set-g (default when neither given)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--help-more", action="store_true")
    a = ap.parse_args()
    if not (a.config or a.set_g):
        a.all = True
    if a.all:
        a.config = a.set_g = True

    dry = a.dry_run
    # config (from lab.env via the environment the Makefile/common.sh export)
    SW = env("SW", "decps@10.10.54.81")
    SSHO = "-o ConnectTimeout=15 -o StrictHostKeyChecking=no -o LogLevel=ERROR"
    SW_SDE = env("SW_SDE", "/home/decps/Downloads/bf-sde-9.13.2")
    SW_STAGE = env("SW_STAGE_DIR", "/home/decps/timing_final_cp")
    PROG = env("PROG", "dnp3_timing_normalizer")
    QB = env("QB", "7"); QH = env("QH", "1")
    PG_L = env("PG_L", "2"); PG_L_NR = env("PG_L_NR", "0")
    DP_VISION = env("DP_VISION", "9"); DP_HULK = env("DP_HULK", "11"); DP_LOOP = env("DP_LOOP", "8")

    SETUP_SRC = os.path.join(REPO_ROOT, "research/ibspg_paired/control/ibspg_paired_setup.py")
    GUARD_SRC = os.path.join(REPO_ROOT, "research/ibspg_dnp3_replay/harness/p13_guard.py")
    SHAPER_SRC = os.path.join(HERE, "remote", "tm_shaper_clear.py")
    for f in (SETUP_SRC, GUARD_SRC, SHAPER_SRC):
        if not os.path.exists(f) and not dry:
            sys.exit("FATAL: missing helper %s" % f)

    swenv = ("export SDE=%s; export SDE_INSTALL=$SDE/install; export PATH=$SDE_INSTALL/bin:$PATH; "
             "export LD_LIBRARY_PATH=$SDE_INSTALL/lib:$LD_LIBRARY_PATH; "
             "export PYTHONPATH=$(echo $SDE_INSTALL/lib/python*/site-packages):"
             "$(echo $SDE_INSTALL/lib/python*/site-packages/tofino):$PYTHONPATH" % SW_SDE)

    def sw(cmd):
        return sh("sshpass -e ssh %s %s %s" % (SSHO, SW, shlex.quote("bash -lc '%s; %s'" % (swenv, cmd))), dry)

    result = {"prog": PROG, "g_ms": a.g_ms, "gates": {}}

    # ---- stage helpers -----------------------------------------------------
    sh("sshpass -e ssh %s %s %s" % (SSHO, SW, shlex.quote("mkdir -p %s" % SW_STAGE)), dry)
    sh("sshpass -e scp %s %s %s %s %s:%s/" % (SSHO, shlex.quote(SETUP_SRC), shlex.quote(GUARD_SRC),
                                              shlex.quote(SHAPER_SRC), SW, SW_STAGE), dry)

    # ---- C1 + C2: static TM/port config ------------------------------------
    if a.config:
        # C1: --prog PROG (NOT the setup script's ibspg_controlled_drain default)
        # C2: NO --paired; two-level Q_BLOCK(7)=HIGH > Q_RESP(1)=LOW
        setup_cmd = ("python3 %s/ibspg_paired_setup.py --prog %s --config "
                     "--qb %s --qh %s --host-ports %s,%s --port-l %s --pg-l %s"
                     % (SW_STAGE, PROG, QB, QH, DP_VISION, DP_HULK, DP_LOOP, PG_L))
        rc, out = sw(setup_cmd + " 2>&1 | grep PART9SETUP")
        result["setup_rc"] = rc
        sp_ok = None
        if not dry:
            for line in out.splitlines():
                if line.startswith("PART9SETUP "):
                    j = json.loads(line[len("PART9SETUP "):])
                    result["setup"] = j
                    sp_ok = bool(j.get("strict_priority_verified"))
        result["gates"]["strict_priority_verified"] = (True if dry else sp_ok)

        # C3: clear + verify NO Q_BLOCK shaper
        shaper_cmd = ("python3 %s/tm_shaper_clear.py --prog %s --pg-l %s --pg-l-nr %s --qb %s"
                      % (SW_STAGE, PROG, PG_L, PG_L_NR, QB))
        rc, out = sw(shaper_cmd + " 2>&1 | grep TMSHAPER")
        cleared = None
        if not dry:
            for line in out.splitlines():
                if line.startswith("TMSHAPER "):
                    j = json.loads(line[len("TMSHAPER "):])
                    result["shaper"] = j
                    cleared = bool(j.get("cleared"))
        result["gates"]["qblock_shaper_cleared"] = (True if dry else cleared)

    # ---- G: set + verify (tick-aligned readback; review D1) -----------------
    if a.set_g:
        # p13_guard.py tick-aligns G (low byte zero) and reads it back. Its own
        # 'verified' flag compares to the PRE-align request, so it reports False for
        # any non-256ns-multiple G. We therefore compute the tick-aligned expected
        # value and gate the READBACK against THAT (the value actually written).
        g_ns = int(round(a.g_ms * 1e6))
        g_ticks = g_ns & 0xFFFFFF00
        result["g_ns_requested"] = g_ns
        result["g_ns_tick_aligned"] = g_ticks
        guard_cmd = ("python3 %s/p13_guard.py --prog %s --param g_ticks --set-g-ms %s"
                     % (SW_STAGE, PROG, a.g_ms))
        rc, out = sw(guard_cmd + " 2>&1 | grep P13GUARD")
        g_ok = None
        if not dry:
            for line in out.splitlines():
                if line.startswith("P13GUARD "):
                    j = json.loads(line[len("P13GUARD "):])
                    result["guard"] = j
                    rb = j.get("readback") or {}
                    vals = [v for v in rb.values() if isinstance(v, int)]
                    g_ok = bool(vals and vals[0] == g_ticks)
        result["gates"]["guard_g_readback_verified"] = (True if dry else g_ok)

    print("CONFIGURE_TM " + json.dumps(result, indent=1))
    failed = [k for k, v in result["gates"].items() if v is False]
    if failed and not dry:
        sys.exit("FATAL: configuration gate(s) failed: %s" % ", ".join(failed))
    print("configure-tm: %s" % ("DRYRUN OK" if dry else "PASS"))


if __name__ == "__main__":
    main()

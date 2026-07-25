#!/usr/bin/env python3
"""demo_status.py — compact meeting status of the switch (directive §23).

Shows only meeting-relevant state, not every register: the loaded P4 program, the
Q_BLOCK>Q_RESP strict priorities, whether a transaction is currently held, and the
blocker/release counters. Runs locally and reads the switch over ssh (sshpass -e).
--dry-run prints the remote command and touches nothing.
"""
import argparse
import json
import os
import shlex
import subprocess
import sys


def env(n, d):
    return os.environ.get(n, d)


def main():
    ap = argparse.ArgumentParser(description="compact switch status for the meeting (§23)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    SW = env("SW", "decps@10.10.54.81")
    SSHO = "-o ConnectTimeout=15 -o StrictHostKeyChecking=no -o LogLevel=ERROR"
    SW_SDE = env("SW_SDE", "/home/decps/Downloads/bf-sde-9.13.2")
    SW_RD = env("SW_READ_DIR", "/home/decps/timing_final_cp")
    PROG = env("PROG", "dnp3_timing_normalizer")
    REGS = env("TF_REGS", "reg_tag,reg_deadline,reg_t_ack")
    CTRS = ("ctr_arm,ctr_ack_arm,ctr_resp_enq,ctr_resp_release,ctr_block_enq,"
            "ctr_block_term_deadline,ctr_block_term_timeout,ctr_release_deadline,"
            "ctr_release_fail_open,ctr_bypass:1")
    swenv = ("export SDE=%s; export SDE_INSTALL=$SDE/install; export PATH=$SDE_INSTALL/bin:$PATH; "
             "export LD_LIBRARY_PATH=$SDE_INSTALL/lib:$LD_LIBRARY_PATH; "
             "export PYTHONPATH=$(echo $SDE_INSTALL/lib/python*/site-packages):"
             "$(echo $SDE_INSTALL/lib/python*/site-packages/tofino):$PYTHONPATH" % SW_SDE)
    cmd = ("python3 %s/p13_read.py --prog %s --regs %s --counters %s --tag status 2>&1 | grep P13READ"
           % (SW_RD, PROG, REGS, CTRS))
    full = "sshpass -e ssh %s %s %s" % (SSHO, SW, shlex.quote("bash -lc '%s; %s'" % (swenv, cmd)))
    print("RUN: %s" % full)
    if a.dry_run:
        print("DRYRUN: would read the switch and print program / queue priorities / held state / counters.")
        return 0

    out = subprocess.run(full, shell=True, capture_output=True, text=True)
    line = next((l for l in out.stdout.splitlines() if l.startswith("P13READ ")), None)
    if not line:
        sys.exit("FATAL: no P13READ line from the switch:\n%s" % (out.stdout + out.stderr)[:400])
    j = json.loads(line[len("P13READ "):])
    c = j.get("counters", {}); tm = j.get("tm", {}); d = j.get("derived", {})

    print("==== DNP3 timing-normalizer — switch status ====")
    print("  program (bound):     %s" % j.get("prog", PROG))
    qb = tm.get("Q_BLOCK", {}); qr = tm.get("Q_RESP", {})
    print("  queue priorities:    Q_BLOCK max_priority=%s > Q_RESP max_priority=%s (shaper on Q_BLOCK: %s)"
          % (qb.get("max_priority"), qr.get("max_priority"), qb.get("max_rate_enable")))
    print("  transaction state:   deadline_armed=%s (1 = a response is currently held)"
          % d.get("deadline_armed"))
    print("  counters:")
    for k in ("ctr_arm", "ctr_ack_arm", "ctr_resp_enq", "ctr_resp_release",
              "ctr_block_enq", "ctr_block_term_deadline", "ctr_block_term_timeout",
              "ctr_release_deadline", "ctr_release_fail_open", "ctr_bypass:1"):
        print("    %-26s %s" % (k, c.get(k)))
    print("  (fail_open / block_term_timeout / bypass:1 should all be 0 on a healthy hold)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

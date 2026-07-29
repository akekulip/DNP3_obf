#!/usr/bin/env python3
# =============================================================================
#  AUTHORED OFF-SWITCH — NOT YET RUN. Nothing in this file has been executed
#  against hardware. The switch is running the proven dnp3_timing_normalizer_pktgen
#  and was not touched while this was written.
#
#  RUNS ON HULK. Injects and captures on dp11 only. It never addresses dp9
#  (Vision) or dp64 (the SEL-751 relay leg) — and cannot, because the loaded P4
#  has no code path that assigns either port (p4/four_queue_oracle.p4).
#
#  Raw AF_PACKET sockets need root: run under sudo on Hulk.
# =============================================================================
"""four_queue_oracle.py — injector / orchestrator for one four-queue dequeue
oracle trial.

Per trial:
    reset counters -> preload (scheduling off) -> inject 130 frames in a
    RANDOMIZED order -> verify all four queues are demonstrably nonempty ->
    release (scheduling on) -> read drops -> write one JSON record.

The capture is taken by the surrounding shell driver (run_four_queue_oracle.sh),
which owns tcpdump; this script owns injection, control-plane sequencing and the
trial record. Order verification is offline, in
analysis/analyze_four_queue_oracle.py.

    sudo python3 four_queue_oracle.py --iface enp59s0f0np0 --trial-id 1 \
        --mode reservoir --k 64 \
        --cp-cmd "ssh decps@10.10.54.81 PYTHONPATH=... python3.8 \
                  /home/decps/fqo/four_queue_oracle_setup.py" \
        --out evidence/four_queue_oracle/trial_0001.json

Python 3.8 compatible. Standard library only.
"""
import argparse
import json
import logging
import os
import random
import shlex
import socket
import struct
import subprocess
import sys
import time

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Wire format — MUST match p4/four_queue_oracle.p4 header oracle_h exactly, and
# analysis/analyze_four_queue_oracle.py. 64-byte frame:
#   0..5  dst MAC | 6..11 src MAC | 12..13 ethertype 0x88C2
#   14..15 trial_id | 16 role | 17..18 per_role_seq | 19..20 global_inj_seq
#   21 pass | 22..63 pad
# ---------------------------------------------------------------------------
ETHERTYPE_ORACLE = 0x88C2      # .p4 const bit<16> ETHERTYPE_ORACLE
FRAME_LEN = 64
HDR_LEN = 22                   # 14 eth + 8 oracle
PAD_LEN = FRAME_LEN - HDR_LEN  # 42

ROLE_ABLOCK = 1                # .p4 const bit<8> ROLE_ABLOCK
ROLE_HELD_ACK = 2              # .p4 const bit<8> ROLE_HELD_ACK
ROLE_RBLOCK = 3                # .p4 const bit<8> ROLE_RBLOCK
ROLE_HELD_RESP = 4             # .p4 const bit<8> ROLE_HELD_RESP
ROLE_NAME = {ROLE_ABLOCK: "ABLOCK", ROLE_HELD_ACK: "HELD_ACK",
             ROLE_RBLOCK: "RBLOCK", ROLE_HELD_RESP: "HELD_RESP"}

# Locally-administered, unicast, and deliberately unlike any host NIC on the
# testbed, so an oracle frame is unmistakable in a capture.
DEFAULT_DST_MAC = "02:00:00:00:C2:01"
DEFAULT_SRC_MAC = "02:00:00:00:C2:02"

# Trial modes. See reports/FOUR_QUEUE_ORACLE_REPORT.md for what each one proves.
MODES = ("reservoir", "resp_waiting", "late_ack_preempt",
         "empty_ack_queue", "empty_resp_queue")


def mac_to_bytes(s):
    """'02:00:00:00:C2:01' -> b'\\x02\\x00\\x00\\x00\\xc2\\x01'."""
    parts = s.replace("-", ":").split(":")
    if len(parts) != 6:
        raise ValueError("bad MAC %r" % s)
    return bytes(int(p, 16) for p in parts)


def build_frame(trial_id, role, per_role_seq, global_inj_seq,
                dst_mac, src_mac, pass_flag=0):
    """Build one 64-byte oracle frame. pass_flag is 0 on injection; the switch
    sets it to 1 on the loopback pass."""
    f = bytearray()
    f += mac_to_bytes(dst_mac)
    f += mac_to_bytes(src_mac)
    f += struct.pack("!H", ETHERTYPE_ORACLE)
    f += struct.pack("!HBHHB", trial_id & 0xFFFF, role & 0xFF,
                     per_role_seq & 0xFFFF, global_inj_seq & 0xFFFF, pass_flag & 0xFF)
    f += b"\x00" * PAD_LEN
    assert len(f) == FRAME_LEN, len(f)
    return bytes(f)


def build_injection_plan(trial_id, n_ablock, n_rblock, n_ack, n_resp, seed,
                         dst_mac, src_mac):
    """Build the full randomized injection sequence.

    The order is RANDOMIZED and recorded. This is load-bearing: if the observed
    dequeue order matched the injection order, the result would be explained by
    arrival order rather than by priority. Randomizing and recording the seed
    lets the analyzer show the observed order is NOT the injection order.
    """
    rng = random.Random(seed)
    items = []
    for i in range(n_ablock):
        items.append((ROLE_ABLOCK, i))
    for i in range(n_ack):
        items.append((ROLE_HELD_ACK, i))
    for i in range(n_rblock):
        items.append((ROLE_RBLOCK, i))
    for i in range(n_resp):
        items.append((ROLE_HELD_RESP, i))
    rng.shuffle(items)

    plan = []
    for gseq, (role, rseq) in enumerate(items):
        plan.append({
            "global_inj_seq": gseq,
            "role": role,
            "role_name": ROLE_NAME[role],
            "per_role_seq": rseq,
            "frame": build_frame(trial_id, role, rseq, gseq, dst_mac, src_mac),
        })
    return plan


def open_raw_socket(iface):
    """Raw AF_PACKET socket bound to iface. Requires root.

    A PermissionError here must be LOUD: a silently failed socket means the
    trial injects nothing and the capture is empty, which is easy to misread as
    a dataplane failure.
    """
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    except AttributeError:
        raise SystemExit("AF_PACKET is Linux-only; this must run on Hulk")
    except PermissionError:
        raise SystemExit("PermissionError opening AF_PACKET on %s — run under sudo "
                         "on Hulk. Injecting nothing would look exactly like a "
                         "dataplane failure, so refusing to continue." % iface)
    s.bind((iface, 0))
    return s


def inject(sock, plan, gap_us=0, subset=None):
    """Send the frames of `plan` (optionally only those whose index is in
    `subset`). Returns the number sent."""
    n = 0
    for i, item in enumerate(plan):
        if subset is not None and i not in subset:
            continue
        sock.send(item["frame"])
        n += 1
        if gap_us:
            time.sleep(gap_us / 1e6)
    return n


# ---------------------------------------------------------------------------
# Control-plane bridge: shell out to four_queue_oracle_setup.py on the switch.
# ---------------------------------------------------------------------------
def cp(cp_cmd, args, timeout=120, dry_run=False):
    """Run the setup script with `args` and return (rc, parsed FQORACLE dict, raw).

    cp_cmd is a full command prefix (typically an ssh invocation). Keeping it a
    caller-supplied string means this script makes no assumption about how the
    switch is reached, and --dry-run exercises every code path with zero remote
    calls.
    """
    cmd = cp_cmd + " " + " ".join(shlex.quote(x) for x in args)
    if dry_run:
        logger.info("DRYRUN cp: %s", cmd)
        return 0, {"dry_run": True}, ""
    logger.debug("cp: %s", cmd)
    try:
        p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, {}, "timeout after %ds" % timeout
    raw = p.stdout.decode("utf-8", "replace")
    parsed = {}
    for line in raw.splitlines():
        if line.startswith("FQORACLE "):
            try:
                parsed = json.loads(line[len("FQORACLE "):])
            except ValueError:
                pass
    return p.returncode, parsed, raw


def queue_usage(occ):
    """occupancy dict -> {label: usage_cells}."""
    return {k: (v or {}).get("usage_cells") for k, v in (occ or {}).items()}


def total_drops(occ):
    tot = 0
    for _k, v in (occ or {}).items():
        d = (v or {}).get("drop_count_packets")
        if d:
            tot += int(d)
    return tot


# ---------------------------------------------------------------------------
# Trial
# ---------------------------------------------------------------------------
def run_trial(a):
    """Run one trial and return the record dict."""
    n_ablock, n_rblock = a.k, a.k
    n_ack, n_resp = 1, 1

    rec = {
        "trial_id": a.trial_id,
        "mode": a.mode,
        "k": a.k,
        "seed": a.seed,
        "iface": a.iface,
        "release_order": a.release_order,
        "shaped": bool(a.shaper_pps),
        "shaper_pps": a.shaper_pps,
        "expected": {"ABLOCK": n_ablock, "HELD_ACK": n_ack,
                     "RBLOCK": n_rblock, "HELD_RESP": n_resp},
        "authored_off_switch": True,
        "silicon_validated": False,
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    plan = build_injection_plan(a.trial_id, n_ablock, n_rblock, n_ack, n_resp,
                                a.seed, a.dst_mac, a.src_mac)
    rec["injection_sequence"] = [
        {"global_inj_seq": p["global_inj_seq"], "role_name": p["role_name"],
         "per_role_seq": p["per_role_seq"]} for p in plan]
    rec["n_planned"] = len(plan)

    # ---- which frames are injected BEFORE the release, and which are late ----
    # The three "late" modes need a frame to arrive mid-drain. See the drain-window
    # arithmetic in the report: unshaped, the whole drain is ~1.7 us and a host
    # CANNOT hit it, so these modes REQUIRE --shaper-pps to stretch the drain.
    late_roles = {
        "reservoir": set(),
        "resp_waiting": set(),
        "late_ack_preempt": {ROLE_HELD_ACK},
        "empty_ack_queue": {ROLE_HELD_ACK},
        "empty_resp_queue": {ROLE_HELD_RESP},
    }[a.mode]
    pre_idx = {i for i, p in enumerate(plan) if p["role"] not in late_roles}
    late_idx = {i for i, p in enumerate(plan) if p["role"] in late_roles}
    rec["n_preloaded"] = len(pre_idx)
    rec["n_late"] = len(late_idx)

    if late_idx and not a.shaper_pps:
        rec.setdefault("warnings", []).append(
            "mode %s injects %d frame(s) AFTER release, but no shaper is configured. "
            "The unshaped drain is ~1.7 us for %d frames at 25G, which a host cannot "
            "hit. This trial's late injection will almost certainly land after the "
            "drain has finished and the result is NOT evidence about preemption."
            % (a.mode, len(late_idx), n_ablock + n_rblock))

    # resp_waiting enqueues HELD_RESP before HELD_ACK. Because everything is
    # preloaded while scheduling is off, "before" means earlier in the injection
    # sequence, which the plan below makes explicit and the record preserves.
    if a.mode == "resp_waiting":
        resp_pos = [p["global_inj_seq"] for p in plan if p["role"] == ROLE_HELD_RESP]
        ack_pos = [p["global_inj_seq"] for p in plan if p["role"] == ROLE_HELD_ACK]
        if resp_pos and ack_pos and resp_pos[0] > ack_pos[0]:
            # Swap so HELD_RESP genuinely precedes HELD_ACK in arrival order.
            i_resp = next(i for i, p in enumerate(plan) if p["role"] == ROLE_HELD_RESP)
            i_ack = next(i for i, p in enumerate(plan) if p["role"] == ROLE_HELD_ACK)
            plan[i_resp], plan[i_ack] = plan[i_ack], plan[i_resp]
            rec["resp_waiting_swap"] = {"resp_idx": i_ack, "ack_idx": i_resp}
        rec["resp_before_ack_in_arrival_order"] = True

    # ---------------- control plane: reset + preload ----------------
    rc, _d, raw = cp(a.cp_cmd, ["--reset-counters"], dry_run=a.dry_run)
    rec["cp_reset_rc"] = rc
    if rc not in (0, 1):
        rec["error"] = "reset-counters failed: %s" % raw[-400:]
        return rec

    rc, _d, raw = cp(a.cp_cmd, ["--preload"], dry_run=a.dry_run)
    rec["cp_preload_rc"] = rc
    if rc != 0:
        rec["error"] = "preload failed (scheduling_enable=False not confirmed): %s" % raw[-400:]
        return rec

    # ---------------- inject the preloaded set ----------------
    if a.dry_run:
        rec["n_injected_pre"] = len(pre_idx)
    else:
        sock = open_raw_socket(a.iface)
        t0 = time.time()
        rec["n_injected_pre"] = inject(sock, plan, a.gap_us, subset=pre_idx)
        rec["inject_pre_seconds"] = round(time.time() - t0, 6)
        sock.close()
    time.sleep(a.settle_ms / 1000.0)

    # ---------------- the "demonstrably nonempty" gate ----------------
    # A trial where any queue reads 0 is INVALID (the packets never got parked),
    # NOT an ordering failure. It is recorded separately so it can never be
    # counted as evidence either way.
    rc, d, raw = cp(a.cp_cmd, ["--occupancy", "--require-nonempty"], dry_run=a.dry_run)
    occ = (d or {}).get("occupancy", {})
    rec["occupancy_before_release"] = occ
    rec["usage_before_release"] = queue_usage(occ)
    rec["all_queues_nonempty"] = bool((d or {}).get("all_queues_nonempty"))
    if a.dry_run:
        rec["all_queues_nonempty"] = True
    if not rec["all_queues_nonempty"]:
        rec["valid"] = False
        rec["invalid_reason"] = "NOT_ALL_QUEUES_NONEMPTY"
        rec["invalid_detail"] = ("usage/watermark per queue = %s; the trial is INVALID "
                                 "(packets were not parked), not an ordering failure"
                                 % rec["usage_before_release"])
        # Still release, so the queues do not stay held for the next trial.
        cp(a.cp_cmd, ["--release", "--release-order", a.release_order], dry_run=a.dry_run)
        return rec
    rec["valid"] = True

    # ---------------- release: THE MEASUREMENT ----------------
    rec["release_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    t_rel = time.time()
    rc, d, raw = cp(a.cp_cmd, ["--release", "--release-order", a.release_order],
                    dry_run=a.dry_run)
    rec["cp_release_rc"] = rc
    rec["release_seconds"] = round(time.time() - t_rel, 6)
    if rc != 0:
        rec["error"] = "release failed: %s" % raw[-400:]
        return rec

    # ---------------- late injection (shaped modes only) ----------------
    if late_idx:
        time.sleep(a.late_delay_ms / 1000.0)
        if a.dry_run:
            rec["n_injected_late"] = len(late_idx)
        else:
            sock = open_raw_socket(a.iface)
            rec["n_injected_late"] = inject(sock, plan, a.gap_us, subset=late_idx)
            sock.close()
        rec["late_delay_ms"] = a.late_delay_ms

    # ---------------- drain + final counters ----------------
    time.sleep(a.drain_ms / 1000.0)
    rc, d, raw = cp(a.cp_cmd, ["--occupancy"], dry_run=a.dry_run)
    occ_after = (d or {}).get("occupancy", {})
    rec["occupancy_after_release"] = occ_after
    rec["drops"] = total_drops(occ_after)
    rec["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return rec


def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        description="Injector / orchestrator for one four-queue dequeue oracle trial. "
                    "Runs on Hulk; needs sudo for AF_PACKET.")
    ap.add_argument("--iface", default="enp59s0f0np0",
                    help="Hulk NIC facing dp11 (default enp59s0f0np0)")
    ap.add_argument("--trial-id", type=int, required=True)
    ap.add_argument("--mode", choices=MODES, default="reservoir")
    ap.add_argument("--k", type=int, default=64,
                    help="blockers per class (64 = the reservoir depth). K=1 is NOT "
                         "part of the plan: a preloaded non-recirculating oracle "
                         "cannot exercise the empty-gap failure, so K=1 would pass "
                         "trivially and prove nothing about reservoir depth. That "
                         "remains a separate recirculating-token experiment.")
    ap.add_argument("--seed", type=int, default=None,
                    help="RNG seed for the injection order; default = derived from "
                         "trial-id so every trial is reproducible")
    ap.add_argument("--release-order", choices=("batch", "lo-first", "hi-first"),
                    default="batch",
                    help="how the four queues are re-enabled. batch = one gRPC Write "
                         "RPC. lo-first / hi-first are the skew controls; the verdict "
                         "is only sound if the order is INVARIANT across all three.")
    ap.add_argument("--shaper-pps", type=int, default=None,
                    help="record that a drain shaper is configured (set it with "
                         "four_queue_oracle_setup.py --shaper). REQUIRED for the "
                         "late-injection modes.")
    ap.add_argument("--late-delay-ms", type=float, default=5.0,
                    help="delay after release before injecting the late frame")
    ap.add_argument("--settle-ms", type=float, default=50.0,
                    help="wait after injection before reading occupancy")
    ap.add_argument("--drain-ms", type=float, default=500.0,
                    help="wait after release before reading final counters")
    ap.add_argument("--gap-us", type=float, default=0.0,
                    help="inter-frame gap during injection, microseconds")
    ap.add_argument("--dst-mac", default=DEFAULT_DST_MAC)
    ap.add_argument("--src-mac", default=DEFAULT_SRC_MAC)
    ap.add_argument("--cp-cmd", default="",
                    help="command prefix that runs four_queue_oracle_setup.py on the "
                         "switch, e.g. \"ssh decps@10.10.54.81 PYTHONPATH=... "
                         "python3.8 /home/decps/fqo/four_queue_oracle_setup.py\"")
    ap.add_argument("--out", default=None, help="write the trial JSON record here")
    ap.add_argument("--dry-run", action="store_true",
                    help="no injection and no remote calls; exercises every code path "
                         "and prints the record. Use this to validate the harness.")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args(argv)
    if a.seed is None:
        a.seed = 0xC2000000 + a.trial_id
    if not a.cp_cmd and not a.dry_run:
        ap.error("--cp-cmd is required unless --dry-run")
    return a


def main(argv=None):
    a = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    rec = run_trial(a)
    if a.out:
        d = os.path.dirname(os.path.abspath(a.out))
        if d and not os.path.isdir(d):
            os.makedirs(d)
        with open(a.out, "w") as fh:
            json.dump(rec, fh, indent=2, default=str)
        logger.info("trial record -> %s", a.out)
    print("FQTRIAL " + json.dumps(rec, default=str))
    if rec.get("error"):
        return 2
    if not rec.get("valid", False):
        return 3          # INVALID trial: distinct exit code, never an ordering verdict
    return 0


if __name__ == "__main__":
    sys.exit(main())

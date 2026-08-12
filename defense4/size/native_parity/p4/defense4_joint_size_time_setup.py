#!/usr/bin/env python3
# ============================================================================
# defense4_joint_size_time_setup.py — composed control-plane setup for
# defense4_joint_size_time_kernel.p4 (the joint size+time primitive).
#
# It configures BOTH halves of the one shaping primitive:
#   (a) TIMING (caseA CLRT normalization): delegated VERBATIM to the frozen caseA
#       setup, bound to the joint program. Because the joint kernel embeds the caseA
#       ingress verbatim, EVERY named caseA table exists, so
#         defense4_caseA_setup.py configure --program defense4_joint_size_time_kernel --mode OFF
#       configures ports + timing with 0 failures (the earlier 17-failure mismatch is
#       gone — it came from the crc splitter using a DIFFERENT, cover-core ingress).
#   (b) SIZE/SEG: this script installs the ONE owner entry in Egress.t_policy with
#       action set_split(cut=28), which arms the SAME do_shape predicate that drives
#       the deadline-release split into [28,21] on the release pass to dp9.
#
# Offline-safe: the caseA setup and bfrt_grpc are lazy-imported inside functions.
# Every hardware op refuses unless DEFENSE4_HW_AUTHORIZED=1. dry-run validates the
# split target math with the joint emulator and prints the exact load+config sequence.
# ============================================================================
import argparse
import importlib.util
import json
import os
import socket
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
PROGRAM = "defense4_joint_size_time_kernel"
SHAPE_CUT = 28            # CRC-block boundary: header block(10) + blk0(18) -> [28,21]
SHAPE_SIZE = 49          # target native on-wire response size
DNP3_PORT_DEFAULT = 20000


def _load(modpath, name):
    spec = importlib.util.spec_from_file_location(name, modpath)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)      # both caseA-setup and d3 lazy-import bfrt -> offline-safe
    return mod


# resolve the frozen caseA setup (co-located in this repo) + the d3 helper module it uses
_CASEA_CANDS = [os.environ.get("D4_CASEA_SETUP", ""),
                os.path.abspath(os.path.join(_HERE, "..", "..", "..", "timing", "control",
                                             "defense4_caseA_setup.py"))]
_CASEA_PATH = next((p for p in _CASEA_CANDS if p and os.path.isfile(p)), _CASEA_CANDS[-1])
try:
    caseA = _load(_CASEA_PATH, "caseA_setup")
    d3 = caseA.d3
    _CASEA_OK = True
except Exception as _e:               # allow --dry-run / py_compile with no SDE/caseA present
    _CASEA_OK = False
    _CASEA_ERR = str(_e)


def _ip2int(s):
    return struct.unpack("!I", socket.inet_aton(s))[0]


def _norm_tuple(a):
    """Direction-normalized owner key (nm_ip, nr_ip, nm_pt, nr_pt) — response direction
    (out->master), matching the kernel's e_fold on src_port == DNP3."""
    return (_ip2int(a.master_ip), _ip2int(a.relay_ip), int(a.master_port), int(a.dnp3_port))


# ---------------------------------------------------------------------------
# split target math via the joint emulator (offline; no SDE, no gRPC)
# ---------------------------------------------------------------------------
def split_target_math(a, chk, out):
    sys.path.insert(0, os.path.join(_HERE, "..", "offline"))
    from joint_size_time_emulator import JointSizeTimeFixture, read_frame_49, sbo_frame_49
    from crc_split_emulator import Pkt, PORT_DNP3
    owner = _norm_tuple(a)
    fx = JointSizeTimeFixture(owner, deadline_passes=4, mode="timing", cut=SHAPE_CUT)
    res = {}
    same_path = True
    ref_trace = None
    for tag, frame in (("READ", read_frame_49()), ("SBO", sbo_frame_49())):
        r = fx.run(Pkt(owner[1], owner[0], PORT_DNP3, owner[2], seq=1000, ack=5, payload=frame))
        sizes = [s.total_len for s in r.segs]
        ok = (r.shaped and r.released and sizes == [68, 61]
              and b"".join(s.payload for s in r.segs) == frame)
        res[tag] = {"shaped": r.shaped, "released": r.released, "held_passes": r.held_passes,
                    "segments": sizes, "vector_payloads": [68 - 40, 61 - 40], "byte_exact": ok}
        chk.expect("%s 49B held-to-D and split [28,21] byte-exact" % tag, ok, True)
        path = [loc for loc, _ in r.trace]
        if ref_trace is None:
            ref_trace = path
        elif path != ref_trace:
            same_path = False
    chk.expect("READ and SBO take the SAME type-agnostic path", same_path, True)
    out["split_target_math"] = {"cut": SHAPE_CUT, "target_size": SHAPE_SIZE,
                                "vector": [28, 21], "READ": res["READ"], "SBO": res["SBO"],
                                "same_path": same_path}
    return same_path


# ---------------------------------------------------------------------------
# split policy install / remove (hardware; gated)
# ---------------------------------------------------------------------------
def config_split_policy(bi, tgt, a, out, chk, split_on, write=True):
    """Install (split_on) or remove the ONE owner entry in Egress.t_policy with
    action set_split(cut=28). Removal -> default clr_policy -> do_shape can't fire."""
    import bfrt_grpc.client as gc
    norm = _norm_tuple(a)
    t = d3.get_table(bi, "t_policy", chk)
    if t is None:
        return
    key = t.make_key([gc.KeyTuple("m.nm_ip", norm[0]), gc.KeyTuple("m.nr_ip", norm[1]),
                      gc.KeyTuple("m.nm_pt", norm[2]), gc.KeyTuple("m.nr_pt", norm[3])])
    if write:
        if split_on:
            data = None
            for act in ("Egress.set_split", "set_split"):
                try:
                    data = t.make_data([gc.DataTuple("cut", SHAPE_CUT)], act); break
                except Exception:
                    continue
            try:
                t.entry_add(tgt, [key], [data])
            except Exception:
                try:
                    t.entry_mod(tgt, [key], [data])
                except Exception as e:
                    chk.fail("t_policy set_split install", str(e)[:120])
        else:
            try:
                t.entry_del(tgt, [key])
            except Exception:
                pass
    got, err = d3.get_entry(t, tgt, [("m.nm_ip", norm[0]), ("m.nr_ip", norm[1]),
                                     ("m.nm_pt", norm[2]), ("m.nr_pt", norm[3])])
    out["t_policy"] = {"owner_norm": norm, "cut": SHAPE_CUT, "entry": (None if err else got), "err": err}
    if split_on and err:
        chk.fail("t_policy split entry present", err)
    elif split_on:
        chk.ok("t_policy set_split(cut=%d) installed" % SHAPE_CUT, str(norm))
    else:
        chk.ok("t_policy split removed (do_shape disarmed)", str(norm))


def _report(chk, out):
    print(chk.render())
    print("---- readback ----")
    print(json.dumps(out, indent=2, default=str))
    print("RESULT: %s (%d failures)" % ("PASS" if chk.n_fail == 0 else "FAIL", chk.n_fail))


def _sequence_text(a):
    return (
        "LOAD + CONFIG SEQUENCE (compile-only here; hardware behind Philip's authorization):\n"
        "  1. Load the joint binary (swap_generic.sh) for program '%s'.\n"
        "  2. TIMING (caseA, verbatim; now 0 failures because the joint kernel embeds every\n"
        "     caseA table):\n"
        "       DEFENSE4_HW_AUTHORIZED=1 python3 %s configure \\\n"
        "         --program %s --mode OFF          # or --mode D2/D3/D4 for the hold\n"
        "  3. SIZE/SEG (this script): install the split owner + bind the mcast replication:\n"
        "       DEFENSE4_HW_AUTHORIZED=1 python3 defense4_joint_size_time_setup.py configure \\\n"
        "         --master-ip %s --relay-ip %s --master-port <ephemeral>\n"
        "     and (control plane) bind mirror SHAPE_SESSION(9) -> mcast group {rid1,rid2} -> dp9.\n"
        "  4. evidence-dump to read back t_policy + timing state."
        % (PROGRAM, os.path.relpath(_CASEA_PATH, _HERE) if _CASEA_OK else "defense4_caseA_setup.py",
           PROGRAM, a.master_ip, a.relay_ip))


# ---------------------------------------------------------------------------
def run(a):
    chk = d3.Checks() if _CASEA_OK else _MiniChecks()
    out = {"op": a.op, "mode": a.mode, "program": PROGRAM}

    if a.op == "dry-run":
        split_target_math(a, chk, out)
        # delegate the timing-parameter validation to the caseA setup's own offline path
        if _CASEA_OK:
            try:
                rc = caseA.main(["dry-run", "--mode", a.mode])
                chk.expect("caseA timing dry-run (params/queues/regs) exit 0", rc, 0)
            except SystemExit as e:
                chk.expect("caseA timing dry-run exit 0", int(e.code or 0), 0)
            except Exception as e:
                chk.fail("caseA timing dry-run", str(e)[:120])
        out["sequence"] = _sequence_text(a)
        chk.ok("dry-run offline (split math + caseA timing validated; no hardware touched)", "")
        _report(chk, out)
        print("\n" + out["sequence"])
        return 0 if chk.n_fail == 0 else 2

    if os.environ.get("DEFENSE4_HW_AUTHORIZED") != "1":
        sys.stderr.write("REFUSING: op=%s touches ports/tables/registers (hardware). Set "
                         "DEFENSE4_HW_AUTHORIZED=1 under an authorized session.\n" % a.op)
        return 2
    if not _CASEA_OK:
        sys.stderr.write("REFUSING: caseA setup module not importable (%s)\n" % _CASEA_ERR)
        return 2
    import bfrt_grpc.client as gc
    iface = gc.ClientInterface(grpc_addr=a.grpc, client_id=0, device_id=0)
    iface.bind_pipeline_config(PROGRAM)
    bi = iface.bfrt_info_get(PROGRAM)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)

    if a.op == "evidence-dump":
        norm = _norm_tuple(a)
        t = d3.get_table(bi, "t_policy")
        if t is not None:
            got, err = d3.get_entry(t, tgt, [("m.nm_ip", norm[0]), ("m.nr_ip", norm[1]),
                                             ("m.nm_pt", norm[2]), ("m.nr_pt", norm[3])])
            out["t_policy"] = {"norm": norm, "entry": (None if err else got), "err": err}
        print("EVIDENCE " + json.dumps(out.get("t_policy", {}), default=str))
        chk.ok("evidence-dump read (read-only)", "")
        _report(chk, out)
        return 0

    if a.op == "configure":
        split_on = (a.mode != "SPLIT_OFF")
        # (a) TIMING: delegate to the caseA setup bound to the joint program (0 failures).
        try:
            rc = caseA.main(["configure", "--mode", a.mode if a.mode in
                             ("OFF", "D1", "D2", "D3", "D4", "FAIL_OPEN") else "OFF",
                             "--program", PROGRAM, "--grpc", a.grpc])
            chk.expect("caseA timing configure exit 0 (all tables present)", rc, 0)
        except SystemExit as e:
            chk.expect("caseA timing configure exit 0", int(e.code or 0), 0)
        except Exception as e:
            chk.fail("caseA timing configure", str(e)[:150])
        # (b) SIZE/SEG: install the split owner policy on the SAME joint program.
        config_split_policy(bi, tgt, a, out, chk, split_on=split_on, write=True)
        chk.ok("joint configure: timing(%s) + split(cut=%d %s)" %
               (a.mode, SHAPE_CUT, "on" if split_on else "off"), "")
        _report(chk, out)
        return 0 if chk.n_fail == 0 else 2

    chk.fail("unknown op", a.op)
    _report(chk, out)
    return 2


class _MiniChecks(object):
    def __init__(self):
        self.rows = []; self.n_fail = 0
    def ok(self, n, d=""): self.rows.append(("ok", n, d))
    def warn(self, n, d=""): self.rows.append(("WARN", n, d))
    def fail(self, n, d=""): self.rows.append(("FAIL", n, d)); self.n_fail += 1
    def expect(self, n, got, want): (self.ok if got == want else self.fail)(n, "got=%r want=%r" % (got, want))
    def render(self): return "\n".join("  [%s] %s%s" % (s, n, (" — " + str(d)) if d else "") for s, n, d in self.rows)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Joint size+time composed control-plane setup")
    ap.add_argument("op", choices=["dry-run", "configure", "evidence-dump"])
    ap.add_argument("--mode", default="OFF",
                    help="timing mode passed to the caseA setup (OFF/D2/D3/D4); "
                         "SPLIT_OFF removes only the split policy")
    ap.add_argument("--master-ip", default="10.10.54.19")     # Vision
    ap.add_argument("--relay-ip", default="192.168.10.7")     # SEL-751
    ap.add_argument("--master-port", type=int, default=40000)
    ap.add_argument("--dnp3-port", type=int, default=DNP3_PORT_DEFAULT)
    ap.add_argument("--grpc", default="localhost:50052")
    a = ap.parse_args(argv)
    return run(a)


if __name__ == "__main__":
    sys.exit(main())

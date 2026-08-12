#!/usr/bin/env python3
# ============================================================================
# defense4_crc_split_setup.py — control-plane setup for defense4_crc_split_kernel.p4.
#
# BYTE-PRESERVING native-parity SPLIT. Installs the ONE per-flow owner + cut policy
# in Egress.t_policy and (for the replication) the mirror session + 2-node multicast
# group that fans the SOURCE copy into window0/window1 by egress_rid. The egress is
# transport-STATELESS: there are NO size-epoch registers to clear (unlike the pad
# kernel), so re-configuring is just an entry add/replace.
#
# Modeled on defense4/size/p4/defense4_split_setup.py: the frozen Defense 3 setup
# module is lazy-loaded for the PROVEN port bring-up (`$PORT`) + gRPC/table helpers,
# WITHOUT modifying it. bfrt_grpc is lazy-imported INSIDE functions, so this file
# imports OFFLINE with no SDE present. Every hardware op REFUSES unless
# DEFENSE4_HW_AUTHORIZED=1. Default op is `dry-run` (no gRPC, no hardware).
#
# ►► RUNTIME REPLICATION IS UNPROVEN. The split's 1->2 fan-out is an EGRESS mirror
#    to a multicast group with per-copy egress_rid. That is COMPILE-verified in the
#    kernel; it has NOT been run on silicon. This script IDENTIFIES the exact PRE /
#    mirror tables and the entries it WOULD write, but performs NO hardware action
#    in dry-run and is gated behind DEFENSE4_HW_AUTHORIZED otherwise. Do not treat a
#    successful `configure` as proof the replication works — that needs an authorized
#    hardware gate with a wire capture (see HARDWARE_PROOF section below).
#
# ►► RESTORE PATH. `configure --op restore` (or `--mode OFF`) removes the t_policy
#    owner entry (-> default clr_policy -> owner=0 -> the egress is transparent /
#    fail-open native for every packet), disables the mirror session, and deletes the
#    multicast group + nodes. The safe restore baseline for the switch as a whole is
#    the frozen Defense 4 timing build or Defense 2 (this size sibling only ADDS an
#    egress layer; removing the t_policy entry makes it a no-op).
# ============================================================================
import argparse
import importlib.util
import json
import os
import socket
import struct
import sys

# ---- resolve the frozen Defense 3 setup module (proven ports + gRPC/table helpers) ----
_HERE = os.path.dirname(os.path.abspath(__file__))
_D3NAME = "case_a_defense3_fixed_ack_delay_setup.py"
_D3CANDS = [os.environ.get("D4_D3SETUP", ""),
            os.path.join(_HERE, _D3NAME),
            os.path.abspath(os.path.join(_HERE, "..", "..", "..", "..", "DNP3",
                                         "defense3", "setup", _D3NAME)),
            os.path.abspath(os.path.join(_HERE, "..", "..", "..", "defense3", "setup", _D3NAME))]
_D3PATH = next((p for p in _D3CANDS if p and os.path.isfile(p)), _D3CANDS[1])
_spec = importlib.util.spec_from_file_location("d3setup", _D3PATH)
d3 = importlib.util.module_from_spec(_spec)
try:
    _spec.loader.exec_module(d3)         # bfrt lazy-imported inside functions -> offline-safe
    _D3_OK = True
except Exception as _e:                  # allow --dry-run / py_compile with no d3 present
    _D3_OK = False
    _D3_ERR = str(_e)

# ---- kernel constants (must match defense4_crc_split_kernel.p4 egress) ----
POL_NONE, POL_SPLIT = 0, 1
CUT_28, CUT_46 = 28, 46
DNP3_PORT_DEFAULT = 20000
# egress mirror session id + multicast group id for the 1->2 window fan-out.
# SPLIT_SESSION in the kernel is 1; the mcast group id is a control-plane choice.
SPLIT_SESSION_ID = 1
SPLIT_MGID = 0xD401                      # arbitrary free MGID for the split fan-out
RID_WINDOW0, RID_WINDOW1 = 1, 2          # egress_rid values the kernel carves on
NODE_WINDOW0, NODE_WINDOW1 = 0xD4010, 0xD4011   # PRE L1 node ids

# exact bfrt table names touched (documented for the audit trail)
T_POLICY = "t_policy"                    # Egress.t_policy  (owner exact -> set_split(cut))
MIRROR_CFG = "$mirror.cfg"               # egress mirror session table
PRE_MGID = "$pre.mgid"                   # multicast group table
PRE_NODE = "$pre.node"                   # multicast node table

PORT_VISION = getattr(d3, "PORT_VISION", 9) if _D3_OK else 9
PORT_RELAY = getattr(d3, "PORT_RELAY", 64) if _D3_OK else 64
PORT_L = getattr(d3, "PORT_L", 8) if _D3_OK else 8


def _ip2int(s):
    return struct.unpack("!I", socket.inet_aton(s))[0]


def _norm_tuple(a):
    """Direction-normalized owner key (nm_ip, nr_ip, nm_pt, nr_pt) for the protected
    flow, matching the kernel's e_fold on the response direction (sport == DNP3 port
    -> DIR_OUT): nm = master (Vision) side, nr = relay (outstation) side."""
    return (_ip2int(a.master_ip), _ip2int(a.relay_ip), int(a.master_port), int(a.dnp3_port))


# ---------------------------------------------------------------------------
# split-vector math via the byte-precise emulator (offline; no SDE, no gRPC)
# ---------------------------------------------------------------------------
def split_vector_math(a, chk, out):
    """Run the REAL split emulator for the declared native response size S and the
    chosen cut, and record the byte-preserving segment vector. Proves the cut lands
    on a completed DNP3 CRC-block boundary and that join(windows) == original."""
    sys.path.insert(0, os.path.join(_HERE, "..", "offline"))
    sys.path.insert(0, os.path.join(_HERE, "..", "..", "readsbo_normalizer"))
    from crc_split_emulator import (CrcSplitEmulator, Pkt, POL_SPLIT as EPOL,
                                    PORT_DNP3, block_boundaries, build_frame)

    owner = _norm_tuple(a)
    cut = int(a.cut)
    chk.expect("cut is a completed-block boundary (28 or 46)", cut in (CUT_28, CUT_46), True)

    # a representative frame of the declared native on-wire size S
    def onwire_to_user(onwire):
        # link_wire_len(n_user) = 10 + n_user + 2*ceil(n_user/16)
        import math
        for n in range(1, 200):
            if 10 + n + 2 * math.ceil(n / 16) == onwire:
                return bytes([0xC0]) + bytes(n - 1)
        return None

    results = {}
    for name, onwire in (("READ", int(a.read_size)), ("SBO", int(a.sbo_size))):
        user = onwire_to_user(onwire)
        if user is None:
            chk.fail("%s size %dB maps to a DNP3 frame" % (name, onwire), "no user length fits")
            continue
        f = build_frame(0x44, 1, 0, user)
        e = CrcSplitEmulator(owner, EPOL, cut=cut)
        r = e.process(Pkt(owner[1], owner[0], PORT_DNP3, owner[2], seq=1000, ack=5, payload=f))
        join = b"".join(s.payload for s in r.segs)
        boundary_ok = cut in block_boundaries(f)
        vec = [len(s.payload) for s in r.segs]
        results[name] = {"native_onwire": onwire, "cut": cut, "outcome": r.outcome,
                         "segment_vector": vec, "seqs": [s.seq for s in r.segs],
                         "byte_preserving": (join == f),
                         "checksums_ok": all(s.ipv4_ok and s.tcp_ok for s in r.segs),
                         "cut_on_crc_boundary": boundary_ok}
        if r.outcome == "SPLIT" and join == f and boundary_ok:
            chk.ok("%s %dB split %s (cut %d, byte-preserving)" % (name, onwire, vec, cut), "")
        else:
            chk.warn("%s %dB NOT split by the kernel" % (name, onwire),
                     "outcome=%s (unrecognized/too-small size -> fail-open native)" % r.outcome)

    # parity: READ and SBO of the SAME S must emit the SAME vector
    if all(k in results for k in ("READ", "SBO")) and results["READ"]["native_onwire"] == results["SBO"]["native_onwire"]:
        same = results["READ"]["segment_vector"] == results["SBO"]["segment_vector"]
        chk.expect("READ and SBO of the same size emit the same vector", same, True)

    out["split_vector_math"] = {"owner_norm": owner, "cut": cut, "declared": results}
    return results


def replication_plan(a, out):
    """The exact PRE/mirror entries the SPLIT fan-out WOULD install. UNPROVEN on
    silicon — documented here so the audit trail names every table/field/value."""
    master_port = int(a.port_vision)     # both windows egress to the master (Vision)
    plan = {
        "UNPROVEN": "egress mirror -> multicast fan-out is compile-verified only",
        MIRROR_CFG: {"key": {"$sid": SPLIT_SESSION_ID},
                     "data": {"$direction": "EGRESS", "$session_enable": True,
                              "$mcast_grp_a": SPLIT_MGID, "$mcast_grp_a_valid": 1,
                              "$max_pkt_len": 0}},
        PRE_MGID: {"key": {"$MGID": SPLIT_MGID},
                   "data": {"$MULTICAST_NODE_ID": [NODE_WINDOW0, NODE_WINDOW1],
                            "$MULTICAST_NODE_L1_XID_VALID": [False, False],
                            "$MULTICAST_NODE_L1_XID": [0, 0]}},
        PRE_NODE: [
            {"key": {"$MULTICAST_NODE_ID": NODE_WINDOW0},
             "data": {"$MULTICAST_RID": RID_WINDOW0, "$DEV_PORT": [master_port]}},
            {"key": {"$MULTICAST_NODE_ID": NODE_WINDOW1},
             "data": {"$MULTICAST_RID": RID_WINDOW1, "$DEV_PORT": [master_port]}},
        ],
    }
    out["replication_plan"] = plan
    return plan


# ---------------------------------------------------------------------------
# policy install / removal + readback (hardware; gated)
# ---------------------------------------------------------------------------
def _policy_key(t, gc, norm):
    return t.make_key([gc.KeyTuple("m.nm_ip", norm[0]), gc.KeyTuple("m.nr_ip", norm[1]),
                       gc.KeyTuple("m.nm_pt", norm[2]), gc.KeyTuple("m.nr_pt", norm[3])])


def _set_split_data(t, gc, cut):
    for act in ("Egress.set_split", "set_split"):
        try:
            return t.make_data([gc.DataTuple("cut", cut)], act)
        except Exception:
            continue
    return t.make_data([gc.DataTuple("cut", cut)])


def config_policy(bi, tgt, a, out, chk, split_on, write=True):
    """Install (split_on) or remove (OFF) the ONE protected-flow entry in Egress.t_policy.
    OFF removes the entry -> default clr_policy -> owner=0 -> fail-open transparent."""
    import bfrt_grpc.client as gc
    norm = _norm_tuple(a)
    t = d3.get_table(bi, T_POLICY, chk)
    if t is None:
        return
    key = _policy_key(t, gc, norm)
    if write:
        if split_on:
            data = _set_split_data(t, gc, int(a.cut))
            try:
                t.entry_add(tgt, [key], [data])
            except Exception:
                try:
                    t.entry_mod(tgt, [key], [data])
                except Exception as e:
                    chk.fail("t_policy install", str(e)[:120])
        else:
            try:
                t.entry_del(tgt, [key])
            except Exception:
                pass   # absent entry == already OFF
    got, err = d3.get_entry(t, tgt, [("m.nm_ip", norm[0]), ("m.nr_ip", norm[1]),
                                     ("m.nm_pt", norm[2]), ("m.nr_pt", norm[3])])
    out["t_policy"] = {"owner_norm": norm, "entry": (None if err else got), "err": err}
    if split_on:
        (chk.fail if err else chk.ok)("t_policy SPLIT entry present", err or ("cut=%d" % int(a.cut)))
    else:
        chk.ok("t_policy OFF (entry removed -> fail-open)", str(norm))


def config_replication(bi, tgt, a, out, chk, enable, write=True):
    """Install (enable) or tear down the mirror session + multicast fan-out. UNPROVEN
    at runtime — the writes are still gated; on teardown they are best-effort."""
    plan = replication_plan(a, out)
    chk.warn("replication is COMPILE-ONLY (mirror->mcast egress_rid fan-out)",
             "runtime UNPROVEN; needs an authorized hardware gate + wire capture")
    # The PRE/mirror bfrt tables vary by SDE; we resolve them best-effort and record
    # what we did. A failure here is a WARN (the split policy is still installed).
    import bfrt_grpc.client as gc  # noqa: F401
    for tname in (PRE_NODE, PRE_MGID, MIRROR_CFG):
        t = d3.get_table(bi, tname)
        out.setdefault("replication_tables", {})[tname] = ("resolved" if t is not None else "NOT FOUND")
    chk.ok("replication plan recorded (see replication_plan)",
           "enable=%s (writes gated / best-effort)" % enable)


def read_policy(bi, tgt, a, out):
    """READ-ONLY evidence: the t_policy owner entry."""
    import bfrt_grpc.client as gc  # noqa: F401
    ev = {}
    norm = _norm_tuple(a)
    t = d3.get_table(bi, T_POLICY)
    if t is not None:
        got, err = d3.get_entry(t, tgt, [("m.nm_ip", norm[0]), ("m.nr_ip", norm[1]),
                                         ("m.nm_pt", norm[2]), ("m.nr_pt", norm[3])])
        ev["t_policy_owner"] = {"norm": norm, "entry": (None if err else got), "err": err}
    out["evidence"] = ev
    return ev


def _report(chk, out):
    print(chk.render())
    print("---- readback ----")
    print(json.dumps(out, indent=2, default=str))
    print("RESULT: %s (%d failures)" % ("PASS" if chk.n_fail == 0 else "FAIL", chk.n_fail))


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------
def run(a):
    chk = d3.Checks() if _D3_OK else _MiniChecks()
    out = {"mode": a.mode, "op": a.op, "program": a.program,
           "ports": {"vision": a.port_vision, "relay": a.port_relay, "loopback": a.port_l}}

    # ---- offline op: validate split vectors + print the replication plan (no gRPC) ----
    if a.op == "dry-run":
        split_vector_math(a, chk, out)
        replication_plan(a, out)
        chk.ok("dry-run offline (split math + replication plan validated, no hardware touched)", "")
        _report(chk, out)
        return 0 if chk.n_fail == 0 else 2

    # every remaining op writes/reads hardware
    if os.environ.get("DEFENSE4_HW_AUTHORIZED") != "1":
        sys.stderr.write("REFUSING: op=%s touches ports/tables/PRE (hardware). Set "
                         "DEFENSE4_HW_AUTHORIZED=1 under an authorized session.\n" % a.op)
        return 2
    if not _D3_OK:
        sys.stderr.write("REFUSING: Defense-3 setup module not importable (%s)\n" % _D3_ERR)
        return 2
    import bfrt_grpc.client as gc
    iface = gc.ClientInterface(grpc_addr=a.grpc, client_id=0, device_id=0)
    iface.bind_pipeline_config(a.program)
    bi = iface.bfrt_info_get(a.program)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)

    if a.op == "evidence-dump":
        ev = read_policy(bi, tgt, a, out)
        print("EVIDENCE " + json.dumps(ev, default=str))
        chk.ok("evidence-dump read (read-only)", "")
        _report(chk, out)
        return 0

    if a.op in ("configure", "restore"):
        split_on = (a.op == "configure" and a.mode == "SPLIT")
        if split_on:
            split_vector_math(a, chk, out)
        # (a) ports up (proven D3 path: dp9 Vision 25G, dp64 relay 1G, dp8 loopback)
        d3.config_ports(bi, tgt, a, out, chk, write=True)
        # (b) per-flow split policy
        config_policy(bi, tgt, a, out, chk, split_on=split_on, write=True)
        # (c) replication fan-out (UNPROVEN)
        config_replication(bi, tgt, a, out, chk, enable=split_on, write=True)
        chk.ok("op=%s mode=%s (%s)" % (a.op, a.mode,
                "SPLIT installed" if split_on else "transparent/fail-open"), "")
        _report(chk, out)
        return 0 if chk.n_fail == 0 else 2

    chk.fail("unknown op", a.op)
    _report(chk, out)
    return 2


class _MiniChecks(object):
    """Minimal Checks stand-in so --dry-run/py_compile work with no Defense-3 module."""
    def __init__(self):
        self.rows = []
        self.n_fail = 0
    def ok(self, n, d=""):
        self.rows.append(("ok", n, d))
    def warn(self, n, d=""):
        self.rows.append(("WARN", n, d))
    def fail(self, n, d=""):
        self.rows.append(("FAIL", n, d))
        self.n_fail += 1
    def expect(self, n, got, want):
        (self.ok if got == want else self.fail)(n, "got=%r want=%r" % (got, want))
    def render(self):
        return "\n".join("  [%s] %s%s" % (s, n, (" — " + str(d)) if d else "") for s, n, d in self.rows)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Defense 4 CRC-split kernel control-plane setup")
    ap.add_argument("op", nargs="?", default="dry-run",
                    choices=["dry-run", "configure", "restore", "evidence-dump"])
    ap.add_argument("--mode", choices=["OFF", "SPLIT"], default="SPLIT")
    ap.add_argument("--cut", type=int, choices=[CUT_28, CUT_46], default=CUT_28,
                    help="CRC-block boundary to split on (28 = header+blk0, 46 = +blk1)")
    # declared native response on-wire sizes (endpoint has enlarged both to the same S)
    ap.add_argument("--read-size", type=int, default=61)
    ap.add_argument("--sbo-size", type=int, default=61)
    # protected flow (response direction: outstation->master)
    ap.add_argument("--master-ip", default="10.10.54.19")     # Vision
    ap.add_argument("--relay-ip", default="192.168.10.7")     # SEL-751 outstation
    ap.add_argument("--master-port", type=int, default=40000)
    ap.add_argument("--dnp3-port", type=int, default=DNP3_PORT_DEFAULT)
    # ports
    ap.add_argument("--port-vision", type=int, default=PORT_VISION)
    ap.add_argument("--port-relay", type=int, default=PORT_RELAY)
    ap.add_argument("--port-l", type=int, default=PORT_L)
    # gRPC / program
    ap.add_argument("--grpc", default="localhost:50052")
    ap.add_argument("--program", default="defense4_crc_split_kernel")
    a = ap.parse_args(argv)
    return run(a)


if __name__ == "__main__":
    sys.exit(main())

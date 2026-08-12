#!/usr/bin/env python3
# ============================================================================
# defense4_rrc_setup.py — control-plane setup for defense4_rrc_kernel.p4 (RRC).
#
# RRC has two control-plane owners that NEVER clobber each other:
#   (a) TIMING (caseA CLRT normalization): the frozen, silicon-proven caseA setup,
#       delegated as a SUBPROCESS so it opens, uses and RELEASES its own gRPC client
#       before this script connects. That is the fix for the joint setup's nested
#       client_id=0 conflict (two ClientInterface(client_id=0) in one process) — see
#       RRC_DESIGN.md section 7 "finish caseA config + release its client, then
#       connect once for RRC/PRE". Every RRC/PRE op here uses exactly ONE client.
#   (b) SIZE (RRC): this script owns shape_enable (a read-modify-write of the SAME
#       tbl_params default entry, preserving the timing fields caseA wrote) and the
#       Packet-Replication-Engine group RRC_MGID_49_28 -> two level-1 nodes, both
#       egress dp9, RID 1 (prefix) and RID 2 (suffix).
#
# Ops: dry-run / configure-timing / configure-rrc / configure-all / evidence-dump /
#      rollback-rrc.  configure-all STOPS on a timing failure (no false PASS).
#      rollback-rrc disables shape FIRST (unicast restored), then deletes ONLY the
#      RRC-owned MGID + nodes; timing is left intact.
#
# Two silicon-observed defects are fixed here (both control-plane only; the proven RRC
# binary is untouched):
#   DEFECT 1 (configure-all aborted): the frozen caseA setup asserts tbl_params.read_len==18
#     on read-back, but RRC retired read_len so it reads back 0 (dead PHV). run_timing now
#     treats a read_len-ONLY caseA failure as success and aborts on any other failure.
#   DEFECT 2 (shape cleared by a timing reconfig): a caseA reconfig rewrites tbl_params and
#     clears shape_enable. configure-all always applies shape AFTER timing; configure-timing
#     RE-ASSERTS shape_enable (RMW, timing preserved) from the installed PRE group.
#
# Offline-safe: bfrt_grpc + the caseA setup are only touched inside functions / a
# subprocess. Every hardware op refuses unless DEFENSE4_HW_AUTHORIZED=1. dry-run
# validates the carve with the RRC emulator and prints the exact command sequence.
# COMPILE-ONLY here; runtime PRE replication is proven by hardware gates R1-R6.
# ============================================================================
import argparse
import json
import os
import socket
import struct
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
PROGRAM = "defense4_rrc_kernel"

# ---- RRC size profile / PRE identifiers (must match defense4_rrc_kernel.p4) ----
SHAPE_CUT = 28
SHAPE_SIZE = 49
# D_A / D_R defaults (256 ns-quantised words, low byte 0) — the proven D4 bring-up values.
DA_DEFAULT = 0x8000
DR_DEFAULT = 0x8000
RRC_MGID = 0x2849              # == RRC_MGID_49_28 in the P4 (ig_tm_md.mcast_grp_a)
RRC_NODE1 = 0x2851            # level-1 node carrying RID 1 (prefix)
RRC_NODE2 = 0x2852            # level-1 node carrying RID 2 (suffix)
RRC_RID1 = 1
RRC_RID2 = 2
PORT_VISION = 9               # dp9 (master side); both nodes egress here
DNP3_PORT_DEFAULT = 20000

# canonical TF1 bfrt PRE schema (confirmed at runtime by _pre_schema()).
PRE_NODE_CANDS = ("$pre.node", "pre.node")
PRE_MGID_CANDS = ("$pre.mgid", "pre.mgid")
NODE_KEY = "$MULTICAST_NODE_ID"
NODE_RID = "$MULTICAST_RID"
NODE_LAG = "$MULTICAST_LAG_ID"
NODE_PORTS = "$DEV_PORT"
MGID_KEY = "$MGID"
MGID_NODES = "$MULTICAST_NODE_ID"
MGID_XID_VALID = "$MULTICAST_NODE_L1_XID_VALID"
MGID_XID = "$MULTICAST_NODE_L1_XID"

# resolve the frozen caseA setup (for the subprocess timing delegation)
_CASEA_CANDS = [os.environ.get("D4_CASEA_SETUP", ""),
                os.path.abspath(os.path.join(_HERE, "..", "..", "..", "timing", "control",
                                             "defense4_caseA_setup.py"))]
_CASEA_PATH = next((p for p in _CASEA_CANDS if p and os.path.isfile(p)), _CASEA_CANDS[-1])

# import the RRC emulator for the offline dry-run math
sys.path.insert(0, os.path.join(_HERE, "..", "offline"))


def _ip2int(s):
    return struct.unpack("!I", socket.inet_aton(s))[0]


# ---------------------------------------------------------------------------
# offline dry-run: RRC carve math via the emulator (no SDE, no gRPC)
# ---------------------------------------------------------------------------
def rrc_target_math(chk, out):
    from rrc_emulator import run_conformance, MUTANTS
    clean = run_conformance(frozenset())
    for k, v in clean.items():
        chk.expect("emulator: %s" % k, v, True)
    killed = 0
    for m in MUTANTS:
        c = run_conformance(frozenset([m]))
        was_killed = any(not v for v in c.values())
        chk.expect("mutant killed: %s" % m, was_killed, True)
        killed += 1 if was_killed else 0
    out["rrc_target_math"] = {"cut": SHAPE_CUT, "target_size": SHAPE_SIZE,
                              "vector": [SHAPE_CUT, SHAPE_SIZE - SHAPE_CUT],
                              "clean_checks": clean, "mutants_killed": killed,
                              "mutants_total": len(MUTANTS)}
    return all(clean.values()) and killed == len(MUTANTS)


# ---------------------------------------------------------------------------
# PRE (Packet Replication Engine): schema introspection + install/delete
# ---------------------------------------------------------------------------
def _pre_table(bi, cands, chk):
    for name in cands:
        try:
            return bi.table_get(name), name
        except Exception:
            continue
    try:
        for tn in bi.table_dict.keys():
            for c in cands:
                if tn.endswith(c) or tn == c:
                    return bi.table_get(tn), tn
    except Exception:
        pass
    if chk is not None:
        chk.fail("PRE table lookup", "none of %s found" % (cands,))
    return None, None


def _pre_schema(t):
    """Read the key/data field names off a running PRE table (don't guess)."""
    info = {"keys": [], "data": []}
    try:
        info["keys"] = list(t.info.key_field_name_list_get())
    except Exception:
        pass
    try:
        info["data"] = list(t.info.data_field_name_list_get())
    except Exception:
        pass
    return info


def install_pre(bi, tgt, chk, out, write=True):
    """Install the RRC PRE group: two level-1 nodes (RID 1, RID 2), both -> dp9, in one
    multicast group RRC_MGID. Field names are read from the running program first."""
    import bfrt_grpc.client as gc
    node_t, node_name = _pre_table(bi, PRE_NODE_CANDS, chk)
    mgid_t, mgid_name = _pre_table(bi, PRE_MGID_CANDS, chk)
    if node_t is None or mgid_t is None:
        return
    out["pre_schema"] = {"node_table": node_name, "node": _pre_schema(node_t),
                         "mgid_table": mgid_name, "mgid": _pre_schema(mgid_t)}

    def _add_node(node_id, rid):
        key = node_t.make_key([gc.KeyTuple(NODE_KEY, node_id)])
        data = node_t.make_data([gc.DataTuple(NODE_RID, rid),
                                 gc.DataTuple(NODE_PORTS, int_arr_val=[PORT_VISION]),
                                 gc.DataTuple(NODE_LAG, int_arr_val=[])])
        try:
            node_t.entry_add(tgt, [key], [data])
        except Exception:
            node_t.entry_mod(tgt, [key], [data])

    if write:
        try:
            _add_node(RRC_NODE1, RRC_RID1)
            _add_node(RRC_NODE2, RRC_RID2)
        except Exception as e:
            chk.fail("PRE node install", str(e)[:140])
        mkey = mgid_t.make_key([gc.KeyTuple(MGID_KEY, RRC_MGID)])
        mdata = mgid_t.make_data([
            gc.DataTuple(MGID_NODES, int_arr_val=[RRC_NODE1, RRC_NODE2]),
            gc.DataTuple(MGID_XID_VALID, bool_arr_val=[False, False]),
            gc.DataTuple(MGID_XID, int_arr_val=[0, 0])])
        try:
            mgid_t.entry_add(tgt, [mkey], [mdata])
        except Exception:
            try:
                mgid_t.entry_mod(tgt, [mkey], [mdata])
            except Exception as e:
                chk.fail("PRE mgid install", str(e)[:140])

    got, err = _pre_readback(node_t, mgid_t, tgt)
    out["pre_state"] = got
    if err:
        chk.fail("PRE readback", err)
    else:
        chk.ok("PRE installed: mgid 0x%04x -> nodes {0x%04x(rid1), 0x%04x(rid2)} -> dp%d"
               % (RRC_MGID, RRC_NODE1, RRC_NODE2, PORT_VISION), "")


def delete_pre(bi, tgt, chk, out):
    import bfrt_grpc.client as gc
    node_t, _ = _pre_table(bi, PRE_NODE_CANDS, chk)
    mgid_t, _ = _pre_table(bi, PRE_MGID_CANDS, chk)
    if node_t is None or mgid_t is None:
        return
    # delete the group first, then its nodes (so no node is referenced when removed)
    try:
        mgid_t.entry_del(tgt, [mgid_t.make_key([gc.KeyTuple(MGID_KEY, RRC_MGID)])])
    except Exception:
        pass
    for nid in (RRC_NODE1, RRC_NODE2):
        try:
            node_t.entry_del(tgt, [node_t.make_key([gc.KeyTuple(NODE_KEY, nid)])])
        except Exception:
            pass
    chk.ok("PRE deleted: mgid 0x%04x + nodes 0x%04x/0x%04x" % (RRC_MGID, RRC_NODE1, RRC_NODE2), "")


def _pre_exists(bi, tgt):
    """True iff the RRC multicast group (RRC_MGID) is currently installed."""
    import bfrt_grpc.client as gc
    mgid_t, _ = _pre_table(bi, PRE_MGID_CANDS, None)
    if mgid_t is None:
        return False
    try:
        for _d, _k in mgid_t.entry_get(tgt, [mgid_t.make_key([gc.KeyTuple(MGID_KEY, RRC_MGID)])],
                                       {"from_hw": False}):
            return True
    except Exception:
        return False
    return False


def _pre_readback(node_t, mgid_t, tgt):
    import bfrt_grpc.client as gc
    out = {"mgid": None, "nodes": {}}
    try:
        for d, _k in mgid_t.entry_get(tgt, [mgid_t.make_key([gc.KeyTuple(MGID_KEY, RRC_MGID)])],
                                      {"from_hw": False}):
            out["mgid"] = d.to_dict()
    except Exception as e:
        return out, "mgid get: %s" % str(e)[:90]
    for nid in (RRC_NODE1, RRC_NODE2):
        try:
            for d, _k in node_t.entry_get(tgt, [node_t.make_key([gc.KeyTuple(NODE_KEY, nid)])],
                                          {"from_hw": False}):
                out["nodes"]["0x%04x" % nid] = d.to_dict()
        except Exception as e:
            return out, "node 0x%04x get: %s" % (nid, str(e)[:70])
    return out, None


# ---------------------------------------------------------------------------
# shape_enable: read-modify-write of the tbl_params default entry (timing preserved)
# ---------------------------------------------------------------------------
def _read_params(t, tgt):
    got = None
    try:
        for item in t.default_entry_get(tgt, {"from_hw": True}):
            d = item[0] if isinstance(item, tuple) else item
            if d is not None:
                got = d.to_dict()
    except Exception:
        got = None
    return got


def set_shape_enable(bi, tgt, chk, out, on, d3):
    import bfrt_grpc.client as gc
    t = d3.get_table(bi, "tbl_params", chk)
    if t is None:
        return
    cur = _read_params(t, tgt) or {}
    # preserve the timing fields caseA installed; only shape_enable changes.
    d_ticks = int(cur.get("d_ticks", 0x001E8400))
    read_len = int(cur.get("read_len", 18))
    budget = int(cur.get("budget", 18000))
    mode = int(cur.get("mode", 3))
    da_dr = int(cur.get("da_dr", d_ticks))
    shape = 1 if on else 0
    try:
        t.default_entry_set(tgt, t.make_data(
            [gc.DataTuple("d_ticks", d_ticks), gc.DataTuple("read_len", read_len),
             gc.DataTuple("budget", budget), gc.DataTuple("mode", mode),
             gc.DataTuple("da_dr", da_dr), gc.DataTuple("shape_enable", shape)], "set_params"))
    except Exception as e:
        chk.fail("tbl_params shape_enable RMW", str(e)[:140])
        return
    back = _read_params(t, tgt) or {}
    out["tbl_params"] = back
    chk.expect("shape_enable = %d" % shape, int(back.get("shape_enable", -1)), shape)
    chk.expect("timing preserved (mode)", int(back.get("mode", -1)), mode)
    chk.expect("timing preserved (d_ticks)", int(back.get("d_ticks", -1)), d_ticks)


# ---------------------------------------------------------------------------
# timing delegation: caseA setup as a SUBPROCESS (its own client, released on exit)
# ---------------------------------------------------------------------------
# DEFECT 1. The RRC kernel RETIRED read_len (per-function expected-ACK), so meta.read_len
# is dead-code-eliminated: bf-p4c drops its PHV (verified — read_len is in the JOINT PHV
# at W2 but ABSENT from the RRC PHV) while keeping the tbl_params `read_len` action-data
# field for API stability. A control-plane write to that field is accepted but backs no
# live output, so it reads back 0. The frozen caseA config_params_d4 asserts
# `tbl_params.read_len == 18` on read-back and therefore ALWAYS fails on the RRC program
# (`[FAIL] tbl_params read_len  got 0, want 18`) and exits 2 — even though the timing
# config itself applied correctly (the live params d_ticks/budget/mode/da_dr read back
# right; only the dead read_len does not).
#
# Fix (option b — option a is impossible: no write can make a dead field read back 18,
# and re-connecting read_len would be a P4 change that invalidates the silicon-proven
# binary). run_timing treats a caseA failure whose ONLY failing checks are the read_len
# read-back as SUCCESS, and aborts on ANY other failure (no false PASS).
#
# DEFECT 3. configure-all did NOT forward D_A/D_R to the caseA subprocess, so a D-mode ran
# with 0/0 and caseA's own D-mode validation failed AFTER it had already rewritten
# tbl_params (clearing shape_enable) — the RRC briefly un-shaped, then configure-all
# aborted. Fix: forward --d-a/--d-r (defaults 0x8000 each, the proven D4 values), and
# _validate_d_mode rejects an invalid mode+D combination EARLY, BEFORE the subprocess ever
# runs (so tbl_params / shape_enable is never touched on a bad request). The rules mirror
# caseA exactly so this early check rejects precisely what caseA would: D2 needs D_A==0 &
# D_R>0; D3 needs D_R==0 & D_A>0; D1/D4 need both>0; OFF/FAIL_OPEN need no D values.
def _validate_d_mode(mode, d_a, d_r):
    if mode in ("OFF", "FAIL_OPEN"):
        return True, ""
    if (d_a & 0xFF) != 0 or (d_r & 0xFF) != 0:
        return False, ("%s: D_A/D_R must be 256 ns-quantised (low byte 0); "
                       "got D_A=0x%x D_R=0x%x" % (mode, d_a, d_r))
    if mode == "D2":
        if d_a != 0:
            return False, "D2 requires D_A == 0 (pass --d-a 0); got D_A=0x%x" % d_a
        if d_r <= 0:
            return False, "D2 requires D_R > 0 (pass --d-r); got D_R=0x%x" % d_r
    elif mode == "D3":
        if d_r != 0:
            return False, "D3 requires D_R == 0 (pass --d-r 0); got D_R=0x%x" % d_r
        if d_a <= 0:
            return False, "D3 requires D_A > 0 (pass --d-a); got D_A=0x%x" % d_a
    elif mode in ("D1", "D4"):
        if d_a <= 0 or d_r <= 0:
            return False, ("%s requires D_A > 0 AND D_R > 0; got D_A=0x%x D_R=0x%x"
                           % (mode, d_a, d_r))
    else:
        return False, "unknown timing mode %r" % mode
    return True, ""


def run_timing(a, chk):
    if not os.path.isfile(_CASEA_PATH):
        chk.fail("caseA setup not found", _CASEA_PATH)
        return 2
    cmd = [sys.executable, _CASEA_PATH, "configure", "--mode", a.mode,
           "--program", PROGRAM, "--grpc", a.grpc]
    if a.mode not in ("OFF", "FAIL_OPEN"):
        cmd += ["--d-a", hex(a.d_a), "--d-r", hex(a.d_r)]   # caseA parses via int(x, 0)
    env = dict(os.environ)
    env["DEFENSE4_HW_AUTHORIZED"] = "1"
    try:
        p = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True)
    except Exception as e:
        chk.fail("caseA timing subprocess", str(e)[:140])
        return 2
    out = p.stdout or ""
    print(out, end="" if out.endswith("\n") else "\n")     # surface the caseA report
    if p.returncode == 0:
        chk.ok("caseA timing configure (mode=%s) clean exit 0" % a.mode, "")
        return 0
    # non-zero exit: is the ONLY failure the vestigial read_len read-back?
    fails = [ln.strip() for ln in out.splitlines() if ln.lstrip().startswith("[FAIL]")]
    non_readlen = [ln for ln in fails if "read_len" not in ln]
    if fails and not non_readlen:
        chk.warn("caseA timing read_len==18 check FAILED but TOLERATED",
                 "RRC retired read_len (dead PHV -> reads back 0); timing applied. "
                 "%d read_len-only failure(s)." % len(fails))
        chk.ok("caseA timing configure (mode=%s) applied (read_len failure is vestigial)"
               % a.mode, "")
        return 0
    chk.fail("caseA timing configure (mode=%s) FAILED" % a.mode,
             ("rc=%s; %d failure(s): %s" % (p.returncode, len(fails),
              "; ".join(non_readlen or fails)[:200])) if fails
             else "rc=%s, no [FAIL] lines (early crash) — see output above" % p.returncode)
    return p.returncode or 2


# ---------------------------------------------------------------------------
def _report(chk, out):
    print(chk.render())
    print("---- readback ----")
    print(json.dumps(out, indent=2, default=str))
    print("RESULT: %s (%d failures)" % ("PASS" if chk.n_fail == 0 else "FAIL", chk.n_fail))


def _sequence_text(a):
    return (
        "LOAD + CONFIG SEQUENCE (compile-only here; hardware behind Philip's authorization):\n"
        "  1. Load the RRC binary for program '%s'.\n"
        "  2a. Configure timing + size in one shot (stops on timing failure). D4 uses the\n"
        "      default D_A=D_R=0x%04x; per mode: D2 needs --d-a 0, D3 needs --d-r 0, OFF needs none.\n"
        "        DEFENSE4_HW_AUTHORIZED=1 python3 defense4_rrc_setup.py configure-all \\\n"
        "          --mode %s --master-ip %s --relay-ip %s --master-port <ephemeral>\n"
        "  2b. Or step by step (first-time bring-up needs configure-rrc to install the PRE):\n"
        "        DEFENSE4_HW_AUTHORIZED=1 python3 defense4_rrc_setup.py configure-timing --mode %s\n"
        "        DEFENSE4_HW_AUTHORIZED=1 python3 defense4_rrc_setup.py configure-rrc\n"
        "  2c. Later timing-mode changes are safe on their own: configure-timing RE-ASSERTS\n"
        "      shape_enable from the installed PRE group, so the split does not silently stop.\n"
        "        DEFENSE4_HW_AUTHORIZED=1 python3 defense4_rrc_setup.py configure-timing \\\n"
        "          --mode D2 --d-a 0 --d-r 0x8000\n"
        "  3. Read back everything:\n"
        "        DEFENSE4_HW_AUTHORIZED=1 python3 defense4_rrc_setup.py evidence-dump\n"
        "  4. Roll back the size layer only (timing left intact):\n"
        "        DEFENSE4_HW_AUTHORIZED=1 python3 defense4_rrc_setup.py rollback-rrc\n"
        "  PRE group: mgid 0x%04x -> node 0x%04x (RID 1, prefix) + node 0x%04x (RID 2, suffix),\n"
        "             both egress dp%d." %
        (PROGRAM, DA_DEFAULT, a.mode, a.master_ip, a.relay_ip, a.mode,
         RRC_MGID, RRC_NODE1, RRC_NODE2, PORT_VISION))


class _MiniChecks(object):
    def __init__(self):
        self.rows = []; self.n_fail = 0
    def ok(self, n, d=""): self.rows.append(("ok", n, d))
    def warn(self, n, d=""): self.rows.append(("WARN", n, d))
    def fail(self, n, d=""): self.rows.append(("FAIL", n, d)); self.n_fail += 1
    def expect(self, n, got, want): (self.ok if got == want else self.fail)(n, "got=%r want=%r" % (got, want))
    def render(self): return "\n".join("  [%s] %s%s" % (s, n, (" - " + str(d)) if d else "") for s, n, d in self.rows)


def _connect(a):
    """Open the ONE ClientInterface used by every RRC/PRE op in this process."""
    import bfrt_grpc.client as gc
    iface = gc.ClientInterface(grpc_addr=a.grpc, client_id=0, device_id=0)
    iface.bind_pipeline_config(PROGRAM)
    bi = iface.bfrt_info_get(PROGRAM)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)
    return iface, bi, tgt


def _load_d3():
    """Lazy-load the d3 helper module (get_table/get_entry/Checks) via the caseA setup."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("caseA_setup", _CASEA_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.d3


def run(a):
    out = {"op": a.op, "mode": a.mode, "program": PROGRAM}
    try:
        d3 = _load_d3()
        chk = d3.Checks()
    except Exception:
        d3 = None
        chk = _MiniChecks()

    if a.op == "dry-run":
        d_ok, d_msg = _validate_d_mode(a.mode, a.d_a, a.d_r)
        chk.expect("timing D-values valid for mode %s" % a.mode, d_ok, True)
        if not d_ok:
            chk.fail("mode %s D-values" % a.mode, d_msg)
        rrc_target_math(chk, out)
        out["sequence"] = _sequence_text(a)
        chk.ok("dry-run offline (RRC carve math + mutant kills validated; no hardware)", "")
        _report(chk, out)
        print("\n" + out["sequence"])
        return 0 if chk.n_fail == 0 else 2

    if os.environ.get("DEFENSE4_HW_AUTHORIZED") != "1":
        sys.stderr.write("REFUSING: op=%s touches ports/tables/PRE (hardware). Set "
                         "DEFENSE4_HW_AUTHORIZED=1 under an authorized session.\n" % a.op)
        return 2

    if a.op == "configure-timing":
        # DEFECT 3: validate the mode+D combination BEFORE the subprocess, so a bad request
        # never rewrites tbl_params (never clears shape_enable) only to abort.
        d_ok, d_msg = _validate_d_mode(a.mode, a.d_a, a.d_r)
        if not d_ok:
            chk.fail("configure-timing rejected (invalid D for mode %s)" % a.mode, d_msg)
            _report(chk, out); return 2
        # (a) timing in a subprocess (its client released on exit; read_len tolerated).
        rc = run_timing(a, chk)
        if rc != 0:
            chk.fail("configure-timing aborted", "timing failed (rc=%s)" % rc)
            _report(chk, out); return 2
        # (b) DEFECT 2: the caseA reconfig cleared shape_enable in tbl_params. RE-ASSERT it
        # from the PRE group's presence (RMW that preserves the timing fields) so a
        # standalone timing-mode change does NOT silently stop the response splitting.
        # If the RRC PRE group is not installed, shape stays 0 (no empty-group drop).
        if d3 is None:
            chk.warn("shape not re-asserted", "d3 helper unavailable; run configure-rrc")
            _report(chk, out); return 0 if chk.n_fail == 0 else 2
        iface, bi, tgt = _connect(a)
        have_pre = _pre_exists(bi, tgt)
        set_shape_enable(bi, tgt, chk, out, on=have_pre, d3=d3)
        out["shape_reasserted"] = {"pre_present": have_pre, "shape_enable": 1 if have_pre else 0}
        if have_pre:
            chk.ok("shape RE-ASSERTED after timing reconfig (PRE present -> shape ON)", "")
        else:
            chk.warn("PRE not installed -> shape left OFF; run configure-rrc to arm size", "")
        _report(chk, out)
        return 0 if chk.n_fail == 0 else 2

    if a.op == "configure-all":
        # DEFECT 3: reject an invalid mode+D combination BEFORE the timing subprocess, so
        # shape_enable is never cleared on a request that would abort. This closes the
        # window where the RRC briefly un-shaped.
        d_ok, d_msg = _validate_d_mode(a.mode, a.d_a, a.d_r)
        if not d_ok:
            chk.fail("configure-all rejected (invalid D for mode %s)" % a.mode, d_msg)
            _report(chk, out); return 2
        # (a) timing first, in a subprocess whose client is released on exit. STOP on failure.
        rc = run_timing(a, chk)
        if rc != 0 or chk.n_fail != 0:
            chk.fail("configure-all aborted", "timing failed (rc=%s) - RRC/PRE NOT applied" % rc)
            _report(chk, out)
            return 2
        # (b) size: the ONE client for shape_enable + PRE
        if d3 is None:
            chk.fail("d3 helper unavailable", "cannot configure RRC")
            _report(chk, out); return 2
        iface, bi, tgt = _connect(a)
        set_shape_enable(bi, tgt, chk, out, on=True, d3=d3)
        install_pre(bi, tgt, chk, out, write=True)
        if chk.n_fail == 0:
            chk.ok("configure-all: timing(%s) + shape ON + PRE installed" % a.mode, "")
        else:
            chk.fail("configure-all INCOMPLETE", "shape/PRE step failed after timing applied")
        _report(chk, out)
        return 0 if chk.n_fail == 0 else 2

    if d3 is None:
        sys.stderr.write("REFUSING: d3 helper module not importable (%s)\n" % _CASEA_PATH)
        return 2
    iface, bi, tgt = _connect(a)

    if a.op == "configure-rrc":
        set_shape_enable(bi, tgt, chk, out, on=True, d3=d3)
        install_pre(bi, tgt, chk, out, write=True)
        if chk.n_fail == 0:
            chk.ok("configure-rrc: shape ON + PRE installed (timing untouched)", "")
        else:
            chk.fail("configure-rrc INCOMPLETE", "shape/PRE step failed")
        _report(chk, out)
        return 0 if chk.n_fail == 0 else 2

    if a.op == "evidence-dump":
        t = d3.get_table(bi, "tbl_params")
        if t is not None:
            out["tbl_params"] = _read_params(t, tgt)
        node_t, node_name = _pre_table(bi, PRE_NODE_CANDS, None)
        mgid_t, mgid_name = _pre_table(bi, PRE_MGID_CANDS, None)
        if node_t is not None and mgid_t is not None:
            out["pre_schema"] = {"node_table": node_name, "node": _pre_schema(node_t),
                                 "mgid_table": mgid_name, "mgid": _pre_schema(mgid_t)}
            got, err = _pre_readback(node_t, mgid_t, tgt)
            out["pre_state"] = got
            out["pre_err"] = err
        print("EVIDENCE " + json.dumps(out, default=str))
        chk.ok("evidence-dump read (read-only)", "")
        _report(chk, out)
        return 0

    if a.op == "rollback-rrc":
        # disable shape FIRST (unicast restored) so no packet is mid-flight to a dead group,
        # THEN delete only the RRC-owned MGID/nodes. Timing is left intact.
        set_shape_enable(bi, tgt, chk, out, on=False, d3=d3)
        delete_pre(bi, tgt, chk, out)
        chk.ok("rollback-rrc: shape OFF (unicast) + RRC PRE removed; timing intact", "")
        _report(chk, out)
        return 0 if chk.n_fail == 0 else 2

    chk.fail("unknown op", a.op)
    _report(chk, out)
    return 2


def main(argv=None):
    ap = argparse.ArgumentParser(description="Defense 4 RRC control-plane setup")
    ap.add_argument("op", choices=["dry-run", "configure-timing", "configure-rrc",
                                   "configure-all", "evidence-dump", "rollback-rrc"])
    ap.add_argument("--mode", default="D4",
                    help="timing mode passed to the caseA setup (OFF/D1/D2/D3/D4/FAIL_OPEN)")
    ap.add_argument("--d-a", dest="d_a", type=lambda x: int(x, 0), default=DA_DEFAULT,
                    help="D_A word (256 ns-quantised, low byte 0); default 0x8000. "
                         "D2 needs 0; D3/D4/D1 need > 0.")
    ap.add_argument("--d-r", dest="d_r", type=lambda x: int(x, 0), default=DR_DEFAULT,
                    help="D_R word (256 ns-quantised, low byte 0); default 0x8000. "
                         "D3 needs 0; D2/D4/D1 need > 0.")
    ap.add_argument("--master-ip", default="10.10.54.19")     # Vision
    ap.add_argument("--relay-ip", default="192.168.10.7")     # SEL-751
    ap.add_argument("--master-port", type=int, default=40000)
    ap.add_argument("--dnp3-port", type=int, default=DNP3_PORT_DEFAULT)
    ap.add_argument("--grpc", default="localhost:50052")
    a = ap.parse_args(argv)
    return run(a)


if __name__ == "__main__":
    sys.exit(main())

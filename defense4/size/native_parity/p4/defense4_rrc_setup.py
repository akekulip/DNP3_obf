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
# Three control-plane defects are fixed here (the proven RRC binary is untouched):
#   DEFECT 1 (configure-all aborted by read_len): the frozen caseA setup asserts
#     tbl_params.read_len == a.read_len on read-back, but RRC retired read_len so it reads
#     back 0 (dead PHV). run_timing therefore ALWAYS forwards --read-len 0 to caseA (the
#     readback then matches) and treats ANY caseA [FAIL] as a hard failure — there is no
#     lenient read_len tolerance that could mask a real pktgen-not-enabled failure.
#   DEFECT 2 (shape cleared by a timing reconfig / loss window): a caseA reconfig rewrites
#     tbl_params and clears shape_enable. The SAFE ORDER installs + VERIFIES the PRE BEFORE
#     enabling shape (no packet is ever multicast to an empty group); configure-timing
#     RE-ASSERTS shape_enable (RMW, timing preserved) from the installed PRE group.
#   DEFECT 3 (meaningless sub-ms deadline): the old 0x8000 ns default (0.033 ms) was a no-op
#     "normalization". D-modes now REQUIRE an explicit millisecond deadline (--d-a-ms/--d-r-ms
#     forwarded to caseA); the raw --d-a/--d-r ns words are an expert override that must still
#     encode at least 1 ms.
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
# A D-mode deadline is a real millisecond hold. A raw --d-a/--d-r ns word (expert override)
# must encode at least this many ns, so the old sub-millisecond 0x8000 (0.033 ms) is rejected.
MIN_DMODE_NS = 1_000_000
RRC_MGID = 0x2849              # == RRC_MGID_49_28 in the P4 (ig_tm_md.mcast_grp_a)
RRC_NODE1 = 0x2851            # level-1 node carrying RID 1 (prefix)
RRC_NODE2 = 0x2852            # level-1 node carrying RID 2 (suffix)
RRC_RID1 = 1
RRC_RID2 = 2
PORT_VISION = 9               # dp9 (master side); both nodes egress here

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
    multicast group RRC_MGID. Field names are read from the running program first.

    Returns True IFF the group + both nodes read back with the EXACT mgid 0x2849, node ids
    0x2851/0x2852, RIDs 1/2 and egress dp9 (criterion 6d — not merely that the mgid exists).
    The caller must NOT enable shape unless this returned True (no empty-group loss)."""
    import bfrt_grpc.client as gc
    node_t, node_name = _pre_table(bi, PRE_NODE_CANDS, chk)
    mgid_t, mgid_name = _pre_table(bi, PRE_MGID_CANDS, chk)
    if node_t is None or mgid_t is None:
        return False
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

    return _pre_verify(node_t, mgid_t, tgt, chk, out)


def _pre_verify(node_t, mgid_t, tgt, chk, out):
    """Read the group back and assert the EXACT identity: mgid 0x2849 contains both node ids,
    node 0x2851 has RID 1 -> dp9, node 0x2852 has RID 2 -> dp9. Returns True iff all hold."""
    got, err = _pre_readback(node_t, mgid_t, tgt)
    out["pre_state"] = got
    if err:
        chk.fail("PRE readback", err)
        return False
    nf0 = chk.n_fail
    mg = got.get("mgid") or {}
    members = mg.get(MGID_NODES)
    if members is None:
        members = mg.get("$MULTICAST_NODE_ID")
    if not isinstance(members, (list, tuple)):
        members = [] if members is None else [members]
    try:
        members = [int(x) for x in members]
    except (TypeError, ValueError):
        members = []
    chk.expect("PRE mgid 0x%04x carries node 0x%04x" % (RRC_MGID, RRC_NODE1), RRC_NODE1 in members, True)
    chk.expect("PRE mgid 0x%04x carries node 0x%04x" % (RRC_MGID, RRC_NODE2), RRC_NODE2 in members, True)
    nodes = got.get("nodes") or {}
    for nid, want_rid in ((RRC_NODE1, RRC_RID1), (RRC_NODE2, RRC_RID2)):
        nd = nodes.get("0x%04x" % nid) or {}
        rid = nd.get(NODE_RID)
        ports = nd.get(NODE_PORTS)
        if isinstance(ports, (list, tuple)):
            port_list = [int(p) for p in ports]
        elif ports is None:
            port_list = []
        else:
            port_list = [int(ports)]
        chk.expect("PRE node 0x%04x RID" % nid, (None if rid is None else int(rid)), want_rid)
        chk.expect("PRE node 0x%04x -> dp%d" % (nid, PORT_VISION), port_list, [PORT_VISION])
    ok = chk.n_fail == nf0
    if ok:
        chk.ok("PRE verified: mgid 0x%04x -> node 0x%04x(rid1)+0x%04x(rid2) -> dp%d"
               % (RRC_MGID, RRC_NODE1, RRC_NODE2, PORT_VISION), "")
    return ok


def _node_exists(node_t, tgt, nid):
    """True iff a level-1 node entry is still present (used to tell an already-gone node
    from a real delete failure during rollback)."""
    import bfrt_grpc.client as gc
    try:
        for _d, _k in node_t.entry_get(tgt, [node_t.make_key([gc.KeyTuple(NODE_KEY, nid)])],
                                       {"from_hw": False}):
            return True
    except Exception:
        return False
    return False


def delete_pre(bi, tgt, chk, out):
    """Delete ONLY the RRC-owned group + nodes. Deletion failures are SURFACED, never
    swallowed (criterion 7): a node/group that is already absent is tolerated (idempotent
    rollback), but a real delete error is a chk.fail. Returns True iff the group is gone."""
    import bfrt_grpc.client as gc
    node_t, _ = _pre_table(bi, PRE_NODE_CANDS, chk)
    mgid_t, _ = _pre_table(bi, PRE_MGID_CANDS, chk)
    if node_t is None or mgid_t is None:
        chk.fail("PRE delete", "PRE tables not found")
        return False
    ok = True
    # delete the group first, then its nodes (so no node is referenced when removed)
    if _pre_exists(bi, tgt):
        try:
            mgid_t.entry_del(tgt, [mgid_t.make_key([gc.KeyTuple(MGID_KEY, RRC_MGID)])])
        except Exception as e:
            chk.fail("PRE mgid 0x%04x delete" % RRC_MGID, str(e)[:140]); ok = False
    else:
        chk.warn("PRE mgid 0x%04x already absent" % RRC_MGID, "nothing to delete")
    for nid in (RRC_NODE1, RRC_NODE2):
        try:
            node_t.entry_del(tgt, [node_t.make_key([gc.KeyTuple(NODE_KEY, nid)])])
        except Exception as e:
            # already-gone node is fine during rollback; a node that is STILL present is not
            if _node_exists(node_t, tgt, nid):
                chk.fail("PRE node 0x%04x delete" % nid, str(e)[:140]); ok = False
            else:
                chk.warn("PRE node 0x%04x already absent" % nid, "")
    if _pre_exists(bi, tgt):
        chk.fail("PRE delete verify", "mgid 0x%04x still present after delete" % RRC_MGID); ok = False
    elif ok:
        chk.ok("PRE deleted: mgid 0x%04x + nodes 0x%04x/0x%04x" % (RRC_MGID, RRC_NODE1, RRC_NODE2), "")
    return ok


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


def set_shape_enable(bi, tgt, chk, out, on, d3, strict=False):
    """Read-modify-write shape_enable in tbl_params, PRESERVING the timing fields caseA wrote
    (only shape_enable changes). strict=True (the safe configure-all / rollback paths) REFUSES
    to write when the current tbl_params read comes back empty — it never substitutes default
    timing values (criterion 6g). Returns True iff the write read back as requested."""
    import bfrt_grpc.client as gc
    t = d3.get_table(bi, "tbl_params", chk)
    if t is None:
        return False
    cur = _read_params(t, tgt)
    if not cur:
        if strict:
            chk.fail("tbl_params read-back before shape RMW",
                     "empty read; refusing to write default timing values")
            return False
        cur = {}
    # preserve the timing fields caseA installed; only shape_enable changes. read_len is a
    # dead field on RRC (reads back 0), so its fallback is 0 — never re-inject 18.
    d_ticks = int(cur.get("d_ticks", 0x001E8400))
    read_len = int(cur.get("read_len", 0))
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
        return False
    back = _read_params(t, tgt) or {}
    out["tbl_params"] = back
    nf0 = chk.n_fail
    chk.expect("shape_enable = %d" % shape, int(back.get("shape_enable", -1)), shape)
    chk.expect("timing preserved (mode)", int(back.get("mode", -1)), mode)
    chk.expect("timing preserved (d_ticks)", int(back.get("d_ticks", -1)), d_ticks)
    return chk.n_fail == nf0


def _verify_all_params(bi, tgt, chk, out, d3, want_shape):
    """Final safe-order readback (criterion 6f/6g): read tbl_params back from HARDWARE and
    confirm EVERY timing + shape field is present and shape_enable == want_shape. An empty
    read aborts — the caller must never trust substituted default timing values."""
    t = d3.get_table(bi, "tbl_params", chk)
    if t is None:
        chk.fail("tbl_params lookup", "table not found")
        return False
    got = _read_params(t, tgt)
    out["tbl_params_final"] = got
    if not got:
        chk.fail("tbl_params final readback", "empty read - refusing to trust default timing")
        return False
    nf0 = chk.n_fail
    chk.expect("final shape_enable", int(got.get("shape_enable", -1)), want_shape)
    for f in ("d_ticks", "da_dr", "budget", "mode", "read_len"):
        chk.expect("final tbl_params has %s" % f, got.get(f) is not None, True)
    return chk.n_fail == nf0


# ---------------------------------------------------------------------------
# timing delegation: caseA setup as a SUBPROCESS (its own client, released on exit)
# ---------------------------------------------------------------------------
# DEFECT 1 (read_len). The RRC kernel RETIRED read_len (per-function expected-ACK), so
# meta.read_len is dead-code-eliminated: bf-p4c drops its PHV (read_len is in the JOINT PHV
# at W2 but ABSENT from the RRC PHV) while keeping the tbl_params `read_len` action-data
# field for API stability. A write to that field is accepted but backs no live output, so it
# reads back 0. The frozen caseA config_params_d4 asserts `tbl_params.read_len == a.read_len`
# on read-back; the fix is to ALWAYS forward `--read-len 0` to caseA (option 2 in the file
# header) so its expected value IS 0 and the readback matches — no lenient tolerance, and
# therefore no way for a real pktgen-not-enabled failure to be silently masked (criterion 5).
#
# DEFECT 3 (deadline). The old 0x8000 ns default (0.033 ms) produced a meaningless
# "normalization". A D-mode now REQUIRES an explicit millisecond deadline, resolved and
# forwarded by _resolve_timing BEFORE the subprocess runs (so tbl_params / shape_enable is
# never touched on a bad request). The rules mirror caseA: D2 needs D_A==0 & D_R>0; D3 needs
# D_R==0 & D_A>0; D1/D4 need both>0; OFF/FAIL_OPEN need no deadline. Millisecond input
# (--d-a-ms/--d-r-ms) is preferred and quantised by caseA's proven quantize_d; a raw ns word
# (--d-a/--d-r) is an expert override that must still encode at least MIN_DMODE_NS (1 ms).
def _component(ms, ns, ms_flag, ns_flag):
    """Resolve ONE deadline component (D_A or D_R) from a millisecond value (preferred) or a
    raw ns word (expert override). Returns (specified, positive, forward_args, err):
      specified  - the user gave a value for this component at all
      positive   - the resolved deadline is > 0
      forward_args - the flag+value to hand to the caseA subprocess ([] if unspecified)
      err        - non-empty on an invalid value (bad quantization / sub-millisecond)."""
    if ms is not None:
        if ms < 0:
            return True, False, [], "%s must be >= 0 (got %s ms)" % (ms_flag, ms)
        return True, (ms > 0), [ms_flag, "%g" % ms], ""
    if ns is not None:
        if ns < 0:
            return True, False, [], "%s must be >= 0" % ns_flag
        if (ns & 0xFF) != 0:
            return True, False, [], ("%s must be 256 ns-quantised (low byte 0); got 0x%x"
                                     % (ns_flag, ns))
        if 0 < ns < MIN_DMODE_NS:
            return True, False, [], ("%s=0x%x is sub-millisecond (%.3f ms); a D-mode needs a "
                                     "real ms deadline — use --d-a-ms/--d-r-ms"
                                     % (ns_flag, ns, ns / 1e6))
        return True, (ns > 0), [ns_flag, hex(ns)], ""
    return False, False, [], ""


def _resolve_timing(a):
    """Validate the timing request for a.mode and build the EXACT deadline flags to forward
    to the caseA subprocess. Returns (ok, err, forward_args, plan). OFF/FAIL_OPEN need no
    deadline; every D-mode REQUIRES an explicit ms deadline (criterion 4)."""
    mode = a.mode
    if mode in ("OFF", "FAIL_OPEN"):
        return True, "", [], {"mode": mode, "deadline": "none (bypass mode)", "forward_args": []}
    if mode not in ("D1", "D2", "D3", "D4"):
        return False, "unknown timing mode %r" % mode, [], {"mode": mode}
    a_spec, a_pos, a_fwd, a_err = _component(getattr(a, "d_a_ms", None), a.d_a, "--d-a-ms", "--d-a")
    r_spec, r_pos, r_fwd, r_err = _component(getattr(a, "d_r_ms", None), a.d_r, "--d-r-ms", "--d-r")
    if a_err:
        return False, a_err, [], {"mode": mode}
    if r_err:
        return False, r_err, [], {"mode": mode}
    if mode in ("D1", "D4"):
        if not a_pos or not r_pos:
            return False, ("%s requires D_A>0 AND D_R>0 as millisecond deadlines, "
                           "e.g. --d-a-ms 2 --d-r-ms 20 (raw --d-a/--d-r ns words are an "
                           "expert override and must encode >= 1 ms)" % mode), [], {"mode": mode}
    elif mode == "D2":
        if a_pos:
            return False, ("D2 requires D_A == 0 (omit --d-a-ms, or pass --d-a 0); "
                           "got a positive D_A"), [], {"mode": mode}
        if not r_pos:
            return False, "D2 requires D_R>0 as a millisecond deadline, e.g. --d-r-ms 20", [], {"mode": mode}
    elif mode == "D3":
        if r_pos:
            return False, ("D3 requires D_R == 0 (omit --d-r-ms, or pass --d-r 0); "
                           "got a positive D_R"), [], {"mode": mode}
        if not a_pos:
            return False, "D3 requires D_A>0 as a millisecond deadline, e.g. --d-a-ms 2", [], {"mode": mode}
    forward = a_fwd + r_fwd
    plan = {"mode": mode, "forward_args": forward, "read_len_forced": 0,
            "note": "RRC read_len is dead (forced 0); D-mode deadline via ms is required"}
    return True, "", forward, plan


def run_timing(a, chk):
    """Delegate the timing config to the frozen caseA setup as a SUBPROCESS (its own gRPC
    client, released on exit — this script holds NO client while it runs; see RRC_DESIGN.md
    §7). It ALWAYS forwards --read-len 0 (DEFECT 1) and the resolved ms/ns deadline, plus the
    master/relay IPs, budget and poll interval. ANY caseA [FAIL] is a hard failure (criterion
    5) — there is no read_len tolerance that could mask a real pktgen-not-enabled failure."""
    if not os.path.isfile(_CASEA_PATH):
        chk.fail("caseA setup not found", _CASEA_PATH)
        return 2
    ok, err, fwd, _plan = _resolve_timing(a)
    if not ok:
        chk.fail("timing request invalid for mode %s" % a.mode, err)
        return 2
    cmd = [sys.executable, _CASEA_PATH, "configure", "--mode", a.mode,
           "--program", PROGRAM, "--grpc", a.grpc,
           "--read-len", "0",                                  # RRC retired read_len -> expect 0
           "--master-ip", a.master_ip, "--relay-ip", a.relay_ip,
           "--budget", str(a.budget), "--poll-ms", "%g" % a.poll_ms]
    cmd += fwd                                                 # caseA parses --d-a/--d-r via int(x,0)
    env = dict(os.environ)
    env["DEFENSE4_HW_AUTHORIZED"] = "1"
    try:
        p = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True)
    except Exception as e:
        chk.fail("caseA timing subprocess", str(e)[:140])
        return 2
    out = p.stdout or ""
    print(out, end="" if out.endswith("\n") else "\n")        # surface the caseA report
    if p.returncode == 0:
        chk.ok("caseA timing configure (mode=%s) clean exit 0 (read_len forced 0)" % a.mode, "")
        return 0
    # non-zero exit is a HARD failure — no read_len tolerance (criterion 5).
    fails = [ln.strip() for ln in out.splitlines() if ln.lstrip().startswith("[FAIL]")]
    chk.fail("caseA timing configure (mode=%s) FAILED" % a.mode,
             ("rc=%s; %d failure(s): %s" % (p.returncode, len(fails), "; ".join(fails)[:200]))
             if fails else "rc=%s, no [FAIL] lines (early crash) — see output above" % p.returncode)
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
        "  2a. Configure timing + size in ONE shot, SAFE ORDER (timing verified, PRE installed\n"
        "      AND verified, THEN shape enabled — no empty-group loss). D-modes REQUIRE a real\n"
        "      millisecond deadline; the RRC read_len is dead and is forced to 0:\n"
        "        DEFENSE4_HW_AUTHORIZED=1 python3 defense4_rrc_setup.py configure-all \\\n"
        "          --mode %s --d-a-ms 2 --d-r-ms 20 --budget %d \\\n"
        "          --master-ip %s --relay-ip %s\n"
        "      (D2: --d-r-ms only; D3: --d-a-ms only; OFF/FAIL_OPEN: no deadline.)\n"
        "  2b. Or step by step (first-time bring-up needs configure-rrc to install the PRE):\n"
        "        DEFENSE4_HW_AUTHORIZED=1 python3 defense4_rrc_setup.py configure-timing \\\n"
        "          --mode %s --d-a-ms 2 --d-r-ms 20\n"
        "        DEFENSE4_HW_AUTHORIZED=1 python3 defense4_rrc_setup.py configure-rrc\n"
        "  2c. Later timing-mode changes are safe on their own: configure-timing RE-ASSERTS\n"
        "      shape_enable from the installed PRE group, so the split does not silently stop.\n"
        "        DEFENSE4_HW_AUTHORIZED=1 python3 defense4_rrc_setup.py configure-timing \\\n"
        "          --mode D2 --d-r-ms 20\n"
        "  3. Read back everything:\n"
        "        DEFENSE4_HW_AUTHORIZED=1 python3 defense4_rrc_setup.py evidence-dump\n"
        "  4. Roll back the size layer only (shape verified OFF first, timing left intact):\n"
        "        DEFENSE4_HW_AUTHORIZED=1 python3 defense4_rrc_setup.py rollback-rrc\n"
        "  PRE group: mgid 0x%04x -> node 0x%04x (RID 1, prefix) + node 0x%04x (RID 2, suffix),\n"
        "             both egress dp%d." %
        (PROGRAM, a.mode, a.budget, a.master_ip, a.relay_ip, a.mode,
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
        # dry-run is offline: it PRINTS the plan and never errors on a missing deadline (an
        # incomplete D-mode request is a WARN here). The enforcement — a hard rejection of a
        # D-mode without an explicit ms deadline — lives in the configure-* paths / run_timing.
        ok, err, fwd, plan = _resolve_timing(a)
        out["timing_plan"] = plan
        if ok:
            chk.ok("timing request valid for mode %s" % a.mode,
                   "forward to caseA: %s" % (" ".join(fwd) if fwd else "(no deadline)"))
        else:
            chk.warn("timing request INCOMPLETE for mode %s" % a.mode,
                     err + "  (configure-* will REJECT this until a deadline is given)")
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
        # DEFECT 3: reject an invalid mode/deadline combination BEFORE the subprocess, so a bad
        # request never rewrites tbl_params (never clears shape_enable) only to abort.
        ok, err, _fwd, _plan = _resolve_timing(a)
        if not ok:
            chk.fail("configure-timing rejected (invalid timing for mode %s)" % a.mode, err)
            _report(chk, out); return 2
        # (a) timing in a subprocess (its client released on exit; --read-len 0 forced).
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
        if not set_shape_enable(bi, tgt, chk, out, on=have_pre, d3=d3, strict=True):
            chk.fail("configure-timing aborted", "shape re-assert readback failed")
            _report(chk, out); return 2
        out["shape_reasserted"] = {"pre_present": have_pre, "shape_enable": 1 if have_pre else 0}
        if have_pre:
            chk.ok("shape RE-ASSERTED after timing reconfig (PRE present -> shape ON)", "")
        else:
            chk.warn("PRE not installed -> shape left OFF; run configure-rrc to arm size", "")
        _report(chk, out)
        return 0 if chk.n_fail == 0 else 2

    if a.op == "configure-all":
        # SAFE ORDER (criterion 6). The caseA timing subprocess must run while THIS script
        # holds NO gRPC client (single-client / client_id=0 invariant, RRC_DESIGN.md §7), so
        # it runs FIRST; caseA's set_params rewrites tbl_params WITHOUT shape_enable, which
        # leaves shape OFF. We then open the ONE client and proceed, in order:
        #   (a) assert shape_enable=0 (shape held OFF across timing) ->
        #   (c) install the PRE -> (d) verify the EXACT mgid/nodes/rids/dp9 ->
        #   (e) enable shape -> (f) read back ALL timing+shape -> (g) abort on any readback
        #       failure, never substituting default timing values.
        # Because shape is enabled ONLY after the PRE is installed AND verified, no packet is
        # ever multicast to an empty group (the loss window this fix closes).
        ok, err, _fwd, _plan = _resolve_timing(a)
        if not ok:
            chk.fail("configure-all rejected (invalid timing for mode %s)" % a.mode, err)
            _report(chk, out); return 2
        # (b) timing first, in a subprocess whose client is released on exit. STOP on failure.
        rc = run_timing(a, chk)
        if rc != 0 or chk.n_fail != 0:
            chk.fail("configure-all aborted", "timing failed (rc=%s) - RRC/PRE NOT applied" % rc)
            _report(chk, out); return 2
        if d3 is None:
            chk.fail("d3 helper unavailable", "cannot configure RRC")
            _report(chk, out); return 2
        iface, bi, tgt = _connect(a)
        # (a) shape OFF first (strict: never substitute default timing on a failed read)
        if not set_shape_enable(bi, tgt, chk, out, on=False, d3=d3, strict=True):
            chk.fail("configure-all aborted", "could not confirm shape_enable=0 before PRE install")
            _report(chk, out); return 2
        # (c) install the PRE + (d) verify the EXACT identity (mgid/nodes/rids/dp9)
        if not install_pre(bi, tgt, chk, out, write=True):
            chk.fail("configure-all aborted", "PRE install/verify failed - shape left OFF (no loss)")
            _report(chk, out); return 2
        # (e) enable shape now that the PRE is present and verified
        if not set_shape_enable(bi, tgt, chk, out, on=True, d3=d3, strict=True):
            chk.fail("configure-all aborted", "could not enable shape after PRE install")
            _report(chk, out); return 2
        # (f) read back ALL timing + shape; (g) abort on any mismatch/empty read
        if not _verify_all_params(bi, tgt, chk, out, d3, want_shape=1):
            chk.fail("configure-all INCOMPLETE", "final timing/shape readback failed")
            _report(chk, out); return 2
        chk.ok("configure-all: timing(%s) VERIFIED + PRE VERIFIED + shape ON (safe order)" % a.mode, "")
        _report(chk, out)
        return 0 if chk.n_fail == 0 else 2

    if d3 is None:
        sys.stderr.write("REFUSING: d3 helper module not importable (%s)\n" % _CASEA_PATH)
        return 2
    iface, bi, tgt = _connect(a)

    if a.op == "configure-rrc":
        # Same safe order as configure-all's size layer: assert shape OFF, install + VERIFY the
        # PRE, THEN enable shape — so shape is never ON without a verified group (no loss).
        if not set_shape_enable(bi, tgt, chk, out, on=False, d3=d3, strict=True):
            chk.fail("configure-rrc aborted", "could not confirm shape_enable=0 before PRE install")
            _report(chk, out); return 2
        if not install_pre(bi, tgt, chk, out, write=True):
            chk.fail("configure-rrc aborted", "PRE install/verify failed - shape left OFF")
            _report(chk, out); return 2
        if not set_shape_enable(bi, tgt, chk, out, on=True, d3=d3, strict=True):
            chk.fail("configure-rrc aborted", "could not enable shape after PRE install")
            _report(chk, out); return 2
        chk.ok("configure-rrc: PRE VERIFIED + shape ON (timing untouched)", "")
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
        # criterion 7: shape MUST be confirmed OFF (unicast restored) BEFORE the PRE is deleted,
        # else a packet could be multicast to an empty group (loss). Set shape=0, READ BACK,
        # and ABORT if it is not 0. delete_pre then SURFACES any deletion failure (returns
        # nonzero); an already-absent group/node is tolerated for an idempotent rollback.
        se_ok = set_shape_enable(bi, tgt, chk, out, on=False, d3=d3, strict=True)
        back = out.get("tbl_params") or {}
        if not se_ok or int(back.get("shape_enable", -1)) != 0:
            chk.fail("rollback-rrc aborted",
                     "shape_enable not confirmed 0; refusing to delete PRE (avoids empty-group loss)")
            _report(chk, out); return 2
        delete_pre(bi, tgt, chk, out)
        if chk.n_fail == 0:
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
    # PREFERRED: millisecond deadlines (quantised by caseA's proven quantize_d). A D-mode
    # REQUIRES an explicit ms deadline — there is no silent sub-millisecond default.
    ap.add_argument("--d-a-ms", dest="d_a_ms", type=float, default=None,
                    help="D_A hold in ms (D1/D3/D4 need > 0; D2 needs D_A==0 so omit it).")
    ap.add_argument("--d-r-ms", dest="d_r_ms", type=float, default=None,
                    help="D_R hold in ms (D1/D2/D4 need > 0; D3 needs D_R==0 so omit it).")
    # EXPERT override: a raw already-encoded deadline WORD in ns (low byte 0). For a D-mode it
    # must encode >= 1 ms, so the old 0.033 ms 0x8000 default is rejected. Default None ->
    # a D-mode with neither ms nor a valid ns word is REJECTED (never a sub-ms fallback).
    ap.add_argument("--d-a", dest="d_a", type=lambda x: int(x, 0), default=None,
                    help="expert: D_A deadline WORD in ns (low byte 0, >= 1 ms for a D-mode).")
    ap.add_argument("--d-r", dest="d_r", type=lambda x: int(x, 0), default=None,
                    help="expert: D_R deadline WORD in ns (low byte 0, >= 1 ms for a D-mode).")
    ap.add_argument("--budget", type=int, default=18000,
                    help="fail-open budget forwarded to caseA (18000 -> ~30.8 ms horizon).")
    ap.add_argument("--poll-ms", dest="poll_ms", type=float, default=400.0,
                    help="master poll interval (ms) forwarded to caseA (deadline < poll check).")
    ap.add_argument("--master-ip", default="10.10.54.19")     # Vision
    ap.add_argument("--relay-ip", default="192.168.10.7")     # SEL-751
    ap.add_argument("--grpc", default="localhost:50052")
    a = ap.parse_args(argv)
    return run(a)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# ============================================================================
# defense4_bor_twopipe_setup.py — the ONE authoritative control-plane setup for
# the FAITHFUL two-pipe BOR + RRC deployment on a Tofino-1 (BFN-T10-032D, num_pipes=2).
#
# TWO programs, one device, one gRPC client per process (except the timing
# subprocess, which opens+releases its own client — see below):
#   * PIPE 0  (program --program-pipe0, pipe_scope [0]):
#       frozen RRC transaction engine (READ/SELECT ACK+response hold, PRE 49B echo
#       carve) + OPERATE T0-admission + cross-pipe route to pipe 1 + the SELECT-
#       prepares-a-BOR-epoch trigger. Its timing (mode/D_A/D_R/budget), the qid7..4
#       ACK/RESP reservoirs, dp8 loopback, dp68 pktgen, session/mirror/value_set are
#       configured by the PROVEN caseA setup as a SUBPROCESS (its client is released
#       before this script connects — the single-client / client_id=0 invariant).
#       This script adds ONLY the pipe-0 size layer (PRE group RRC_MGID 0x2849 ->
#       RID1/RID2 -> dp9, shape_enable RMW) and clears the pipe-0 reg_epoch allocator.
#   * PIPE 1  (program --program-pipe1, pipe_scope [1]):
#       the faithful BOR hold/release core. This script owns ALL of it: the qid3
#       OPERATE blocker reservoir + qid2 hold strict-priority ladder on PORT_L1
#       (dp136), the leak-safe J codebook (tbl_bor_codebook), the keyless budget
#       (tbl_params), the qid3 pktgen fill on PORT_PGEN1 (dp196) + its mirror session
#       + value_set, and the epoch machinery (reg_epoch/reg_ready/reg_gen/reg_topj
#       cleared to a clean start).
#
# Ops:
#   dry-run        offline: validate the BOR deadline matrix + timing mode + the TCP-
#                  timestamp preflight vectors + a unit self-check of the matrix + the
#                  faithful two-pipe emulator + the RRC carve math; print the plan; NEVER
#                  connect. Exit 0 iff the config is admissible, 2 otherwise.
#   configure      SAFE ORDER: validate -> pipe-0 timing (subprocess) -> connect one client
#                  -> pipe-0 PRE install+verify -> pipe-1 tables+reservoir install+verify
#                  -> ENABLE BOR + shape ONLY after everything is installed and verified
#                  -> final readback-or-abort. Never reports PASS on an empty/absent readback.
#   verify         read both pipes back read-only; PASS/FAIL per element (no writes).
#   evidence-dump  read-only dump of both pipes (tbl_params, PRE, pipe-1 queues/codebook/
#                  pktgen/registers) for the bring-up scorer.
#   disable-bor    turn the BOR hold OFF (pipe-1 pktgen app disabled -> no qid3 reservoir ->
#                  the OPERATE fails open, forwarded once, unshaped). Timing + size intact.
#   disable-rrc    turn the SIZE layer OFF (shape_enable=0 -> unicast restored, then delete the
#                  PRE group). Verifies shape==0 BEFORE deleting (no empty-group loss). Timing +
#                  BOR intact.
#   rollback       full teardown to a benign forwarding state, in verify-disabled-then-delete
#                  order: shape off -> BOR off -> delete PRE -> pipe-0 timing OFF (subprocess) ->
#                  pipe-1 pktgen off. Verifies each disable read back before the destructive step.
#   recover        after a PARTIAL failure: read the live state of both pipes and force it to the
#                  same benign state as rollback, tolerating anything already absent (idempotent).
#
# Deadlines (BOR_RRC_DESIGN.md section 1) are validated in MILLISECONDS and REJECTED (nonzero
# exit, no default substitution) if any of these fail:
#     A  > J_max + native_ACK_bound
#     R  > J_max + native_response_bound
#     R >= A
#     A, R, J_max  all <  min( operational_command_to_actuation_limit,
#                              master_SBO_timeout - guard,
#                              TCP_retransmit_bound - guard,
#                              BOR_fail_open_horizon,
#                              operational_latency_budget )
# where A = the OPERATE ACK release total-from-T0 (default = D_A), R = the OPERATE echo release
# total-from-T0 (default = D_A + D_R), J_max = max of the admissible J codebook. The old sub-
# millisecond 0x8000 ns (0.033 ms) "normalization" is rejected: D-modes REQUIRE a real ms deadline.
#
# Offline-safe: bfrt_grpc is only imported inside functions / the subprocess. Every hardware op
# refuses unless DEFENSE4_HW_AUTHORIZED=1. dry-run touches no gRPC and no ports.
# COMPILE-ONLY / OFFLINE here; nothing in this file was run against silicon.
# ============================================================================
import argparse
import importlib.util
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)   # bfrt_grpc is lazy-imported inside functions -> import is offline-safe
    return mod


# Reuse the proven setups WITHOUT modifying them:
#   rrc   -> PRE install/verify/delete + shape_enable RMW + timing-mode deadline resolver + RRC carve math
#   caseA -> the frozen d3 helper module (Checks, quantize_d, failopen_horizon, get_table, reg_*, TM/pktgen)
_RRC_PATH = os.path.join(_HERE, "defense4_rrc_setup.py")
_CASEA_PATH = os.environ.get("D4_CASEA_SETUP", "") or os.path.abspath(
    os.path.join(_HERE, "..", "..", "..", "timing", "control", "defense4_caseA_setup.py"))
rrc = _load_module("d4_rrc_setup", _RRC_PATH)
caseA = _load_module("d4_caseA_setup", _CASEA_PATH)
d3 = caseA.d3

# the offline emulators live one level up (rrc already inserted this path; belt and braces)
sys.path.insert(0, os.path.join(_HERE, "..", "offline"))

# ---------------------------------------------------------------------------
# constants — must match the two frozen P4 probes
# ---------------------------------------------------------------------------
PIPE0 = 0
PIPE1 = 1
DEV = 0xFFFF                       # device-scope target (global fixed tables: PRE)

# pipe-0 ports (proven; caseA owns their bring-up)
PORT_VISION = 9                    # dp9  master (pipe 0)
PORT_RELAY = 64                    # dp64 relay  (pipe 0)
PORT_L = 8                         # dp8  pipe-0 hold ring (MAC loopback)
PORT_PGEN = 68                     # dp68 pipe-0 pktgen/recirc
# pipe-1 ports (this script owns their bring-up) — dev_port = (pipe<<7)|local, so all >= 128
PORT_X1 = 144                      # dp144 pipe-1 cross-pipe ENTRY (MAC near loopback)
PORT_L1 = 136                      # dp136 pipe-1 BOR hold ring     (MAC near loopback)
PORT_PGEN1 = 196                   # dp196 pipe-1 pktgen/recirc (local port 68 of pipe 1)

# pipe-1 strict-priority ladder on PORT_L1 (qid == max_priority), STRICT DESCENDING.
# (The full qid7..qid2 ladder of BOR_RRC_DESIGN.md section 3 is SPLIT across the two pipes:
#  pipe 0 carries qid7>qid6>qid5>qid4 (ACK/RESP reservoirs, set by caseA); pipe 1 carries the
#  OPERATE reservoir qid3 > the OPERATE hold qid2. qid0 is the default forward FIFO.)
QID_OP_BLOCK = 3
QID_OP_HOLD = 2
PIPE1_QUEUE_PLAN = [("Q_OP_BLOCK", QID_OP_BLOCK, "3"), ("Q_OP_HOLD", QID_OP_HOLD, "2")]

# pipe-1 reservoir / pktgen / mirror / codebook (match defense4_twopipe_pipe1_faithful_probe.p4)
K_OP = 64                          # qid3 OPERATE reservoir depth (BUDGET_DEFAULT in the P4)
PIPE1_APP_ID = 2                   # pipe-1 pktgen app id (distinct from pipe-0 app id 1)
PIPE1_CLONE_SID = 7                # pipe-1 mirror session (CLONE_SESSION_ID in the P4)
RELAY_DST_PORT = 20000             # tbl_bor_codebook key: the relay-facing DNP3 TCP dst port
EPOCH_NONE = 0                     # reg_epoch clean value
GEN_INACTIVE = 0                   # reg_gen clean value
PIPE1_REGS_ZERO = ("reg_epoch", "reg_ready", "reg_gen", "reg_topj")

# the P4 J-word encoding: topj_cand = (xpipe.t0 & 0xFFFFFF00 | 1) + j_ticks, i.e. j_ticks is a
# DELAY IN NANOSECONDS with a zero low byte — EXACTLY the deadline-word encoding of d3.quantize_d.
# (NOTE: the P4 default J_DEFAULT_TICKS=0x2800 is 10240 ns = 0.010 ms, NOT the ~2.7 ms its comment
#  claims; the control plane MUST install an explicit J entry and never rely on that default.)

PROGRAM_PIPE0_DEFAULT = "twopipe_pipe0"
PROGRAM_PIPE1_DEFAULT = "twopipe_pipe1"


# ---------------------------------------------------------------------------
# offline validation: the BOR deadline matrix (all milliseconds)
# ---------------------------------------------------------------------------
def _parse_ms_set(s):
    out = []
    for tok in str(s).replace(";", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        out.append(float(tok))
    return out


def _failopen_horizon_ms(a):
    if getattr(a, "failopen_horizon_ms", None) is not None:
        return float(a.failopen_horizon_ms)
    try:
        h = d3.failopen_horizon(a.budget)
        return float(h["horizon_ms"] if isinstance(h, dict) else h)
    except Exception:
        return None


def validate_bor_deadlines(a):
    """Validate the BOR deadline set (BOR_RRC_DESIGN.md section 1) in milliseconds.

    Returns (ok, errors, plan). A bad set is REJECTED — the caller must never substitute a
    default. A = OPERATE ACK release total-from-T0 (default D_A); R = OPERATE echo release
    total-from-T0 (default D_A+D_R); J_max = max of the admissible codebook."""
    errs = []
    checks = []

    def req(name, cond, detail):
        checks.append((name, bool(cond), detail))
        if not cond:
            errs.append("%s [%s]" % (name, detail))

    j_set = _parse_ms_set(a.j_set)
    if not j_set:
        errs.append("admissible J set is empty (--j-set)")
    j_max = max(j_set) if j_set else None

    d_a = getattr(a, "d_a_ms", None)
    d_r = getattr(a, "d_r_ms", None)
    A = a.op_a_ms if getattr(a, "op_a_ms", None) is not None else d_a
    if getattr(a, "op_r_ms", None) is not None:
        R = a.op_r_ms
    elif d_a is not None and d_r is not None:
        R = d_a + d_r
    else:
        R = None
    op_j = getattr(a, "op_j_ms", None)

    H = _failopen_horizon_ms(a)
    ceiling_terms = {
        "operational_command_to_actuation_limit": a.op_actuation_ms,
        "master_SBO_timeout - guard": a.master_timeout_ms - a.guard_ms,
        "TCP_retransmit_bound - guard": a.tcp_rto_ms - a.guard_ms,
        "BOR_fail_open_horizon": H,
        "operational_latency_budget": a.op_latency_budget_ms,
    }
    live_terms = {k: v for k, v in ceiling_terms.items() if v is not None}
    ceiling = min(live_terms.values()) if live_terms else None
    ceiling_binding = (min(live_terms, key=live_terms.get) if live_terms else None)

    if A is None:
        errs.append("A undefined (give --d-a-ms or --op-a-ms)")
    if R is None:
        errs.append("R undefined (give --d-a-ms + --d-r-ms, or --op-r-ms)")
    if j_max is None:
        errs.append("J_max undefined (give --j-set)")

    if A is not None and A <= 0:
        errs.append("BOR requires A>0 (an OPERATE ACK hold); mode/D_A gives A=%g — use a mode with D_A>0 (D1/D4)" % A)
    if R is not None and R <= 0:
        errs.append("BOR requires R>0 (an OPERATE echo hold); mode/D_R gives R=%g — use a mode with D_R>0 (D1/D4)" % R)

    if A is not None and j_max is not None:
        req("A > J_max + native_ACK", A > j_max + a.native_ack_ms,
            "A=%g  J_max+nACK=%g" % (A, j_max + a.native_ack_ms))
    if R is not None and j_max is not None:
        req("R > J_max + native_response", R > j_max + a.native_resp_ms,
            "R=%g  J_max+nRESP=%g" % (R, j_max + a.native_resp_ms))
    if A is not None and R is not None:
        req("R >= A", R >= A, "R=%g  A=%g" % (R, A))
    if ceiling is not None:
        for label, val in (("A", A), ("R", R), ("J_max", j_max)):
            if val is not None:
                req("%s < ceiling" % label, val < ceiling,
                    "%s=%g  ceiling=%g (%s)" % (label, val, ceiling, ceiling_binding))
    else:
        errs.append("ceiling undefined (no admissible bound term)")

    if op_j is not None and j_set:
        req("operating J is in the admissible set", any(abs(op_j - x) < 1e-9 for x in j_set),
            "op_J=%g  set=%s" % (op_j, j_set))
        if j_max is not None:
            req("operating J <= J_max", op_j <= j_max + 1e-9, "op_J=%g  J_max=%g" % (op_j, j_max))

    plan = {
        "mode": a.mode,
        "A_ms": A, "R_ms": R, "J_max_ms": j_max, "operating_J_ms": op_j,
        "admissible_J_set_ms": j_set,
        "native_ACK_ms": a.native_ack_ms, "native_response_ms": a.native_resp_ms,
        "ceiling_terms_ms": ceiling_terms, "ceiling_ms": ceiling, "ceiling_binding": ceiling_binding,
        "checks": [{"name": n, "pass": c, "detail": d} for n, c, d in checks],
    }
    return (len(errs) == 0, errs, plan)


# ---------------------------------------------------------------------------
# offline validation: the TCP-timestamp preflight (control-plane SYN/SYN-ACK gate)
# ---------------------------------------------------------------------------
def tcp_options_has_timestamp(opt_bytes):
    """Parse a TCP options blob and return (parsed_ok, has_timestamp).

    Kind 0 = End-of-Options, 1 = NOP (single byte), all others are [kind, len, ...len-2 bytes].
    Kind 8 = Timestamps. A malformed / truncated blob returns parsed_ok=False so the preflight can
    FAIL CLOSED. This walks the actual option KINDS — data_offset==8 (a 20-byte options field) is
    NOT proof of option kind 8, and this parser is exactly why (BOR_RRC_DESIGN.md section 2)."""
    b = bytes(opt_bytes)
    i, n, has = 0, len(b), False
    while i < n:
        kind = b[i]
        if kind == 0:            # EOL
            break
        if kind == 1:            # NOP
            i += 1
            continue
        if i + 1 >= n:           # a length-prefixed option with no length byte
            return (False, has)
        length = b[i + 1]
        if length < 2 or i + length > n:
            return (False, has)
        if kind == 8:            # Timestamps
            has = True
        i += length
    return (True, has)


def _hex_to_bytes(s):
    if s is None:
        return None
    s = s.strip().replace(" ", "").replace(":", "")
    if s.lower().startswith("0x"):
        s = s[2:]
    if not s:
        return b""
    return bytes.fromhex(s)


def preflight_tcp_timestamp(a, chk, out):
    """Timestamp-safe iff BOTH the SYN and SYN-ACK option blobs parse cleanly AND neither carries
    kind 8. Offline, the operator supplies the captured option bytes via --syn-options/--synack-
    options (hex). On hardware this is fed from the captured handshake of the protected flow.
    Returns True only when timestamp-absence is PROVEN in both directions (fail closed otherwise)."""
    syn = _hex_to_bytes(getattr(a, "syn_options", None))
    synack = _hex_to_bytes(getattr(a, "synack_options", None))
    out["tcp_ts_preflight"] = {"syn_provided": syn is not None, "synack_provided": synack is not None}
    if syn is None or synack is None:
        chk.warn("TCP-timestamp preflight DEFERRED",
                 "no SYN/SYN-ACK option bytes supplied; on hardware capture the protected flow's "
                 "handshake and pass --syn-options/--synack-options. The anti-subtraction claim is "
                 "INVALID until this proves kind-8 absence in BOTH directions.")
        return None
    ok = True
    for label, blob in (("SYN", syn), ("SYN-ACK", synack)):
        parsed, has_ts = tcp_options_has_timestamp(blob)
        out["tcp_ts_preflight"]["%s_parsed" % label] = parsed
        out["tcp_ts_preflight"]["%s_has_timestamp" % label] = has_ts
        if not parsed:
            chk.fail("TCP-timestamp preflight (%s)" % label, "options malformed/truncated — fail closed")
            ok = False
        elif has_ts:
            chk.fail("TCP-timestamp preflight (%s)" % label,
                     "TCP timestamp option (kind 8) present — anti-subtraction is INVALID for this flow")
            ok = False
        else:
            chk.ok("TCP-timestamp preflight (%s)" % label, "no kind-8 option (timestamp-safe)")
    return ok


# ---------------------------------------------------------------------------
# offline validation: unit self-checks (deadline matrix + TCP-ts parser)
# ---------------------------------------------------------------------------
def _selfcheck_args(**over):
    base = dict(mode="D4", d_a_ms=16.0, d_r_ms=6.0, op_a_ms=None, op_r_ms=None,
                op_j_ms=10.0, j_set="0,2,4,6,8,10,12", native_ack_ms=1.9, native_resp_ms=1.9,
                guard_ms=5.0, master_timeout_ms=200.0, tcp_rto_ms=200.0, op_actuation_ms=100.0,
                op_latency_budget_ms=50.0, failopen_horizon_ms=None, budget=18000)
    base.update(over)
    return argparse.Namespace(**base)


def selfcheck_deadline_matrix(chk):
    """A truth table: each row states whether validate_bor_deadlines MUST accept or reject."""
    cases = [
        ("valid D4 (A=16,R=22,Jmax=12,H~30.8)", _selfcheck_args(), True),
        ("A too small (old D_A=2 does not survive BOR)", _selfcheck_args(d_a_ms=2.0), False),
        ("mode D2 gives A=0 (no OPERATE ACK hold)", _selfcheck_args(d_a_ms=0.0, mode="D2"), False),
        ("R < A (explicit override)", _selfcheck_args(op_a_ms=20.0, op_r_ms=15.0), False),
        ("J_max exceeds the fail-open horizon", _selfcheck_args(j_set="0,10,20,35"), False),
        ("R exceeds the ceiling", _selfcheck_args(op_r_ms=35.0), False),
        ("operating J not in the admissible set", _selfcheck_args(op_j_ms=7.0), False),
        ("R just above A and above J_max+native", _selfcheck_args(d_a_ms=16.0, d_r_ms=0.5), True),
    ]
    for name, ns, want_ok in cases:
        ok, errs, _plan = validate_bor_deadlines(ns)
        chk.expect("matrix: %s -> %s" % (name, "ACCEPT" if want_ok else "REJECT"), ok, want_ok)


def selfcheck_tcp_ts(chk):
    """The parser must find kind 8 by walking options, not by trusting the 20-byte data_offset==8."""
    # MSS(2,4) + SACK-permitted(4,2) + timestamp(8,10) + NOP(1) + WScale(3,3): HAS timestamp
    with_ts = bytes([2, 4, 0x05, 0xB4, 4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 7])
    # MSS(2,4) + SACK-permitted(4,2) + NOP + NOP + NOP + WScale(3,3): 12 bytes -> pads to a 20B
    # (data_offset==8) options field with NO kind-8 option
    no_ts = bytes([2, 4, 0x05, 0xB4, 4, 2, 1, 1, 1, 3, 3, 7, 0, 0, 0, 0, 0, 0, 0, 0])
    truncated = bytes([8, 10, 0, 0])   # a length byte that runs off the end
    p1, h1 = tcp_options_has_timestamp(with_ts)
    p2, h2 = tcp_options_has_timestamp(no_ts)
    p3, _h3 = tcp_options_has_timestamp(truncated)
    chk.expect("tcp-ts: timestamp option detected", (p1, h1), (True, True))
    chk.expect("tcp-ts: data_offset==8 but NO kind-8 (not a false positive)", (p2, h2), (True, False))
    chk.expect("tcp-ts: truncated options fail closed (parsed_ok False)", p3, False)


def emulator_math(chk, out):
    """Run the faithful two-pipe emulator conformance + mutation suite + the RRC carve math."""
    ok = True
    try:
        import bor_twopipe_faithful_emulator as fem
        clean = fem.run_conformance(frozenset())
        for k, v in clean.items():
            chk.expect("bor emulator: %s" % k, v, True)
            ok = ok and v
        faithful_ok, sr4_shaped = fem.run_first_operate_discrimination()
        chk.expect("bor emulator: first_operate_shaped(faithful)", faithful_ok, True)
        chk.expect("bor emulator: first_operate NOT shaped(SR4 fail-open-first)", sr4_shaped, False)
        wrap_ok = fem.run_seq_wrap_stray()
        chk.expect("bor emulator: seq_wrap_stray_fails_open", wrap_ok, True)
        killed = 0
        for name, expect, _desc in fem.MUTANTS:
            if name == "first_operate_fail_open_mode":
                r = fem.run_two_pipe(fem.Scenario(first_operate_fail_open=True))
                was_killed = (not r.first_operate_shaped)
            else:
                c = dict(fem.run_conformance(frozenset([name])))
                c["seq_wrap_stray_fails_open"] = fem.run_seq_wrap_stray(frozenset([name]))
                was_killed = (expect in [k for k, v in c.items() if not v])
            chk.expect("bor mutant killed: %s" % name, was_killed, True)
            killed += 1 if was_killed else 0
            ok = ok and was_killed
        out["bor_emulator"] = {"clean_checks": clean, "mutants_killed": killed,
                               "mutants_total": len(fem.MUTANTS),
                               "first_operate_discrimination": bool(faithful_ok and not sr4_shaped),
                               "seq_wrap_stray_fails_open": wrap_ok}
    except Exception as e:
        chk.fail("bor emulator import/run", str(e)[:160])
        ok = False
    # RRC carve math (the pipe-0 PRE 49B echo carve is unchanged)
    try:
        ok = rrc.rrc_target_math(chk, out) and ok
    except Exception as e:
        chk.fail("rrc carve math", str(e)[:160])
        ok = False
    return ok


# ---------------------------------------------------------------------------
# hardware: gRPC connection (ONE client; both programs' bfrt_info)
# ---------------------------------------------------------------------------
def _connect(a):
    """Open the ONE ClientInterface for this process and get BOTH programs' bfrt_info.
    Pipe-0 P4 tables use pipe_id=0; pipe-1 P4 tables use pipe_id=1; PRE uses device scope."""
    import bfrt_grpc.client as gc
    iface = gc.ClientInterface(grpc_addr=a.grpc, client_id=0, device_id=0)
    iface.bind_pipeline_config(a.program_pipe0)
    bi0 = iface.bfrt_info_get(a.program_pipe0)
    # HW-ASSUMPTION: a single client can fetch a second program's bfrt_info in a multi-program
    # (pipe_scope) device without a second bind. Confirmed only on hardware.
    bi1 = iface.bfrt_info_get(a.program_pipe1)
    tgt0 = gc.Target(device_id=0, pipe_id=PIPE0)
    tgt1 = gc.Target(device_id=0, pipe_id=PIPE1)
    tdev = gc.Target(device_id=0, pipe_id=DEV)
    return iface, bi0, bi1, tgt0, tgt1, tdev


# ---------------------------------------------------------------------------
# hardware: pipe-0 timing via the caseA setup as a SUBPROCESS (its client released on exit)
# ---------------------------------------------------------------------------
def run_timing_pipe0(a, chk, op="configure"):
    """Delegate the pipe-0 fixed-function + timing config to the frozen caseA setup as a SUBPROCESS
    targeting --program <pipe0>. ALWAYS forwards --read-len 0 (RRC retired read_len -> reads back 0)
    and the resolved ms deadline. ANY caseA [FAIL] is a hard failure. `op` is caseA's op (configure
    to install, or 'configure --mode OFF' semantics via a.mode for a rollback disable)."""
    import subprocess
    if not os.path.isfile(_CASEA_PATH):
        chk.fail("caseA setup not found", _CASEA_PATH)
        return 2
    ok, err, fwd, _plan = rrc._resolve_timing(a)
    if not ok:
        chk.fail("pipe-0 timing request invalid for mode %s" % a.mode, err)
        return 2
    cmd = [sys.executable, _CASEA_PATH, op, "--mode", a.mode,
           "--program", a.program_pipe0, "--grpc", a.grpc,
           "--read-len", "0",
           "--master-ip", a.master_ip, "--relay-ip", a.relay_ip,
           "--budget", str(a.budget), "--poll-ms", "%g" % a.poll_ms,
           "--port-vision", str(a.port_vision), "--port-relay", str(a.port_relay),
           "--port-l", str(a.port_l), "--port-pgen", str(a.port_pgen)]
    cmd += fwd
    env = dict(os.environ)
    env["DEFENSE4_HW_AUTHORIZED"] = "1"
    try:
        p = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True)
    except Exception as e:
        chk.fail("caseA pipe-0 timing subprocess", str(e)[:140])
        return 2
    txt = p.stdout or ""
    print(txt, end="" if txt.endswith("\n") else "\n")
    if p.returncode == 0:
        chk.ok("caseA pipe-0 timing %s (mode=%s) clean exit 0 (read_len forced 0)" % (op, a.mode), "")
        return 0
    fails = [ln.strip() for ln in txt.splitlines() if ln.lstrip().startswith("[FAIL]")]
    chk.fail("caseA pipe-0 timing %s (mode=%s) FAILED" % (op, a.mode),
             ("rc=%s; %s" % (p.returncode, "; ".join(fails)[:200])) if fails
             else "rc=%s, no [FAIL] lines (early crash)" % p.returncode)
    return p.returncode or 2


# ---------------------------------------------------------------------------
# hardware: pipe-1 bring-up (ports, queues, codebook, params, pktgen, mirror, value_set, epoch)
# ---------------------------------------------------------------------------
def config_pipe1_ports(bi1, tdev, a, out, chk, write=True):
    """Bring up the three pipe-1 ports: X1 (cross-pipe entry) and L1 (hold ring) as MAC-near
    loopback, PGEN1 as a pktgen/recirc port. MAC loopback needs delete-then-add (a live entry
    silently rejects a loopback-mode change — the same trap dp8 has)."""
    import bfrt_grpc.client as gc
    port_tbl = d3.get_table(bi1, "$PORT", chk)
    if port_tbl is None:
        chk.fail("pipe-1 $PORT table", "not found")
        return
    speed = a.pipe1_lpbk_speed

    def loopback_up(dp):
        lk = [port_tbl.make_key([gc.KeyTuple("$DEV_PORT", dp)])]
        try:
            port_tbl.entry_del(tdev, lk)
        except Exception:
            pass
        try:
            port_tbl.entry_add(tdev, lk, [port_tbl.make_data([
                gc.DataTuple("$SPEED", str_val=speed),
                gc.DataTuple("$FEC", str_val="BF_FEC_TYP_NONE"),
                gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_FORCE_DISABLE"),
                gc.DataTuple("$LOOPBACK_MODE", str_val="BF_LPBK_MAC_NEAR"),
                gc.DataTuple("$PORT_ENABLE", bool_val=True)])])
        except Exception as e:
            chk.fail("pipe-1 dp%d loopback up" % dp, str(e)[:80])

    def pktgen_port_up(dp):
        key = [port_tbl.make_key([gc.KeyTuple("$DEV_PORT", dp)])]
        data = [port_tbl.make_data([
            gc.DataTuple("$SPEED", str_val=speed),
            gc.DataTuple("$FEC", str_val="BF_FEC_TYP_NONE"),
            gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_FORCE_DISABLE"),
            gc.DataTuple("$LOOPBACK_MODE", str_val="BF_LPBK_MAC_NEAR"),
            gc.DataTuple("$PORT_ENABLE", bool_val=True)])]
        try:
            port_tbl.entry_add(tdev, key, data)
        except Exception:
            try:
                port_tbl.entry_mod(tdev, key, data)
            except Exception as e:
                chk.fail("pipe-1 dp%d up" % dp, str(e)[:80])

    if write:
        loopback_up(a.port_x1)
        loopback_up(a.port_l1)
        pktgen_port_up(a.port_pgen1)   # pktgen recirc bits are set in config_pipe1_pktgen
    rec = {}
    for dp in (a.port_x1, a.port_l1, a.port_pgen1):
        got, err = d3.get_entry(port_tbl, tdev, [("$DEV_PORT", dp)])
        rec["dp%d" % dp] = err or {k: got.get(k) for k in
                                   ("$PORT_UP", "$SPEED", "$PORT_ENABLE", "$LOOPBACK_MODE")}
        if not err:
            chk.expect("pipe-1 dp%d loopback mode" % dp, got.get("$LOOPBACK_MODE"), "BF_LPBK_MAC_NEAR")
    out["pipe1_ports"] = rec


def config_pipe1_queues(bi1, tgt1, a, out, chk, write=True):
    """qid3 (OPERATE blocker) > qid2 (OPERATE hold) strict priority on PORT_L1, both shapers off,
    read back and asserted strictly descending. (The reservoir starves the hold until it drains
    at T0+J.)"""
    import bfrt_grpc.client as gc
    pg_id, pg_nr = d3.resolve_pg(bi1, tgt1, a.port_l1, chk, {})
    q_cfg = d3.get_table(bi1, "tf1.tm.queue.sched_cfg", chk)
    if pg_id is None or q_cfg is None:
        chk.fail("resolve pipe-1 dp%d queues" % a.port_l1, "no port-group map / sched_cfg")
        return
    observed = []
    for label, qid, want_pri in PIPE1_QUEUE_PLAN:
        pgq = d3.pg_queue_of(pg_nr, qid)
        key = q_cfg.make_key([gc.KeyTuple("pg_id", pg_id), gc.KeyTuple("pg_queue", pgq)])
        if write:
            data = [gc.DataTuple("min_rate_enable", bool_val=False),
                    gc.DataTuple("max_rate_enable", bool_val=False),
                    gc.DataTuple("max_priority", str_val=want_pri),
                    gc.DataTuple("scheduling_enable", bool_val=True)]
            try:
                q_cfg.entry_mod(tgt1, [key], [q_cfg.make_data(data)])
            except Exception as e:
                chk.fail("%s sched_cfg write" % label, str(e)[:90])
        sc, err = d3.get_entry(q_cfg, tgt1, [("pg_id", pg_id), ("pg_queue", pgq)])
        if err:
            chk.fail("%s sched_cfg readback" % label, err)
            continue
        got_pri = d3.pnorm(sc.get("max_priority"))
        chk.expect("%s max_priority" % label, got_pri, int(want_pri))
        chk.expect("%s scheduling_enable" % label, sc.get("scheduling_enable"), True)
        chk.expect("%s max shaping disabled" % label, sc.get("max_rate_enable"), False)
        observed.append((label, got_pri))
        out.setdefault("pipe1_queues", {})[label] = {"qid": qid, "pg_queue": pgq, "max_priority": got_pri}
    vals = [v for _l, v in observed]
    strict = (len(vals) == 2 and all(v is not None for v in vals) and vals[0] > vals[1])
    out["pipe1_strict_priority_verified"] = strict
    chk.expect("pipe-1 strict ladder qid3>qid2", strict, True)


def config_pipe1_codebook(bi1, tgt1, a, out, chk, write=True):
    """Install the leak-safe J codebook entry for the relay dst_port. The compiled probe matches
    hdr.tcp.dst_port EXACTLY -> ONE J per flow (deterministic). J is encoded like a deadline word
    (ns, low byte zero) via d3.quantize_d, consistent with topj_cand = t0_word + j_ticks.

    LEAK-SAFETY LIMITATION (surfaced, not silently accepted): a single fixed J per flow is a known
    constant an observer can subtract. Per-OPERATE randomization (Random<>/salt) is NOT in this
    probe; only the T0-anchoring (response-timing channel) is closed here."""
    import bfrt_grpc.client as gc
    t = d3.get_table(bi1, "tbl_bor_codebook", chk)
    if t is None:
        chk.fail("tbl_bor_codebook", "not found")
        return
    q = d3.quantize_d(float(a.op_j_ms))
    j_word = q["word"]
    out["pipe1_codebook"] = {"dst_port": a.relay_dst_port, "op_J_ms": a.op_j_ms,
                             "j_word": j_word, "j_word_hex": "0x%08X" % j_word,
                             "realized_ms": q["realized_ms"],
                             "note": "exact dst_port match -> deterministic J; leak-safe randomization is a P4 follow-up"}
    key = t.make_key([gc.KeyTuple("hdr.tcp.dst_port", a.relay_dst_port)])
    data = t.make_data([gc.DataTuple("j_ticks", j_word)], "set_j")
    if write:
        try:
            t.entry_add(tgt1, [key], [data])
        except Exception:
            try:
                t.entry_mod(tgt1, [key], [data])
            except Exception as e:
                chk.fail("tbl_bor_codebook set_j", str(e)[:120])
    got, err = d3.get_entry(t, tgt1, [("hdr.tcp.dst_port", a.relay_dst_port)])
    if err:
        chk.fail("tbl_bor_codebook readback", err)
    else:
        chk.expect("codebook J word for dst_port %d" % a.relay_dst_port, got.get("j_ticks"), j_word)


def config_pipe1_params(bi1, tgt1, a, out, chk, write=True):
    """Keyless tbl_params: set_params(budget = K_OP) — the qid3 reservoir pass budget."""
    import bfrt_grpc.client as gc
    t = d3.get_table(bi1, "tbl_params", chk)
    if t is None:
        chk.fail("pipe-1 tbl_params", "not found")
        return
    if write:
        try:
            t.default_entry_set(tgt1, t.make_data([gc.DataTuple("budget", a.k_op)], "set_params"))
        except Exception as e:
            chk.fail("pipe-1 tbl_params set_params", str(e)[:120])
    got = None
    try:
        for item in t.default_entry_get(tgt1, {"from_hw": True}):
            d = item[0] if isinstance(item, tuple) else item
            if d is not None:
                got = d.to_dict()
    except Exception as e:
        chk.fail("pipe-1 tbl_params readback", str(e)[:90])
    out["pipe1_params"] = got
    if got:
        chk.expect("pipe-1 tbl_params budget (K_OP)", got.get("budget"), a.k_op)


def config_pipe1_mirror(bi1, tgt1, a, out, chk, write=True):
    """Clone session for the qid3 reservoir seed: pipe1_clone_sid -> PORT_PGEN1 (INGRESS, $normal).

    HW-ASSUMPTION / RISK (surfaced): pipe 0's frozen RRC also uses mirror session 7 (-> dp68).
    TF1 mirror sessions are device-global; if the SDE does not scope a session per pipe under
    pipe_scope, pipe-0's session 7 and pipe-1's session 7 COLLIDE. Resolution before hardware:
    confirm per-pipe session scoping, OR re-spin the pipe-1 probe with a distinct session id."""
    import bfrt_grpc.client as gc
    mtbl = d3.get_table(bi1, "$mirror.cfg", chk)
    if mtbl is None:
        chk.fail("pipe-1 $mirror.cfg", "not found")
        return
    mkey = [mtbl.make_key([gc.KeyTuple("$sid", a.pipe1_clone_sid)])]
    if write:
        mdata = [mtbl.make_data([
            gc.DataTuple("$direction", str_val="INGRESS"),
            gc.DataTuple("$ucast_egress_port", a.port_pgen1),
            gc.DataTuple("$ucast_egress_port_valid", bool_val=True),
            gc.DataTuple("$session_enable", bool_val=True),
            gc.DataTuple("$max_pkt_len", a.mirror_max_len)], "$normal")]
        try:
            mtbl.entry_add(tgt1, mkey, mdata)
        except Exception:
            try:
                mtbl.entry_mod(tgt1, mkey, mdata)
            except Exception as e:
                chk.fail("pipe-1 $mirror.cfg sid %d" % a.pipe1_clone_sid, str(e)[:90])
    got, err = d3.get_entry(mtbl, tgt1, [("$sid", a.pipe1_clone_sid)])
    out["pipe1_mirror"] = err or {k: got.get(k) for k in
                                  ("$direction", "$ucast_egress_port", "$session_enable")}
    if not err:
        chk.expect("pipe-1 mirror -> dp%d" % a.port_pgen1, got.get("$ucast_egress_port"), a.port_pgen1)
        chk.expect("pipe-1 mirror enabled", got.get("$session_enable"), True)


def config_pipe1_value_set(bi1, a, out, chk, write=True):
    """pipe-1 parser value_set pgen_recirc: admit the pktgen tokens generated on pipe 1. Reuse the
    proven d3 idiom (byte = (pipe<<3)|app_id, mask EXACT 0xFF) with pipe=1, app_id=pipe1 app id."""
    shim = argparse.Namespace(pipe=PIPE1, app_id=a.pipe1_app_id)
    d3.config_value_set(bi1, shim, out, chk, write=write)


def config_pipe1_pktgen(bi1, tgt1, a, out, chk, write=True, app_enable=False):
    """pipe-1 pktgen app: ONE recirc-triggered batch of K_OP=64 that seeds the qid3 OPERATE reservoir
    (arm_clone mirrors -> PORT_PGEN1 -> pattern match -> burst). increment_source_port MUST read back
    False. app_enable is the BOR on/off lever (off -> no reservoir -> OPERATE fails open)."""
    import bfrt_grpc.client as gc
    template = d3.build_token_template(a.token_len)
    pcfg = d3.get_table(bi1, d3.PKTGEN_PORT_CFG, chk)
    if pcfg is not None and write:
        try:
            pcfg.entry_mod(tgt1, [pcfg.make_key([gc.KeyTuple("dev_port", a.port_pgen1)])],
                           [pcfg.make_data([gc.DataTuple("pktgen_enable", bool_val=True),
                                            gc.DataTuple("recirculation_enable", bool_val=True),
                                            gc.DataTuple("pattern_matching_enable", bool_val=True)])])
        except Exception as e:
            chk.fail("pipe-1 pktgen port_cfg dp%d" % a.port_pgen1, str(e)[:100])
    pbuf = d3.get_table(bi1, d3.PKTGEN_PKT_BUFFER, chk)
    if pbuf is not None and write:
        try:
            pbuf.entry_mod(tgt1, [pbuf.make_key([gc.KeyTuple("pkt_buffer_offset", a.buf_offset),
                                                 gc.KeyTuple("pkt_buffer_size", len(template))])],
                           [pbuf.make_data([gc.DataTuple("buffer", bytearray(template))])])
        except Exception as e:
            chk.fail("pipe-1 pktgen pkt_buffer", str(e)[:100])
    acfg = d3.get_table(bi1, d3.PKTGEN_APP_CFG, chk)
    if acfg is None:
        chk.fail("pipe-1 pktgen app_cfg", "not found")
        return
    # HW-ASSUMPTION: pktgen app tables are addressed per-pipe by tgt1; pipe_local_source_port is the
    # LOCAL port of dp196 within pipe 1 (196 & 0x7F = 68). Confirm on hardware.
    local_src = a.port_pgen1 & 0x7F
    if write:
        try:
            acfg.entry_mod(tgt1, [acfg.make_key([gc.KeyTuple("app_id", a.pipe1_app_id)])],
                           [acfg.make_data([
                               gc.DataTuple("pattern_value", d3.CLONE_TAG_MARKER << 24),
                               gc.DataTuple("pattern_mask", 0xFF000000),
                               gc.DataTuple("pkt_len", len(template)),
                               gc.DataTuple("pkt_buffer_offset", a.buf_offset),
                               gc.DataTuple("pipe_local_source_port", local_src),
                               gc.DataTuple("increment_source_port", bool_val=False),
                               gc.DataTuple("batch_count_cfg", 0),
                               gc.DataTuple("packets_per_batch_cfg", a.k_op - 1),
                               gc.DataTuple("ipg", 0), gc.DataTuple("ibg", 0),
                               gc.DataTuple("trigger_counter", 0), gc.DataTuple("batch_counter", 0),
                               gc.DataTuple("pkt_counter", 0),
                               gc.DataTuple("app_enable", bool_val=app_enable)],
                              "trigger_recirc_pattern")])
        except Exception as e:
            chk.fail("pipe-1 pktgen app_cfg write", str(e)[:120])
    got, err = d3.get_entry(acfg, tgt1, [("app_id", a.pipe1_app_id)])
    out["pipe1_pktgen"] = err or {k: got.get(k) for k in
                                  ("pattern_value", "pattern_mask", "pkt_len", "pipe_local_source_port",
                                   "increment_source_port", "packets_per_batch_cfg", "app_enable")}
    if not err:
        chk.expect("pipe-1 pktgen increment_source_port == False", got.get("increment_source_port"), False)
        chk.expect("pipe-1 pktgen packets_per_batch_cfg (K_OP-1)", got.get("packets_per_batch_cfg"), a.k_op - 1)
        chk.expect("pipe-1 pktgen app_enable", got.get("app_enable"), app_enable)


def pipe1_pktgen_enable(bi1, tgt1, a, value, chk):
    import bfrt_grpc.client as gc
    acfg = d3.get_table(bi1, d3.PKTGEN_APP_CFG, chk)
    if acfg is None:
        chk.fail("pipe-1 pktgen app_cfg", "not found")
        return False
    try:
        acfg.entry_mod(tgt1, [acfg.make_key([gc.KeyTuple("app_id", a.pipe1_app_id)])],
                       [acfg.make_data([gc.DataTuple("app_enable", bool_val=value)], "trigger_recirc_pattern")])
    except Exception as e:
        chk.fail("pipe-1 pktgen app_enable=%s" % value, str(e)[:100])
        return False
    got, err = d3.get_entry(acfg, tgt1, [("app_id", a.pipe1_app_id)])
    if err:
        chk.fail("pipe-1 pktgen app_enable readback", err)
        return False
    return chk.expect("pipe-1 pktgen app_enable readback == %s" % value, got.get("app_enable"), value)


def clear_pipe1_epoch_state(bi1, tgt1, chk, out):
    """Clean start: reg_epoch/reg_ready/reg_gen/reg_topj := 0, then READ BACK and assert 0. This is
    the control-plane half of the epoch machinery (allocation/matching is data-plane)."""
    got = {}
    for r in PIPE1_REGS_ZERO:
        try:
            d3.reg_write(bi1, tgt1, r, 0, chk=chk)
        except Exception as e:
            chk.fail("pipe-1 %s clear" % r, str(e)[:80])
    for r in PIPE1_REGS_ZERO:
        try:
            v = d3.reg_read(bi1, tgt1, r)
            got[r] = v
            chk.expect("pipe-1 %s == 0 (clean epoch)" % r, int(v), 0)
        except Exception as e:
            chk.fail("pipe-1 %s readback" % r, str(e)[:80])
            got[r] = None
    out["pipe1_registers"] = got


def clear_pipe0_epoch(bi0, tgt0, chk, out):
    """Clear pipe-0's reg_epoch allocator to a clean start (EPOCH_NONE)."""
    try:
        d3.reg_write(bi0, tgt0, "reg_epoch", EPOCH_NONE, chk=chk)
        v = d3.reg_read(bi0, tgt0, "reg_epoch")
        out["pipe0_reg_epoch"] = v
        chk.expect("pipe-0 reg_epoch == 0 (allocator clean)", int(v), EPOCH_NONE)
    except Exception as e:
        chk.fail("pipe-0 reg_epoch clear", str(e)[:80])


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------
def _report(chk, out):
    print(chk.render())
    print("---- readback ----")
    print(json.dumps(out, indent=2, default=str))
    print("RESULT: %s (%d failures)" % ("PASS" if chk.n_fail == 0 else "FAIL", chk.n_fail))


def _bringup_sequence_text(a):
    return (
        "HARDWARE BRING-UP SEQUENCE (all steps behind DEFENSE4_HW_AUTHORIZED=1; hardware gated on Philip):\n"
        "  0. Load the TWO-program device: pipe_scope [0]=%s, [1]=%s (one .conf, two p4_programs).\n"
        "  1. Validate + configure in ONE shot (SAFE ORDER — timing, then PRE + pipe-1 reservoir, then\n"
        "     BOR + shape enabled ONLY after every readback passes):\n"
        "       DEFENSE4_HW_AUTHORIZED=1 python3 defense4_bor_twopipe_setup.py configure \\\n"
        "         --mode %s --d-a-ms %g --d-r-ms %g --op-j-ms %g --j-set '%s' \\\n"
        "         --syn-options <hex> --synack-options <hex>   # the protected flow's handshake\n"
        "  2. Read back both pipes:\n"
        "       DEFENSE4_HW_AUTHORIZED=1 python3 defense4_bor_twopipe_setup.py verify\n"
        "       DEFENSE4_HW_AUTHORIZED=1 python3 defense4_bor_twopipe_setup.py evidence-dump\n"
        "  3. Disable BOR only / size only / full teardown / recover from a partial failure:\n"
        "       ... disable-bor    (pipe-1 pktgen off -> OPERATE fails open; timing + size intact)\n"
        "       ... disable-rrc    (shape off + PRE deleted; timing + BOR intact)\n"
        "       ... rollback       (shape off -> BOR off -> PRE del -> pipe-0 timing OFF -> pipe-1 pktgen off)\n"
        "       ... recover        (force to the benign state, idempotent, after any partial failure)\n"
        "  Ports: pipe 0 dp8/9/64/68 (caseA); pipe 1 dp%d(X1,MAC-loop) dp%d(L1,MAC-loop) dp%d(PGEN1).\n"
        "  PRE: mgid 0x%04X -> node 0x%04X(RID1) + 0x%04X(RID2) -> dp%d." %
        (a.program_pipe0, a.program_pipe1, a.mode, a.d_a_ms or 0, a.d_r_ms or 0, a.op_j_ms, a.j_set,
         a.port_x1, a.port_l1, a.port_pgen1,
         rrc.RRC_MGID, rrc.RRC_NODE1, rrc.RRC_NODE2, rrc.PORT_VISION))


# ---------------------------------------------------------------------------
# ops
# ---------------------------------------------------------------------------
def op_dry_run(a):
    chk = d3.Checks()
    out = {"op": "dry-run", "mode": a.mode,
           "program_pipe0": a.program_pipe0, "program_pipe1": a.program_pipe1}
    # (1) BOR deadline matrix
    ok, errs, plan = validate_bor_deadlines(a)
    out["bor_deadline_plan"] = plan
    if ok:
        chk.ok("BOR deadline set ADMISSIBLE for mode %s" % a.mode, "")
    else:
        for e in errs:
            chk.fail("BOR deadline REJECTED", e)
    # (2) timing-mode deadline sanity (reuses the RRC/caseA resolver; rejects sub-ms 0x8000)
    tok, terr, _fwd, tplan = rrc._resolve_timing(a)
    out["timing_mode_plan"] = tplan
    if tok:
        chk.ok("pipe-0 timing request valid for mode %s" % a.mode, "")
    else:
        chk.fail("pipe-0 timing request INVALID", terr)
    # (3) TCP-timestamp preflight (provided vectors; deferred otherwise)
    preflight_tcp_timestamp(a, chk, out)
    # (4) unit self-checks
    selfcheck_deadline_matrix(chk)
    selfcheck_tcp_ts(chk)
    # (5) behavioral models
    emulator_math(chk, out)
    out["sequence"] = _bringup_sequence_text(a)
    _report(chk, out)
    print("\n" + out["sequence"])
    # dry-run exit reflects BOTH the requested config's admissibility AND the self-checks
    return 0 if chk.n_fail == 0 else 2


def _require_hw(a):
    if os.environ.get("DEFENSE4_HW_AUTHORIZED") != "1":
        sys.stderr.write("REFUSING: op=%s programs ports/tables/PRE/pktgen (hardware). Set "
                         "DEFENSE4_HW_AUTHORIZED=1 under an authorized session.\n" % a.op)
        return False
    return True


def op_configure(a):
    chk = d3.Checks()
    out = {"op": "configure", "mode": a.mode,
           "program_pipe0": a.program_pipe0, "program_pipe1": a.program_pipe1}
    # (0) pre-connection validation — REJECT before any hardware touch
    ok, errs, plan = validate_bor_deadlines(a)
    out["bor_deadline_plan"] = plan
    if not ok:
        for e in errs:
            chk.fail("configure REJECTED (bad BOR deadline set)", e)
        _report(chk, out)
        return 2
    tok, terr, _fwd, _tp = rrc._resolve_timing(a)
    if not tok:
        chk.fail("configure REJECTED (invalid pipe-0 timing for mode %s)" % a.mode, terr)
        _report(chk, out)
        return 2
    ts_ok = preflight_tcp_timestamp(a, chk, out)
    if ts_ok is False:
        chk.fail("configure REJECTED (TCP-timestamp preflight failed)",
                 "the protected flow negotiated timestamps — anti-subtraction is invalid")
        _report(chk, out)
        return 2
    if not _require_hw(a):
        return 2
    # (1) pipe-0 fixed-function + timing via the caseA subprocess (its client released on exit)
    rc = run_timing_pipe0(a, chk, op="configure")
    if rc != 0 or chk.n_fail != 0:
        chk.fail("configure aborted", "pipe-0 timing failed (rc=%s) — nothing further applied" % rc)
        _report(chk, out)
        return 2
    # (2) ONE client for the size layer (pipe 0) + all of pipe 1
    iface, bi0, bi1, tgt0, tgt1, tdev = _connect(a)
    # (3) pipe-0 size layer, SAFE ORDER: shape OFF -> PRE install+verify (shape stays OFF for now)
    if not rrc.set_shape_enable(bi0, tgt0, chk, out, on=False, d3=d3, strict=True):
        chk.fail("configure aborted", "could not confirm pipe-0 shape_enable=0 before PRE install")
        _report(chk, out)
        return 2
    if not rrc.install_pre(bi0, tdev, chk, out, write=True):
        chk.fail("configure aborted", "PRE install/verify failed — shape left OFF (no empty-group loss)")
        _report(chk, out)
        return 2
    clear_pipe0_epoch(bi0, tgt0, chk, out)
    # (4) pipe-1 bring-up (ports -> queues -> codebook -> params -> mirror -> value_set -> pktgen(off)
    #     -> clear epoch registers). pktgen app stays DISABLED until every readback passes.
    config_pipe1_ports(bi1, tdev, a, out, chk, write=True)
    config_pipe1_queues(bi1, tgt1, a, out, chk, write=True)
    config_pipe1_codebook(bi1, tgt1, a, out, chk, write=True)
    config_pipe1_params(bi1, tgt1, a, out, chk, write=True)
    config_pipe1_mirror(bi1, tgt1, a, out, chk, write=True)
    config_pipe1_value_set(bi1, a, out, chk, write=True)
    config_pipe1_pktgen(bi1, tgt1, a, out, chk, write=True, app_enable=False)
    clear_pipe1_epoch_state(bi1, tgt1, chk, out)
    if chk.n_fail != 0:
        chk.fail("configure aborted", "a pipe-1 install/readback failed — BOR + shape left OFF (safe)")
        _report(chk, out)
        return 2
    # (5) ENABLE BOR (pipe-1 reservoir) only now that every table + reservoir readback passed
    if not pipe1_pktgen_enable(bi1, tgt1, a, True, chk):
        chk.fail("configure aborted", "could not enable the pipe-1 qid3 reservoir")
        _report(chk, out)
        return 2
    # (6) ENABLE the size split (pipe-0 shape) only now that the PRE is verified present
    if not rrc.set_shape_enable(bi0, tgt0, chk, out, on=True, d3=d3, strict=True):
        chk.fail("configure aborted", "could not enable pipe-0 shape after PRE install")
        _report(chk, out)
        return 2
    # (7) final readback-or-abort: pipe-0 tbl_params (shape=1 + timing fields, read_len dead=0 tolerated)
    if not rrc._verify_all_params(bi0, tgt0, chk, out, d3, want_shape=1):
        chk.fail("configure INCOMPLETE", "final pipe-0 timing/shape readback failed")
        _report(chk, out)
        return 2
    chk.ok("configure: pipe-0 timing+PRE+shape VERIFIED, pipe-1 BOR reservoir+codebook VERIFIED (safe order)", "")
    _report(chk, out)
    return 0 if chk.n_fail == 0 else 2


def op_verify(a):
    chk = d3.Checks()
    out = {"op": "verify", "program_pipe0": a.program_pipe0, "program_pipe1": a.program_pipe1}
    if not _require_hw(a):
        return 2
    iface, bi0, bi1, tgt0, tgt1, tdev = _connect(a)
    # pipe-0: tbl_params present + PRE present
    rrc._verify_all_params(bi0, tgt0, chk, out, d3, want_shape=1)
    if not rrc._pre_exists(bi0, tdev):
        chk.fail("PRE group present", "mgid 0x%04X absent" % rrc.RRC_MGID)
    else:
        chk.ok("PRE group present", "mgid 0x%04X" % rrc.RRC_MGID)
    # pipe-1: queues + codebook + pktgen enabled + registers readable
    config_pipe1_queues(bi1, tgt1, a, out, chk, write=False)
    config_pipe1_codebook(bi1, tgt1, a, out, chk, write=False)
    config_pipe1_pktgen(bi1, tgt1, a, out, chk, write=False, app_enable=True)
    for r in PIPE1_REGS_ZERO:
        try:
            out.setdefault("pipe1_registers", {})[r] = d3.reg_read(bi1, tgt1, r)
        except Exception:
            chk.fail("pipe-1 %s read" % r, "register not readable")
    _report(chk, out)
    return 0 if chk.n_fail == 0 else 2


def op_evidence_dump(a):
    chk = d3.Checks()
    out = {"op": "evidence-dump"}
    if not _require_hw(a):
        return 2
    iface, bi0, bi1, tgt0, tgt1, tdev = _connect(a)
    # pipe-0 tbl_params + PRE state
    t = d3.get_table(bi0, "tbl_params")
    if t is not None:
        out["pipe0_tbl_params"] = rrc._read_params(t, tgt0)
    node_t, node_name = rrc._pre_table(bi0, rrc.PRE_NODE_CANDS, None)
    mgid_t, mgid_name = rrc._pre_table(bi0, rrc.PRE_MGID_CANDS, None)
    if node_t is not None and mgid_t is not None:
        got, err = rrc._pre_readback(node_t, mgid_t, tdev)
        out["pre_state"] = got
        out["pre_err"] = err
    # pipe-1 queues / codebook / pktgen / registers
    config_pipe1_queues(bi1, tgt1, a, out, chk, write=False)
    config_pipe1_codebook(bi1, tgt1, a, out, chk, write=False)
    config_pipe1_pktgen(bi1, tgt1, a, out, chk, write=False, app_enable=True)
    for r in PIPE1_REGS_ZERO:
        try:
            out.setdefault("pipe1_registers", {})[r] = d3.reg_read(bi1, tgt1, r)
        except Exception:
            out.setdefault("pipe1_registers", {})[r] = None
    print("EVIDENCE " + json.dumps(out, default=str))
    chk.ok("evidence-dump read (read-only)", "")
    _report(chk, out)
    return 0


def op_disable_bor(a):
    chk = d3.Checks()
    out = {"op": "disable-bor"}
    if not _require_hw(a):
        return 2
    iface, bi0, bi1, tgt0, tgt1, tdev = _connect(a)
    # BOR off = pipe-1 reservoir off (no qid3 tokens -> OPERATE fails open, forwarded once). Then
    # retire any pending epoch so a stale flag cannot revalidate. Timing + size are untouched.
    ok = pipe1_pktgen_enable(bi1, tgt1, a, False, chk)
    clear_pipe1_epoch_state(bi1, tgt1, chk, out)
    if ok and chk.n_fail == 0:
        chk.ok("disable-bor: pipe-1 reservoir OFF (OPERATE fails open); timing + size intact", "")
    _report(chk, out)
    return 0 if chk.n_fail == 0 else 2


def op_disable_rrc(a):
    chk = d3.Checks()
    out = {"op": "disable-rrc"}
    if not _require_hw(a):
        return 2
    iface, bi0, bi1, tgt0, tgt1, tdev = _connect(a)
    # SIZE off: shape_enable=0 (unicast restored), CONFIRM 0, THEN delete the PRE (no empty-group loss).
    se_ok = rrc.set_shape_enable(bi0, tgt0, chk, out, on=False, d3=d3, strict=True)
    back = out.get("tbl_params") or {}
    if not se_ok or int(back.get("shape_enable", -1)) != 0:
        chk.fail("disable-rrc aborted", "shape_enable not confirmed 0; refusing to delete PRE")
        _report(chk, out)
        return 2
    rrc.delete_pre(bi0, tdev, chk, out)
    if chk.n_fail == 0:
        chk.ok("disable-rrc: shape OFF (unicast) + PRE removed; timing + BOR intact", "")
    _report(chk, out)
    return 0 if chk.n_fail == 0 else 2


def op_rollback(a):
    chk = d3.Checks()
    out = {"op": "rollback"}
    if not _require_hw(a):
        return 2
    iface, bi0, bi1, tgt0, tgt1, tdev = _connect(a)
    # order: shape off (verify) -> BOR off (verify) -> delete PRE -> pipe-0 timing OFF -> pipe-1 pktgen off
    se_ok = rrc.set_shape_enable(bi0, tgt0, chk, out, on=False, d3=d3, strict=True)
    back = out.get("tbl_params") or {}
    if not se_ok or int(back.get("shape_enable", -1)) != 0:
        chk.fail("rollback aborted", "shape_enable not confirmed 0; refusing to delete PRE")
        _report(chk, out)
        return 2
    bor_off = pipe1_pktgen_enable(bi1, tgt1, a, False, chk)
    if not bor_off:
        chk.fail("rollback aborted", "pipe-1 reservoir not confirmed OFF; refusing to tear down")
        _report(chk, out)
        return 2
    rrc.delete_pre(bi0, tdev, chk, out)
    clear_pipe1_epoch_state(bi1, tgt1, chk, out)
    # pipe-0 timing OFF via the caseA subprocess (mode OFF disables the pipe-0 pktgen reservoirs).
    off_args = argparse.Namespace(**vars(a))
    off_args.mode = "OFF"
    off_args.d_a_ms = None
    off_args.d_r_ms = None
    off_args.d_a = 0
    off_args.d_r = 0
    rc = run_timing_pipe0(off_args, chk, op="configure")
    if rc != 0:
        chk.warn("rollback: pipe-0 timing OFF returned rc=%s" % rc, "size + BOR already disabled")
    if chk.n_fail == 0:
        chk.ok("rollback: shape OFF + BOR OFF + PRE removed + pipe-0 timing OFF (benign forwarding)", "")
    _report(chk, out)
    return 0 if chk.n_fail == 0 else 2


def op_recover(a):
    """After a PARTIAL configure/rollback failure, read the live state and force it to the benign
    state, tolerating anything already absent (idempotent). Never fails on an already-gone element."""
    chk = d3.Checks()
    out = {"op": "recover"}
    if not _require_hw(a):
        return 2
    iface, bi0, bi1, tgt0, tgt1, tdev = _connect(a)
    found = {}
    # 1) shape off (best-effort; strict False so a missing tbl_params does not hard-fail here)
    try:
        found["shape_off"] = rrc.set_shape_enable(bi0, tgt0, chk, out, on=False, d3=d3, strict=False)
    except Exception as e:
        chk.warn("recover: shape off", str(e)[:80])
        found["shape_off"] = False
    # 2) BOR off (pipe-1 reservoir)
    try:
        found["bor_off"] = pipe1_pktgen_enable(bi1, tgt1, a, False, chk)
    except Exception as e:
        chk.warn("recover: BOR off", str(e)[:80])
        found["bor_off"] = False
    # 3) delete PRE only if present (idempotent)
    try:
        if rrc._pre_exists(bi0, tdev):
            found["pre_present"] = True
            rrc.delete_pre(bi0, tdev, chk, out)
        else:
            found["pre_present"] = False
            chk.ok("recover: PRE already absent", "")
    except Exception as e:
        chk.warn("recover: PRE delete", str(e)[:80])
    # 4) clear pipe-1 epoch registers to a clean start
    try:
        clear_pipe1_epoch_state(bi1, tgt1, chk, out)
    except Exception as e:
        chk.warn("recover: pipe-1 epoch clear", str(e)[:80])
    out["recover_found"] = found
    chk.ok("recover: forced to benign state (shape off, BOR off, PRE absent, epoch clean)", "")
    _report(chk, out)
    return 0 if chk.n_fail == 0 else 2


# ---------------------------------------------------------------------------
def run(a):
    a.op = a.op  # for _require_hw messages
    if a.op == "dry-run":
        return op_dry_run(a)
    if a.op == "configure":
        return op_configure(a)
    if a.op == "verify":
        return op_verify(a)
    if a.op == "evidence-dump":
        return op_evidence_dump(a)
    if a.op == "disable-bor":
        return op_disable_bor(a)
    if a.op == "disable-rrc":
        return op_disable_rrc(a)
    if a.op == "rollback":
        return op_rollback(a)
    if a.op == "recover":
        return op_recover(a)
    sys.stderr.write("unknown op %r\n" % a.op)
    return 2


def main(argv=None):
    ap = argparse.ArgumentParser(description="Defense 4 faithful two-pipe BOR + RRC control-plane setup")
    ap.add_argument("op", choices=["dry-run", "configure", "verify", "evidence-dump",
                                   "disable-bor", "disable-rrc", "rollback", "recover"])
    # programs / pipe_scope
    ap.add_argument("--program-pipe0", dest="program_pipe0", default=PROGRAM_PIPE0_DEFAULT,
                    help="pipe-0 program name in the two-program .conf (pipe_scope [0])")
    ap.add_argument("--program-pipe1", dest="program_pipe1", default=PROGRAM_PIPE1_DEFAULT,
                    help="pipe-1 program name in the two-program .conf (pipe_scope [1])")
    # pipe-0 timing (forwarded to the caseA subprocess)
    ap.add_argument("--mode", default="D4",
                    help="pipe-0 timing mode (OFF/D1/D2/D3/D4/FAIL_OPEN); BOR needs both holds -> D1/D4")
    ap.add_argument("--d-a-ms", dest="d_a_ms", type=float, default=16.0,
                    help="D_A hold in ms; also the default OPERATE ACK release total A")
    ap.add_argument("--d-r-ms", dest="d_r_ms", type=float, default=6.0,
                    help="D_R hold in ms; R defaults to D_A+D_R")
    ap.add_argument("--d-a", dest="d_a", type=lambda x: int(x, 0), default=None,
                    help="expert: D_A deadline WORD in ns (low byte 0, >= 1 ms for a D-mode)")
    ap.add_argument("--d-r", dest="d_r", type=lambda x: int(x, 0), default=None,
                    help="expert: D_R deadline WORD in ns (low byte 0, >= 1 ms for a D-mode)")
    ap.add_argument("--budget", type=int, default=18000, help="fail-open budget (18000 -> ~30.8 ms horizon)")
    ap.add_argument("--poll-ms", dest="poll_ms", type=float, default=400.0)
    # BOR deadline set (all ms)
    ap.add_argument("--op-j-ms", dest="op_j_ms", type=float, default=10.0,
                    help="operating J (ms); must be in --j-set and <= J_max")
    ap.add_argument("--j-set", dest="j_set", default="0,2,4,6,8,10,12",
                    help="admissible J codebook (ms, comma-separated); J_max = max")
    ap.add_argument("--op-a-ms", dest="op_a_ms", type=float, default=None,
                    help="override the OPERATE ACK release total A (ms); default = D_A")
    ap.add_argument("--op-r-ms", dest="op_r_ms", type=float, default=None,
                    help="override the OPERATE echo release total R (ms); default = D_A+D_R")
    ap.add_argument("--native-ack-ms", dest="native_ack_ms", type=float, default=1.9)
    ap.add_argument("--native-resp-ms", dest="native_resp_ms", type=float, default=1.9)
    ap.add_argument("--guard-ms", dest="guard_ms", type=float, default=5.0)
    ap.add_argument("--master-timeout-ms", dest="master_timeout_ms", type=float, default=200.0)
    ap.add_argument("--tcp-rto-ms", dest="tcp_rto_ms", type=float, default=200.0)
    ap.add_argument("--op-actuation-ms", dest="op_actuation_ms", type=float, default=100.0)
    ap.add_argument("--op-latency-budget-ms", dest="op_latency_budget_ms", type=float, default=50.0)
    ap.add_argument("--failopen-horizon-ms", dest="failopen_horizon_ms", type=float, default=None,
                    help="override the fail-open horizon (ms); default computed from --budget")
    # TCP-timestamp preflight vectors (offline; hardware feeds these from the captured handshake)
    ap.add_argument("--syn-options", dest="syn_options", default=None,
                    help="protected-flow SYN TCP options (hex) for the timestamp preflight")
    ap.add_argument("--synack-options", dest="synack_options", default=None,
                    help="protected-flow SYN-ACK TCP options (hex) for the timestamp preflight")
    # ports
    ap.add_argument("--port-vision", type=int, default=PORT_VISION)
    ap.add_argument("--port-relay", type=int, default=PORT_RELAY)
    ap.add_argument("--port-l", type=int, default=PORT_L)
    ap.add_argument("--port-pgen", type=int, default=PORT_PGEN)
    ap.add_argument("--port-x1", type=int, default=PORT_X1)
    ap.add_argument("--port-l1", type=int, default=PORT_L1)
    ap.add_argument("--port-pgen1", type=int, default=PORT_PGEN1)
    ap.add_argument("--pipe1-lpbk-speed", dest="pipe1_lpbk_speed", default="BF_SPEED_25G")
    # pipe-1 reservoir / codebook / mirror / pktgen
    ap.add_argument("--k-op", dest="k_op", type=int, default=K_OP, help="qid3 OPERATE reservoir depth")
    ap.add_argument("--relay-dst-port", dest="relay_dst_port", type=int, default=RELAY_DST_PORT,
                    help="tbl_bor_codebook key: relay-facing DNP3 TCP dst port")
    ap.add_argument("--pipe1-app-id", dest="pipe1_app_id", type=int, default=PIPE1_APP_ID)
    ap.add_argument("--pipe1-clone-sid", dest="pipe1_clone_sid", type=int, default=PIPE1_CLONE_SID)
    ap.add_argument("--token-len", dest="token_len", type=int, default=getattr(d3, "TOKEN_LEN", 60))
    ap.add_argument("--buf-offset", dest="buf_offset", type=int, default=144)
    ap.add_argument("--mirror-max-len", dest="mirror_max_len", type=int, default=128)
    # infra
    ap.add_argument("--master-ip", dest="master_ip", default="10.10.54.19")
    ap.add_argument("--relay-ip", dest="relay_ip", default="192.168.10.7")
    ap.add_argument("--grpc", default="localhost:50052")
    a = ap.parse_args(argv)
    return run(a)


if __name__ == "__main__":
    sys.exit(main())

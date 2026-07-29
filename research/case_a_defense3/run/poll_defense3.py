#!/usr/bin/env python3
"""
poll_defense3.py — the ON-SWITCH trial driver for DEFENSE 3, §13 GATE 2.

Drives the SYNTHETIC-EVENT build of
    research/case_a_defense3/p4/case_a_defense3_fixed_ack_delay.p4
compiled with  -DD3_SYNTH_EVENTS.

AUTHORED OFF-SWITCH. Nothing here has been executed against bf_switchd by this
work. The synthetic build has NOT been loaded; loading it displaces whatever is
running and is a separate, explicitly authorized step that this file does not
take and `run/run_defense3.sh` refuses to take.

---------------------------------------------------------------------------
WHY THIS FILE EXISTS AT ALL

§13 Gate 2 needs a synthetic READ, ACK and RESPONSE. The P4 carries a
`D3_REPLAY_ON_HULK` ifdef for a host-side injector on dp11, but **dp11 is not
configured and its link is dark**, so that path is unavailable. The events are
therefore generated INSIDE the chip by a SECOND packet-generator application,
the construction proven in
    research/case_a_read_anchored_dual_release/p4/case_a_dual_min.p4  (FROZEN).

    app 1  trigger_recirc_pattern  — the K=64 blocker reservoir, fired by the
           READ's own mirrored 0xE1 clone. Already built for Gate 1; untouched.
    app 2  trigger_timer_one_shot  — ONE batch of THREE synthetic events spaced
           by the HARDWARE inter-packet gap `ipg`.

THE SPACING MUST BE HARDWARE, AND THAT IS NOT A STYLE CHOICE. gRPC write skew
is milliseconds; D is 2 ms; the RESPONSE has to land inside the hold window and
the ACK has to land after the reservoir is standing. Three host-armed timers
cannot express that at all. A SCENARIO IS THEREFORE EXACTLY (ipg, role map) —
no second P4 variant, no recompile.

---------------------------------------------------------------------------
WHAT IS REAL AND WHAT IS NOT (the same ledger as the P4's own header)

All three events are byte-identical copies of ONE buffer template: a real
relay->master PURE TCP ACK, data_offset 8 / total_len 52 (the corpus case). The
only hardware difference between them is `packet_id`, and `tbl_synth_role` maps
packet_id -> transaction role.

  REAL for all three : the ipv4 ihl / MF / frag_offset gate, the TCP
                       flags-and-length gate, the seq / ack / master-port
                       comparisons (real SALUs, real decode-table keys), the
                       generation state machine, the K=64 reservoir, the
                       deadline arm-once, the queues, the release path.
  RELAXED            : `ingress_port == PORT_RELAY` (CONSENSUS §8.1 conjunct 1)
                       — a generated packet arrives on dp68; and the reverse
                       5-tuple lookup is served by tbl_synth_role instead of
                       tbl_session (one template, one 5-tuple, three roles).
  NOT EXERCISED      : the DNP3 content gates for the READ and the RESPONSE
                       (their roles come from packet_id), and data-plane
                       LEARNING of EXP_RELAY_SEQ / the master's ephemeral port
                       — there is no real connection and no SYN here, so this
                       script SEEDS reg_exp_relay_seq and reg_session_port.
                       EXP_ACK is still installed by the synthetic READ through
                       the real exp_ack_w SALU: the template is built with
                       ack_no == seq_no + read_len so the real arithmetic lands
                       on the template's own acknowledgment.

---------------------------------------------------------------------------
THE FIVE BLOCKING CONTROLS (CONSENSUS §7), all enforced here

  R1  dp8 $SPEED == BF_SPEED_25G is asserted BEFORE every trial and the run
      ABORTS otherwise (exit 4). K=64's margin and the fail-open horizon both
      scale with it; a prior campaign was silently voided by dp8 at 10G.
  R2  RESERVOIR STANDING: t_first_blocker_admitted - t_READ must be < 100 us.
      The ACK arrives a measured minimum of 0.400 ms after the READ, so a late
      reservoir is a SILENT ZERO-HOLD that reads as a working run. reg_ts_read
      exists in the synthetic build for exactly this measurement.
  R4  ACK_RELEASE_FAILOPEN == 0. A fail-open release means the trial measured
      the pass budget B, not D. Scored by the analyzer from
      CD_BLOCK_TERM_TMO + CD_RELEASE_FAILOPEN.
  R5  THE DEADLINE INSTANT IS NOT THE RELEASE INSTANT. They differ by a
      deterministic K/rate = 1.711 us bias. This file records K and rate_dp8 in
      the manifest so the analyzer scores against D + K/rate; scoring against D
      logs 1.7 us of systematic offset as jitter.
  R6  the per-queue and dp8 PORT shapers are forced off and read back (inherited
      from the Gate-1 setup, which this file reuses rather than reimplements).

  Plus §1.3: a trial ASSERTS A CLEAN START and REFUSES to run dirty (exit 3),
  and cleanup runs from a `finally` so an INVALID trial leaves the switch in
  exactly the state a PASS does.

---------------------------------------------------------------------------
---------------------------------------------------------------------------
TODO(silicon): THE THREE SYNTHETIC FRAMES ARE FORWARDED TO dp9 (Vision).
  The synthetic READ, the released ACK and the released RESPONSE all take the
  REAL forward path, D3_TO_FWD() -> meta.fwd_port -> dp9 qid 0, deliberately:
  using the real egress is what makes the release path under test the same one
  the campaign uses. If dp9 is DOWN the three frames are dropped inside the TM.
  That affects NO Gate-2 measurement — every quantity scored here is an
  INGRESS-side register or counter, all of them written before the frame ever
  reaches dp9 — but it is worth knowing rather than discovering.
  RESOLVING CHECK: out["snapshot"]["ports"]["dp9"]["$PORT_UP"], recorded every
  run, and the dp9 queue drop counters. Three frames per trial cannot fill
  anything, but a long campaign on a down dp9 accumulates them.

---------------------------------------------------------------------------
ENVIRONMENT: python3.8 on the switch, STDLIB ONLY (numpy is not installed
there). The Gate-1 setup module is IMPORTED, not copied, so there is one
definition of every bfrt idiom:

    SDE=/home/decps/Downloads/bf-sde-9.13.2
    SP="$SDE/install/lib/python3.8/site-packages"
    PYTHONPATH=$SP:$SP/tofino python3.8 poll_defense3.py --gate2

Machine-readable stdout tag: `D3GATE2 {json}`.
Exit codes: 0 ok / 1 checks failed / 2 nothing to do / 3 dirty start / 4 dp8 speed.
"""

import argparse
import json
import os
import sys
import time

# The Gate-1 control plane is imported for every bfrt idiom (table lookup,
# register/counter access, queue + shaper config, speed assertion, cleanup).
# Both the in-repo layout (../setup) and a flat staging directory on the switch
# are supported, because the switch copy is staged flat.
_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(_HERE, os.pardir, "setup")):
    _p = os.path.abspath(_p)
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)
import case_a_defense3_fixed_ack_delay_setup as d3     # noqa: E402


SCHEMA = "d3_gate2/1"

# ---------------------------------------------------------------------------
# Synthetic-event constants. Every one mirrors the P4 it drives.
# ---------------------------------------------------------------------------
APP_EVENT_DEFAULT = 2       # -> generator header byte 0 (pipe 0) = 0x02,
                            #    the pgen_event value_set match. Distinct from
                            #    app 1's 0x01 and from the 0xE1 clone marker.
ETYPE_SYNTH_ACK  = 0x88C6   # const bit<16> ETYPE_SYNTH_ACK  = 0x88C6
ETYPE_SYNTH_RESP = 0x88C7   # const bit<16> ETYPE_SYNTH_RESP = 0x88C7

# The event buffer template lives well past the 60-byte blocker template at
# offset 0. 128 keeps the two provably disjoint with room to grow.
BUF_OFF_EVENT_DEFAULT = 128

# Synthetic frame identity. Locally-administered MACs; these frames exist only
# inside the chip and on the dp9 forward leg.
SYN_RELAY_MAC  = bytes([0x02, 0x00, 0x00, 0x00, 0x07, 0x51])
SYN_MASTER_MAC = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
SYN_SEQ_DEFAULT   = 0x11223344   # the relay's SND.NXT == EXP_RELAY_SEQ
SYN_MPORT_DEFAULT = 51000        # the master's ephemeral port
SYN_TSVAL = 0x0A0B0C0D
SYN_TSECR = 0x01020304

# Generation for the synthetic transaction. tbl_txn_active recognises 0xC0..0xCF
# and the parser pins the live domain to the same range, so a synthetic
# generation must live there too or txn_active reads 0 and nothing holds.
GEN_DEFAULT = 0xC0

# Gate-2 scenario: (ipg_ns, packet_id -> role). ONE ipg spaces both gaps, so it
# must satisfy   reservoir_standing < ipg   and   ipg < D.
#   ipg = 500 us with D = 2 ms gives  t_ACK  = t_READ + 500 us
#                                     t_RESP = t_ACK  + 500 us  (EARLY, held)
# and leaves 4x headroom on the R2 bound of 100 us.
SCENARIOS = {
    "gate2-normal": {"ipg_ns": 500000, "map": {0: "READ", 1: "ACK", 2: "RESP"}},
}

# ---- indexed counter slots. COMPILE-TIME CONSTANTS in the P4; named here so
# the JSON the analyzer reads is self-describing rather than positional. ----
CF_SLOTS = {
    "BYPASS_FWD": 0, "BAD_PORT": 1, "ARM_FRESH": 2, "ARM_DUP": 3, "ARM_BUSY": 4,
    "ACK_HOLD": 5, "ACK_DUP_HOLD": 6, "ACK_REJECT": 7, "RESP_HOLD_EARLY": 8,
    "RESP_HOLD_LATE": 9, "RESP_BYPASS": 10, "UNSUP_SEG": 11, "BLOCK_ENQ": 12,
    "PKTGEN_ADMIT": 13, "PKTGEN_DROP": 14,
}
CD_SLOTS = {
    "BLOCK_LOOP": 0, "BLOCK_TERM_STALE": 1, "BLOCK_TERM_DL": 2,
    "BLOCK_TERM_TMO": 3, "RELEASE_DEADLINE": 4, "RELEASE_FAILOPEN": 5,
    "ACK_RELEASE": 6,
}

# Registers the synthetic build adds and that must be zeroed / read back.
SYNTH_REGS = ("reg_ts_read", "reg_ts_resp_release")

TS_REGS = ("reg_ts_read", "reg_ts_first_block", "reg_ts_ack_arm",
           "reg_ts_block_term", "reg_ts_ack_release", "reg_ts_resp_release")
STATE_REGS = ("reg_tag", "reg_deadline", "reg_ack_rel", "reg_exp_relay_seq",
              "reg_exp_ack", "reg_session_port")


# ===========================================================================
# Offline: the synthetic event template
# ===========================================================================
def _ck16(data):
    """Ones-complement Internet checksum over a byte string."""
    if len(data) % 2:
        data = data + b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_event_template(relay_ip, master_ip, mport, seq, read_len):
    """The ONE buffer template all three synthetic events are copies of.

    A REAL relay->master pure TCP ACK: ihl 5, DF set, no fragment, flags 0x10
    exactly, data_offset 8 with a 12-byte NOP/NOP/Timestamp option block, and
    ip.total_len == 20 + 4*data_offset == 52. Those are precisely the fields
    parse_ipv4 and parse_tcp gate on, so the ACK reaches ROLE_ACK through the
    REAL parser with nothing relaxed.

    ack_no == seq_no + read_len IS LOAD-BEARING AND IS THE WHOLE TRICK that
    keeps EXP_ACK real. The synthetic READ is a copy of this same frame, so the
    real exp_ack_w SALU computes  EXP_ACK = tcp.seq_no + read_len  and stores
    exactly this frame's ack_no; the synthetic ACK and RESPONSE then compare
    against it through the real exp_ack_r SALU and read a difference of 0. No
    register pre-seeding, no weakened decode entry.

    The pktgen hardware PREPENDS the 6-byte generator header, so this buffer
    holds only what follows it: exactly what the P4 parses after
    extract(hdr.pgen) -> parse_eth.
    """
    if not (0 <= mport <= 0xFFFF):
        raise ValueError("master ephemeral port out of range: %r" % (mport,))
    ack = (seq + read_len) & 0xFFFFFFFF

    opts = (bytes([0x01, 0x01, 0x08, 0x0A])
            + SYN_TSVAL.to_bytes(4, "big") + SYN_TSECR.to_bytes(4, "big"))
    assert len(opts) == 12, "the option block must make data_offset exactly 8"
    data_offset = 5 + len(opts) // 4                    # == 8
    total_len = 20 + 20 + len(opts)                     # == 52

    src_ip, dst_ip = d3.ip2int(relay_ip), d3.ip2int(master_ip)

    ip = bytearray()
    ip += bytes([0x45, 0x00])                           # version/ihl=5, dscp 0
    ip += total_len.to_bytes(2, "big")
    ip += bytes([0xAB, 0xCD])                           # identification
    ip += (0x4000).to_bytes(2, "big")                   # DF set: tolerated by
                                                        # the 0xBFFF/0x0000 gate
    ip += bytes([64, 6])                                # ttl, proto TCP
    ip += bytes([0x00, 0x00])                           # checksum placeholder
    ip += src_ip.to_bytes(4, "big")
    ip += dst_ip.to_bytes(4, "big")
    ipck = _ck16(bytes(ip))
    ip[10:12] = ipck.to_bytes(2, "big")

    tcp = bytearray()
    tcp += d3.DNP3_PORT.to_bytes(2, "big")              # relay src port 20000
    tcp += mport.to_bytes(2, "big")                     # master ephemeral dst
    tcp += seq.to_bytes(4, "big")
    tcp += ack.to_bytes(4, "big")
    tcp += bytes([(data_offset << 4) | 0x00, 0x10])     # data_offset, flags ACK
    tcp += (8192).to_bytes(2, "big")                    # window
    tcp += bytes([0x00, 0x00])                          # checksum placeholder
    tcp += bytes([0x00, 0x00])                          # urgent pointer
    tcp += opts
    pseudo = (src_ip.to_bytes(4, "big") + dst_ip.to_bytes(4, "big")
              + bytes([0, 6]) + len(tcp).to_bytes(2, "big"))
    tck = _ck16(pseudo + bytes(tcp))
    tcp[16:18] = tck.to_bytes(2, "big")

    frame = bytes(SYN_MASTER_MAC) + bytes(SYN_RELAY_MAC) + b"\x08\x00" \
        + bytes(ip) + bytes(tcp)
    meta = {
        "len": len(frame),                              # 14 + 52 = 66
        "eth_dst": SYN_MASTER_MAC.hex(), "eth_src": SYN_RELAY_MAC.hex(),
        "ip_src": relay_ip, "ip_dst": master_ip,
        "ip_total_len": total_len, "ip_ihl": 5, "ip_flags_frag": "0x4000 (DF)",
        "tcp_src_port": d3.DNP3_PORT, "tcp_dst_port": mport,
        "tcp_seq": seq, "tcp_ack": ack, "tcp_data_offset": data_offset,
        "tcp_flags": "0x10", "read_len_implied": read_len,
        "hex": frame.hex(),
    }
    return frame, meta


def offline_synth_checks(a, out, chk):
    """Everything about the synthetic path that needs no switch."""
    tmpl, tmeta = build_event_template(a.relay_ip, a.master_ip, a.mport,
                                       a.syn_seq, a.read_len)
    out["event_template"] = tmeta

    # The parse_tcp pure-ACK gate is (flags & 0x3F) == 0x10 AND
    # total_len == 20 + 4*data_offset. Check the template satisfies it here,
    # because a template that misses it produces CF_ACK_REJECT == 1 on silicon
    # and looks like a predicate bug rather than a template bug.
    chk.expect("template ip.total_len == 20 + 4*data_offset",
               tmeta["ip_total_len"], 20 + 4 * tmeta["tcp_data_offset"])
    chk.expect("template tcp.flags == 0x10 (pure ACK)", tmeta["tcp_flags"], "0x10")
    chk.expect("template ack_no == seq_no + read_len (keeps EXP_ACK real)",
               tmeta["tcp_ack"], (a.syn_seq + a.read_len) & 0xFFFFFFFF)
    chk.expect("template length", tmeta["len"], 66)

    sc = SCENARIOS.get(a.scenario)
    if sc is None:
        chk.fail("scenario known", "%r not in %s" % (a.scenario, sorted(SCENARIOS)))
        return
    ipg = a.ipg_ns if a.ipg_ns is not None else sc["ipg_ns"]
    out["scenario"] = {"name": a.scenario, "ipg_ns": ipg,
                       "map": {str(k): v for k, v in sc["map"].items()}}

    qd = d3.quantize_d(a.d_ms)
    # The two inequalities the single hardware ipg has to satisfy at once.
    if ipg >= qd["realized_ns"]:
        chk.fail("ipg < D (the RESPONSE must arrive INSIDE the hold window)",
                 "ipg=%d ns, D=%d ns: the RESPONSE would arrive after the "
                 "deadline and Gate 2's 'one early RESPONSE' would not be "
                 "exercised at all" % (ipg, qd["realized_ns"]))
    else:
        chk.ok("ipg < D", "ipg=%d ns < D=%d ns" % (ipg, qd["realized_ns"]))
    if ipg <= a.r2_bound_ns:
        chk.fail("ipg > the R2 reservoir bound",
                 "ipg=%d ns <= %d ns: the ACK could arrive before the K=64 "
                 "reservoir is standing, which is a SILENT zero-hold"
                 % (ipg, a.r2_bound_ns))
    else:
        chk.ok("ipg > the R2 reservoir bound (%d ns)" % a.r2_bound_ns,
               "ipg=%d ns" % ipg)

    if not (0xC0 <= a.gen <= 0xCF):
        chk.fail("generation inside tbl_txn_active's 0xC0..0xCF domain",
                 "gen=0x%02X: txn_active would read 0 and NOTHING would be held"
                 % a.gen)
    else:
        chk.ok("generation inside 0xC0..0xCF", "0x%02X" % a.gen)

    # R5, recorded in the manifest so the analyzer cannot silently score against D.
    tau_ns = (float(a.k) / float(d3.RATE_DP8_PPS)) * 1e9
    out["release_bias"] = {"k": a.k, "rate_dp8_pps": d3.RATE_DP8_PPS,
                           "tau_ns": tau_ns,
                           "note": "R5: the release instant is the deadline plus "
                                   "this deterministic K/rate bias. Score the hold "
                                   "against D + tau, not D."}
    chk.ok("R5 release bias recorded", "K/rate = %.3f ns" % tau_ns)


# ===========================================================================
# On-switch: the synthetic-path configuration
# ===========================================================================
def _set_app(bi, tgt, app_id, enable, chk=None):
    """Toggle ONE generator app by id.

    d3.set_app_enable only ever addresses app 1, and a one-shot app does NOT
    auto-disable after its batch, so it must be driven False before it can be
    re-armed True.
    """
    import bfrt_grpc.client as gc
    acfg = d3.get_table(bi, d3.PKTGEN_APP_CFG, chk)
    if acfg is None:
        return False
    try:
        acfg.entry_mod(tgt, [acfg.make_key([gc.KeyTuple("app_id", app_id)])],
                       [acfg.make_data([gc.DataTuple("app_enable", bool_val=enable)])])
        return True
    except Exception as e:                                       # noqa: BLE001
        if chk is not None:
            chk.fail("app %d enable=%s" % (app_id, enable), str(e)[:90])
        return False


def _read_app(bi, tgt, app_id):
    got, err = d3.get_entry(d3.get_table(bi, d3.PKTGEN_APP_CFG), tgt,
                            [("app_id", app_id)])
    if err:
        return {"err": err}
    return {k: got.get(k) for k in
            ("app_enable", "trigger_counter", "batch_counter", "pkt_counter",
             "pkt_len", "pkt_buffer_offset", "ipg", "ibg", "batch_count_cfg",
             "packets_per_batch_cfg", "increment_source_port",
             "pipe_local_source_port")}


# ===========================================================================
# F01 microbenchmark: PER-PIPE readback
# ---------------------------------------------------------------------------
# Every readback the failed Gate-2 run used collapses the four pipes into one
# number: d3.reg_read and d3.ctr_read run the raw list through _flatten_max,
# and d3.get_entry keeps only the LAST entry the iterator yields. That is fine
# when exactly one pipe is doing anything, and it is actively misleading when
# that assumption is what is in question — the failure packet's three symptoms
# are all "a number that does not add up across pipes".
#
# Two specific traps these helpers exist to avoid:
#   * reg_tag's INITIAL value is 0xFF and its ARMED value is 0xC0, so `max`
#     over the pipes returns the value of an IDLE pipe and an armed pipe 0 is
#     invisible. Any register whose written value is numerically BELOW its
#     initial value is unreadable through _flatten_max.
#   * a pktgen app configured at device scope exists in every pipe; whether the
#     counters come back per pipe or aggregated is exactly what "fired twice"
#     needs settled.
# ===========================================================================
def _pipe_targets(n_pipes):
    import bfrt_grpc.client as gc
    return [(p, gc.Target(device_id=0, pipe_id=p)) for p in range(n_pipes)]


def read_num_pipes(bi):
    """num_pipes from the FIXED table tf1.dev.device_configuration.

    This is not cosmetic. `bf_pktgen_get_{trigger,batch,pkt}_counter` SUM over
    `start_pipe..num_active_pipes-1` when the target is BF_DEV_PIPE_ALL, and a
    BfRt Target defaults to pipe_id 0xFFFF — so a device-scope pktgen counter
    readback returns the SUM ACROSS PIPES, while the configuration fields in the
    same readback come from pipe 0's shadow only. A timer app armed at device
    scope arms one generator PER PIPE, so on an N-pipe device ONE arm reads back
    as trigger_counter == N. Without num_pipes in the manifest that number has
    no interpretation at all.
    """
    for name in ("tf1.dev.device_configuration", "device_configuration"):
        try:
            t = bi.table_get(name)
        except Exception:
            continue
        try:
            import bfrt_grpc.client as gc
            for d, _ in t.default_entry_get(gc.Target(device_id=0)):
                dd = d.to_dict()
                return {"num_pipes": dd.get("num_pipes"),
                        "sku": dd.get("sku"),
                        "num_stages": dd.get("num_stages"),
                        "source": name}
        except Exception as e:                                   # noqa: BLE001
            return {"err": "%s: %s" % (name, str(e)[:80])}
    return {"err": "device_configuration table not found"}


def _probe_n_pipes(bi, max_pipes=4):
    """How many pipes answer a pipe-scoped read? Measured, not assumed."""
    import bfrt_grpc.client as gc
    t = d3.get_table(bi, d3.PKTGEN_APP_CFG)
    if t is None:
        return 0, {}
    seen = {}
    for p in range(max_pipes):
        tp = gc.Target(device_id=0, pipe_id=p)
        got, err = d3.get_entry(t, tp, [("app_id", 1)])
        seen[p] = "ok" if not err else str(err)[:60]
    return sum(1 for v in seen.values() if v == "ok"), seen


def _read_app_per_pipe(bi, app_id, n_pipes):
    out = {}
    for p, tp in _pipe_targets(n_pipes):
        got, err = d3.get_entry(d3.get_table(bi, d3.PKTGEN_APP_CFG), tp,
                                [("app_id", app_id)])
        out["pipe%d" % p] = {"err": str(err)[:80]} if err else {
            k: got.get(k) for k in ("app_enable", "trigger_counter",
                                    "batch_counter", "pkt_counter")}
    return out


def _reg_read_per_pipe(bi, name, n_pipes, idx=0):
    """Register value per pipe, WITHOUT the max() collapse."""
    import bfrt_grpc.client as gc
    t = d3.get_table(bi, name)
    if t is None:
        return {}
    out = {}
    for p, tp in _pipe_targets(n_pipes):
        k = t.make_key([gc.KeyTuple("$REGISTER_INDEX", idx)])
        try:
            vals = []
            for d, _ in t.entry_get(tp, [k], {"from_hw": True}):
                dd = d.to_dict()
                for kk, vv in dd.items():
                    if kk == "$REGISTER_INDEX" or kk == "action_name" \
                            or kk.startswith("is_"):
                        continue
                    vals.append(vv)
            flat = []
            stack = list(vals)
            while stack:
                v = stack.pop()
                if isinstance(v, (list, tuple)):
                    stack.extend(v)
                elif isinstance(v, int):
                    flat.append(v)
            out["pipe%d" % p] = flat if len(set(flat)) > 1 else (
                flat[0] if flat else None)
        except Exception as e:                                   # noqa: BLE001
            out["pipe%d" % p] = "err: %s" % str(e)[:60]
    return out


def _ctr_read_per_pipe(bi, name, idx, n_pipes):
    import bfrt_grpc.client as gc
    t = d3.get_table(bi, name)
    if t is None:
        return {}
    out = {}
    for p, tp in _pipe_targets(n_pipes):
        try:
            t.operations_execute(tp, "SyncCounters")
        except Exception:
            pass
        k = t.make_key([gc.KeyTuple("$COUNTER_INDEX", idx)])
        try:
            tot = 0
            for d, _ in t.entry_get(tp, [k], {"from_hw": True}):
                dd = d.to_dict()
                if "$COUNTER_SPEC_PKTS" in dd:
                    v = dd["$COUNTER_SPEC_PKTS"]
                    tot = max(tot, v if isinstance(v, int) else 0)
            out["pipe%d" % p] = tot
        except Exception as e:                                   # noqa: BLE001
            out["pipe%d" % p] = "err: %s" % str(e)[:60]
    return out


def config_event_value_set(bi, a, out, chk, write=True):
    """The app-2 discriminator byte, on the SECOND parser value_set.

    A separate value_set from pgen_recirc, not a second entry in it, because the
    two apps take different parser paths: a blocker token's generator header is
    ADVANCED over, an event's is EXTRACTED so packet_id can be read.

    THE MASK MUST BE EXACT 0xFF. Under the SDE example's 0x1F the 0xE1 clone
    marker aliases onto an app id and the recirculated clone is mis-admitted —
    the failure that cost a silicon run on Defense 2.

    TODO(silicon): TWO value_sets FEEDING ONE PARSER SELECT. bf-p4c accepts it
      (both resolve in bfrt.json as pipe.IgParser.pgen_recirc and
      pipe.IgParser.pgen_event), and both are programmed on parser 17 in pipe 0
      with an exact mask, but a two-value_set select has not been run on this
      switch.
      RESOLVING CHECK: ctr_fresh[BAD_PORT] == 0 after a transaction, with
      ctr_fresh[PKTGEN_ADMIT] == 64 AND ctr_fresh[ARM_FRESH] == 1. BAD_PORT
      counting the events (3) or the tokens (64) is what a value_set that did
      not take looks like, and the two are distinguishable by the count.
    """
    import bfrt_grpc.client as gc
    vs_byte = (a.pipe << 3) | a.app_event
    out["event_value_set"] = {"byte": vs_byte, "mask": 0xFF,
                              "prsr_id": d3.PGEN_PRSR_ID, "pipe": a.pipe}
    if vs_byte == ((a.pipe << 3) | a.app_id):
        chk.fail("app 2 byte distinct from app 1", "both resolve to 0x%02X" % vs_byte)
        return
    if vs_byte == d3.CLONE_TAG_MARKER:
        chk.fail("app 2 byte distinct from the 0xE1 clone marker",
                 "0x%02X" % vs_byte)
        return
    try:
        vs = bi.table_get("pipe.IgParser.pgen_event")
    except Exception as e:                                       # noqa: BLE001
        chk.fail("value_set pgen_event lookup",
                 "%s — is the SYNTHETIC build (-DD3_SYNTH_EVENTS) loaded?"
                 % str(e)[:80])
        return
    if write:
        if d3.bfr_pb2 is not None:
            try:
                vs.attribute_entry_scope_set(
                    gc.Target(device_id=0, pipe_id=0xffff),
                    config_pipe_scope=True, predefined_pipe_scope=True,
                    predefined_pipe_scope_val=d3.bfr_pb2.Mode.SINGLE,
                    config_gress_scope=True,
                    predefined_gress_scope_val=d3.bfr_pb2.Mode.ALL,
                    config_prsr_scope=True,
                    predefined_prsr_scope_val=d3.bfr_pb2.Mode.SINGLE)
            except Exception as se:                              # noqa: BLE001
                out["event_value_set_scope_note"] = \
                    "scope already set (ok on re-run): " + str(se)[:40]
        vtgt = gc.Target(device_id=0, pipe_id=a.pipe, prsr_id=d3.PGEN_PRSR_ID)
        vkey = [vs.make_key([gc.KeyTuple("f1", vs_byte, 0xFF)])]
        try:
            vs.entry_del(vtgt, vkey)          # idempotent
        except Exception:
            pass
        try:
            vs.entry_add(vtgt, vkey)
        except Exception as e:                                   # noqa: BLE001
            chk.fail("value_set pgen_event add", str(e)[:90])
            return
    chk.ok("value_set pgen_event programmed",
           "byte=0x%02X mask=0xFF" % vs_byte)


def config_event_app(bi, tgt, a, out, chk, ipg_ns, write=True):
    """app 2: ONE batch of THREE events, ipg apart, one-shot timer, DISABLED.

    Counts are ZERO-BASED: batch_count_cfg = 0 is ONE batch and
    packets_per_batch_cfg = 2 is THREE packets.

    ONE batch is also what makes packet_id unique across the burst: packet_id
    restarts at 0 for every batch, so two batches would both emit packet_id 0
    with no way to tell them apart.

    increment_source_port MUST be False (it caps packets_per_batch at 127-68=59
    and is the only driver bound on batch size), and pipe_local_source_port is
    REQUIRED on this silicon despite the SDE's "implicit on Tofino-1" note —
    without it the generated packets carry the wrong ingress_port, miss
    from_pgen entirely and are dropped with port_ok = 0. The localizing symptom
    is pkt_counter = 3 with CF_BAD_PORT = 3.

    TODO(silicon): TWO GENERATOR APPS ON ONE PORT, ONE OF EACH TRIGGER KIND.
      Defense 2 proved a single recirculation-pattern app on dp68 on this
      switch; nothing has yet run a timer app beside it. The apps have
      independent configuration and independent counters, so they should not
      interact, but that is an inference.
      RESOLVING CHECK: after ONE transaction,
        app_event.pkt_counter == 3            (three events emitted)
        app_block.trigger_counter == 1        (the clone fired the reservoir)
        app_block.pkt_counter == 64           (K tokens emitted)
      All three are in out["pktgen_after"]. Any one of them at 0 while the
      others are right localizes the failure to that app alone.

    TODO(silicon): THE CLONE THAT TRIGGERS app 1 IS NOW ITSELF A dp68 PACKET.
      In Defense 2 the READ that produced the mirrored 0xE1 clone arrived on a
      HOST port. Here the synthetic READ arrives on dp68, so the mirror copy is
      a dp68 packet mirrored back to dp68. The pattern matcher inspects frames
      arriving on the recirculation port and should not care where the mirror
      came from — but that has not been observed, and it is the single point
      that could give a Gate-2 run zero blockers.
      RESOLVING CHECK: ctr_fresh[ARM_FRESH] == 1 together with
      app_block.trigger_counter == 1. ARM_FRESH == 1 with trigger_counter == 0
      means the READ was processed and the clone was requested but nothing
      triggered, which is exactly this and nothing else.

    TODO(silicon): `timer_nanosec` is the one app_cfg field this program uses
      that the frozen Defense 2 setup never wrote (it only ever used
      trigger_recirc_pattern).
      RESOLVING CHECK: the app_cfg readback below must return without error and
      the arm must be followed by pkt_counter == 3 within a.wait_s. A driver
      that rejects the field fails at entry_mod with an explicit error, not
      silently.
    """
    import bfrt_grpc.client as gc
    tmpl, tmeta = build_event_template(a.relay_ip, a.master_ip, a.mport,
                                       a.syn_seq, a.read_len)

    if a.buf_off_event < len(d3.build_token_template(a.token_len)):
        chk.fail("event buffer offset clears the blocker template",
                 "offset %d overlaps the %d-byte token buffer at 0"
                 % (a.buf_off_event, a.token_len))
        return

    pbuf = d3.get_table(bi, d3.PKTGEN_PKT_BUFFER, chk)
    if pbuf is not None and write:
        try:
            pbuf.entry_mod(
                tgt,
                [pbuf.make_key([gc.KeyTuple("pkt_buffer_offset", a.buf_off_event),
                                gc.KeyTuple("pkt_buffer_size", len(tmpl))])],
                [pbuf.make_data([gc.DataTuple("buffer", bytearray(tmpl))])])
        except Exception as e:                                   # noqa: BLE001
            chk.fail("pktgen pkt_buffer (events)", str(e)[:90])

    acfg = d3.get_table(bi, d3.PKTGEN_APP_CFG, chk)
    if acfg is None:
        return
    if write:
        try:
            acfg.entry_mod(
                tgt,
                [acfg.make_key([gc.KeyTuple("app_id", a.app_event)])],
                [acfg.make_data([
                    gc.DataTuple("timer_nanosec", int(a.timer_ns)),
                    gc.DataTuple("pkt_len", len(tmpl)),
                    gc.DataTuple("pkt_buffer_offset", a.buf_off_event),
                    gc.DataTuple("pipe_local_source_port", a.port_pgen),
                    gc.DataTuple("increment_source_port", bool_val=False),
                    gc.DataTuple("batch_count_cfg", 0),          # ONE batch
                    gc.DataTuple("packets_per_batch_cfg", a.n_events - 1),
                    gc.DataTuple("ipg", int(ipg_ns)),
                    gc.DataTuple("ibg", 0),
                    gc.DataTuple("trigger_counter", 0),
                    gc.DataTuple("batch_counter", 0),
                    gc.DataTuple("pkt_counter", 0),
                    gc.DataTuple("app_enable", bool_val=False),
                ], "trigger_timer_one_shot")])
        except Exception as e:                                   # noqa: BLE001
            chk.fail("pktgen app_cfg (events, app %d)" % a.app_event, str(e)[:90])

    got = _read_app(bi, tgt, a.app_event)
    got["ipg_ns_requested"] = int(ipg_ns)
    got["timer_ns_requested"] = int(a.timer_ns)
    out["app_event"] = got
    if "err" in got:
        chk.warn("app %d readback" % a.app_event, str(got["err"])[:80])
        return
    chk.expect("app %d packets_per_batch_cfg (%d events)"
               % (a.app_event, a.n_events),
               got.get("packets_per_batch_cfg"), a.n_events - 1)
    chk.expect("app %d batch_count_cfg (1 batch)" % a.app_event,
               got.get("batch_count_cfg"), 0)
    chk.expect("app %d increment_source_port == False" % a.app_event,
               got.get("increment_source_port"), False)
    chk.expect("app %d pipe_local_source_port" % a.app_event,
               got.get("pipe_local_source_port"), a.port_pgen)
    chk.expect("app %d app_enable at config time" % a.app_event,
               got.get("app_enable"), False)
    # ipg is converted ns -> core clocks by the driver, so the readback is the
    # QUANTIZED value. Report the drift; fail only if it is large enough to
    # break one of the two inequalities offline_synth_checks enforced.
    gi = got.get("ipg")
    try:
        gi = int(gi)
    except (TypeError, ValueError):
        gi = None
    if gi is not None:
        drift = abs(gi - int(ipg_ns))
        got["ipg_ns_readback"] = gi
        if drift > max(1000, int(ipg_ns) // 1000):
            chk.fail("app %d ipg readback" % a.app_event,
                     "wrote %d ns, read %d ns" % (ipg_ns, gi))
        else:
            chk.ok("app %d ipg readback" % a.app_event,
                   "wrote %d ns, read %d ns (core-clock quantization)"
                   % (ipg_ns, gi))


def config_role_map(bi, tgt, a, out, chk, mapping, write=True):
    """packet_id -> transaction role. THE SCENARIO, in three table entries.

    packet_id 0 is the READ and carries the generation as action data. Which of
    packet_id 1 and 2 is the ACK and which the RESPONSE is written here, so a
    different arrival order is a control-plane change, not a recompile. All
    three entries are read back into the manifest: what ran is recorded, not
    assumed.
    """
    import bfrt_grpc.client as gc
    t = d3.get_table(bi, "tbl_synth_role", chk)
    if t is None:
        chk.fail("tbl_synth_role lookup",
                 "not found — is the SYNTHETIC build (-DD3_SYNTH_EVENTS) loaded?")
        return
    act_of = {"READ": ("synth_read", [("gen", a.gen)]),
              "ACK":  ("synth_ack", []),
              "RESP": ("synth_resp", [])}
    installed = {}
    if write:
        for pid, role in sorted(mapping.items()):
            act, params = act_of[role]
            key = t.make_key([gc.KeyTuple("hdr.pgen.packet_id", int(pid))])
            data = None
            for an in ("Ingress." + act, act):
                try:
                    data = t.make_data([gc.DataTuple(n, v) for n, v in params], an)
                    break
                except Exception:
                    continue
            if data is None:
                chk.fail("tbl_synth_role action %s" % act,
                         "make_data rejected both name forms")
                continue
            try:
                t.entry_add(tgt, [key], [data])
            except Exception:
                try:
                    t.entry_mod(tgt, [key], [data])
                except Exception as e:                           # noqa: BLE001
                    chk.fail("tbl_synth_role pid %s -> %s" % (pid, role),
                             str(e)[:90])
    for pid, role in sorted(mapping.items()):
        got, err = d3.get_entry(t, tgt, [("hdr.pgen.packet_id", int(pid))])
        installed[str(pid)] = err or {"action_name": got.get("action_name"),
                                      "gen": got.get("gen"), "want_role": role}
    out["role_map"] = installed
    ok = all(isinstance(v, dict) and v.get("action_name") for v in installed.values())
    if ok:
        chk.ok("tbl_synth_role installed",
               ", ".join("pid%s->%s" % (k, mapping[int(k)]) for k in sorted(installed)))
    else:
        chk.fail("tbl_synth_role readback", json.dumps(installed, default=str)[:160])


def seed_trackers(bi, tgt, a, out, chk, write=True):
    """Seed the two trackers the synthetic build cannot LEARN.

    In the live build reg_exp_relay_seq and reg_session_port are learned in the
    data plane from a master->relay frame on a real connection, ultimately
    seeded free by the three-way handshake. There is no master, no connection
    and no SYN here, so the control plane writes them.

    THIS IS A DISCLOSED RELAXATION, NOT A HIDDEN ONE. What the seeding buys is
    that the comparisons stay real: exp_seq_rmw and sess_port_rmw still execute,
    the differences still key the real decode entries, and a wrong seed shows up
    as CF_ACK_REJECT == 1 with CF_ACK_HOLD == 0 rather than as a mystery.

    reg_exp_ack is deliberately NOT seeded: the synthetic READ installs it
    through the real exp_ack_w SALU.
    """
    want = {"reg_exp_relay_seq": a.syn_seq & 0xFFFFFFFF,
            "reg_session_port": a.mport & 0xFFFF}
    if write:
        for name, val in want.items():
            d3.reg_write(bi, tgt, name, val, chk=chk)
    got = {name: d3.reg_read(bi, tgt, name) for name in want}
    out["seeded_trackers"] = {"written": want, "readback": got}
    for name, val in want.items():
        chk.expect("seed %s" % name, got.get(name), val)


def zero_synth_regs(bi, tgt):
    for r in SYNTH_REGS:
        d3.reg_write(bi, tgt, r, 0)


# ===========================================================================
# Clean start / cleanup, extended with the synthetic facts
# ===========================================================================
def read_clean_state_synth(bi, tgt, tgt0, a, out, chk):
    st = d3.read_clean_state(bi, tgt, tgt0, a, out, chk)
    ev = _read_app(bi, tgt, a.app_event)
    st["pktgen_event"] = ev
    if "err" in ev:
        st["reasons"].append("pktgen app %d unreadable: %s"
                             % (a.app_event, ev["err"]))
    elif ev.get("app_enable") is not False:
        st["reasons"].append("pktgen app %d app_enable = %r (want False)"
                             % (a.app_event, ev.get("app_enable")))
    for r in SYNTH_REGS:
        v = d3.reg_read(bi, tgt, r)
        st[r] = v
        if v is None:
            st["reasons"].append("%s unreadable" % r)
        elif v != 0:
            st["reasons"].append("%s = %d (want 0; a previous trial's timestamp "
                                 "would be latched and never overwritten, because "
                                 "these registers are write-if-zero)" % (r, v))
    st["clean"] = not st["reasons"]
    return st


def assert_clean_start_synth(bi, tgt, tgt0, a, out, chk):
    st = read_clean_state_synth(bi, tgt, tgt0, a, out, chk)
    out["clean_start"] = st
    if a.first_after_load:
        st["clean"] = False
        st["reasons"].append(
            "first trial after a program load — measured to leak 4, 5 and 6 "
            "packets across three runs; it is discarded or repeated, never a "
            "data point")
    if st["clean"]:
        chk.ok("CLEAN START asserted",
               "reg_tag=0x%02X deadline=0x%08X both apps disabled, ts regs zero"
               % (st["reg_tag"], st["reg_deadline"]))
        return st
    detail = "; ".join(st["reasons"])
    chk.fail("CLEAN START asserted", detail)
    raise d3.DirtyStateError(detail)


def cleanup_synth(bi, tgt, tgt0, tgts, a, out, chk):
    """MANDATORY cleanup, run from a `finally`. Order is load-bearing.

    The EVENT app is disabled FIRST — before the blocker app — because an event
    that fires after the blockers stop would arm a transaction with no reservoir
    and leave a live generation behind for the next trial to trip over. Then the
    Gate-1 cleanup runs verbatim (disable app 1, restore line rate, drain,
    verify drops, reset), and only after it are the two synthetic registers
    zeroed.
    """
    rec = {"order": ["disable_event_app", "d3.cleanup_trial", "zero_synth_regs"]}
    rec["disable_event_app"] = _set_app(bi, tgt, a.app_event, False, chk)
    try:
        d3.cleanup_trial(bi, tgt, tgt0, tgts, a, out, chk)
        rec["base_cleanup"] = out.get("cleanup")
    except Exception as e:                                       # noqa: BLE001
        chk.fail("base cleanup raised", str(e)[:120])
        rec["base_cleanup_error"] = str(e)[:160]
    if not a.no_reset:
        zero_synth_regs(bi, tgt)
        rec["synth_regs_after"] = {r: d3.reg_read(bi, tgt, r) for r in SYNTH_REGS}
        for r, v in rec["synth_regs_after"].items():
            chk.expect("cleanup: %s == 0" % r, v, 0)
    rec["pktgen_event_after"] = _read_app(bi, tgt, a.app_event)
    out["cleanup_synth"] = rec
    return rec


# ===========================================================================
# Readout
# ===========================================================================
def read_all(bi, tgt, tgt0, a, out, chk):
    regs = {}
    for r in STATE_REGS + TS_REGS:
        regs[r] = d3.reg_read(bi, tgt, r)
    out["registers"] = regs
    out["counters"] = {
        "fresh": {n: d3.ctr_read(bi, tgt, "ctr_fresh", i) for n, i in CF_SLOTS.items()},
        "deq": {n: d3.ctr_read(bi, tgt, "ctr_deq", i) for n, i in CD_SLOTS.items()},
    }
    # BOTH scopes, deliberately. The device-scope numbers are the SUM across
    # pipes (bf_pktgen_get_*_counter loops 0..num_active_pipes-1 under
    # BF_DEV_PIPE_ALL); the pipe-0 numbers are the ones that describe the
    # generator whose packets this program can actually see, because only dp68
    # carries pktgen_enable and a generated packet in pipe N arrives on
    # dev_port 68+128N, which the parser rejects. Reporting only the sum is what
    # made ONE arm of a one-shot timer read back as "fired twice".
    out["pktgen_after"] = {"app_block": _read_app(bi, tgt, a.app_id),
                           "app_event": _read_app(bi, tgt, a.app_event),
                           "app_block_pipe0": _read_app(bi, tgt0, a.app_id),
                           "app_event_pipe0": _read_app(bi, tgt0, a.app_event),
                           "device_configuration": read_num_pipes(bi)}
    out["queue_counters_after"] = d3.read_queue_counters(bi, tgt0, a, out, chk)
    return out


# ===========================================================================
# F01 MICROBENCHMARK — the smallest reproduction, four arms
# ---------------------------------------------------------------------------
# §12 requires at least two technically valid constructions for generating the
# blocker burst when the trigger source is itself a dp68 packet, microbenchmark
# both, and select the simplest correct one. The arms are:
#
#   A0  READ only, app 1 (blockers) DISABLED — the failed Gate-2 configuration,
#       reduced to one packet. Reproduces F01-a and, because nothing retires the
#       generation without blockers, it is also the ONLY arm in which reg_tag can
#       be observed in its armed state. Settles F01-b's precondition.
#   A1  C3 — identical to A0 except app 1 is ENABLED before the READ. If the
#       diagnosis is right this is the whole fix: same P4, same clone, same
#       recirculation-pattern trigger, same mirror session.
#   A2  READ + ACK, app 1 disabled. Isolates F01-b from F01-a: with no reservoir
#       the ACK is held and released immediately, but CF_ACK_HOLD still records
#       whether the §8.1 predicate ACCEPTED it.
#   A3  C2 — app 1 reconfigured as trigger_timer_one_shot and armed BEFORE the
#       event app, so the reservoir is built with no clone and no pattern
#       trigger at all. The alternative construction, measured rather than
#       argued.
#
# Every arm reads back PER PIPE. A device-scope readback is what made three
# separate symptoms look like three separate failures.
# ===========================================================================
MB_ARMS = ("A0_read_app1_disabled", "A1_read_app1_enabled",
           "A2_read_ack_app1_disabled", "A3_c2_timer_reservoir")


def config_block_app_as_timer(bi, tgt, a, out, chk, timer_ns):
    """C2: re-point app 1 from trigger_recirc_pattern to trigger_timer_one_shot.

    Everything else about app 1 is unchanged — same K, same buffer, same
    pipe_local_source_port — so this isolates the TRIGGER and nothing else.
    """
    import bfrt_grpc.client as gc
    template = d3.build_token_template(a.token_len)
    acfg = d3.get_table(bi, d3.PKTGEN_APP_CFG, chk)
    if acfg is None:
        return
    try:
        acfg.entry_mod(
            tgt,
            [acfg.make_key([gc.KeyTuple("app_id", a.app_id)])],
            [acfg.make_data([
                gc.DataTuple("timer_nanosec", int(timer_ns)),
                gc.DataTuple("pkt_len", len(template)),
                gc.DataTuple("pkt_buffer_offset", a.buf_offset),
                gc.DataTuple("pipe_local_source_port", a.port_pgen),
                gc.DataTuple("increment_source_port", bool_val=False),
                gc.DataTuple("batch_count_cfg", 0),
                gc.DataTuple("packets_per_batch_cfg", a.k - 1),
                gc.DataTuple("ipg", 0),
                gc.DataTuple("ibg", 0),
                gc.DataTuple("trigger_counter", 0),
                gc.DataTuple("batch_counter", 0),
                gc.DataTuple("pkt_counter", 0),
                gc.DataTuple("app_enable", bool_val=False),
            ], "trigger_timer_one_shot")])
        chk.ok("C2: app %d re-pointed to trigger_timer_one_shot" % a.app_id,
               "timer=%d ns, K=%d" % (timer_ns, a.k))
    except Exception as e:                                       # noqa: BLE001
        chk.fail("C2 app_cfg trigger_timer_one_shot", str(e)[:110])


def _mb_readout(bi, tgt, tgt0, a, n_pipes):
    """Everything the microbenchmark needs, per pipe and at device scope."""
    rec = {"n_pipes_probed": n_pipes}
    rec["app_block_per_pipe"] = _read_app_per_pipe(bi, a.app_id, n_pipes)
    rec["app_event_per_pipe"] = _read_app_per_pipe(bi, a.app_event, n_pipes)
    rec["app_block_device"] = _read_app(bi, tgt, a.app_id)
    rec["app_event_device"] = _read_app(bi, tgt, a.app_event)
    # reg_tag FIRST and per pipe: its initial value 0xFF is numerically ABOVE
    # its armed value 0xC0, so the device-scope max() collapse reports an idle
    # pipe and an armed pipe 0 is invisible. Every input to tbl_state_decode is
    # here too, so a rejected ACK can be attributed to a specific conjunct
    # instead of guessed at.
    rec["regs_per_pipe"] = {
        r: _reg_read_per_pipe(bi, r, n_pipes)
        for r in ("reg_tag", "reg_deadline", "reg_ack_rel",
                  "reg_exp_relay_seq", "reg_exp_ack", "reg_session_port",
                  "reg_ts_read", "reg_ts_first_block", "reg_ts_ack_arm",
                  "reg_ts_block_term", "reg_ts_ack_release")}
    rec["regs_device_maxcollapse"] = {
        r: d3.reg_read(bi, tgt, r)
        for r in ("reg_tag", "reg_deadline", "reg_exp_ack")}
    rec["ctr_fresh_per_pipe"] = {
        n: _ctr_read_per_pipe(bi, "ctr_fresh", i, n_pipes)
        for n, i in CF_SLOTS.items()}
    rec["ctr_deq_per_pipe"] = {
        n: _ctr_read_per_pipe(bi, "ctr_deq", i, n_pipes)
        for n, i in CD_SLOTS.items()}
    return rec


def _mb_arm(bi, tgt, tgt0, tgts, a, out, chk, arm, n_pipes):
    """ONE microbenchmark arm, fully isolated: clean start, configure, fire,
    read per pipe, cleanup. Cleanup runs from a `finally` exactly as a trial's
    does, so a failed arm cannot poison the next one."""
    rec = {"arm": arm}
    n_events = 2 if arm == "A2_read_ack_app1_disabled" else 1
    mapping = {0: "READ", 1: "ACK"} if n_events == 2 else {0: "READ"}
    enable_block_recirc = (arm == "A1_read_app1_enabled")
    c2_timer = (arm == "A3_c2_timer_reservoir")
    rec["plan"] = {"n_events": n_events, "role_map": mapping,
                   "app1_recirc_enabled": enable_block_recirc,
                   "app1_timer_armed": c2_timer}
    a.n_events = n_events

    d3.assert_dp8_speed(bi, tgt, tgt0, a, out, chk, pre=True)
    assert_clean_start_synth(bi, tgt, tgt0, a, out, chk)
    d3._trial_body(bi, tgt, tgt0, tgts, a, out, chk, write=True)
    config_event_value_set(bi, a, out, chk, write=True)
    config_event_app(bi, tgt, a, out, chk, a.ipg_ns or 500000, write=True)
    config_role_map(bi, tgt, a, out, chk, mapping, write=True)
    seed_trackers(bi, tgt, a, out, chk, write=True)
    zero_synth_regs(bi, tgt)
    for _n, i in CF_SLOTS.items():
        d3.ctr_zero(bi, tgt, "ctr_fresh", i)
    for _n, i in CD_SLOTS.items():
        d3.ctr_zero(bi, tgt, "ctr_deq", i)

    rec["before"] = _mb_readout(bi, tgt, tgt0, a, n_pipes)

    try:
        if c2_timer:
            # C2: the reservoir is timer-armed and must be STANDING before the
            # event app fires, so it is armed first and given the whole event
            # timer as head start.
            config_block_app_as_timer(bi, tgt, a, out, chk, timer_ns=1000)
            _set_app(bi, tgt, a.app_id, True, chk)
            time.sleep(0.05)
        elif enable_block_recirc:
            # C3: the reservoir app is LISTENING before the READ that clones to
            # it. This single write is the whole of the F01-a fix.
            d3.set_app_enable(bi, tgt, a, True, chk)
        rec["armed_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        _set_app(bi, tgt, a.app_event, True, chk)
        time.sleep(a.wait_s)
    finally:
        _set_app(bi, tgt, a.app_event, False, chk)
        _set_app(bi, tgt, a.app_id, False, chk)
        time.sleep(a.drain_s)

    rec["after"] = _mb_readout(bi, tgt, tgt0, a, n_pipes)
    return rec


def microbench_f01(bi, tgt, tgt0, tgts, a, out, chk):
    """The F01 smallest reproduction, all four arms, per-pipe throughout."""
    dev = read_num_pipes(bi)
    out["device_configuration"] = dev
    n_pipes, probe = _probe_n_pipes(bi)
    if isinstance(dev.get("num_pipes"), int) and dev["num_pipes"] > 0:
        n_pipes = dev["num_pipes"]
    out["pipe_probe"] = {"n_pipes_answering": n_pipes, "detail": probe,
                         "device_configuration": dev}
    chk.ok("pipe probe", "%d pipe(s) answer a pipe-scoped pktgen read" % n_pipes)
    if n_pipes == 0:
        chk.fail("pipe probe", "no pipe answered; cannot instrument per pipe")
        return out

    arms = {}
    for arm in (a.mb_arms or MB_ARMS):
        chk.ok("---- microbench arm %s ----" % arm, "")
        try:
            arms[arm] = _mb_arm(bi, tgt, tgt0, tgts, a, out, chk, arm, n_pipes)
        except d3.DirtyStateError as e:
            arms[arm] = {"arm": arm, "REFUSED_DIRTY": str(e)[:200]}
            chk.fail("arm %s refused a dirty start" % arm, str(e)[:140])
        except Exception as e:                                   # noqa: BLE001
            arms[arm] = {"arm": arm, "ERROR": str(e)[:200]}
            chk.fail("arm %s raised" % arm, str(e)[:140])
        finally:
            try:
                cleanup_synth(bi, tgt, tgt0, tgts, a, out, chk)
            except Exception as e:                               # noqa: BLE001
                chk.fail("arm %s cleanup raised" % arm, str(e)[:120])
    out["microbench"] = arms

    # ---- the three findings the arms are supposed to settle ----
    def _p0(rec, path, name):
        try:
            return rec["after"][path][name]["pipe0"]
        except Exception:                                        # noqa: BLE001
            return None

    a0 = arms.get("A0_read_app1_disabled", {})
    a1 = arms.get("A1_read_app1_enabled", {})
    if "after" in a0:
        tc = a0["after"]["app_block_per_pipe"].get("pipe0", {}).get("trigger_counter")
        chk.expect("F01-a NEGATIVE CONTROL: app 1 disabled -> trigger_counter", tc, 0)
        chk.ok("F01-b precondition: reg_tag pipe0 after a lone READ",
               "%r (0xC0 = the ARM wrote; 0xFF = it did not)"
               % (a0["after"]["regs_per_pipe"]["reg_tag"].get("pipe0"),))
    if "after" in a1:
        tc = a1["after"]["app_block_per_pipe"].get("pipe0", {}).get("trigger_counter")
        pc = a1["after"]["app_block_per_pipe"].get("pipe0", {}).get("pkt_counter")
        adm = _p0(a1, "ctr_fresh_per_pipe", "PKTGEN_ADMIT")
        chk.expect("F01-a FIX: app 1 enabled -> trigger_counter", tc, 1)
        chk.expect("F01-a FIX: app 1 enabled -> pkt_counter", pc, a.k)
        chk.expect("F01-a FIX: blockers ADMITTED", adm, a.k)
    return out


# ===========================================================================
# The Gate-2 transaction
# ===========================================================================
def gate2_transaction(bi, tgt, tgt0, tgts, a, out, chk):
    """ONE transaction. Exactly one, then stop. §13 Gate 2."""
    sc = SCENARIOS[a.scenario]
    ipg = a.ipg_ns if a.ipg_ns is not None else sc["ipg_ns"]
    mapping = sc["map"]

    # R1 first and last: the speed is a correctness parameter, so it is asserted
    # before the port write and re-asserted after it.
    d3.assert_dp8_speed(bi, tgt, tgt0, a, out, chk, pre=True)

    # §1.3 — refuse a dirty start BEFORE writing anything.
    assert_clean_start_synth(bi, tgt, tgt0, a, out, chk)

    # Gate-1 configuration, reused verbatim: dp8 loopback + speed re-assert, the
    # two queues and their strict-priority ladder, the shaper disarm (R6), D /
    # read_len / budget, the 5-tuple, the mirror session, the app-1 value_set,
    # app 1 (K=64) and the register initialisation.
    d3._trial_body(bi, tgt, tgt0, tgts, a, out, chk, write=True)

    # Synthetic path.
    config_event_value_set(bi, a, out, chk, write=True)
    config_event_app(bi, tgt, a, out, chk, ipg, write=True)
    config_role_map(bi, tgt, a, out, chk, mapping, write=True)
    seed_trackers(bi, tgt, a, out, chk, write=True)
    zero_synth_regs(bi, tgt)
    for _n, i in CF_SLOTS.items():
        d3.ctr_zero(bi, tgt, "ctr_fresh", i)
    for _n, i in CD_SLOTS.items():
        d3.ctr_zero(bi, tgt, "ctr_deq", i)

    if chk.n_fail:
        # Arming a half-configured switch produces a plausible-looking number
        # from an unknown configuration. Refuse.
        out["verdict"] = "INVALID"
        out["not_armed"] = ("configuration reported %d failed check(s); the "
                            "generator was NOT armed" % chk.n_fail)
        chk.fail("armed the transaction", out["not_armed"])
        return out

    # ---- F01-a FIX. THE RESERVOIR APP MUST BE LISTENING BEFORE THE READ. ----
    # d3._trial_body configures app 1 with app_enable = False (its Gate-1
    # contract: configure, arm nothing), and the failed Gate-2 run never turned
    # it on. A packet-generator application whose app_enable bit is 0 does not
    # respond to its recirculation-pattern trigger, so the clone reached dp68,
    # recirculated (it is the CF_BAD_PORT = 1 in that run's readback) and hit a
    # generator that was switched off: trigger_counter = 0 with ARM_FRESH = 1.
    #
    # Ordering is load-bearing and is the reason this is not folded into
    # _trial_body: app 1 must be enabled BEFORE app 2 is armed, because the
    # clone that triggers it is produced by app 2's very first packet.
    # Defense 2 does the same thing through its mode switch
    # (app_enable = (mode == "protected")); nothing about the trigger path
    # itself is changed here, which is why the live build stays
    # request-triggered.
    out["app_block_enabled"] = d3.set_app_enable(bi, tgt, a, True, chk)
    if not out["app_block_enabled"]:
        out["verdict"] = "INVALID"
        chk.fail("armed the transaction",
                 "app %d (the K=%d reservoir) could not be enabled"
                 % (a.app_id, a.k))
        return out
    chk.ok("enabled pktgen app %d (K=%d recirc-pattern reservoir)"
           % (a.app_id, a.k), "enabled BEFORE the event app is armed")

    out["armed_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out["arm_monotonic"] = time.time()
    ok = _set_app(bi, tgt, a.app_event, True, chk)
    out["armed"] = ok
    if not ok:
        out["verdict"] = "INVALID"
        return out
    chk.ok("armed pktgen app %d (one-shot timer)" % a.app_event,
           "timer=%d ns, 1 batch x %d events, ipg=%d ns"
           % (a.timer_ns, a.n_events, ipg))

    # The whole transaction is  timer + 2*ipg + D  plus the release tail, i.e.
    # ~3.5 ms at the Gate-2 settings, and at most the fail-open horizon
    # H = B*K/rate = 30.8 ms if something goes wrong. The wait is two orders of
    # magnitude above both, so a timeout can never be mistaken for a hold.
    time.sleep(a.wait_s)
    _set_app(bi, tgt, a.app_event, False, chk)
    _set_app(bi, tgt, a.app_id, False, chk)
    time.sleep(a.drain_s)

    read_all(bi, tgt, tgt0, a, out, chk)
    d3.assert_dp8_speed(bi, tgt, tgt0, a, out, chk)   # R1, after the fact
    out["verdict"] = "COMPLETE"
    return out


# ===========================================================================
# CLI
# ===========================================================================
def build_args(argv):
    ap = argparse.ArgumentParser(
        description="Defense 3 §13 Gate 2 — ONE synthetic transaction.")
    ap.add_argument("--config", action="store_true",
                    help="write the full configuration (Gate-1 + synthetic), "
                         "leave both generator apps DISABLED")
    ap.add_argument("--verify-only", action="store_true",
                    help="read everything back, write nothing")
    ap.add_argument("--assert-clean", action="store_true",
                    help="read the clean facts; exit 3 if any is wrong")
    ap.add_argument("--cleanup", action="store_true",
                    help="run the mandatory cleanup path on its own")
    ap.add_argument("--gate2", action="store_true",
                    help="ONE complete synthetic transaction, then STOP")
    ap.add_argument("--microbench", action="store_true",
                    help="F01 smallest reproduction: four arms, per-pipe readback")
    ap.add_argument("--mb-arms", default=None,
                    help="comma-separated subset of %s" % (",".join(MB_ARMS),))
    ap.add_argument("--dry-run", action="store_true",
                    help="no gRPC at all: template, quantization, plan; exit")

    ap.add_argument("--scenario", default="gate2-normal",
                    choices=sorted(SCENARIOS))
    ap.add_argument("--ipg-ns", type=int, default=None,
                    help="override the scenario's hardware inter-packet gap")
    ap.add_argument("--timer-ns", type=int, default=1000000,
                    help="one-shot timer delay from app_enable to the batch")
    ap.add_argument("--n-events", type=int, default=3)
    ap.add_argument("--app-event", type=int, default=APP_EVENT_DEFAULT)
    ap.add_argument("--buf-off-event", type=int, default=BUF_OFF_EVENT_DEFAULT)
    ap.add_argument("--gen", type=lambda s: int(s, 0), default=GEN_DEFAULT,
                    help="transaction generation; must be 0xC0..0xCF")
    ap.add_argument("--mport", type=int, default=SYN_MPORT_DEFAULT,
                    help="the master's ephemeral port carried by the template")
    ap.add_argument("--syn-seq", type=lambda s: int(s, 0), default=SYN_SEQ_DEFAULT,
                    help="the template's tcp.seq_no, == EXP_RELAY_SEQ")
    ap.add_argument("--r2-bound-ns", type=int, default=100000,
                    help="CONSENSUS R2: reservoir standing bound, 100 us")
    ap.add_argument("--wait-s", type=float, default=0.5)
    ap.add_argument("--txn-index", type=int, default=1)
    # Every Gate-1 flag (--prog, --grpc, --d-ms, --budget, --read-len, --out,
    # --relay-ip, --no-cleanup, --first-after-load, ...) is forwarded to the
    # Gate-1 parser rather than redeclared, so there is ONE definition of each
    # and no chance of the two drifting apart.
    mine, rest = ap.parse_known_args(argv)
    base = d3.parse_args(rest)
    for k, v in vars(mine).items():
        setattr(base, k, v)
    if base.mb_arms:
        base.mb_arms = [s.strip() for s in base.mb_arms.split(",") if s.strip()]
        bad = [s for s in base.mb_arms if s not in MB_ARMS]
        if bad:
            raise SystemExit("unknown microbench arm(s): %s (have %s)"
                             % (",".join(bad), ",".join(MB_ARMS)))
    return base


def main(argv=None):
    a = build_args(argv if argv is not None else sys.argv[1:])
    chk = d3.Checks()
    out = {"schema": SCHEMA, "prog": a.prog, "build": "D3_SYNTH_EVENTS",
           "gate": "13.2", "authored_off_switch": True,
           "silicon_validated": False, "txn_index": a.txn_index}

    d3.offline_checks(a, out, chk)
    offline_synth_checks(a, out, chk)
    out["params"] = {
        "d_ms": a.d_ms, "d_ticks": out.get("D", {}).get("ticks"),
        "d_realized_ns": out.get("D", {}).get("realized_ns"),
        "budget": a.budget, "k": a.k, "rate_dp8_pps": d3.RATE_DP8_PPS,
        "read_len": a.read_len, "generation": a.gen,
        "ipg_ns": (a.ipg_ns if a.ipg_ns is not None
                   else SCENARIOS[a.scenario]["ipg_ns"]),
        "timer_ns": a.timer_ns, "n_events": a.n_events,
        "r2_bound_ns": a.r2_bound_ns,
        "required_dp8_speed": d3.REQUIRED_DP8_SPEED,
    }

    if a.dry_run:
        print(chk.render())
        out["n_fail"] = chk.n_fail
        out["mode"] = "dry-run"
        if a.out:
            with open(a.out, "w") as fh:
                json.dump(out, fh, indent=2, default=str)
        print("D3GATE2 " + json.dumps(out, default=str))
        return 1 if chk.n_fail else 0

    if not (a.config or a.verify_only or a.assert_clean or a.cleanup
            or a.gate2 or a.microbench):
        print("nothing to do: pass --gate2, --microbench, --config, "
              "--verify-only, --assert-clean, --cleanup or --dry-run",
              file=sys.stderr)
        return 2

    import bfrt_grpc.client as gc
    iface = gc.ClientInterface(a.grpc, client_id=a.client_id, device_id=0,
                               notifications=None)
    iface.bind_pipeline_config(a.prog)
    bi = iface.bfrt_info_get(a.prog)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)
    tgt0 = gc.Target(device_id=0, pipe_id=0)
    tgts = [("pipe0", tgt0), ("device", tgt)]

    rc = 0
    ran_trial = False
    try:
        d3.snapshot(bi, tgt, tgt0, tgts, a, out, chk)
        if a.cleanup and not a.gate2:
            out["mode"] = "cleanup"
            cleanup_synth(bi, tgt, tgt0, tgts, a, out, chk)
        if a.assert_clean and not a.gate2:
            out["mode"] = out.get("mode", "assert-clean")
            assert_clean_start_synth(bi, tgt, tgt0, a, out, chk)
        if a.config and not a.gate2:
            out["mode"] = "config"
            write = not a.verify_only
            d3.assert_dp8_speed(bi, tgt, tgt0, a, out, chk, pre=True)
            d3._trial_body(bi, tgt, tgt0, tgts, a, out, chk, write)
            sc = SCENARIOS[a.scenario]
            ipg = a.ipg_ns if a.ipg_ns is not None else sc["ipg_ns"]
            config_event_value_set(bi, a, out, chk, write)
            config_event_app(bi, tgt, a, out, chk, ipg, write)
            config_role_map(bi, tgt, a, out, chk, sc["map"], write)
            seed_trackers(bi, tgt, a, out, chk, write)
            if write:
                zero_synth_regs(bi, tgt)
        if a.verify_only and not (a.gate2 or a.config):
            out["mode"] = "verify-only"
            read_all(bi, tgt, tgt0, a, out, chk)
        if a.microbench and not a.gate2:
            out["mode"] = "microbench"
            ran_trial = True
            microbench_f01(bi, tgt, tgt0, tgts, a, out, chk)
        if a.gate2:
            out["mode"] = "gate2"
            ran_trial = True
            gate2_transaction(bi, tgt, tgt0, tgts, a, out, chk)
    except d3.SpeedError as e:
        out["verdict"] = "ABORTED_SPEED"
        out["aborted"] = str(e)
        rc = 4
    except d3.DirtyStateError as e:
        out["verdict"] = "INVALID"
        out["refused_dirty_start"] = str(e)
        chk.fail("trial REFUSED to start", str(e)[:160])
        rc = 3
    finally:
        # MANDATORY, and not conditional on the verdict: an INVALID trial must
        # leave the switch in exactly the state a PASS does, or the NEXT trial
        # inherits its backlog. Measured: 124 leftover packets corrupted a
        # following trial when this was skipped.
        if a.no_cleanup:
            chk.warn("cleanup SKIPPED",
                     "--no-cleanup (debug only). The next trial will refuse to start.")
        elif ran_trial or a.gate2 or a.config:
            try:
                cleanup_synth(bi, tgt, tgt0, tgts, a, out, chk)
            except Exception as e:                               # noqa: BLE001
                chk.fail("cleanup raised", str(e)[:120])

    print(chk.render())
    out["n_fail"] = chk.n_fail
    out["checks"] = [{"result": r, "check": n, "detail": d} for r, n, d in chk.rows]
    if a.out:
        with open(a.out, "w") as fh:
            json.dump(out, fh, indent=2, default=str)
    print("D3GATE2 " + json.dumps(out, default=str))
    if rc:
        return rc
    return 1 if chk.n_fail else 0


if __name__ == "__main__":
    sys.exit(main())

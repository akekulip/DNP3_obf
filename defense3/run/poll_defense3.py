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
# The second event app. app id 3 -> generator header byte 0 (pipe 0) = 0x03. It shares
# the event TEMPLATE and therefore the same packet buffer offset as app 2: all three
# events are copies of one relay->master frame and the ROLE is assigned by
# tbl_synth_role, not by the bytes.
APP_EVENT2_DEFAULT = 3
# app 4: the STALE-RESPONSE injector. Its own app id AND its own packet buffer, because
# it must carry a tcp.seq from the PREVIOUS transaction -- the only transaction identity
# this design has. Sharing app 3's template would make the injected response
# indistinguishable from the current one, so the test would prove nothing.
APP_EVENT3_DEFAULT = 4
BUF_OFF_EVENT3_DEFAULT = 256

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
# A scenario is (ipg, role map) plus, for the SPLIT schedules, which app each role
# comes from. `split: True` means: READ alone from app 2 (timer, run ends at once) and
# the remaining events from app 3 (recirc-pattern on the same 0xE1 clone the READ
# produced). The map keys are then (app_id, packet_id).
SCENARIOS = {
    # ►► THE GATE-2 SCHEDULE, corrected by CHECK 2. app 3's leading packet_id 0 has NO
    # role entry, so it is a DUMMY that bypasses; the ACK is packet_id 1 and therefore
    # lands ONE ipg after the trigger, at ~0.5 ms after the READ — inside the relay's
    # measured 0.400 ms min / 0.505 ms median READ->ACK band, which is what the
    # direction means by "a synthetic schedule consistent with the physical READ->ACK
    # timing, not an artificially delayed ACK". The RESPONSE follows one further ipg
    # later, i.e. 0.5 ms after the ACK and well inside D = 2 ms.
    "gate2-split": {"ipg_ns": 500000, "split": True,
                    "map": {(2, 0): "READ", (3, 1): "ACK", (3, 2): "RESP"}},
    # SUPERSEDED, kept because CHECK 2's attribution arms use it and because it is the
    # configuration whose failure produced the whole investigation: all three events in
    # ONE app-2 run, which withholds the blocker burst for the run's whole span and so
    # cannot ever have the reservoir standing before the ACK.
    # ►►►► THE GATE-2 SCHEDULE. Two TIMER apps, which is the only construction left
    # standing after CHECK 2 and the two diagnostics, and it uses nothing unproven.
    #
    #   app 2  timer T2       {READ}          run ends immediately -> the generator is
    #                                          free when the clone arrives, exactly as
    #                                          production is
    #   app 3  timer T2 + Δ   {ACK, RESP}     Δ is the READ->ACK offset and ipg is the
    #                                          ACK->RESPONSE gap; BOTH are hardware
    #                                          timer/ipg quantities, not software ones
    #
    # Why not the alternatives, each ruled out by measurement rather than by argument:
    #   * ONE run holding all three events — CHECK 2: the blocker burst is withheld
    #     for the run's whole span, so the reservoir is late by ipg + 1215 ns at EVERY
    #     ipg, and no re-ordering of the roles inside the run fixes it.
    #   * a recirculation-pattern app for the ACK/RESPONSE, fired by the READ's own
    #     clone — TWO independent failures, both observed: (i) its packets cannot be
    #     told apart, `packet_id` decoded as the same value for all three, so a
    #     leading DUMMY is impossible and roles collapse onto one entry; and (ii) it
    #     was served BEFORE app 1, so the reservoir waited for its whole run span.
    #
    # Both timers start when their own app_enable is written, so app 2 is enabled
    # FIRST and app 3 second: the write skew s then ADDS to the offset (Δ + s) instead
    # of subtracting from it, which keeps the ordering safe in the only direction that
    # matters — the reservoir cannot be late because app 3's run cannot start early.
    # The realised READ->ACK is recorded from the hardware timestamps every trial
    # rather than assumed, and C-R2 gates the reservoir independently.
    "gate2-2timer": {"ipg_ns": 500000, "two_timer": True, "split": True,
                     "map": {(2, 0): "READ", (3, 0): "ACK", (3, 1): "RESP"}},
    # SUITE 6 — DUPLICATE EARLY RESPONSE. app 3 emits ACK, RESP, RESP with ipg 500 us,
    # so both RESPONSEs land inside D = 2 ms. Only the first may mark the tag; the
    # second must read txn_active == 2, miss the hold branch and be forwarded once.
    "g6-duplicate-resp": {"ipg_ns": 500000, "two_timer": True, "split": True,
                          "duplicate_response": True,
                          "map": {(2, 0): "READ", (3, 0): "ACK", (3, 1): "RESP",
                                  (3, 2): "RESP"}},
    # SUITE 8 — STALE RESPONSE DURING A NEW ACTIVE TRANSACTION. N+1 arms, its reservoir
    # stands and its deadline is armed; then app 4 injects a RESPONSE carrying the
    # PREVIOUS transaction's tcp.seq. It must be bypassed and must not touch anything.
    "g8-stale-active": {"ipg_ns": 500000, "two_timer": True, "split": True,
                        "stale_injector": True,
                        "map": {(2, 0): "READ", (3, 0): "ACK", (3, 1): "RESP",
                                (4, 0): "RESP_ALT"}},
    # SUITE 7 — STALE RESPONSE. app 3 emits a RESPONSE with NO READ and NO ACK, so it
    # arrives against a retired/idle transaction. It must bypass and must leave
    # reg_tag, reg_deadline and the blockers untouched.
    "g7-stale-resp": {"ipg_ns": 500000, "two_timer": True, "split": True,
                      "no_read": True, "no_response": False,
                      "map": {(3, 0): "RESP"}},
    # ---- §13 GATE 4 boundary cases. Same two-timer construction as Gate 2; only
    # the app-3 ipg (the ACK->RESPONSE gap) and its packet count change, so none of
    # these is a different mechanism being tested.
    #   A  ipg just UNDER D: the RESPONSE is the last thing to arrive before the
    #      deadline, and must still queue behind the held ACK.
    #   B  ipg ABOVE D + drain: the RESPONSE arrives after the held ACK has already
    #      committed, and must be forwarded exactly once with no re-hold.
    #   C  app 3 emits ONE packet, the ACK. There is no RESPONSE at all.
    "g4a-resp-near-deadline": {"ipg_ns": 1995000, "two_timer": True, "split": True,
                               "map": {(2, 0): "READ", (3, 0): "ACK",
                                       (3, 1): "RESP"}},
    "g4b-resp-after-release": {"ipg_ns": 2500000, "two_timer": True, "split": True,
                               "late_response": True,
                               "map": {(2, 0): "READ", (3, 0): "ACK",
                                       (3, 1): "RESP"}},
    "g4c-missing-resp": {"ipg_ns": 1995000, "two_timer": True, "split": True,
                         "no_response": True,
                         "map": {(2, 0): "READ", (3, 0): "ACK"}},
    # SUITE 9 — FAIL-OPEN. A READ arms and NOTHING else ever arrives: no ACK, so no
    # deadline is ever armed and the tokens cannot terminate on one. They loop until the
    # pass budget runs out. This is the ONLY scenario the fail-open horizon exists for,
    # and until now it had never been executed: CD_BLOCK_TERM_TMO and RELEASE_FAILOPEN
    # were 0 in every gate and in both physical campaigns, because H = 30.8 ms is ~15x
    # the deadline and the deadline always won. Run it with a SHRUNK budget (--budget)
    # so H falls below the observation window; with B = 500, H = 500 x 1.711 us = 855 us.
    "g9-failopen": {"ipg_ns": 0, "two_timer": True, "split": True,
                    "no_ack_no_resp": True,
                    "map": {(2, 0): "READ"}},
    # ►► DIAGNOSTIC for the two unknowns the first split run exposed, both in one
    # trial. The first split Gate 2 gave ACK_HOLD=1 + ACK_DUP_HOLD=2 with NO RESPONSE
    # and NO bypass, i.e. all three of app 3's packets took the synth_ack entry, and
    # it also showed the reservoir standing at 1 000 689 ns = app 3's whole run span,
    # i.e. app 3 was served BEFORE app 1.
    #   (a) packet_id decoding for a RECIRCULATION-PATTERN app has never been proven
    #       on this switch -- the frozen Defense 2 only ADVANCES over the generator
    #       header and never reads it, and the "classify on packet_id" note came from
    #       a compile-time study, not from silicon. This map gives packet_id 0 and 2
    #       the RESPONSE role and 1 the ACK role, so:
    #         RESP_HOLD_* = 2, ACK_HOLD = 1   -> packet_id INCREMENTS (dummy design ok)
    #         ACK_HOLD = 1, ACK_DUP_HOLD = 2  -> packet_id is CONSTANT 1 (design dead)
    #         BYPASS_FWD = 3                  -> packet_id is something else entirely
    #   (b) run it with --app-id 5 to put the blockers ABOVE the events in app-id
    #       order. If the reservoir then stands in ~1215 ns, arbitration follows the
    #       app id and the split design works as-is; if it still waits a run span,
    #       two apps on one trigger can never be ordered and the events app must be
    #       fired by a SECOND clone emitted once the reservoir exists.
    "diag-pid": {"ipg_ns": 500000, "split": True,
                 "map": {(2, 0): "READ", (3, 0): "RESP", (3, 1): "ACK",
                         (3, 2): "RESP"}},
    "gate2-normal": {"ipg_ns": 500000, "map": {0: "READ", 1: "ACK", 2: "RESP"}},
    # F02 DIAGNOSTIC — READ only. Isolates blocker ADMISSION from everything the
    # ACK and the RESPONSE do. If the 64 tokens are admitted here but dropped in
    # gate2-normal, the RESPONSE's RESP_BYPASS retirement is RACING the tokens
    # and F02 is an event-ORDERING fault, not an admission-logic fault.
    "f02-read-only": {"ipg_ns": 500000, "map": {0: "READ"}},
    # F02 DIAGNOSTIC — READ + ACK, no RESPONSE. Separates the ACK's effect from
    # the RESPONSE's.
    "f02-read-ack":  {"ipg_ns": 500000, "map": {0: "READ", 1: "ACK"}},
}

# ---- indexed counter slots. COMPILE-TIME CONSTANTS in the P4; named here so
# the JSON the analyzer reads is self-describing rather than positional. ----
CF_SLOTS = {
    "BYPASS_FWD": 0, "BAD_PORT": 1, "ARM_FRESH": 2, "ARM_DUP": 3, "ARM_BUSY": 4,
    "ACK_HOLD": 5, "ACK_DUP_HOLD": 6, "ACK_REJECT": 7, "RESP_HOLD_EARLY": 8,
    "RESP_HOLD_LATE": 9, "RESP_BYPASS": 10, "UNSUP_SEG": 11, "BLOCK_ENQ": 12,
    "PKTGEN_ADMIT": 13, "PKTGEN_DROP": 14,
    # CF_CLONE_SEEN — the tagged clone coming back on dp68. It USED to be charged
    # to BAD_PORT, so BAD_PORT read 1 on every armed transaction and "no
    # off-topology packets" could never be true while the defense was working.
    # Now: CLONE_SEEN == 1 per fresh ARM, and BAD_PORT means what it says.
    "CLONE_SEEN": 15,
    # an EXACT RESPONSE retransmission, dropped on purpose while the tag is in the
    # pending domain. Kept separate from RESP_BYPASS: "suppressed a duplicate" and
    # "forwarded something unprotected" must never be summed.
    "RESP_DUP_SUPP": 16,
}
CD_SLOTS = {
    "BLOCK_LOOP": 0, "BLOCK_TERM_STALE": 1, "BLOCK_TERM_DL": 2,
    "BLOCK_TERM_TMO": 3, "RELEASE_DEADLINE": 4, "RELEASE_FAILOPEN": 5,
    # E1 partitions the ACK releases by WHICH retirement path ran, so their SUM is the
    # release count: ACK_RELEASE = a RESPONSE was pending (the queued RESPONSE will
    # retire), ACK_REL_RETIRE = nothing was pending and the ACK retired the
    # transaction itself. This is the Gate 4C repair's direct readout.
    "ACK_RELEASE": 6, "ACK_REL_RETIRE": 7,
}

# Registers the synthetic build adds and that must be zeroed / read back.
SYNTH_REGS = ("reg_ts_read", "reg_ts_resp_release",
              # CHECK 2 (direction 2026-07-29): the two instants that DECOMPOSE the
              # blocker-start latency. reg_ts_clone is t_pktgen_trigger (the clone
              # re-entering dp68, i.e. the generator's pattern matcher being fed);
              # reg_ts_last_block is t_final_blocker_admitted, hence
              # READ-to-FULL-RESERVOIR, which is the quantity that has to beat the
              # physical ACK floor. Without them a late reservoir cannot be
              # attributed to the clone chain or to the generator.
              "reg_ts_clone", "reg_ts_last_block", "reg_ts_last_term",
              "reg_ts_resp_bypass")

TS_REGS = ("reg_ts_read", "reg_ts_clone", "reg_ts_first_block",
           "reg_ts_last_block", "reg_ts_ack_arm",
           "reg_ts_block_term", "reg_ts_last_term",
           "reg_ts_ack_release", "reg_ts_resp_release", "reg_ts_resp_bypass")
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
    split = bool(sc.get("split"))
    out["scenario"] = {"name": a.scenario, "ipg_ns": ipg, "split": split,
                       "map": {str(k): v for k, v in sc["map"].items()}}

    qd = d3.quantize_d(a.d_ms)
    # THE TWO INEQUALITIES THE SINGLE HARDWARE ipg HAS TO SATISFY AT ONCE.
    #
    # In the SPLIT schedule ipg means the app-3 gap, so it sets BOTH the ACK's offset
    # from the trigger (one ipg, behind the leading DUMMY) and the RESPONSE's offset
    # from the ACK (one more ipg). That makes the two bounds below tighter and more
    # meaningful than they were in the single-run schedule, not looser.
    if sc.get("no_response"):
        chk.ok("no RESPONSE is scheduled (Gate 4 case C)",
               "app %d emits the ACK only; nothing on the data path retires the "
               "generation, which is the property under test" % a.app_event2)
    elif sc.get("late_response"):
        # Gate 4 case B INVERTS this bound on purpose: the RESPONSE must land after
        # the held ACK has committed, i.e. after D + the measured drain + tail.
        need = qd["realized_ns"] + d3.C2_BURST_SPAN_NS + 2000
        if ipg <= need:
            chk.fail("ipg > D + drain (the RESPONSE must arrive AFTER the ACK "
                     "commits)",
                     "ipg=%d ns <= %d ns: the RESPONSE could still be queued behind "
                     "the ACK and case B would be indistinguishable from case A"
                     % (ipg, need))
        else:
            chk.ok("ipg > D + drain (Gate 4 case B)",
                   "ipg=%d ns > %d ns, so the RESPONSE arrives %d ns after the ACK "
                   "commits" % (ipg, need, ipg - qd["realized_ns"]))
    elif ipg >= qd["realized_ns"]:
        chk.fail("ipg < D (the RESPONSE must arrive INSIDE the hold window)",
                 "ipg=%d ns, D=%d ns: the RESPONSE would arrive after the "
                 "deadline and Gate 2's 'one early RESPONSE' would not be "
                 "exercised at all" % (ipg, qd["realized_ns"]))
    else:
        chk.ok("ipg < D", "ipg=%d ns < D=%d ns (RESPONSE is EARLY by %d ns)"
               % (ipg, qd["realized_ns"], qd["realized_ns"] - ipg))
    if ipg <= a.r2_bound_ns:
        chk.fail("ipg > the R2 reservoir bound",
                 "ipg=%d ns <= %d ns: the ACK could arrive before the K=64 "
                 "reservoir is standing, which is a SILENT zero-hold"
                 % (ipg, a.r2_bound_ns))
    else:
        chk.ok("ipg > the R2 reservoir bound (%d ns)" % a.r2_bound_ns,
               "ipg=%d ns" % ipg)

    # ---- CHECK 2 (direction 2026-07-29): THE SCHEDULE MUST BE SPLIT ---------
    # A single generator run cannot hold both the READ and the ACK: the reservoir
    # stands at READ + run_span + ~527 ns while the ACK is admitted at or before
    # READ + run_span, so the reservoir is ALWAYS later. Measured at four points, see
    # evidence/defense3/CHECK2_PRODUCTION_BLOCKER_START_LATENCY.md. Refuse to score a
    # single-run schedule as Gate 2 rather than let it fail R2 again.
    if not split:
        chk.warn("scenario is a SPLIT schedule",
                 "%r puts every event in ONE generator run. CHECK 2 measured that "
                 "the blocker burst is withheld for the whole run span, so the "
                 "reservoir CANNOT stand before the ACK at any ipg. Use "
                 "gate2-split for Gate 2; this scenario is a diagnostic."
                 % a.scenario)
    else:
        chk.ok("scenario is a SPLIT schedule",
               "READ alone from app %d (run ends at once), ACK+RESPONSE from app %d "
               "fired by the same 0xE1 clone" % (a.app_event, a.app_event2))
        # the measured full-reservoir time, with the margin stated explicitly
        if ipg <= d3.C2_FULL_RESERVOIR_NS:
            chk.fail("ipg > the MEASURED full-reservoir time",
                     "ipg=%d ns <= %d ns" % (ipg, d3.C2_FULL_RESERVOIR_NS))
        else:
            chk.ok("ipg > the MEASURED full-reservoir time (%d ns)"
                   % d3.C2_FULL_RESERVOIR_NS,
                   "ipg=%d ns, margin %.0fx" % (ipg, ipg / float(
                       d3.C2_FULL_RESERVOIR_NS)))
        # and the resulting READ->ACK must sit in the relay's measured band
        r2a = ipg + d3.C2_CLONE_CHAIN_NS
        if not (a.c2_ack_floor_ns * 0.5 <= r2a <= a.c2_ack_median_ns * 3):
            chk.warn("resulting READ->ACK is physically plausible",
                     "%d ns is outside [%d, %d] — the relay measures 0.400 ms min / "
                     "0.505 ms median, and the direction asks for a schedule "
                     "CONSISTENT with that"
                     % (r2a, int(a.c2_ack_floor_ns * 0.5),
                        int(a.c2_ack_median_ns * 3)))
        else:
            chk.ok("resulting READ->ACK is physically plausible",
                   "~%d ns, against the relay's 400000 ns min / 505000 ns median"
                   % r2a)

    # ---- CHECK 1 (direction 2026-07-29): INACTIVE-MARKER SAFETY ------------
    # The P4 cannot check its own action data, so the ONE generation this build
    # installs is range-checked here. Two separate obligations:
    #   (a) it must be inside tbl_txn_active's 0xC0..0xCF domain, else txn_active
    #       reads 0 and nothing is ever held;
    #   (b) it must NOT be TAG_INACTIVE. Since TAG_INACTIVE is now 0x00 and
    #       tag_arm's write predicate is `v == TAG_INACTIVE`, a generation of 0x00
    #       would make "armed" and "idle" the same state: tag_diff would be 0 from
    #       idle, decode as ARM_DUP, and the transaction would silently never arm.
    # (a) implies (b) for this build, but (b) is asserted separately so a future
    # change to either constant cannot quietly remove the guarantee.
    if not (0xC0 <= a.gen <= 0xCF):
        chk.fail("generation inside tbl_txn_active's 0xC0..0xCF domain",
                 "gen=0x%02X: txn_active would read 0 and NOTHING would be held"
                 % a.gen)
    else:
        chk.ok("generation inside 0xC0..0xCF", "0x%02X" % a.gen)
    if a.gen == d3.TAG_INACTIVE:
        chk.fail("generation != TAG_INACTIVE (no active generation may be zero)",
                 "gen=0x%02X == TAG_INACTIVE: idle and armed become the same state"
                 % a.gen)
    else:
        chk.ok("generation != TAG_INACTIVE (0x%02X)" % d3.TAG_INACTIVE,
               "gen=0x%02X" % a.gen)
    # The sentinel collision that CHECK 1 actually caught: tag_rmw and ack_rel_rmw
    # write on `meta.tag_val != TAG_NO_WRITE`, and BOTH transaction-retire paths
    # (fail-open blocker, released RESPONSE) write TAG_INACTIVE through tag_rmw. If
    # the two constants are equal, both retires are silent no-ops and reg_tag keeps a
    # live generation for ever.
    if d3.TAG_NO_WRITE == d3.TAG_INACTIVE:
        chk.fail("TAG_NO_WRITE != TAG_INACTIVE",
                 "both are 0x%02X: the transaction-retire write is a NO-OP and the "
                 "generation is never retired" % d3.TAG_INACTIVE)
    else:
        chk.ok("TAG_NO_WRITE (0x%02X) != TAG_INACTIVE (0x%02X)"
               % (d3.TAG_NO_WRITE, d3.TAG_INACTIVE),
               "the retire write can commit")

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
def _set_app(bi, tgt, app_id, enable, chk=None, pipe=0):
    """Toggle ONE generator app by id, SCOPED TO ONE PIPE.

    d3.set_app_enable only ever addresses app 1, and a one-shot app does NOT
    auto-disable after its batch, so it must be driven False before it can be
    re-armed True.

    F01-c ROOT CAUSE — the pipe scope is load-bearing, not cosmetic.
    The caller's `tgt` is Target(pipe_id=0xffff), i.e. DEVICE-WIDE, and this chip
    has TWO pipes (tf1.dev.device_configuration: num_pipes=2, BFN-T10-032D).
    A device-wide app_enable therefore arms the generator in BOTH pipes, and a
    TIMER-triggered app fires in every pipe where it is armed:
        app_event  trigger_counter=2  batch_counter=2  pkt_counter=6   (2 x 3 events)
    App 1 was masked from this because its trigger is a RECIRC PATTERN and only
    pipe 0 can see the clone (dp68 is pipe 0's recirculation port), so it read
    1/1/64 and looked correct. Scoping the write to one pipe makes the event
    count deterministic and removes the duplicate transaction that retires the
    generation underneath the first pipe's tokens.
    """
    import bfrt_grpc.client as gc
    acfg = d3.get_table(bi, d3.PKTGEN_APP_CFG, chk)
    if acfg is None:
        return False
    ptgt = gc.Target(device_id=0, pipe_id=pipe)
    try:
        acfg.entry_mod(ptgt, [acfg.make_key([gc.KeyTuple("app_id", app_id)])],
                       [acfg.make_data([gc.DataTuple("app_enable", bool_val=enable)])])
        return True
    except Exception as e:                                       # noqa: BLE001
        if chk is not None:
            chk.fail("app %d enable=%s" % (app_id, enable), str(e)[:90])
        return False


def _set_apps_together(bi, app_ids, enable, chk=None, pipe=0):
    """Enable/disable SEVERAL generator apps in ONE entry_mod call.

    WHY THIS EXISTS. In the two-timer schedule each one-shot timer starts when its
    OWN app_enable is written, so the realised READ->ACK offset is
    (timer3 - timer2) + s where s is the gap between the two writes. Two separate
    gRPC round trips measured s ~= 1.15 ms, which swamped the intended 500 us offset
    and pushed READ->ACK to 1.65 ms — above the relay's measured 0.400 ms min /
    0.505 ms median band, i.e. no longer "a synthetic schedule consistent with the
    physical READ->ACK timing".

    One entry_mod carrying BOTH keys is a single gRPC message applied by the driver
    back to back, so s collapses to the driver's own per-entry write time. The skew
    is still MEASURED and reported every trial rather than assumed away — I-01 reads
    the hardware timestamps, not this function's intent.

    Falls back to sequential writes if the driver rejects a multi-key entry_mod, and
    says which path it took.
    """
    import bfrt_grpc.client as gc
    acfg = d3.get_table(bi, d3.PKTGEN_APP_CFG, chk)
    if acfg is None:
        return False, "app_cfg table not found"
    ptgt = gc.Target(device_id=0, pipe_id=pipe)
    keys = [acfg.make_key([gc.KeyTuple("app_id", int(i))]) for i in app_ids]
    data = [acfg.make_data([gc.DataTuple("app_enable", bool_val=enable)])
            for _ in app_ids]
    try:
        acfg.entry_mod(ptgt, keys, data)
        return True, "batched"
    except Exception as e:                                       # noqa: BLE001
        if chk is not None:
            chk.warn("batched app_enable for apps %s" % (list(app_ids),),
                     "%s — falling back to sequential writes, which reintroduces "
                     "the inter-write skew" % str(e)[:70])
        okall = True
        for i in app_ids:
            okall = _set_app(bi, None, int(i), enable, chk, pipe=pipe) and okall
        return okall, "sequential-fallback"


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
    """The EVENT-APP discriminator bytes, on the second parser value_set.

    TWO entries now, one per event app (CHECK 2 split the events across app 2 and
    app 3), which is why pgen_event is declared size 2 in the P4. A missing second
    entry is not a soft failure: app 3's packets would not match the select at all,
    would keep port_ok = 0 and would be charged to BAD_PORT — visible as
    BAD_PORT == 3 with the ACK and RESPONSE simply absent.

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
    app_ids = [a.app_event, a.app_event2, a.app_event3]
    bytes_ = [(a.pipe << 3) | i for i in app_ids]
    out["event_value_set"] = {"bytes": ["0x%02X" % b for b in bytes_],
                              "app_ids": app_ids, "mask": 0xFF,
                              "prsr_id": d3.PGEN_PRSR_ID, "pipe": a.pipe}
    blocker_byte = (a.pipe << 3) | a.app_id
    for i, b in zip(app_ids, bytes_):
        if b == blocker_byte:
            chk.fail("event app %d byte distinct from app 1 (blockers)" % i,
                     "both resolve to 0x%02X" % b)
            return
        if b == d3.CLONE_TAG_MARKER:
            chk.fail("event app %d byte distinct from the 0xE1 clone marker" % i,
                     "0x%02X" % b)
            return
    if bytes_[0] == bytes_[1]:
        chk.fail("the two event apps have distinct bytes",
                 "both resolve to 0x%02X" % bytes_[0])
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
        for b in bytes_:
            vkey = [vs.make_key([gc.KeyTuple("f1", b, 0xFF)])]
            try:
                vs.entry_del(vtgt, vkey)      # idempotent
            except Exception:
                pass
            try:
                vs.entry_add(vtgt, vkey)
            except Exception as e:                               # noqa: BLE001
                chk.fail("value_set pgen_event add 0x%02X" % b, str(e)[:90])
                return
    chk.ok("value_set pgen_event programmed (both event apps)",
           "bytes=%s mask=0xFF"
           % ", ".join("0x%02X" % b for b in bytes_))


def config_event_app(bi, tgt, a, out, chk, ipg_ns, write=True,
                    n_batches=1, ibg_ns=0, app_id=None, n_events=None,
                    trigger="trigger_timer_one_shot", out_key=None,
                    timer_ns=None, buf_off=None, syn_seq=None):
    """ONE event generator app: n_events packets, ipg apart, DISABLED.

    THE EVENTS ARE SPLIT ACROSS TWO APPS (CHECK 2, 2026-07-29). The generator will
    not start app 1's triggered blocker batch until the triggering app's whole RUN
    has finished, and the wait equals the run SPAN — measured at four points, see the
    note on pgen_event in the P4. So one run cannot hold both the READ and the ACK.

        app 2  trigger_timer_one_shot   ONE packet: the READ. Its run ends
                                        immediately, leaving the generator free the
                                        instant the clone is emitted — which is the
                                        condition production has, because in
                                        production there is no event app at all.
        app 3  trigger_recirc_pattern   the ACK and the RESPONSE, fired by the SAME
                                        0xE1 clone the READ produced, behind a
                                        leading DUMMY packet so the ACK lands one
                                        ipg after the trigger instead of on it.

    The DUMMY is what makes READ->ACK physically realistic (~0.5 ms, against the
    relay's measured 0.400 ms minimum / 0.505 ms median) rather than ~2 us, which
    the direction requires: "a synthetic schedule consistent with the physical
    READ->ACK timing, not an artificially delayed ACK". An unmapped packet_id takes
    synth_none(), falls through to ROLE_BYPASS and is counted CF_BYPASS_FWD, so a
    mis-sized batch shows up as a bypass count rather than as a missing event.

    Counts are ZERO-BASED: batch_count_cfg = 0 is ONE batch and
    packets_per_batch_cfg = 2 is THREE packets.

    ONE batch per app, still: packet_id restarts at 0 for every batch, so two
    batches would both emit packet_id 0 with no way to tell them apart. Across the
    two APPS the collision is resolved differently — tbl_synth_role keys on
    (pipe_app, packet_id), and pipe_app is the app discriminator the parser already
    matches on.

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
    app_id = a.app_event if app_id is None else int(app_id)
    n_events = a.n_events if n_events is None else int(n_events)
    out_key = out_key or ("app_event" if app_id == a.app_event
                          else "app_event%d" % app_id)
    timer_ns = a.timer_ns if timer_ns is None else int(timer_ns)
    buf_off = a.buf_off_event if buf_off is None else int(buf_off)
    syn_seq = a.syn_seq if syn_seq is None else int(syn_seq)
    tmpl, tmeta = build_event_template(a.relay_ip, a.master_ip, a.mport,
                                       syn_seq, a.read_len)

    if buf_off < len(d3.build_token_template(a.token_len)):
        chk.fail("event buffer offset clears the blocker template",
                 "offset %d overlaps the %d-byte token buffer at 0"
                 % (a.buf_off_event, a.token_len))
        return

    pbuf = d3.get_table(bi, d3.PKTGEN_PKT_BUFFER, chk)
    if pbuf is not None and write:
        try:
            pbuf.entry_mod(
                tgt,
                [pbuf.make_key([gc.KeyTuple("pkt_buffer_offset", buf_off),
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
                [acfg.make_key([gc.KeyTuple("app_id", app_id)])],
                [acfg.make_data(([gc.DataTuple("timer_nanosec", int(timer_ns))]
                                 if trigger == "trigger_timer_one_shot" else
                                 [gc.DataTuple("pattern_value",
                                               d3.CLONE_TAG_MARKER << 24),
                                  gc.DataTuple("pattern_mask", 0xFF000000)]) + [
                    gc.DataTuple("pkt_len", len(tmpl)),
                    gc.DataTuple("pkt_buffer_offset", buf_off),
                    gc.DataTuple("pipe_local_source_port", a.port_pgen),
                    gc.DataTuple("increment_source_port", bool_val=False),
                    # Counts are ZERO-BASED. n_batches defaults to 1 (value 0),
                    # which is the Gate-2 configuration; the CHECK 2 batch probe
                    # raises it to ask whether the generator frees BETWEEN batches.
                    gc.DataTuple("batch_count_cfg", int(n_batches) - 1),
                    gc.DataTuple("packets_per_batch_cfg", n_events - 1),
                    gc.DataTuple("ipg", int(ipg_ns)),
                    gc.DataTuple("ibg", int(ibg_ns)),
                    gc.DataTuple("trigger_counter", 0),
                    gc.DataTuple("batch_counter", 0),
                    gc.DataTuple("pkt_counter", 0),
                    gc.DataTuple("app_enable", bool_val=False),
                ], trigger)])
        except Exception as e:                                   # noqa: BLE001
            chk.fail("pktgen app_cfg (events, app %d)" % app_id, str(e)[:90])

    got = _read_app(bi, tgt, app_id)
    got["ipg_ns_requested"] = int(ipg_ns)
    got["trigger"] = trigger
    got["n_events_requested"] = n_events
    if trigger == "trigger_timer_one_shot":
        got["timer_ns_requested"] = int(timer_ns)
    out[out_key] = got
    if "err" in got:
        chk.warn("app %d readback" % app_id, str(got["err"])[:80])
        return
    chk.expect("app %d packets_per_batch_cfg (%d events)"
               % (app_id, n_events),
               got.get("packets_per_batch_cfg"), n_events - 1)
    chk.expect("app %d batch_count_cfg (%d batch(es))"
               % (app_id, n_batches),
               got.get("batch_count_cfg"), int(n_batches) - 1)
    chk.expect("app %d increment_source_port == False" % app_id,
               got.get("increment_source_port"), False)
    chk.expect("app %d pipe_local_source_port" % app_id,
               got.get("pipe_local_source_port"), a.port_pgen)
    chk.expect("app %d app_enable at config time" % app_id,
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
            chk.fail("app %d ipg readback" % app_id,
                     "wrote %d ns, read %d ns" % (ipg_ns, gi))
        else:
            chk.ok("app %d ipg readback" % app_id,
                   "wrote %d ns, read %d ns (core-clock quantization)"
                   % (ipg_ns, gi))


def config_role_map(bi, tgt, a, out, chk, mapping, write=True):
    """(app_id, packet_id) -> transaction role. THE SCENARIO, in table entries.

    Keyed on BOTH because CHECK 2 split the events across two generator apps and
    packet_id alone is no longer unique — app 2's READ and app 3's leading DUMMY are
    both packet_id 0. `mapping` is therefore {(app_id, packet_id): role}; a plain
    {packet_id: role} is still accepted and is read as app 2, so the old scenarios
    keep working.

    The READ carries the generation as action data. Which packet is the ACK and which
    the RESPONSE is written here, so a different arrival order is a control-plane
    change rather than a recompile. Every entry is read back into the manifest: what
    ran is recorded, not assumed. A packet_id with NO entry takes synth_none() and is
    bypassed — which is exactly how the leading DUMMY is expressed, and it means a
    mis-sized batch shows up as a bypass count rather than as a missing event.
    """
    import bfrt_grpc.client as gc
    t = d3.get_table(bi, "tbl_synth_role", chk)
    if t is None:
        chk.fail("tbl_synth_role lookup",
                 "not found — is the SYNTHETIC build (-DD3_SYNTH_EVENTS) loaded?")
        return
    act_of = {"READ": ("synth_read", [("gen", a.gen)]),
              "ACK":  ("synth_ack", []),
              "RESP": ("synth_resp", []),
              # RESP_ALT is case F's stale injector. Same session, same role, same
              # §8.2 treatment -- it differs ONLY in the ethertype it leaves with, so
              # the two RESPONSES are separable in the master-side capture. Without
              # this both mapped to synth_resp and the case could not be scored.
              "RESP_ALT": ("synth_resp_alt", [])}
    def _norm(m):
        """{(app,pid): role} or {pid: role} -> [((app, pid), role)] sorted."""
        outl = []
        for k, v in m.items():
            if isinstance(k, tuple):
                outl.append(((int(k[0]), int(k[1])), v))
            else:
                outl.append(((int(a.app_event), int(k)), v))
        return sorted(outl)

    entries = _norm(mapping)
    installed = {}
    if write:
        for (app, pid), role in entries:
            act, params = act_of[role]
            key = t.make_key([
                gc.KeyTuple("hdr.pgen.pipe_app", (a.pipe << 3) | int(app)),
                gc.KeyTuple("hdr.pgen.packet_id", int(pid))])
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
                    chk.fail("tbl_synth_role app%s pid%s -> %s"
                             % (app, pid, role), str(e)[:90])
    for (app, pid), role in entries:
        got, err = d3.get_entry(t, tgt, [
            ("hdr.pgen.pipe_app", (a.pipe << 3) | int(app)),
            ("hdr.pgen.packet_id", int(pid))])
        installed["app%d.pid%d" % (app, pid)] = err or {
            "action_name": got.get("action_name"), "gen": got.get("gen"),
            "want_role": role}
    out["role_map"] = installed
    ok = all(isinstance(v, dict) and v.get("action_name")
             for v in installed.values())
    if ok:
        chk.ok("tbl_synth_role installed",
               ", ".join("app%d.pid%d->%s" % (app, pid, role)
                         for (app, pid), role in entries))
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
    # BOTH event apps. app 3 is recirculation-pattern triggered on the SAME 0xE1
    # marker as the reservoir, so an app 3 left enabled is not inert: the next clone
    # emits an ACK/RESPONSE pair into a transaction that did not ask for one.
    for _aid, _key in ((a.app_event, "pktgen_event"),
                       (a.app_event2, "pktgen_event2"),
                       (a.app_event3, "pktgen_event3")):
        ev = _read_app(bi, tgt, _aid)
        st[_key] = ev
        if "err" in ev:
            st["reasons"].append("pktgen app %d unreadable: %s"
                                 % (_aid, ev["err"]))
        elif ev.get("app_enable") is not False:
            st["reasons"].append("pktgen app %d app_enable = %r (want False)"
                                 % (_aid, ev.get("app_enable")))
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
               "reg_tag=0x%02X deadline=0x%08X all three apps disabled, "
               "ts regs zero"
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
    rec = {"order": ["disable_event_apps", "d3.cleanup_trial", "zero_synth_regs"]}
    # BOTH event apps. Leaving app 3 enabled would leave a recirculation-pattern app
    # armed on the same 0xE1 marker as the reservoir, so the NEXT run's clone would
    # fire an ACK/RESPONSE pair nobody asked for.
    rec["disable_event_app"] = _set_app(bi, tgt, a.app_event, False, chk, pipe=a.pipe)
    rec["disable_event_app2"] = _set_app(bi, tgt, a.app_event2, False, chk,
                                         pipe=a.pipe)
    rec["disable_event_app3"] = _set_app(bi, tgt, a.app_event3, False, chk,
                                         pipe=a.pipe)
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
    # ►► app_event3 (the STALE INJECTOR) IS READ BACK HERE, and its absence is why
    # the 2026-07-29 stale-response case could not be scored. The record showed
    # app_block / app_event / app_event2 only, so there was NO evidence that app 4
    # had fired, when it fired, or how many packets it emitted -- and the single
    # bypass timestamp landed 200 us from where app 4 was scheduled. With no way to
    # tell which of the two RESPONSES the switch had held, the PASS was withdrawn.
    # See ../AUDIT_RESPONSE.md item 1 and REPORT.md 9.8.
    out["pktgen_after"] = {"app_block": _read_app(bi, tgt, a.app_id),
                           "app_event": _read_app(bi, tgt, a.app_event),
                           "app_event2": _read_app(bi, tgt, a.app_event2),
                           "app_event3": _read_app(bi, tgt, a.app_event3),
                           "app_block_pipe0": _read_app(bi, tgt0, a.app_id),
                           "app_event_pipe0": _read_app(bi, tgt0, a.app_event),
                           "app_event2_pipe0": _read_app(bi, tgt0, a.app_event2),
                           "app_event3_pipe0": _read_app(bi, tgt0, a.app_event3),
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
    # reg_tag FIRST and per pipe. The device-scope readback is a max() collapse
    # across pipes, so it cannot be trusted to describe pipe 0: under the old 0xFF
    # marker an idle pipe (0xFF) outranked an armed pipe 0 (0xC0) and hid it
    # completely, and under the current 0x00 marker the collapse instead hides an
    # IDLE pipe 0 behind any armed pipe. Either way, read per pipe. Every input to tbl_state_decode is
    # here too, so a rejected ACK can be attributed to a specific conjunct
    # instead of guessed at.
    rec["regs_per_pipe"] = {
        r: _reg_read_per_pipe(bi, r, n_pipes)
        for r in ("reg_tag", "reg_deadline", "reg_ack_rel",
                  "reg_exp_relay_seq", "reg_exp_ack", "reg_session_port",
                  "reg_ts_read", "reg_ts_clone", "reg_ts_first_block",
                  "reg_ts_last_block", "reg_ts_ack_arm",
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
        _set_app(bi, tgt, a.app_event, True, chk, pipe=a.pipe)
        time.sleep(a.wait_s)
    finally:
        _set_app(bi, tgt, a.app_event, False, chk, pipe=a.pipe)
        _set_app(bi, tgt, a.app_id, False, chk, pipe=a.pipe)
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
               "%r (0xC0 = the ARM wrote; 0x00 = TAG_INACTIVE, it did not)"
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
    if sc.get("two_timer"):
        # app 2: the READ ALONE, one packet, so its run ends immediately and the
        # generator is free when the clone arrives (CHECK 2's production condition).
        config_event_app(bi, tgt, a, out, chk, 0, write=True,
                         app_id=a.app_event, n_events=1,
                         trigger="trigger_timer_one_shot", out_key="app_event",
                         timer_ns=a.timer_ns)
        # app 3: the ACK then the RESPONSE, one ipg apart, on a timer offset by
        # --ack-offset-ns from app 2's. packet_id discrimination is PROVEN for timer
        # apps (it is what decoded READ/ACK/RESP in every earlier run) and is the
        # reason this is a timer app and not a pattern one.
        config_event_app(bi, tgt, a, out, chk, ipg, write=True,
                         app_id=a.app_event2, n_events=2,
                         trigger="trigger_timer_one_shot", out_key="app_event2",
                         timer_ns=a.timer_ns + a.ack_offset_ns)
    elif sc.get("split"):
        config_event_app(bi, tgt, a, out, chk, 0, write=True,
                         app_id=a.app_event, n_events=1,
                         trigger="trigger_timer_one_shot", out_key="app_event")
        config_event_app(bi, tgt, a, out, chk, ipg, write=True,
                         app_id=a.app_event2, n_events=3,
                         trigger="trigger_recirc_pattern", out_key="app_event2")
    else:
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

    if sc.get("split") and not sc.get("two_timer"):
        # a PATTERN-triggered app 3 has to be listening before the READ for exactly
        # the reason app 1 does (F01-a).
        out["app_event2_enabled"] = _set_app(bi, tgt, a.app_event2, True, chk,
                                             pipe=a.pipe)
        if not out["app_event2_enabled"]:
            out["verdict"] = "INVALID"
            chk.fail("armed the transaction",
                     "event app %d (ACK + RESPONSE) could not be enabled"
                     % a.app_event2)
            return out
        chk.ok("enabled pktgen app %d (ACK + RESPONSE, recirc-pattern)"
               % a.app_event2, "enabled BEFORE the READ app is armed")

    out["armed_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out["arm_monotonic"] = time.time()
    # ORDER: app 2 (the READ) FIRST, app 3 (the ACK) SECOND. Each one-shot timer
    # starts when its own app_enable is written, so the inter-write skew s lands on
    # app 3 and the realised READ->ACK is (Δ + s), never (Δ - s). That is the safe
    # direction: app 3's run cannot start EARLY, so it can never withhold the blocker
    # burst, and C-R2 still gates the reservoir on the hardware timestamps. s is
    # measured here rather than assumed.
    _t0 = time.time()
    if sc.get("two_timer"):
        # BOTH timers armed in ONE entry_mod, so the write skew cannot swamp the
        # intended offset. app 2 is listed first, so if the driver falls back to
        # sequential writes the skew still lands on app 3 (the safe direction).
        ok, how = _set_apps_together(bi, [a.app_event, a.app_event2], True, chk,
                                     pipe=a.pipe)
        _t1 = time.time()
        out["app_event2_enabled"] = ok
        out["arm_skew"] = {
            "write_path": how, "both_writes_s": _t1 - _t0,
            "ack_offset_ns_requested": a.ack_offset_ns,
            "note": "the realised READ->ACK is ack_offset_ns plus whatever skew the "
                    "driver adds between the two entries; I-01 reports what the "
                    "HARDWARE timestamps actually saw, which is the number that "
                    "counts"}
        if ok:
            chk.ok("armed pktgen apps %d + %d TOGETHER (%s)"
                   % (a.app_event, a.app_event2, how),
                   "timers %d / %d ns (offset %d ns), ipg=%d ns, both writes in "
                   "%.0f us" % (a.timer_ns, a.timer_ns + a.ack_offset_ns,
                                a.ack_offset_ns, ipg, (_t1 - _t0) * 1e6))
    else:
        ok = _set_app(bi, tgt, a.app_event, True, chk, pipe=a.pipe)
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
    _set_app(bi, tgt, a.app_event, False, chk, pipe=a.pipe)
    if sc.get("split") or sc.get("two_timer"):
        _set_app(bi, tgt, a.app_event2, False, chk, pipe=a.pipe)
    _set_app(bi, tgt, a.app_id, False, chk, pipe=a.pipe)
    time.sleep(a.drain_s)

    read_all(bi, tgt, tgt0, a, out, chk)
    d3.assert_dp8_speed(bi, tgt, tgt0, a, out, chk)   # R1, after the fact
    out["verdict"] = "COMPLETE"
    return out




# ===========================================================================
# CHECK 2 — PRODUCTION BLOCKER-START LATENCY
# ---------------------------------------------------------------------------
# meeting_direction.md (2026-07-29) forbids delaying the synthetic ACK to let the
# reservoir start until it is known WHOSE latency the ~1 ms observed in the first
# working Gate 2 actually is. This is that measurement.
#
# WHAT IS UNDER TEST IS THE PRODUCTION TRIGGER CHAIN, UNCHANGED:
#
#     READ -> fresh ARM -> arm_clone() I2E mirror -> egress dp68 -> loopback ->
#     generator pattern match on 0xE1 -> app 1 emits K=64 tokens -> admission
#
# Every element of that chain is bit-for-bit what the live build runs; §14 re-verifies
# it against the real SEL-751. The ONE thing this bench substitutes is the ORIGIN of
# the READ: on the rig it arrives from the master on a host port, here it is emitted by
# generator app 2. That substitution is the whole point — it is also the SUSPECT.
#
# THE HYPOTHESIS BEING TESTED. In the failed Gate 2 the first blocker was admitted
# 1 000 012 ns after the READ, and the READ/ACK/RESPONSE came from ONE app-2 batch of
# three packets spaced by ipg = 500 000 ns, i.e. a batch spanning exactly 1 000 000 ns.
# If the generator will not start app 1's triggered batch until app 2's batch has
# finished, then that 1 ms belongs to the HARNESS and not to Defense 3 — and in
# production, where the generator is idle when the READ arrives, it cannot occur.
#
# So each trial emits the READ ALONE (one batch, ONE packet), leaving the generator
# free immediately, which is also the closest available proxy for production. The
# `--c2-events` arm re-runs the same measurement with the Gate-2 batch to convict or
# acquit the harness rather than assuming.
#
# WHY A READ-ONLY TRIAL TERMINATES. dec_arm_fresh writes UNARMED_WORD, so with no ACK
# no deadline is ever armed and the reservoir drains on the pass budget instead:
# H = B*K/rate = 30.802 ms, after which the tokens self-terminate (BLOCK_TERM_TMO) and
# the fail-open path retires the generation. Every wait here is a multiple of H.
#
# It also means each trial independently exercises the fail-open retire — the path
# CHECK 1 found was a silent no-op — so a clean reg_tag afterwards is 100 confirmations
# on silicon that the TAG_NO_WRITE repair works.
# ===========================================================================
C2_REGS_READ = ("reg_ts_read", "reg_ts_clone", "reg_ts_first_block",
                "reg_ts_last_block", "reg_tag", "reg_deadline")


def _c2_reset(bi, tgt, a, chk):
    """Return the chip to its pre-READ state WITHOUT re-running the port, queue,
    shaper or session configuration — those are per-CAMPAIGN, and rewriting them
    every trial would make the measurement a measurement of the control plane.
    Everything a trial can leave behind IS reset: both counter arrays, every
    timestamp register, the deadline and the tag."""
    zero_synth_regs(bi, tgt)
    d3.reg_write(bi, tgt, d3.REG_TAG, d3.TAG_INACTIVE)
    for r in d3.REGS_ZERO:
        d3.reg_write(bi, tgt, r, 0)
    for _n, i in CF_SLOTS.items():
        d3.ctr_zero(bi, tgt, "ctr_fresh", i)
    for _n, i in CD_SLOTS.items():
        d3.ctr_zero(bi, tgt, "ctr_deq", i)


def _c2_trial(bi, tgt, tgt0, tgts, a, chk, index, ipg, n_events, mapping,
              n_batches=1, ibg_ns=0):
    """ONE trial. Returns a self-describing record; never raises."""
    rec = {"index": index, "ipg_ns": ipg, "n_events": n_events,
           "n_batches": n_batches, "ibg_ns": ibg_ns,
           "map": {str(k): v for k, v in mapping.items()}}
    sub = d3.Checks()
    tmp = {}

    # app 1 and app 2 are rewritten every trial for ONE reason: entry_mod resets
    # their trigger/batch/packet counters, and those counters are how a trial proves
    # it fired exactly once. Reading a delta instead would hide a double fire.
    a_events_saved = a.n_events
    a.n_events = n_events
    try:
        d3.config_pktgen(bi, tgt, a, tmp, sub, write=True, app_enable=False)
        config_event_app(bi, tgt, a, tmp, sub, ipg, write=True,
                         n_batches=n_batches, ibg_ns=ibg_ns)
        config_role_map(bi, tgt, a, tmp, sub, mapping, write=True)
        seed_trackers(bi, tgt, a, tmp, sub, write=True)
        _c2_reset(bi, tgt, a, sub)
        rec["reg_tag_before"] = d3.reg_read(bi, tgt, d3.REG_TAG)

        # ORDERING IS LOAD-BEARING and is the F01-a fix: app 1 must be listening
        # before app 2 emits the READ whose clone triggers it.
        rec["app_block_enabled"] = d3.set_app_enable(bi, tgt, a, True, sub)
        rec["armed"] = _set_app(bi, tgt, a.app_event, True, sub, pipe=a.pipe)
        time.sleep(a.c2_wait_s)
        _set_app(bi, tgt, a.app_event, False, sub, pipe=a.pipe)
        _set_app(bi, tgt, a.app_id, False, sub, pipe=a.pipe)
        time.sleep(a.drain_s)

        rec["registers"] = {r: d3.reg_read(bi, tgt, r) for r in C2_REGS_READ}
        rec["counters"] = {
            "fresh": {n: d3.ctr_read(bi, tgt, "ctr_fresh", i)
                      for n, i in CF_SLOTS.items()},
            "deq": {n: d3.ctr_read(bi, tgt, "ctr_deq", i)
                    for n, i in CD_SLOTS.items()},
        }
        # pipe 0, not device scope: the device-scope pktgen counters SUM over pipes
        # and that is what once made one arm of a one-shot timer read as two fires.
        rec["app_block"] = _read_app(bi, tgt0, a.app_id)
        rec["app_event"] = _read_app(bi, tgt0, a.app_event)
        qout = {}
        rec["queues"] = d3.read_queue_counters(bi, tgt0, a, qout, sub)
    except Exception as e:                       # noqa: BLE001 - a trial must not
        rec["error"] = "%s: %s" % (type(e).__name__, str(e)[:200])
    finally:
        a.n_events = a_events_saved
    rec["n_fail_config"] = sub.n_fail
    return rec


def check2_trigger_latency(bi, tgt, tgt0, tgts, a, out, chk):
    """CHECK 2. N trials of the production trigger chain, plus the harness-batch
    comparison arm the verdict needs."""
    d3.assert_dp8_speed(bi, tgt, tgt0, a, out, chk, pre=True)
    assert_clean_start_synth(bi, tgt, tgt0, a, out, chk)

    # per-CAMPAIGN configuration, identical to a Gate-2 trial's
    d3._trial_body(bi, tgt, tgt0, tgts, a, out, chk, write=True)
    config_event_value_set(bi, a, out, chk, write=True)

    if chk.n_fail:
        out["verdict"] = "INVALID"
        out["not_armed"] = ("configuration reported %d failed check(s); nothing "
                            "was armed" % chk.n_fail)
        chk.fail("armed the CHECK 2 campaign", out["not_armed"])
        return out

    # THE ARMS. The first is the measurement the direction asks for; the rest exist
    # so its verdict is an attribution rather than an assertion.
    arms = []
    arms.append({"arm": "production", "n_events": 1, "ipg_ns": a.ipg_ns or 500000,
                 "map": {0: "READ"}, "trials": a.c2_trials,
                 "why": "READ ALONE in a one-packet batch: the generator is free the "
                        "instant the clone is emitted, as it is in production"})
    for ipg in a.c2_batch_ipgs:
        arms.append({"arm": "harness_batch_ipg%d" % ipg, "n_events": 3,
                     "ipg_ns": ipg, "map": {0: "READ", 1: "ACK", 2: "RESP"},
                     "trials": a.c2_batch_trials,
                     "why": "the Gate-2 schedule. If READ->first-blocker tracks "
                            "2*ipg (the batch SPAN) the 1 ms belongs to the harness"})
    # ---- THE DESIGN-DECIDING PROBE ------------------------------------------
    # The production arm settles WHOSE latency the 1 ms is. This settles WHAT TO DO
    # about it, which is a different question with two candidate answers.
    #
    # A batch cannot contain both the READ and the ACK: the reservoir stands at
    # READ + batch_span + 1215 ns while the ACK is admitted at READ + ipg, so the
    # reservoir is ALWAYS later by ipg + 1215 ns, at every ipg, and no re-ordering
    # of the three roles inside one batch fixes it (an ACK placed last is still
    # admitted at the batch END, 1215 ns before the reservoir). So the events must
    # be split. The only open question is the CHEAPEST place to split them:
    #
    #   if the generator frees BETWEEN BATCHES of the same app
    #       -> N batches x 1 packet with ibg as the event gap, and tbl_synth_role
    #          keys on batch_id instead of packet_id. One key change.
    #   if it does not
    #       -> the ACK/RESPONSE move to a SECOND generator app, and the role key
    #          gains the app-id byte. A wider change, and a second value_set.
    #
    # The probe needs NO P4 change to answer it: 2 batches x 1 packet with a large
    # ibg. Both packets carry packet_id 0 and therefore both decode as READ (the
    # second is a harmless ARM_DUP) -- the ROLES are irrelevant here, only WHEN the
    # blockers appear. Read clone_to_first:
    #       ~700 ns   -> the generator freed after batch 0. Batch-level split works.
    #       ~ibg      -> it withheld the burst for the whole APP RUN. Second app.
    for nb, ibg in ((2, 500000), (3, 200000)):
        arms.append({"arm": "batch_probe_%dx1_ibg%d" % (nb, ibg),
                     "n_events": 1, "ipg_ns": 0, "n_batches": nb, "ibg_ns": ibg,
                     "map": {0: "READ"}, "trials": a.c2_batch_trials,
                     "why": "does the generator free BETWEEN batches? clone->first "
                            "~700 ns = yes (split by batch); ~ibg = no (second app)"})

    out["check2"] = {"arms": [], "physical_ack_floor_ns": a.c2_ack_floor_ns,
                     "physical_ack_median_ns": a.c2_ack_median_ns,
                     "failopen_horizon_ns": int(out.get("failopen", {})
                                                .get("horizon_ns", 0) or 0),
                     "wait_s": a.c2_wait_s}
    for spec in arms:
        trials = []
        for i in range(spec["trials"]):
            t = _c2_trial(bi, tgt, tgt0, tgts, a, chk, i, spec["ipg_ns"],
                          spec["n_events"], spec["map"],
                          n_batches=spec.get("n_batches", 1),
                          ibg_ns=spec.get("ibg_ns", 0))
            trials.append(t)
            # A trial that could not even configure is worth stopping for: 100
            # broken trials cost 20 s and prove nothing.
            if t.get("error") and i == 0:
                chk.fail("CHECK 2 arm %s trial 0" % spec["arm"], t["error"])
                break
        rec = dict(spec)
        rec["trial_records"] = trials
        out["check2"]["arms"].append(rec)
        chk.ok("CHECK 2 arm %s" % spec["arm"],
               "%d trial(s), n_events=%d, ipg=%d ns"
               % (len(trials), spec["n_events"], spec["ipg_ns"]))

    d3.assert_dp8_speed(bi, tgt, tgt0, a, out, chk)
    out["verdict"] = "COMPLETE"
    return out




# ===========================================================================
# GATE 3 / GATE 4 — CONSECUTIVE TRANSACTIONS ON ONE LOADED PROGRAM
# ---------------------------------------------------------------------------
# §13 Gate 3 is five consecutive normal transactions with NO P4 reload between
# them; Gate 4 is three boundary cases, three repetitions each, plus one normal
# transaction after the missing-response case to prove recovery.
#
# ►► THE STATE RESET IS THE POINT OF THE TEST, SO IT IS NOT PERFORMED.
#
# Between transactions this driver clears ONLY the write-if-zero timestamp
# registers and the two counter arrays. Those are MEASUREMENT INSTRUMENTS: a
# write-if-zero register latches the first value it ever sees, so leaving them
# would silently report transaction 1's timings for transaction 5.
#
# It deliberately does NOT write reg_tag, reg_deadline or reg_ack_rel. Those are
# TRANSACTION STATE, and two of Gate 3's requirements — "transaction state
# retires completely" and "next transaction begins from a clean state" — are only
# testable if nothing resets them on the transaction's behalf. The generation is
# also ADVANCED every transaction (0xC0, 0xC1, ... — the DNP3 application
# sequence), which makes retirement directly observable in one counter:
#
#     retired  -> reg_tag == 0x00 -> tag_diff == gen      -> ARM_FRESH
#     retained -> reg_tag == 0xCm -> tag_diff == gen - m  -> ARM_BUSY
#
# so a transaction that fails to retire cannot be mistaken for one that did.
# ===========================================================================
G34_STATE_REGS = ("reg_tag", "reg_deadline", "reg_ack_rel")


def _pre_state_verdict(ps, gen):
    """Does this transaction BEGIN FROM A CLEAN STATE?

    ►► CORRECTED after the first Gate-3 attempt, which stopped at transaction 2 on
    THIS criterion and not on the defense. The original rule demanded
    reg_tag == reg_ack_rel == 0 AND reg_deadline == 0 — a zero the architecture never
    promised for two of the three. What transaction 2 actually inherited was
    reg_deadline = 652185089 (transaction 1's armed word) and reg_ack_rel = 0xC0
    (transaction 1's released-ACK generation), and it was materially correct on every
    other count: ARM_FRESH=1, ACK_HOLD=1, RESP_HOLD_EARLY=1, 64 admitted, and it
    retired to 0x00 again.

    Both of those registers are SELF-CLEARING BY CONSTRUCTION, which is a documented
    design decision and not an accident:
      * reg_deadline — the fresh ARM writes UNARMED_WORD unconditionally
        (dec_arm_fresh), and deadline_arm_once only writes when the stored word IS
        UNARMED_WORD. A stale armed word therefore cannot let a duplicate ACK re-arm,
        and cannot survive its own transaction's READ.
      * reg_ack_rel — the RESPONSE's early/late test is the DIFFERENCE
        cur_gen - reg_ack_rel, so a new generation reads non-zero with no reset. That
        is why the P4 calls it generation-bound rather than a boolean.

    So the corrected rule keeps the requirement that actually carries "the transaction
    retires completely" and ADDS the one the old rule never tested:

      1. reg_tag == TAG_INACTIVE          the generation retired. REQUIRED.
      2. reg_ack_rel != this generation   otherwise cur_gen - reg_ack_rel == 0 at the
                                          RESPONSE and an EARLY response would be
                                          misclassified as LATE — silently inverting
                                          the one ordering property Defense 3 claims.
                                          The old rule could not see this at all.

    This is a correction and a tightening, not a relaxation: (2) is a new, sharp
    failure mode, and the harmlessness of a stale deadline is not asserted here — it
    is MEASURED, by T-05 (exactly one ACK_HOLD, zero ACK_DUP_HOLD) and T-10
    (hold >= D) in the very same transaction.
    """
    why = []
    if ps.get("reg_tag") != d3.TAG_INACTIVE:
        why.append("reg_tag = 0x%02X, not TAG_INACTIVE: the previous transaction "
                   "did not retire its generation"
                   % (ps.get("reg_tag") or 0))
    if gen is not None and ps.get("reg_ack_rel") == gen:
        why.append("reg_ack_rel = 0x%02X == this transaction's generation: the "
                   "RESPONSE's early/late difference would read 0 and an EARLY "
                   "response would be scored LATE" % gen)
    return (not why), why


def _g34_pre_state(bi, tgt, a):
    """The transaction state as the PREVIOUS transaction left it. Read, never
    written."""
    return {r: d3.reg_read(bi, tgt, r) for r in G34_STATE_REGS}


def _g34_zero_instruments(bi, tgt):
    """Timestamp registers and counters ONLY — see the block comment above."""
    zero_synth_regs(bi, tgt)
    for r in ("reg_ts_first_block", "reg_ts_ack_arm", "reg_ts_block_term",
              "reg_ts_ack_release"):
        d3.reg_write(bi, tgt, r, 0)
    for _n, i in CF_SLOTS.items():
        d3.ctr_zero(bi, tgt, "ctr_fresh", i)
    for _n, i in CD_SLOTS.items():
        d3.ctr_zero(bi, tgt, "ctr_deq", i)


def _txn_once(bi, tgt, tgt0, tgts, a, idx, sc, ipg, gen, n_events2,
              reset_state=False, label=""):
    """ONE synthetic transaction on an ALREADY-CONFIGURED switch.

    Returns a record shaped like a Gate-2 manifest, so analyze_defense3.score_trial
    scores it with the SAME 17 requirements rather than a second, weaker rubric.
    """
    chk = d3.Checks()
    rec = {"schema": SCHEMA, "txn_index": idx, "label": label,
           "scenario": {"name": a.scenario, "ipg_ns": ipg,
                        "split": True, "two_timer": True,
                        "n_events_app3": n_events2,
                        "map": {str(k): v for k, v in sc["map"].items()}},
           "generation": gen, "reset_state": bool(reset_state)}
    try:
        # ---- what the PREVIOUS transaction left behind, read before anything ----
        rec["pre_state"] = _g34_pre_state(bi, tgt, a)
        ok, why = _pre_state_verdict(rec["pre_state"], gen)
        rec["pre_state_clean"] = ok
        rec["pre_state_reasons"] = why
        if reset_state:
            # ONLY the missing-response repetitions ask for this, and they say so in
            # the record, because it is exactly the crutch Gate 3 must not have.
            for r in G34_STATE_REGS:
                d3.reg_write(bi, tgt, r,
                             d3.TAG_INACTIVE if r != "reg_deadline" else 0)
            rec["state_reset_performed"] = True

        _g34_zero_instruments(bi, tgt)

        # per-transaction configuration: the fresh generation, and the two event
        # apps (rewriting them is what resets their trigger/batch/packet counters,
        # so "one and only one pktgen trigger" is an absolute count, not a delta)
        tmp = {}
        config_role_map(bi, tgt, _GenOverride(a, gen), tmp, chk, sc["map"],
                        write=True)
        rec["role_map"] = tmp.get("role_map")
        d3.config_pktgen(bi, tgt, a, tmp, chk, write=True, app_enable=False)
        if not sc.get("no_read"):
            config_event_app(bi, tgt, a, tmp, chk, 0, write=True,
                             app_id=a.app_event, n_events=1,
                             trigger="trigger_timer_one_shot", out_key="app_event",
                             timer_ns=a.timer_ns)
        if sc.get("no_ack_no_resp"):
            n_events2 = 0          # app 3 is not configured and not armed at all
        if n_events2 > 0:
            config_event_app(bi, tgt, a, tmp, chk, ipg, write=True,
                             app_id=a.app_event2, n_events=n_events2,
                             trigger="trigger_timer_one_shot",
                             out_key="app_event2",
                             timer_ns=a.timer_ns + a.ack_offset_ns)
        if sc.get("stale_injector"):
            # app 4: ONE packet, from the SECOND buffer, carrying a tcp.seq that is
            # --stale-seq-delta away from the trackers this transaction seeds. It
            # therefore fails the 8.2 seq conjunct and is stale BY IDENTITY, not by
            # timing. Its timer places it inside the hold window.
            config_event_app(bi, tgt, a, tmp, chk, 0, write=True,
                             app_id=a.app_event3, n_events=1,
                             trigger="trigger_timer_one_shot",
                             out_key="app_event3",
                             timer_ns=a.timer_ns + a.stale_offset_ns,
                             buf_off=a.buf_off_event3,
                             syn_seq=(a.syn_seq + a.stale_seq_delta) & 0xFFFFFFFF)
        seed_trackers(bi, tgt, a, tmp, chk, write=True)
        rec["config"] = tmp

        if chk.n_fail:
            rec["verdict"] = "INVALID"
            rec["not_armed"] = ("configuration reported %d failed check(s)"
                                % chk.n_fail)
            rec["checks"] = chk.render()
            return rec

        # ---- arm. Both timers in ONE entry_mod so the write skew cannot leak
        # into the READ->ACK offset (measured: 1.15 ms with two writes). ----
        no_read = bool(sc.get("no_read"))
        apps = ([] if no_read else [a.app_event]) \
            + ([a.app_event2] if n_events2 > 0 else []) \
            + ([a.app_event3] if sc.get("stale_injector") else [])
        rec["app_block_enabled"] = d3.set_app_enable(bi, tgt, a, True, chk)
        t0 = time.time()
        ok, how = _set_apps_together(bi, apps, True, chk, pipe=a.pipe)
        rec["arm"] = {"apps": apps, "write_path": how,
                      "both_writes_s": time.time() - t0}
        rec["armed"] = bool(ok and rec["app_block_enabled"])
        if not rec["armed"]:
            rec["verdict"] = "INVALID"
            rec["checks"] = chk.render()
            return rec

        time.sleep(a.wait_s)
        for i in apps:
            _set_app(bi, tgt, i, False, chk, pipe=a.pipe)
        _set_app(bi, tgt, a.app_id, False, chk, pipe=a.pipe)
        time.sleep(a.drain_s)

        # ---- read out. The same reader Gate 2 uses. ----
        read_all(bi, tgt, tgt0, a, rec, chk)
        d3.assert_dp8_speed(bi, tgt, tgt0, a, rec, chk)
        rec["params"] = {"d_ms": a.d_ms,
                         "d_realized_ns": d3.quantize_d(a.d_ms)["realized_ns"],
                         "budget": a.budget, "k": a.k,
                         "rate_dp8_pps": d3.RATE_DP8_PPS, "ipg_ns": ipg,
                         "generation": gen, "n_events_app3": n_events2}
        # score_trial insists on these three; they are true by construction here
        # (this driver's own `finally` is the cleanup, at the end of the sequence)
        rec["clean_start"] = {"clean": rec["pre_state_clean"],
                              "reasons": rec.get("pre_state_reasons") or []}
        rec["cleanup_synth"] = {"deferred": "sequence-level, see the manifest"}
        rec["verdict"] = "COMPLETE"
    except Exception as e:                                       # noqa: BLE001
        rec["verdict"] = "INVALID"
        rec["error"] = "%s: %s" % (type(e).__name__, str(e)[:200])
    rec["checks"] = chk.render()
    rec["n_fail"] = chk.n_fail
    return rec


class _GenOverride(object):
    """A shim so config_role_map can install a DIFFERENT generation per
    transaction without the argparse namespace being mutated (which would make
    the manifest's `params.generation` a lie about earlier transactions)."""

    def __init__(self, a, gen):
        self._a = a
        self.gen = gen

    def __getattr__(self, k):
        return getattr(self._a, k)


def _g34_campaign_setup(bi, tgt, tgt0, tgts, a, out, chk):
    """Everything that is configured ONCE for the whole sequence. Deliberately
    the same call sequence Gate 2 uses, so Gate 3 is not a different experiment."""
    d3.assert_dp8_speed(bi, tgt, tgt0, a, out, chk, pre=True)
    assert_clean_start_synth(bi, tgt, tgt0, a, out, chk)
    d3._trial_body(bi, tgt, tgt0, tgts, a, out, chk, write=True)
    config_event_value_set(bi, a, out, chk, write=True)
    return chk.n_fail == 0


def gate3_transactions(bi, tgt, tgt0, tgts, a, out, chk):
    """§13 GATE 3 — N consecutive normal transactions, no reload, no state reset."""
    sc = SCENARIOS[a.scenario]
    ipg = a.ipg_ns if a.ipg_ns is not None else sc["ipg_ns"]
    if not _g34_campaign_setup(bi, tgt, tgt0, tgts, a, out, chk):
        out["verdict"] = "INVALID"
        chk.fail("armed the GATE 3 sequence",
                 "campaign configuration reported %d failed check(s)" % chk.n_fail)
        return out

    txns = []
    out["gate3"] = {"n_requested": a.g3_txns, "scenario": a.scenario,
                    "ipg_ns": ipg, "d_ms": a.d_ms,
                    "generations": [], "transactions": txns,
                    "state_reset_between": False,
                    "note": "reg_tag / reg_deadline / reg_ack_rel are NEVER written "
                            "between transactions; only the write-if-zero timestamp "
                            "registers and the counters are cleared"}
    for i in range(a.g3_txns):
        gen = 0xC0 + (i % 16)          # the DNP3 application sequence, advancing
        out["gate3"]["generations"].append(gen)
        rec = _txn_once(bi, tgt, tgt0, tgts, a, i + 1, sc, ipg, gen,
                        n_events2=2, reset_state=False,
                        label="gate3 normal transaction %d/%d" % (i + 1, a.g3_txns))
        txns.append(rec)
        bad = (rec.get("verdict") != "COMPLETE") or not rec.get("pre_state_clean")
        if bad:
            # STOP CONDITION: a transaction that inherited state, or one that could
            # not run, makes every later transaction uninterpretable.
            out["gate3"]["stopped_after"] = i + 1
            out["gate3"]["stop_reason"] = (
                "transaction %d verdict=%s pre_state_clean=%s — stopping so the "
                "smallest failure is isolated rather than buried under four more"
                % (i + 1, rec.get("verdict"), rec.get("pre_state_clean")))
            chk.fail("GATE 3 ran all %d transactions" % a.g3_txns,
                     out["gate3"]["stop_reason"])
            break
    else:
        chk.ok("GATE 3 ran all %d transactions consecutively" % a.g3_txns,
               "generations %s, no P4 reload, no state reset between them"
               % ["0x%02X" % g for g in out["gate3"]["generations"]])
    out["verdict"] = "COMPLETE"
    return out


def gate4_cases(bi, tgt, tgt0, tgts, a, out, chk):
    """§13 GATE 4 — the three boundary cases, N repetitions each, then one normal
    transaction to prove recovery from the missing-response case."""
    if not _g34_campaign_setup(bi, tgt, tgt0, tgts, a, out, chk):
        out["verdict"] = "INVALID"
        chk.fail("armed the GATE 4 sequence",
                 "campaign configuration reported %d failed check(s)" % chk.n_fail)
        return out

    d_ns = d3.quantize_d(a.d_ms)["realized_ns"]
    cases = [
        {"case": "A_response_just_before_deadline",
         "scenario": "g4a-resp-near-deadline", "n_events2": 2,
         "ipg_ns": a.g4a_ipg_ns,
         "why": "the RESPONSE arrives %d ns before the deadline — as close as the "
                "hardware generator's ipg permits while still being EARLY"
                % (d_ns - a.g4a_ipg_ns),
         "reset_state": False},
        {"case": "B_response_after_ack_release",
         "scenario": "g4b-resp-after-release", "n_events2": 2,
         "ipg_ns": a.g4b_ipg_ns,
         "why": "the RESPONSE arrives %d ns AFTER the deadline, i.e. after the held "
                "ACK has already committed" % (a.g4b_ipg_ns - d_ns),
         "reset_state": False},
        {"case": "C_missing_response",
         "scenario": "g4c-missing-resp", "n_events2": 1,
         "ipg_ns": a.g4a_ipg_ns,
         "why": "READ and ACK only. Under E1 the ACK's commitment must retire the "
                "transaction, because nothing is pending",
         # ►► NO state reset, and a recovery transaction after EVERY repetition. The
         # direction requires the FIRST recovery transaction to pass, so the harness
         # must not be able to help it: if the ACK release did not retire, the very
         # next READ decodes ARM_BUSY and the recovery fails loudly.
         "reset_state": False, "recover_after_each": True},
    ]
    cases.append(
        {"case": "D_duplicate_early_response",
         "scenario": "g6-duplicate-resp", "n_events2": 3, "ipg_ns": 500000,
         "why": "TWO RESPONSEs, both inside D. Only the first may mark the tag; the "
                "second must read txn_active == 2, miss the hold branch and be "
                "forwarded once as a bypass",
         "reset_state": False})
    cases.append(
        {"case": "F_stale_during_active_txn",
         "scenario": "g8-stale-active", "n_events2": 2, "ipg_ns": 500000,
         "why": "N+1 is armed with its reservoir standing and its deadline armed when a "
                "RESPONSE carrying the PREVIOUS transaction's tcp.seq is injected. It "
                "must not be held as N+1's RESPONSE and must not retire N+1",
         "reset_state": False})
    cases.append(
        {"case": "E_stale_response",
         "scenario": "g7-stale-resp", "n_events2": 1, "ipg_ns": 500000,
         "why": "a RESPONSE with NO READ and NO ACK, against an idle transaction. It "
                "must bypass and leave reg_tag, the deadline and the blockers alone",
         "reset_state": False})
    out["gate4"] = {"reps": a.g4_reps, "d_realized_ns": d_ns, "cases": []}
    for spec in cases:
        a.scenario = spec["scenario"]
        sc = SCENARIOS[spec["scenario"]]
        recs = []
        base = len(out["gate4"]["cases"]) * 5
        for r in range(a.g4_reps):
            gen = 0xC0 + ((r * 2 + base) % 16)
            recs.append(_txn_once(bi, tgt, tgt0, tgts, a, r + 1, sc,
                                  spec["ipg_ns"], gen, spec["n_events2"],
                                  reset_state=spec["reset_state"],
                                  label="%s rep %d/%d"
                                        % (spec["case"], r + 1, a.g4_reps)))
            if spec.get("recover_after_each"):
                # IMMEDIATELY, with no reset: suite 2's requirement is that the FIRST
                # recovery transaction passes.
                nsc = SCENARIOS["gate2-2timer"]
                a.scenario = "gate2-2timer"
                recs.append(_txn_once(
                    bi, tgt, tgt0, tgts, a, r + 1, nsc, nsc["ipg_ns"],
                    0xC1 + ((r * 2 + base) % 16), 2, reset_state=False,
                    label="IMMEDIATE RECOVERY after %s rep %d — normal transaction, "
                          "no state reset" % (spec["case"], r + 1)))
                a.scenario = spec["scenario"]
        entry = dict(spec)
        entry["transactions"] = recs
        out["gate4"]["cases"].append(entry)
        chk.ok("GATE 4 case %s ran %d repetition(s)" % (spec["case"], a.g4_reps),
               spec["why"])

    # ---- RECOVERY. Deliberately WITHOUT a state reset: this is the only way to
    # test "no stale state affects a subsequent normal transaction". If the
    # missing-response case leaves the generation live, this transaction decodes
    # ARM_BUSY instead of ARM_FRESH and says so.
    a.scenario = "gate2-2timer"
    sc = SCENARIOS["gate2-2timer"]
    out["gate4"]["recovery"] = _txn_once(
        bi, tgt, tgt0, tgts, a, 1, sc, sc["ipg_ns"], 0xCF, 2,
        reset_state=False,
        label="recovery 1: one NORMAL transaction after the missing-response case, "
              "with NO state reset")
    # ---- and a SECOND one, also with no reset. The first recovery transaction's own
    # RESPONSE writes TAG_INACTIVE on the dequeued ROLE_RESP path, so it should clear
    # the stale generation even though it was itself unprotected. Whether the defense
    # is then WORKING again is a measurement, not an inference — so it is measured.
    out["gate4"]["recovery2"] = _txn_once(
        bi, tgt, tgt0, tgts, a, 2, sc, sc["ipg_ns"], 0xC0, 2,
        reset_state=False,
        label="recovery 2: a SECOND normal transaction, still with no state reset — "
              "does protection actually resume, and after how many transactions?")
    chk.ok("GATE 4 recovery transactions ran",
           "two of them, neither preceded by a state reset, so the COST of a lost "
           "RESPONSE is measured in transactions rather than argued")
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

    ap.add_argument("--scenario", default="gate2-2timer",
                    choices=sorted(SCENARIOS))
    ap.add_argument("--ipg-ns", type=int, default=None,
                    help="override the scenario's hardware inter-packet gap")
    ap.add_argument("--timer-ns", type=int, default=1000000,
                    help="one-shot timer delay from app_enable to the batch")
    ap.add_argument("--n-events", type=int, default=3)
    ap.add_argument("--app-event", type=int, default=APP_EVENT_DEFAULT)
    ap.add_argument("--gate3", action="store_true",
                    help="§13 GATE 3: N consecutive normal transactions, no P4 "
                         "reload and NO transaction-state reset between them")
    ap.add_argument("--g3-txns", type=int, default=5)
    ap.add_argument("--gate4", action="store_true",
                    help="§13 GATE 4: the three boundary cases, N repetitions "
                         "each, then one normal transaction to prove recovery")
    ap.add_argument("--g4-reps", type=int, default=3)
    ap.add_argument("--g4a-ipg-ns", type=int, default=1995000,
                    help="case A: the ACK->RESPONSE gap, just under D. At D = "
                         "1999872 ns this puts the RESPONSE 4872 ns before the "
                         "deadline")
    ap.add_argument("--g4b-ipg-ns", type=int, default=2500000,
                    help="case B: the ACK->RESPONSE gap, above D + drain, so the "
                         "RESPONSE arrives after the held ACK has committed")
    ap.add_argument("--ack-offset-ns", type=int, default=500000,
                    help="app 3's timer minus app 2's = the intended READ->ACK "
                         "offset. 500 us sits inside the relay's measured band "
                         "(0.400 ms min / 0.505 ms median)")
    ap.add_argument("--app-event3", type=int, default=APP_EVENT3_DEFAULT,
                    help="the STALE-RESPONSE injector app")
    ap.add_argument("--buf-off-event3", type=int, default=BUF_OFF_EVENT3_DEFAULT)
    ap.add_argument("--stale-seq-delta", type=lambda s: int(s, 0), default=0x1000,
                    help="how far the stale template's tcp.seq sits from the current "
                         "transaction's, i.e. how stale its identity is")
    ap.add_argument("--stale-offset-ns", type=int, default=800000,
                    help="when the stale RESPONSE arrives, relative to the READ. The "
                         "default lands it INSIDE the hold window with the reservoir "
                         "standing and the deadline armed")
    ap.add_argument("--app-event2", type=int, default=APP_EVENT2_DEFAULT,
                    help="the SECOND event app (ACK + RESPONSE), fired by the same "
                         "0xE1 clone as the blockers. CHECK 2 forces the split: one "
                         "generator run cannot hold both the READ and the ACK")
    ap.add_argument("--buf-off-event", type=int, default=BUF_OFF_EVENT_DEFAULT)
    ap.add_argument("--gen", type=lambda s: int(s, 0), default=GEN_DEFAULT,
                    help="transaction generation; must be 0xC0..0xCF")
    ap.add_argument("--mport", type=int, default=SYN_MPORT_DEFAULT,
                    help="the master's ephemeral port carried by the template")
    ap.add_argument("--syn-seq", type=lambda s: int(s, 0), default=SYN_SEQ_DEFAULT,
                    help="the template's tcp.seq_no, == EXP_RELAY_SEQ")
    # ---- CHECK 2 (direction 2026-07-29) ----
    ap.add_argument("--check2", action="store_true",
                    help="CHECK 2: measure the PRODUCTION blocker-start latency over "
                         "many trials. Does NOT hold an ACK and does NOT need one.")
    ap.add_argument("--c2-trials", type=int, default=100,
                    help="trials in the production arm (direction: at least 100)")
    ap.add_argument("--c2-batch-trials", type=int, default=10,
                    help="trials per harness-batch comparison arm")
    ap.add_argument("--c2-batch-ipgs", type=lambda s: [int(x) for x in s.split(",")],
                    default=[200000, 500000],
                    help="ipg values for the 3-event comparison arms. Two points are "
                         "what distinguishes 'tracks the batch span' from 'a constant'")
    ap.add_argument("--c2-wait-s", type=float, default=0.2,
                    help="per-trial dwell. Must exceed the fail-open horizon "
                         "H = B*K/rate = 30.8 ms, because with no ACK the reservoir "
                         "drains on the budget; 0.2 s is ~6.5x")
    ap.add_argument("--c2-ack-floor-ns", type=int, default=400000,
                    help="the measured physical READ->ACK MINIMUM the full reservoir "
                         "has to beat (direction: ~0.400 ms)")
    ap.add_argument("--c2-ack-median-ns", type=int, default=505000,
                    help="the measured physical READ->ACK median (~0.505 ms)")
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
    # CHECK 2 is READ-ONLY BY CONSTRUCTION -- it sends a READ and nothing else, which
    # is why it is the only mode that reaches the pass budget at all. Tell the Gate-1
    # horizon check so a deliberately shrunk budget is not refused as "it would cut a
    # legitimate hold short": in this mode there is no hold.
    if getattr(base, "check2", False):
        base.read_only_trial = True
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
           "gate": "13.2", "authored_off_switch": False,
           "silicon_validated": True, "txn_index": a.txn_index}

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
            or a.gate2 or a.microbench or a.check2 or a.gate3 or a.gate4):
        print("nothing to do: pass --gate2, --gate3, --gate4, --check2, "
              "--microbench, --config, "
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
        if a.cleanup and not (a.gate2 or a.check2 or a.gate3 or a.gate4):
            out["mode"] = "cleanup"
            cleanup_synth(bi, tgt, tgt0, tgts, a, out, chk)
        if a.assert_clean and not (a.gate2 or a.check2 or a.gate3 or a.gate4):
            out["mode"] = out.get("mode", "assert-clean")
            assert_clean_start_synth(bi, tgt, tgt0, a, out, chk)
        if a.config and not (a.gate2 or a.check2 or a.gate3 or a.gate4):
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
        if a.verify_only and not (a.gate2 or a.config or a.check2 or a.gate3 or a.gate4):
            out["mode"] = "verify-only"
            read_all(bi, tgt, tgt0, a, out, chk)
        if a.gate3:
            out["mode"] = "gate3"
            ran_trial = True
            gate3_transactions(bi, tgt, tgt0, tgts, a, out, chk)
        if a.gate4:
            out["mode"] = "gate4"
            ran_trial = True
            gate4_cases(bi, tgt, tgt0, tgts, a, out, chk)
        if a.check2 and not a.gate2:
            out["mode"] = "check2"
            ran_trial = True
            check2_trigger_latency(bi, tgt, tgt0, tgts, a, out, chk)
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
        elif ran_trial or a.gate2 or a.config or a.check2 or a.gate3 or a.gate4:
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

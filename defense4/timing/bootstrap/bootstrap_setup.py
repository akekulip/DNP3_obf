#!/usr/bin/env python3
# ============================================================================
# bootstrap_setup.py — Defense 4 §3 (G8): the EXACT one-time control-plane setup
# for bootstrap_probe_v2.p4. This is the reproducible RECORD of the one-time
# configuration the R11 contract depends on (two pktgen timer apps, templates,
# packet count, period, parser value-set entries, four-queue priorities, enable
# sequence).
#
# ►► NOT EXECUTED IN §3. This program is a committed record, not a run. It
#    programs Traffic-Manager queue priorities and the packet generator, i.e.
#    hardware/switch state, which is GATED on Philip's explicit authorization.
#    It refuses to run unless DEFENSE4_HW_AUTHORIZED=1 is set in the environment
#    AND a bfrt gRPC client is available. In §3 it is imported/inspected only.
#
# One-time-only property: EVERY call here is issued ONCE at setup. Nothing in the
# steady state re-invokes the control plane — the periodic timer, once enabled,
# free-runs, and the data plane (bootstrap_probe_v2.p4) does all admission,
# stamping, readiness, confirmation, termination, and re-seed. There is NO
# per-transaction control-plane action.
#
# What stays UNVERIFIED (silicon, R2/R11): whether PERIOD_NS keeps each domain's
# K tokens re-seeded AND confirmed (pop==K) within the CLRT after a READ turns
# the pool over. PERIOD_NS below is a placeholder to be tuned on silicon.
# ============================================================================
import os
import sys

# ---- parameters (must match bootstrap_probe_v2.p4) ----
K_TOKENS      = 64            # packets_per_batch = K; packet_id 0..63
PIPE_ID       = 0
PGEN_PORT     = 68           # dp68, pipe-local packet-generator port
LOOPBACK_PORT = 8            # dp8, where the four queues live
PERIOD_NS     = 1000         # periodic top-up period; SILICON-TUNED (R2/R11)

# reservoir apps: app_id -> (role byte in the template, leading value-set byte)
APP_ACK  = 0                 # -> TOK_ACK reservoir  (Q_ACK_BLOCK  = qid7)
APP_RESP = 1                 # -> TOK_RESP reservoir (Q_RESP_BLOCK = qid5)

# token identity constants (must match the P4)
ETH_TOKEN   = 0x88C1
MARKER      = 0xE1
SD_LOOP     = 0x5A
TOK_ACK     = 0xA1
TOK_RESP    = 0xA2

# four queues on the loopback (G1): qids 7/6/5/4.
#
# ►► UNRESOLVED, LOAD-BEARING (R11 / R2): the block-queue SCHEDULING POLICY is NOT
#    settled and is NOT proven on silicon. A naive strict priority 7 > 6 > 5 > 4
#    STARVES the RESPONSE reservoir: qid7 (ACK block) recirculates continuously and
#    is essentially never empty, so under strict priority qid5 (RESP block) never
#    dequeues -> RESP tokens never loop back -> never CONFIRM -> pop[RESP] never
#    reaches K -> BOTH_READY (0x00400040) is unreachable -> every transaction fails
#    open. The two BLOCK reservoirs must instead be CO-EQUAL (same priority, WRR) or
#    each rate-shaped, with the HOLD queues below them. Whether two continuously
#    recirculating reservoirs can coexist on one loopback port at all was NEVER
#    concluded on silicon (the four-queue oracle pilots failed). This is a TM design
#    question for Gate 3 / hardware, not a data-plane one. The dict below is the
#    queue-id -> name map ONLY; it deliberately does NOT encode a priority policy.
QUEUE_NAMES = {
    7: "Q_ACK_BLOCK",   # ACK reservoir
    6: "Q_ACK_HOLD",    # held ACK
    5: "Q_RESP_BLOCK",  # RESPONSE reservoir
    4: "Q_RESP_HOLD",   # held RESPONSE
}


def build_template(role_byte: int) -> bytes:
    """The seed packet placed in the pktgen packet buffer for one reservoir app.

    HW prepends the 6-byte pktgen_timer_header_t; this buffer is
    ethernet(etype=0x88C1) + token_h + padding to a 64-byte minimum. The data
    plane RE-STAMPS every token field on admission (admit_stamp), so generation
    and token_id here are placeholders; marker/sdomain/role are set correctly so
    the template is self-describing even before the data-plane stamp.
    """
    eth = (b"\x00\x00\x00\x00\x00\x00"      # dst  (rewritten irrelevant; token never egresses to a host)
           b"\x00\x00\x00\x00\x00\x00"      # src
           + ETH_TOKEN.to_bytes(2, "big"))  # etype 0x88C1
    token = (bytes([MARKER, SD_LOOP, role_byte])   # marker, sdomain, role
             + (0).to_bytes(2, "big")              # generation placeholder (DP stamps reg_gen)
             + (0).to_bytes(2, "big"))             # token_id placeholder  (DP stamps packet_id)
    frame = eth + token
    if len(frame) < 64:
        frame = frame + b"\x00" * (64 - len(frame))
    return frame


def make_vs_key(pipe_id: int, app_id: int) -> int:
    """Tofino-1 pktgen_timer_header_t leading byte = 000 ++ pipe_id(2) ++ app_id(3)."""
    return (pipe_id << 3) | app_id


# ---------------------------------------------------------------------------
# The one-time sequence. Each helper issues its calls ONCE.
# ---------------------------------------------------------------------------
def configure_value_set(bfrt):
    """Parser value_set pgen_timer <- {leading byte of app 0, app 1}."""
    vs = bfrt.table_get("IgParser.pgen_timer")
    for app_id in (APP_ACK, APP_RESP):
        vs.entry_add(bfrt.target,
                     [vs.make_key([("f1", make_vs_key(PIPE_ID, app_id))])])


def configure_queue_scheduling(bfrt):
    """G1 (UNRESOLVED): configure the four loopback queues' scheduling.

    ►► This function is intentionally left as a STUB. The block-queue scheduling
    policy is the open R11/R2 question (see QUEUE_NAMES): a naive strict priority
    7>6>5>4 starves the RESP reservoir. The correct policy (co-equal/WRR block
    queues, or per-reservoir shapers, holds below) must be DETERMINED AND PROVEN on
    silicon before this is written — it is NOT assumed here. Writing a policy that
    has not been validated would repeat the over-reach this probe is correcting.
    """
    raise NotImplementedError(
        "block-queue scheduling policy is unresolved (R11/R2); determine and prove "
        "co-equal/WRR-or-shaped block queues on silicon before configuring.")


def configure_pktgen_apps(bfrt):
    """Two one-time periodic timer apps: app 0 -> ACK reservoir, app 1 -> RESP."""
    port_cfg = bfrt.table_get("tf1.pktgen.port_cfg")
    port_cfg.entry_mod(bfrt.target,
                       [port_cfg.make_key([("dev_port", PGEN_PORT)])],
                       [port_cfg.make_data([("pktgen_enable", True)])])

    pkt_buffer = bfrt.table_get("tf1.pktgen.pkt_buffer")
    app_cfg    = bfrt.table_get("tf1.pktgen.app_cfg")

    for app_id, role_byte in ((APP_ACK, TOK_ACK), (APP_RESP, TOK_RESP)):
        template = build_template(role_byte)
        offset   = app_id * 128                      # distinct 16B-aligned buffer slots
        pkt_buffer.entry_add(
            bfrt.target,
            [pkt_buffer.make_key([("pkt_buffer_offset", offset),
                                  ("pkt_buffer_size", len(template))])],
            [pkt_buffer.make_data([("buffer", template)])])

        # trigger_timer_periodic: ONE batch of K packets every PERIOD_NS, forever.
        # batch_count_cfg      = 0     -> one batch per fire
        # packets_per_batch_cfg= K-1   -> packet_id 0..K-1
        app_cfg.entry_mod(
            bfrt.target,
            [app_cfg.make_key([("app_id", app_id)])],
            [app_cfg.make_data([
                ("timer_nanosec",        PERIOD_NS),
                ("pkt_buffer_offset",    offset),
                ("pkt_buffer_size",      len(template)),
                ("batch_count_cfg",      0),
                ("packets_per_batch_cfg", K_TOKENS - 1),
                ("ipg",                  0),
                ("ibg",                  0),
                ("batch_counter",        0),
                ("assigned_chnl_id",     PGEN_PORT),
                ("app_enable",           True),      # arm: the periodic timer starts now
            ], "trigger_timer_periodic")])


def main():
    if os.environ.get("DEFENSE4_HW_AUTHORIZED") != "1":
        sys.stderr.write(
            "REFUSING TO RUN: this programs the packet generator + TM queue priorities "
            "(hardware state), which is gated on explicit authorization. This file is the "
            "committed one-time-setup RECORD for bootstrap_probe_v2.p4; it is inspected in "
            "§3, not executed. Set DEFENSE4_HW_AUTHORIZED=1 only under an authorized "
            "hardware session.\n")
        return 2
    # A real run would construct the bfrt gRPC client here; intentionally not
    # wired up in §3 so import/inspection cannot reach hardware.
    raise SystemExit(
        "bfrt client not wired in this record; provide one under an authorized session.")


if __name__ == "__main__":
    sys.exit(main())

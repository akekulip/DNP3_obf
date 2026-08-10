/* ============================================================================
 * ►►►► case_a_defense3.p4 — CANONICAL PRODUCTION BUILD — R1 + R2 + R3 UNCONDITIONAL ◄◄◄◄
 *
 * This is the final Case A Defense 3 program. The three defects confirmed by the
 * 2026-07-30 audit (see ../AUDIT_RESPONSE.md and REPORT.md §7.5–§7.8) are fixed, and the
 * three repairs are compiled UNCONDITIONALLY — there are no defect toggles, so a build with
 * no flags is the safe, repaired program (CORRECTIONS.md §2.1). It was validated on silicon
 * against the physical SEL-751 relay.
 *
 *   R1  a RESPONSE does not mark the transaction until its seq/ack/port conjuncts have
 *       been checked (tbl_resp_authorise).              (silicon: §7.6, §10.5)
 *   R2  fail-open retirement is generation-qualified via a second register reg_failopen;
 *       the destructive reg_tag write is removed.       (silicon: §7.7)
 *   R3  a fresh, non-generator 0x88C1 frame is dropped, not enqueued into the strict-
 *       priority queue (CF_BLOCK_REJECT).               (silicon: §7.8)
 *
 * BUILD FLAGS (variants, NOT defect toggles): D3_LIVE_FULL_TELEMETRY (two timestamp
 * registers, 11/12 stages), D3_SYNTH_EVENTS (in-chip gate driver), D3_INJECT (adversarial
 * injector, synthetic builds only). Core (no flags) is 10/12 stages, critical path 10.
 *
 * RELATED SOURCES:
 *   - probes/case_a_defense3_toggled.p4 — the toggled A/B source (D3_REPAIR_R1/R2/R3 kept);
 *     flags-off compiles the unrepaired control, flags-on ≡ this file (proven token-identical).
 *   - ../archive/pre_audit/case_a_defense3_fixed_ack_delay.p4 — the frozen pre-audit
 *     unrepaired original (historical control; its 9/12-stage resource logs are the baseline).
 *   Repair narrative: ../REPAIR_HISTORY.md.
 * ============================================================================
 * case_a_defense3_fixed_ack_delay.p4 — DEFENSE 3, PREDETERMINED ACK-DELAY RELEASE
 *
 *   Hold the outstation's original pure TCP ACK until  d_ACK = t_ACK + D  and
 *   release it independently of the RESPONSE. An in-transaction RESPONSE queues
 *   behind the ACK in the SAME FIFO with the SAME loopback pass count, so the
 *   wire order ACK -> RESPONSE is structural, not timed.
 *
 * PROVENANCE. This file is a derivative of
 *   research/case_a_read_anchored_dual_release/p4/case_a_stripped_baseline.p4
 *   (8 ingress / 0 egress / critical path 8 / 57 tables, bf-p4c 9.13.1),
 * which is itself a pure-deletion pass over the frozen, silicon-proven Defense 2
 *   research/defense2_pktgen/p4/dnp3_timing_normalizer_pktgen.p4.
 * BOTH source trees are FROZEN and are NOT modified by this work. The
 * request-triggered pktgen path, the K=64 blocker reservoir, the packed
 * generation state, the whole-container expiry match, the fail-open budget and
 * the byte-preserving deparser/egress are carried over verbatim except where a
 * line is marked "D3:".
 *
 * AUTHORITIES (where they disagree, CONSENSUS wins — it is the PI's synthesis):
 *   - meeting_direction.md  §6 architecture, §7 lifecycle, §8 predicates,
 *                           §9 state, §10 gress placement, §11 resource-led
 *                           re-engineering
 *   - research/case_a_defense3/design/defense3_panel/CONSENSUS.md
 *   - research/case_a_defense3/design/DEFENSE3_BASELINE.md (measured facts)
 *
 * BUILD AND LOAD STATUS: **LOADED AND VALIDATED ON TOFINO-1.** The R1+R2+R3 build was
 * loaded on the switch and run against the physical SEL-751 across the repaired campaigns
 * (§10.5) and the injector matrix (§7.8). Between experiments the switch is returned to
 * the frozen baseline conf (d3_abs.conf); this file is the repaired program, not that
 * baseline. (Provenance of the baseline itself is unchanged, below.)
 *
 * ---------------------------------------------------------------------------
 * WHAT DEFENSE 3 CHANGES vs THE STRIPPED BASELINE
 * ---------------------------------------------------------------------------
 * 1. THE HELD PACKET IS THE ACK, NOT THE RESPONSE.  Q_RESP (qid 1) is renamed
 *    Q_HOLD and now receives the ACK first and the RESPONSE second. Q_BLOCK
 *    (qid 7, strict-priority HIGH) is unchanged: one K=64 request-triggered
 *    reservoir, one blocker class, one deadline.
 * 2. THE BASE MECHANISM ADDS ONE NEW REGISTER (CONSENSUS §4): reg_ack_rel, the
 *    ACK-RELEASE GENERATION. It is written as a GENERATION and read as an
 *    8-bit SALU DIFFERENCE (rv = cur_gen - v), never as a boolean.
 *    NOTE: the R2 repair adds a SECOND register, reg_failopen, under
 *    D3_REPAIR_R2 (see the R2 note further down). "One new register" describes
 *    the pre-repair baseline; the final repaired build has two.
 *    NOT created, because each is already implied by an existing encoding:
 *      deadline_valid    -> bit 0 of the deadline word (ARMED_MARK)
 *      awaiting_ack      -> enforced atomically inside deadline_arm_once
 *      transaction_active-> cur_gen in 0xC0..0xCF (tbl_txn_active)
 *      response_queued   -> derivable from rel_diff
 * 3. THE EXACT §8 PREDICATES.  The baseline's coarse classifier is replaced by
 *    the empirically derived conjuncts of CONSENSUS §8.1/§8.2 (622 transactions,
 *    56 connections, 8 PCAPs). Three trackers are added — reg_exp_relay_seq,
 *    reg_exp_ack, reg_session_port — all learned in the data plane.
 * 4. EVERY IN-TRANSACTION RESPONSE GOES TO Q_HOLD UNCONDITIONALLY.  There is NO
 *    `expired` test and NO deadline term anywhere on the RESPONSE path
 *    (CONSENSUS §6.3). `if (expired) to_fwd()` races the measured 1,736 ns
 *    release tail and inverts wire order; it is not implemented here.
 * 5. FAIL-OPEN BUDGET 100 000 -> 18 000 (CONSENSUS §6.1), and the comment now
 *    carries the MODEL  H = B x K / rate_dp8  instead of a per-pass constant.
 *    The inherited "~10 us/pass" comment was ~5.8x wrong.
 * 6. D, the READ TCP payload length and the budget are RUNTIME parameters of one
 *    keyless table (tbl_params), rewritten with default_entry_set — the proven
 *    Defense 2 idiom that resolved on silicon for G (g_ticks readback 24999936).
 *
 * ---------------------------------------------------------------------------
 * THE ORDERING INVARIANT (CONSENSUS §8.3) — the property the whole design rests on
 * ---------------------------------------------------------------------------
 * Strict priority buys the HOLD. It does NOT buy the ordering. Ordering requires
 * every protected packet to share ALL FOUR of:
 *    (a) the same ingress port          -> PORT_RELAY (dp64), pinned in the parser
 *    (b) the same dp8 qid               -> QID_HOLD, written by exactly ONE named
 *                                          action to_hold() (verifiable in
 *                                          pipe/context.json action immediates)
 *    (c) the SAME NUMBER OF LOOPBACK PASSES -> exactly 1 for the ACK and for
 *                                          every IN-TRANSACTION RESPONSE that
 *                                          must stay ordered behind it. This is
 *                                          why item 4 is unconditional FOR
 *                                          in-transaction responses: a direct
 *                                          forward would be 0 passes, and
 *                                          UNEQUAL PASS COUNT IS WHAT BIT THE
 *                                          PRIOR DESIGN. A RESPONSE arriving
 *                                          AFTER the ACK has retired the
 *                                          transaction is a DIFFERENT case: no
 *                                          held ACK is left to race, so it is
 *                                          forwarded DIRECTLY (0 passes) — which
 *                                          is correct precisely because ordering
 *                                          no longer applies to it. (State table
 *                                          "response after the end"; REPORT §9.5.)
 *    (d) the same dp9 qid               -> qid 0, written by exactly ONE action
 *                                          to_fwd(), used by every egress path
 *
 * ---------------------------------------------------------------------------
 * SAFETY PROPERTIES AND WHERE THEY LIVE (all carried from the baseline)
 * ---------------------------------------------------------------------------
 *   generation safety  : reg_tag holds the generation; the blocker decode entry
 *                        fires only on an exact tag match, so only a token of the
 *                        CURRENT generation is ever live.
 *   arm-once           : tag_arm writes ONLY from the idle state (v ==
 *                        TAG_INACTIVE), so a duplicate or concurrent READ can
 *                        never overwrite an active transaction.
 *   hold-once          : deadline_arm_once writes ONLY when the stored word is
 *                        still UNARMED_WORD, so a duplicate ACK cannot push the
 *                        deadline out.
 *   pass-budget fail-open : REPAIRED (R2). A budget-zero token records its own generation
 *                        in reg_failopen and LEAVES reg_tag UNCHANGED; the next READ arms
 *                        if reg_tag is idle or equals the noted generation. (The baseline
 *                        wrote budget_zero -> TAG_INACTIVE at the tag write, which was
 *                        defect 2; that destructive write is removed under D3_REPAIR_R2.)
 *   blocker isolation  : ethertype 0x88C1 is FORCED to ROLE_BLOCK in the parser,
 *                        so a token can only reach to_block() or drop_pkt().
 *   byte preservation  : no MAU action reads or writes any byte of any host
 *                        frame in ingress OR egress. The only field written
 *                        anywhere is hdr.ib.seq, the internal token's own pass
 *                        counter. Ingress emits in extraction order; egress
 *                        extracts only ethernet and re-emits the rest as residual.
 *   never-dropped      : the one-shot state rejects the ARMING, never the original packet:
 *                        NO original request, ACK or FIRST response is intentionally
 *                        dropped; a duplicate/retransmitted READ, a second qualifying ACK
 *                        and every non-qualifying packet are FORWARDED. TWO deliberate
 *                        exceptions (CORRECTIONS.md §5.3): (R1) a matching RESPONSE
 *                        RETRANSMISSION may be SUPPRESSED while the first copy is still
 *                        queue-resident, by a current-session TCP-POSITION match (§9.6) --
 *                        this is a real reliability change, a TCP retransmission being
 *                        legitimate traffic, traded for ACK-before-RESPONSE order; and (R3)
 *                        a fresh non-generator 0x88C1 frame is DROPPED, not enqueued. The
 *                        match is TCP-position on the session, NOT byte-exact and NOT a DNP3
 *                        transaction-identity check (§5.2).
 *
 * ---------------------------------------------------------------------------
 * NOT CLAIMED
 * ---------------------------------------------------------------------------
 * Multi-segment and multi-fragment DNP3 responses are DETECTED AND BYPASSED
 * UNPROTECTED, not handled. K=64 is not claimed minimal. One active transaction
 * is the measured capacity of the reservoir, not a prototype simplification.
 * The repairs against a real WIRE adversary are not established — the injectors
 * are in-switch stand-ins, not frames from an external host (REPORT §12.2).
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---- ethertypes ---- */
const bit<16> ETHERTYPE_IBSPG_TOKEN = 0x88C1;  /* BLOCK(1) private marker, internal only */
const bit<16> ETHERTYPE_IPV4        = 0x0800;
const bit<8>  IP_PROTO_TCP          = 8w6;

#ifdef D3_SYNTH_EVENTS
/* ##########################################################################
 * ##            SYNTHETIC-EVENT BUILD — §13 GATE 2 ONLY                   ##
 * ##########################################################################
 *
 * COMPILE-TIME SWITCH. Everything guarded by D3_SYNTH_EVENTS exists so that ONE
 * complete Defense 3 transaction can be driven end to end with NOTHING outside
 * the chip: no host injector, no physical relay, no dp11 (which is unconfigured
 * and dark). The LIVE CAMPAIGN BUILD MUST NOT DEFINE IT. With the macro undefined
 * the preprocessed source is byte-identical to the Gate-1 program that is loaded
 * on the switch — that identity is checked, not asserted (see the resource
 * ledger's synthetic row).
 *
 * ------------------------------------------------------------------------
 * WHAT IT ADDS
 * ------------------------------------------------------------------------
 * A SECOND packet-generator application (app 2) on dp68, fired by a one-shot
 * HARDWARE TIMER, emitting ONE batch of three packets spaced by the hardware
 * inter-packet gap `ipg`. The construction is the one proven in
 *   research/case_a_read_anchored_dual_release/p4/case_a_dual_min.p4
 * and the reason it must be hardware-spaced is quantitative: gRPC write skew is
 * milliseconds and D is 2 ms, so three host-armed timers cannot express the
 * event spacing at all. A scenario is exactly (ipg, event role map) — no second
 * P4 variant, no recompile.
 *
 * All three generated packets are BYTE-IDENTICAL copies of ONE buffer template.
 * The template is a REAL relay->master pure TCP ACK. Their only hardware
 * distinguishing mark is `packet_id`, which lives in the 6-byte generator header
 * — and that header is STRIPPED at the ingress deparser, so a role that must
 * survive the dp8 loopback is STAMPED INTO THE FRAME (see the ethertype stamp
 * below).
 *
 * ------------------------------------------------------------------------
 * WHICH REAL PREDICATES EACH SYNTHETIC EVENT ACTUALLY SATISFIES
 * ------------------------------------------------------------------------
 * This is the honest ledger. It is here, in the source, and not only in a
 * report, because the whole risk of a synthetic gate is quietly grading a
 * defense against a weaker predicate than the one it will run.
 *
 * packet_id 1 — the ACK, the packet Defense 3 exists to hold. It is classified
 *   by the REAL predicates almost end to end:
 *     REAL  ipv4.ihl == 5, MF == 0, frag_offset == 0    (parse_ipv4, unmodified)
 *     REAL  (tcp.flags & 0x3F) == 0x10                  (parse_tcp, unmodified)
 *     REAL  ip.total_len == 20 + 4*data_offset          (parse_tcp, unmodified)
 *     REAL  tcp.seq  == EXP_RELAY_SEQ  (exp_seq_rmw, real SALU, real decode key)
 *     REAL  tcp.ack  == EXP_ACK        (exp_ack_r,   real SALU, real decode key)
 *     REAL  master port match          (sess_port_rmw, real SALU, real decode key)
 *     REAL  generation active AND deadline unarmed      (tag_rmw + arm-once)
 *     REAL  the dec_ack_arm entry of tbl_state_decode, unmodified
 *   RELAXED, and there are exactly two:
 *     (1) `ingress_port == PORT_RELAY` — CONSENSUS §8.1's FIRST conjunct. A
 *         generated packet necessarily arrives on dp68, so the synthetic build
 *         assigns DIR_RELAY in parse_pktgen_event. This is the conjunct that
 *         CANNOT be satisfied synthetically, and it is why this build must never
 *         be the campaign build.
 *     (2) the reverse-5-tuple SESSION lookup is served by tbl_synth_role rather
 *         than tbl_session, because all three copies share one 5-tuple and the
 *         READ needs SESS_MASTER while the ACK and RESPONSE need SESS_RELAY.
 *         tbl_synth_role's actions reproduce sess_relay()/sess_master()'s writes
 *         exactly; what is NOT exercised is the ternary lookup itself.
 *   NOT LEARNED IN THE DATA PLANE: EXP_RELAY_SEQ and the master's ephemeral port
 *     are learned in the live build from a master->relay frame on a real
 *     connection (ultimately seeded by the handshake). There is no such frame
 *     here, so the control plane SEEDS reg_exp_relay_seq and reg_session_port to
 *     the template's own values. The comparisons they feed are real; their
 *     seeding is not. EXP_ACK *is* installed by the synthetic READ through the
 *     real exp_ack_w SALU (the control plane sets read_len = ack_no - seq_no so
 *     the real arithmetic lands on the template's acknowledgment).
 *
 * packet_id 0 — the READ. ROLE_ARM comes from tbl_synth_role's packet_id entry,
 *   NOT from the real DNP3 parse chain (start 0x0564 / LEN / FIR+FIN / 0xCn /
 *   func 1), because the template is a pure ACK and carries no DNP3 bytes. Its
 *   generation is control-plane action data. Everything downstream of the class
 *   assignment is real: tag_arm's compare-and-arm-once, dec_arm_fresh, the
 *   UNARMED_WORD disarm, arm_clone()'s mirror, and therefore the REAL K=64
 *   request-triggered reservoir.
 *
 * packet_id 2 — the RESPONSE. ROLE_RESP likewise comes from packet_id, not from
 *   the real §8.2 DNP3 gates (tp_ctrl & 0xC0, app_control & 0xF0, func 129).
 *   Its seq / ack / port conjuncts and its txn_active generation binding ARE
 *   real, and so is the whole unconditional-hold path it then takes.
 *
 * The DNP3 content gates are therefore NOT exercised by Gate 2 at all. They were
 * derived and validated offline against 622 transactions across 8 PCAPs, and
 * they are exercised on the wire by §14's physical SEL-751 campaign. Gate 2 is a
 * LIFECYCLE gate: hold, order, terminate, return clean.
 *
 * ------------------------------------------------------------------------
 * THE ETHERTYPE STAMP, AND WHY THE FRAME STOPS BEING BYTE-PRESERVED HERE
 * ------------------------------------------------------------------------
 * On the dp8 loopback pass the generator header is gone, so a released frame
 * would be re-parsed purely from its own bytes — and all three synthetic events
 * are the same bytes. The released RESPONSE would come back looking like an ACK,
 * be counted as a second ACK release, and never retire the generation, so the
 * transaction could not return clean. tbl_synth_role therefore rewrites
 * hdr.eth.etype to 0x88C6 (ACK) / 0x88C7 (RESPONSE) on the enqueue pass, and
 * parse_eth decodes those two values straight back to ROLE_ACK / ROLE_RESP.
 *
 * CONSEQUENCE, STATED PLAINLY: in this build a held frame is NOT byte-preserved
 * — two bytes of its ethertype are rewritten. Byte preservation is a property of
 * the LIVE build, where no MAU action writes any byte of any host frame. Gate 2
 * makes no byte-identity claim, and none should be read into it.
 * ####################################################################### */
const bit<16> ETYPE_SYNTH_ACK  = 0x88C6;  /* stamped on the held synthetic ACK      */
const bit<16> ETYPE_SYNTH_RESP = 0x88C7;  /* stamped on the held synthetic RESPONSE */
/* ►► THE STALE INJECTOR'S OWN ETHERTYPE. Case F fires TWO synthetic RESPONSES -- N+1's
 * own and a stale copy from app 4 -- and until now tbl_synth_role mapped BOTH to
 * synth_resp, so nothing in any counter, register or timestamp could say which of the
 * two the switch had held and which it had forwarded. That is precisely why the case
 * was withdrawn (REPORT.md 9.8). Giving app 4 its own ethertype costs no state and
 * makes the answer visible in the MASTER-SIDE CAPTURE: a bypassed copy goes straight
 * out, a held copy leaves only after the deadline, so which is which is readable off
 * the wire rather than inferred. */
const bit<16> ETYPE_SYNTH_RESP_ALT = 0x88C8;
#endif

/* ---- DNP3 ---- */
const bit<16> DNP3_START       = 0x0564;   /* link-layer start magic                      */
const bit<8>  DNP3_FC_READ     = 8w1;      /* master -> outstation : arms the transaction */
const bit<8>  DNP3_FC_RESPONSE = 8w129;    /* outstation -> master : SOLICITED response   */

/* ---- roles (parser-assigned, once per path) ---- */
const bit<8> ROLE_BYPASS     = 0;  /* forwarded unchanged, never held, never arms         */
const bit<8> ROLE_BLOCK      = 1;  /* 0x88C1 : enqueue Q_BLOCK (qid7); deadline-checking   */
/* Defense 4: blocker sub-role carried in ibspg_h.slot — ACK reservoir vs RESP reservoir. */
const bit<8> SLOT_ACK        = 0;  /* ACK  blocker token: qid7, checks reg_deadline (T_A)   */
const bit<8> SLOT_RESP       = 1;  /* RESP blocker token: qid5, checks reg_tresp  (T_RESP)  */
const bit<8> ROLE_RESP       = 2;  /* DNP3 solicited RESPONSE, single-segment: Q_HOLD      */
/* D3: a DNP3 RESPONSE that FAILS the single-segment / single-fragment / CON=0 test.
 * Forwarded unprotected and counted UNSUPPORTED_SEGMENTATION (direction §8). */
const bit<8> ROLE_RESP_UNSUP = 3;
const bit<8> ROLE_ARM        = 6;  /* DNP3 READ     : takes the tag, clears the deadline   */
const bit<8> ROLE_ACK        = 7;  /* pure TCP ACK  : HELD to t_ACK + D (this is Defense 3)*/
const bit<8> ROLE_CLONE      = 8;  /* the tagged clone back on dp68: counted, then dropped*/

/* ---- direction ----
 * D3: DIR_RELAY is NEW. The baseline lumped every outstation-side port into
 * DIR_OUT; CONSENSUS §8.1's first conjunct is `ingress_port == PORT_RELAY`, so the
 * live relay leg gets its own direction value. This costs ZERO new PHV (meta.dir
 * already exists) and makes the relay-facing conjunct a single whole-container
 * compare rather than a port re-test in the MAU. */
const bit<8> DIR_MASTER = 0;   /* arrived from the master side (dp9)                  */
const bit<8> DIR_OUT    = 1;   /* loopback dp8, pktgen dp68, or the dp11 replay leg   */
const bit<8> DIR_RELAY  = 2;   /* D3: arrived from the LIVE relay leg (dp64)          */

/* ---- ports ---- */
const PortId_t PORT_L      = 9w8;   /* internal loopback L (dev_port 8, pipe 0)           */
const PortId_t PORT_VISION = 9w9;   /* master side (dp9)                                  */
const PortId_t PORT_HULK   = 9w11;  /* outstation side, REPLAY injector (dp11)            */
/* live inline: the physical SEL-751 hangs off front-panel E1/33 = dev_port 64, reached
 * through an unmanaged switch whose only other active port is the relay's 100M RJ45.
 * Measured to link at BF_SPEED_1G / FEC none / AN force-disable. dev_port 64 is pipe 0
 * (64 < 128), so the dp8 loopback blocker ring is unaffected. */
const PortId_t PORT_RELAY  = 9w64;  /* outstation side, LIVE relay leg (E1/33)            */

/* ---- Defense 4 four-queue ladder on PORT_L (qid == max_priority, static CP setup) ----
 * qid7 = ACK blocker reservoir · qid6 = held original ACK ·
 * qid5 = RESPONSE blocker reservoir · qid4 = held original RESPONSE.
 * Real ACK/RESPONSE stay queue-resident (qid6/qid4); only blocker tokens loop (qid7/qid5). */
const bit<5> QID_ACK_BLOCK  = 5w7;   /* Q_ACK_BLOCK  (HIGH) : ACK blocker reservoir      */
const bit<5> QID_ACK_HOLD   = 5w6;   /* Q_ACK_HOLD          : held original ACK          */
const bit<5> QID_RESP_BLOCK = 5w5;   /* Q_RESP_BLOCK        : RESPONSE blocker reservoir  */
const bit<5> QID_RESP_HOLD  = 5w4;   /* Q_RESP_HOLD  (LOW)  : held original RESPONSE      */
/* back-compat aliases so the reused Defense 3 ACK path keeps compiling unchanged: the
 * Defense 3 "QID_BLOCK/QID_HOLD" are the ACK reservoir + ACK hold in Defense 4. */
const bit<5> QID_BLOCK = QID_ACK_BLOCK;
const bit<5> QID_HOLD  = QID_ACK_HOLD;

/* dp68 (pipe-local port 68, pipe 0) is Tofino-1's packet-generator / recirculation
 * port. BOTH the recirculated tagged clone AND the generated blocker tokens enter
 * ingress on dp68; no ordinary host traffic ever arrives here. */
const PortId_t PORT_PGEN = 9w68;

/* I2E mirror used to spawn the recirculating clone. mirror_type is bit<3> on
 * Tofino-1 (matches the SDE tna_mirror example). Value 0 = no mirror; CLONE = 1. */
typedef bit<3> mirror_type_t;
const mirror_type_t MIRROR_TYPE_CLONE = 1;

/* mirror session id that the control plane binds to egress dp68 ($mirror.cfg).
 * Held in a metadata field (never passed to mirror.emit as a literal — bf-p4c rejects a
 * constant session selector). */
const MirrorId_t CLONE_SESSION_ID = 10w7;

/* The 4-byte recirc tag = MARKER(byte0) | gen(low byte). Control-plane
 * pattern_value/mask pin byte 0 == 0xE1. */
const bit<32> CLONE_TAG_MARKER = 32w0xE1000000;
/* the same marker as the parser sees it: the first byte of the 4-byte recirc tag, and
 * therefore the first byte of the whole clone frame on dp68. It is what the generator's
 * pattern matcher keys on (pattern_value 0xE1000000 / mask 0xFF000000) and what
 * from_pgen must recognise so the clone is not mistaken for an off-topology packet. */
const bit<8>  CLONE_TAG_BYTE   = 8w0xE1;

/* 6-byte pktgen_recirc_header_t (tofino1_base.p4) prefix on every generated packet;
 * skipped with advance() in the parser. 6 bytes = 48 bits. */
const bit<32> PGEN_HDR_BITS = 32w48;

/* ================= D3: FAIL-OPEN PASS BUDGET =============================
 * The budget is PER TOKEN, decremented once per that token's own dp8 loop. The
 * horizon is therefore
 *
 *     H = B x tau        where tau = K / rate_dp8          <- THE MODEL
 *
 * i.e. the reservoir's own loop period, NOT a per-pass wall-clock constant. At
 * K = 64 and the MEASURED dp8 line rate of 37.4 Mpps (25G, 64 B frames):
 *
 *     tau = 64 / 37.4e6 = 1.711 us      (measured 1.715 us, Defense 2 gate f)
 *     H   = 18 000 x 1.711 us = 30.8 ms
 *
 * Sizing (CONSENSUS §6.1). H must NEVER fire during a legitimate hold and must
 * NEVER approach the master's TCP RTO:
 *     longest legitimate hold at D = 3 ms, worst observed READ->ACK a = 22 ms
 *                                                  -> H / T_hold = 8.8x   clear
 *     master RTO floor 200 ms (211 ms measured, loopback)
 *                                                  -> RTO / H    = 6.8x   clear
 * The INHERITED B = 100 000 gives H = 171.5 ms = 0.81 x RTO — too close, and it
 * was sized for Defense 2's G = 25 ms.
 *
 * WARNING — H SCALES WITH PORT SPEED. tau = K / rate_dp8, so a silent dp8 speed
 * change rescales the horizon (at 10G, tau = 5.5 us and H = 99 ms). The setup
 * script asserts $SPEED == BF_SPEED_25G and aborts otherwise. Do not re-derive
 * this number from a per-pass constant; re-derive it from the model.
 *
 * B is a RUNTIME parameter of tbl_params (Panel F: "B must be a runtime parameter
 * alongside D"), so the horizon sweeps without a recompile. The constant below is
 * only the compiled-in default. */
const bit<32> BUDGET_DEFAULT = 32w18000;

/* ---- packed-state constants ---- */
const bit<32> TICK_MASK    = 32w0xFFFFFF00;  /* keep 24 tick bits, clear the marker byte */
const bit<32> ARMED_MARK   = 32w0x00000001;  /* bit 0 of the deadline word = armed       */
const bit<32> UNARMED_WORD = 32w0x00000002;  /* explicit "armed nothing" (marker clear)  */
const bit<32> DL_NO_WRITE  = 32w0;           /* SALU sentinel: leave the deadline be     */
const bit<8>  TAG_INACTIVE = 8w0x00;         /* "no transaction". 0x00, NOT 0xFF —       */
/* F02/F01-b ROOT CAUSE. A LARGE-CONSTANT SALU COMPARISON WAS BEHAVIOURALLY INCORRECT ON
 * SILICON IN THIS CONSTRUCTION: with TAG_INACTIVE = 0xFF the predicate
 * `v == TAG_INACTIVE` did not fire, so the conditional state write never committed, while
 * the SALU's RETURN path (`sub hi, phv_lo, lo`) kept working. With TAG_INACTIVE = 0x00 the
 * write commits (0 -> 64 tokens admitted on hardware).
 * ►► THE EXACT IMMEDIATE-WIDTH CAUSE IS NOT CLAIMED TO BE PROVEN FROM THE BFA. The broken
 * build's .bfa reads `equ lo, lo, -255` and the working one `equ lo, lo`, but a probe over
 * 13 constants (p4/probe_salu_immediate.p4) shows bf-p4c emits `equ lo, lo, -K` for EVERY
 * K from 1 to 255, identically and with no error or warning — so the .bfa cannot
 * distinguish a safe constant from an unsafe one and no width conclusion follows from it.
 * That is why ARM_FRESH fired on tag_diff while the conditional write never committed —
 * reg_tag stayed 0xFF, so
 * cur_gen was 0xFF for every blocker token, tbl_txn_active did not match 0xC0&&&0xF0, and
 * all 64 tokens were dropped (PKTGEN_DROP=64) while the ACK failed its generation conjunct
 * (ACK_REJECT=1). ONE fault, both symptoms.
 * tag_rmw was immune because ITS predicate compares against ZERO (neq lo, phv_hi — the
 * shape bf-p4c emits for `!= 0`, identical to sess_port_rmw's and exp_seq_rmw's), not
 * against a large constant.
 * 0x00 keeps the three decode sets disjoint: fresh -> rv = gen_in - 0 = 0xCn (matches
 * 0xC0&&&0xF0), duplicate -> 0x00, concurrent -> small non-zero; and it is the register's
 * natural init.
 *
 * THE LOWERING CONVENTION, established from the loaded build's own assembly:
 *   `equ lo, lo`        <=>  v == 0                (no immediate)
 *   `equ lo, lo, -K`    <=>  v == K                (the immediate holds MINUS K)
 *   `neq lo, phv_hi`    <=>  <that PHV field> != 0 (no immediate)
 * The AUDIT RULE is STRUCTURAL, not an assembly inspection, because the assembly looks
 * the same for safe and unsafe constants: NEVER compare SALU state against a large
 * constant — compare against zero or against a PHV field. K = 2 (deadline_arm_once) is
 * proven working on silicon; K = 255 is proven broken on silicon; nothing in between has
 * been tested and nothing in between should be relied on.
 * After this repair exactly ONE remains in the whole program — deadline_arm_once against
 * UNARMED_WORD = 2 — and nothing anywhere compares against 0x80..0xFF. */

/* THE NO-WRITE SENTINEL MUST NOT BE ZERO ANY MORE, AND THIS IS NOT COSMETIC.
 * tag_rmw and ack_rel_rmw both write conditionally on `meta.tag_val != TAG_NO_WRITE`,
 * which the compiler lowers to "this PHV field is non-zero". Moving TAG_INACTIVE to 0x00
 * therefore COLLIDED the "retire the transaction" write value with the "do not write"
 * sentinel, and BOTH retire paths — the fail-open blocker (budget_zero) and the released
 * RESPONSE that completes the transaction — became silent no-ops: reg_tag would keep a
 * live generation for ever, so a later keepalive would find a live transaction and G-10
 * ("returns clean") could never pass. Caught by the CHECK 1 audit before it ever ran.
 * 0x01 is safe because meta.tag_val only ever holds TAG_NO_WRITE, TAG_INACTIVE (0x00) or
 * a generation (0xC0..0xCF): 0x01 is in none of those. */
const bit<8>  TAG_NO_WRITE = 8w0x01;         /* SALU sentinel: leave the tag be          */

/* ============ E1: THE EARLY-RESPONSE PENDING MARKER (Gate 4C repair) ==========
 * reg_tag carries the transaction's LIFECYCLE PHASE as well as its generation, in
 * three DISJOINT domains:
 *
 *     0x00                 INACTIVE
 *     0xC0 .. 0xCF         LIVE, no early RESPONSE pending      (MSB SET)
 *     0x10 .. 0x1F         LIVE, early RESPONSE pending         (MSB CLEAR, never 0)
 *
 * The transition is a single constant ADD: generation + 0x50 maps 0xCn -> 0x1n, and
 * it is ONE-SHOT BY CONSTRUCTION rather than by a separate flag — the add is
 * predicated on the MSB being set, and applying it CLEARS the MSB, so a duplicate,
 * retransmitted or stale RESPONSE arriving afterwards cannot apply it again.
 *
 * WHY THIS ENCODING EXISTS. Gate 4C measured that a missing RESPONSE never retires
 * the generation: the only retire paths are the released RESPONSE and the fail-open
 * budget, and the deadline pre-empts the budget. The natural repair — a second
 * register holding response_pending_gen, tested on the ACK-release pass — DOES NOT
 * PLACE: CLASS_RESP needs reg_tag before reg_ack_rel and CLASS_ACK_REL needs the
 * reverse, and register placement is static, so the pair is a dependency cycle.
 * Reduced to a two-register minimal probe in p4/probe_retire_dependency.p4
 * (-DPROBE_CYCLE reproduces `Table placement cannot make any more progress`).
 * Keeping the phase INSIDE reg_tag removes the cycle entirely: one register, one
 * access per packet, no new persistent state.
 *
 * The marker is GENERATION-BOUND, not a boolean: the stored value still identifies
 * WHICH transaction is pending (0x1n carries n), so it cannot leak across
 * generations, and the difference a blocker sees is the constant 0xB0 for EVERY
 * generation — see the CD_BLOCK decode note. */
const bit<8>  TAG_PENDING_DELTA = 8w0x50;

/* ================ D3_LIVE_FULL_TELEMETRY ================================
 * A NARROW flag that adds ONLY reg_ts_last_block (full-reservoir standing: the instant
 * the LAST of the K tokens is admitted) and reg_ts_last_term (the FINAL blocker
 * termination). Those two, and the drain and release tail derived from them, are events
 * INSIDE the pipeline that no packet capture on any host can observe, so the physical
 * validation build has to carry them.
 *
 * It adds NOTHING else: no synthetic packet generator application, no role table, no
 * value set, no packet buffer, no synthetic parser state, and no synthetic event
 * timestamps. It is NOT D3_SYNTH_EVENTS and must never be compiled together with it as a
 * substitute for it.
 *
 * Both registers are WRITE-ONLY. No predicate, no forwarding decision and no state
 * transition reads either of them, so the flag cannot change behaviour — it can only
 * change resource use. MEASURED: the core live build is 9/12 ingress and the instrumented
 * one is 10/12, both at 0 egress and critical path 8. The 9/12 artifact and its compiler
 * report are preserved as the stripped/core implementation. */
#if defined(D3_SYNTH_EVENTS) || defined(D3_LIVE_FULL_TELEMETRY)
#define D3_TS_INTERNAL 1
#endif    /* 0xCn + 0x50 == 0x1n                      */

/* ================= D3: THE PREDETERMINED ACK DELAY  D  ===================
 * D is expressed in 256 ns TICKS in bits [31:8]; the LOW BYTE MUST BE ZERO so the
 * ARMED marker in bit 0 survives  dl_cand = now_word + D  untouched.
 *
 * Default 0x001E8400 = 7 812 ticks = 1 999 872 ns = 1.999872 ms (D = 2 ms, the
 * direction's §13 Gate 2 starting value, quantized down to one tick).
 *
 * D IS RUNTIME-WRITABLE: the control plane rewrites tbl_params' default action
 * parameter (default_entry_set), which is the Defense 2 idiom already resolved on
 * silicon for G. It is deliberately NOT a P4 Register — CONSENSUS §4 permits
 * exactly ONE new register in the base design (reg_ack_rel; the R2 audit repair
 * later adds a second, reg_failopen, outside this budget) and a register for D
 * would cost an SALU access and a PHV pair for a value that never changes inside
 * a transaction.
 *
 * CLAMP: the control plane refuses D > 40 ms (CONSENSUS §8.4 — poll-period overlap
 * at ~40 ms on the 400 ms schedule). The clamp is enforced in setup/, not here,
 * because a P4 constant cannot bound a runtime write. */
const bit<32> D_DEFAULT_TICKS = 32w0x001E8400;

/* D3: the master's READ TCP payload length, used ONLY to derive
 *     EXP_ACK = READ.tcp.seq_no + read_len
 * which is the "expected TCP acknowledgment number" conjunct of CONSENSUS §8.1.
 * (EXP_RELAY_SEQ needs no arithmetic; EXP_ACK does, and this is the whole of it —
 * one add against a runtime immediate, no payload-length computation in the MAU.)
 * 18 B is the observed Class-0 integrity poll: 10 link + 1 transport + 2 app +
 * 3 object (3c 01 06) + 2 CRC. Runtime-writable; the control plane sets it from
 * the calibration capture. A wrong value does not mis-hold anything — it makes
 * every ACK fail the predicate and be forwarded unprotected, which reads out as
 * CF_ACK_REJECT == n_txn and CF_ACK_HOLD == 0. */
const bit<32> READ_LEN_DEFAULT = 32w18;

/* ---- packet classes (drive the ONE decode table) ---- */
const bit<8> CLASS_OTHER     = 8w0;
const bit<8> CLASS_ARM       = 8w1;   /* master DNP3 READ on the protected session   */
const bit<8> CLASS_ACK       = 8w2;   /* relay pure TCP ACK, fresh from dp64         */
const bit<8> CLASS_BLOCK_DEQ = 8w3;   /* blocker token back from the dp8 loopback    */
const bit<8> CLASS_RESP      = 8w4;   /* D3: relay DNP3 RESPONSE, fresh from dp64    */
const bit<8> CLASS_ACK_REL   = 8w5;   /* D3: the RELEASED ACK on its dp8 return pass */

/* ---- Defense 4 mode selection (per-transaction, static control-plane params table) ----
 * TIMING_SPEC §1/§2: T_A = t_A + D_A (ACK deadline), T_RESP = T_A + D_R (RESPONSE deadline).
 * D_A=0 -> D2 policy (RESPONSE-deadline only); D_R=0 -> D3 policy (this Defense 3 base). */
const bit<8> MODE_OFF       = 8w0;   /* bypass: forward ACK + RESPONSE immediately        */
const bit<8> MODE_D1_EVENT  = 8w1;   /* ACK held until matching-RESPONSE event / watchdog */
const bit<8> MODE_D2_RESP   = 8w2;   /* ACK immediate; RESPONSE held to T_RESP            */
const bit<8> MODE_D3_ACK    = 8w3;   /* ACK held to T_A; RESPONSE after ACK (Defense 3)   */
const bit<8> MODE_D4_DUAL   = 8w4;   /* ACK held to T_A AND RESPONSE held to T_RESP       */
const bit<8> MODE_FAIL_OPEN = 8w5;   /* safety: bounded release of both                   */

/* ============================================================================
 * ►► DEFENSE 4 CASE-A INTEGRATION — COMPLETE, PLACES 12/12 (BF-SDE 9.13.1). Base = the
 * silicon-validated Defense 3 (case_a_defense3.p4), whose exact matching, generation
 * isolation, one-shot admission, watchdog, cleanup and byte preservation are REUSED
 * unchanged. Added for Defense 4 (four-queue dual-deadline Case A):
 *   - four-queue ladder: qid7 ACK-blocker / qid6 ACK-hold / qid5 RESP-blocker / qid4
 *     RESP-hold (QID_BLOCK/QID_HOLD alias the ACK reservoir + ACK hold);
 *   - reg_tresp: the RESPONSE deadline, symmetric to reg_deadline(=reg_ta). T_RESP =
 *     t_A + D_A + D_R, armed one-shot at the native ACK from a precomputed (D_A+D_R)
 *     param (ONE MAU add); SEPARATE reg_ta/reg_tresp, each <=2 access sites;
 *   - the RESPONSE is queue-resident in qid4, starved by the qid5 reservoir until
 *     T_RESP; the qid5 blocker is symmetric to qid7 and keyed on the token slot
 *     (SLOT_ACK / SLOT_RESP). ACK-before-RESPONSE by strict priority (qid6 > qid4) plus
 *     T_RESP >= T_A — no extra commitment register;
 *   - modes (static per-transaction params): OFF and FAIL_OPEN are TRUE bypass (no
 *     reg_tag arm, no arm_clone / blocker burst, ACK+RESPONSE forwarded immediately);
 *     D1_EVENT releases the held ACK on the RESPONSE EVENT (the existing reg_tag 0x1n
 *     pending marker -> a live ACK blocker decodes V_BLOCK_PENDING), NOT on the ACK
 *     deadline; D2 (D_A=0), D3 (D_R=0), D4 (D_A>0,D_R>0) via the deadline params;
 *   - reservoirs are HARNESS-established (static, read-triggered), no v5 pktgen bootstrap,
 *     no per-transaction controller action, no dynamic TM.
 * Runtime setup (both reservoirs + queue priorities + mode/D_A/D_R params, with readback
 * and rollback) is a separate control-plane script. Silicon behaviour NOT yet validated.
 * ==========================================================================*/

/* ---- D3: session role, from the control-plane-installed 5-tuple table ---- */
const bit<8> SESS_NONE   = 8w0;
const bit<8> SESS_RELAY  = 8w1;   /* relay -> master, on the protected session */
const bit<8> SESS_MASTER = 8w2;   /* master -> relay, on the protected session */

/* ---- D3: the ONE decode verdict field ==================================
 * Replaces the baseline's separate meta.ack_ok and meta.tag_ok flags with a single
 * 8-bit code, so the decode widens WITHOUT widening the 8-bit PHV group (MAU group
 * B0-15 is at 16/16 containers — see the PHV note on ig_meta_t). Net 8-bit PHV
 * delta for the whole of Defense 3 is ZERO. */
const bit<8> V_NONE        = 8w0;   /* nothing decided: bypass                       */
const bit<8> V_ARM_FRESH   = 8w1;   /* READ armed a NEW generation -> trigger pktgen  */
const bit<8> V_ARM_DUP     = 8w2;   /* duplicate/retransmitted READ -> no second burst*/
const bit<8> V_ARM_BUSY    = 8w3;   /* CONCURRENT READ while active -> escape         */
const bit<8> V_ACK_ARM     = 8w4;   /* pure ACK passed EVERY §8.1 conjunct -> HOLD    */
const bit<8> V_ACK_REJECT  = 8w5;   /* pure ACK failed a conjunct -> forward unprotected*/
const bit<8> V_BLOCK_LIVE  = 8w6;   /* blocker token of the CURRENT generation, no RESP yet */
const bit<8> V_RESP        = 8w7;   /* RESPONSE passed the §8.2 conjuncts -> HOLD     */
const bit<8> V_RESP_BYPASS = 8w8;   /* RESPONSE failed a conjunct -> forward           */
/* Defense 4 D1: blocker of the CURRENT generation whose RESPONSE is PENDING (reg_tag is
 * 0x1n, so a live token sees tag_diff == 0xB0). This is the D1 event, derived from the
 * EXISTING reg_tag pending marker — no new register. */
const bit<8> V_BLOCK_PENDING = 8w9;

/* ---- indexed-counter slots (COMPILE-TIME CONSTANTS ONLY) ==================
 * Stats-ALU occupancy is charged per (counter OBJECT, stage) pair, so every
 * validation counter lives in ONE of two indexed Counter arrays — the baseline's
 * proven collapse, extended with the Defense 3 reasons. There is deliberately NO
 * per-branch Counter object: each array is touched AT MOST ONCE per packet on any
 * path, which is what bf-p4c requires (one Stats ALU access per object per packet)
 * and what keeps the ACT block from growing a stage.
 *
 * INDEXED COUNTERS REPLICATE ACROSS THE STAGES THEY ARE TOUCHED IN, so the control
 * plane must AGGREGATE a slot across instances, not read one. */
/* ctr_fresh — the FRESH (non-dequeued) path, plus the bad-port drop */
const bit<8> CF_BYPASS_FWD     = 8w0;   /* ROLE_BYPASS forwarded transparently        */
const bit<8> CF_BAD_PORT       = 8w1;   /* dropped: ingress port not in the topology  */
const bit<8> CF_ARM_FRESH      = 8w2;   /* READ armed a new generation + one K=64 burst*/
const bit<8> CF_ARM_DUP        = 8w3;   /* duplicate READ: forwarded, NO second burst  */
const bit<8> CF_ARM_BUSY       = 8w4;   /* CONCURRENT_TRANSACTION_ESCAPE (direction §7)*/
const bit<8> CF_ACK_HOLD       = 8w5;   /* qualifying ACK -> Q_HOLD, deadline armed    */
const bit<8> CF_ACK_DUP_HOLD   = 8w6;   /* second qualifying ACK -> Q_HOLD, NO re-arm  */
const bit<8> CF_ACK_REJECT     = 8w7;   /* ACK failed §8.1 -> forwarded unprotected    */
const bit<8> CF_RESP_HOLD_EARLY= 8w8;   /* RESPONSE before the ACK release (rel_diff!=0)*/
const bit<8> CF_RESP_HOLD_LATE = 8w9;   /* RESPONSE after  the ACK release (rel_diff==0)*/
const bit<8> CF_RESP_BYPASS    = 8w10;  /* RESPONSE failed §8.2 / stale / no active txn */
const bit<8> CF_UNSUP_SEG      = 8w11;  /* UNSUPPORTED_SEGMENTATION (direction §8)      */
const bit<8> CF_BLOCK_ENQ      = 8w12;  /* host token ACCEPTED into Q_BLOCK (legacy A/B; NOT the R3-drop) */
const bit<8> CF_PKTGEN_ADMIT   = 8w13;  /* generated token -> Q_BLOCK                   */
const bit<8> CF_PKTGEN_DROP    = 8w14;  /* generated token, no active txn -> dropped    */
/* THE TRIGGERING CLONE IS AN EXPECTED PACKET, NOT AN OFF-TOPOLOGY ONE.
 * Before this slot existed the tagged clone fell through from_pgen's `default` with
 * port_ok = 0 and was charged to CF_BAD_PORT, so BAD_PORT read 1 on EVERY armed
 * transaction in both builds — which silently made §13's "no off-topology packets"
 * clause unsatisfiable whenever the defense actually armed. The clone has already
 * done its whole job inside the generator's pattern matcher by the time the parser
 * sees it; the pipeline drops it, and now says so in its own counter. */
const bit<8> CF_CLONE_SEEN     = 8w15;  /* the tagged clone came back on dp68: dropped  */
/* DUPLICATE-RESPONSE SUPPRESSION. Its own slot, because "we dropped a retransmission
 * on purpose" and "we forwarded something unprotected" are different events and must
 * never be summed. MEASURED before this existed: the bypassed duplicate committed
 * 1 001 449 / 1 001 341 / 1 001 421 ns BEFORE the held ACK across three repetitions,
 * i.e. it OVERTOOK the packet the whole defense exists to delay, because the bypass arm
 * forwards straight out and never enters Q_HOLD. */
const bit<8> CF_RESP_DUP_SUPP  = 8w16;  /* TCP-position-matched RESPONSE retransmission, suppressed (NOT byte-exact) */
const bit<8> CF_BLOCK_REJECT   = 8w17;  /* R3: fresh host 0x88C1 REJECTED before Q_BLOCK */
/* E1 needs NO new ctr_fresh slot. "The first RESPONSE marked the tag" is proven by the
 * ACK-release counter split (CD_ACK_RELEASE vs CD_ACK_REL_RETIRE), which reads the
 * retirement SALU's own pre-state decision, and a duplicate RESPONSE shows up as
 * CF_RESP_BYPASS because it reads txn_active == 2 and misses the hold branch. */
/* ctr_deq — the DEQUEUED (dp8 loopback) path */
const bit<8> CD_BLOCK_LOOP       = 8w0; /* token re-enqueued, one budget unit consumed  */
const bit<8> CD_BLOCK_TERM_STALE = 8w1; /* token terminated: not the current generation */
const bit<8> CD_BLOCK_TERM_DL    = 8w2; /* token terminated: deadline reached           */
const bit<8> CD_BLOCK_TERM_TMO   = 8w3; /* token terminated: ACK_MISSING_FAIL_OPEN      */
const bit<8> CD_RELEASE_DEADLINE = 8w4; /* RESPONSE released, reservoir drained on D    */
const bit<8> CD_RELEASE_FAILOPEN = 8w5; /* RESPONSE released, reservoir drained on B    */
const bit<8> CD_ACK_RELEASE      = 8w6; /* D3: ACK left Q_HOLD, a RESPONSE was pending  */
/* E1: the ACK left Q_HOLD and, finding NO pending RESPONSE, RETIRED the transaction.
 * The two slots PARTITION the ACK releases, so their sum is the release count and the
 * split is the direct evidence of which retirement path ran. One ctr_deq access. */
const bit<8> CD_ACK_REL_RETIRE   = 8w7; /* D3/E1: ACK left Q_HOLD and retired the txn   */

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }

/* the 4-byte recirc tag prepended onto the mirror (clone) copy by
 * clone_mirror.emit at the ingress deparser. Emitted ONLY on the mirror copy. */
header recirc_tag_h { bit<32> tag; }

/* internal blocker token: seq = pass budget, gen = transaction generation.
 * role/slot are kept for wire compatibility with the Part 9/11/12 injector but are
 * NOT read — an 0x88C1 frame is FORCED to ROLE_BLOCK in the parser. */
header ibspg_h { bit<8> role; bit<8> slot; bit<8> gen; bit<32> seq; }

header ipv4_h {
    bit<4>  version; bit<4>  ihl;      bit<8>  diffserv;    bit<16> total_len;
    bit<16> identification;
    /* D3: the 3-bit flags and the 13-bit fragment offset are carried as the ONE
     * 16-bit word they occupy on the wire. Bit-for-bit identical on emit (same
     * field order, same widths, same total) — the deparser cannot tell the
     * difference — but it lets the parser test BOTH new §8.1 conjuncts
     * (MF == 0 AND frag_offset == 0) with a SINGLE masked select field instead of
     * two, which is what keeps parse_ipv4 inside its match-register budget.
     *   mask 0xBFFF, value 0x0000  =>  reserved bit clear, MF clear, offset zero,
     *                                  DF (0x4000) tolerated.
     * Never read in the MAU. */
    bit<16> flags_frag;
    bit<8>  ttl;     bit<8>  protocol; bit<16> hdr_checksum;
    bit<32> src_addr; bit<32> dst_addr;
}

header tcp_h {
    bit<16> src_port; bit<16> dst_port; bit<32> seq_no; bit<32> ack_no;
    bit<4>  data_offset; bit<4> res; bit<8> flags;
    bit<16> window; bit<16> checksum; bit<16> urgent_ptr;
}

/* TCP options carried verbatim; one fixed-size header per data_offset (the TNA
 * parser cannot advance by a runtime amount). NEVER read in the MAU. */
header tcp_opt4_h  { bit<32> data; }
header tcp_opt8_h  { bit<64> data; }
header tcp_opt12_h { bit<96> data; }

/* DNP3 data-link header, 10 B. */
header dnp3_dl_h {
    bit<16> start; bit<8> length; bit<8> ctrl;
    bit<16> dst_addr; bit<16> src_addr; bit<16> crc;
}
header dnp3_tp_h  { bit<8> tp_ctrl; }                      /* transport header, 1 B */
header dnp3_app_h { bit<8> app_control; bit<8> func_code; } /* classification only   */

/* The 6-byte hardware packet-generator header, as a byte-exact overlay. Available in
 * the LIVE build (Defense 4): the blocker path now EXTRACTS it on parse_pktgen_token so
 * `packet_id` selects the reservoir — 0..63 = ACK blocker (qid7), 64..127 = RESPONSE
 * blocker (qid5) — from ONE recirc-triggered 2K batch. It is NEVER emitted (not in the
 * deparser emit list), so the recirculated token frame is still the template without the
 * generator header, exactly as the old advance() produced. bytes 1..3 are never read. */
header pktgen_hdr_h {
    bit<8>  pipe_app;      /* pad(3) ++ pipe_id(2) ++ app_id(3) — app discriminator */
    bit<24> key_or_batch;  /* timer: pad ++ batch_id ; recirc: key — NEVER read     */
    bit<16> packet_id;     /* 0..127: [6]=reservoir (0 ACK / 1 RESP); [15:7]!=0 invalid */
}

#ifdef D3_EGRESS_MARKER
/* D3 PROBE VARIANTS B and C ONLY (direction §10). A 1-byte bridged role marker,
 * added by to_fwd() in ingress and STRIPPED by the egress parser so the frame that
 * leaves is still byte-identical. Variant A — the pre-registered selection — does
 * not compile this and keeps the egress a pure "extract ethernet, re-emit residual"
 * pass-through. */
header bridge_h { bit<8> role; }
#endif

struct headers_t {
    pktgen_hdr_h pgen;    /* consumed on the dp68 blocker/event path; NEVER emitted */
#ifdef D3_EGRESS_MARKER
    bridge_h    br;
#endif
    ethernet_h  eth;
    ibspg_h     ib;
    ipv4_h      ipv4;
    tcp_h       tcp;
    tcp_opt4_h  tcp_opt4;
    tcp_opt8_h  tcp_opt8;
    tcp_opt12_h tcp_opt12;
    dnp3_dl_h   dnp3_dl;
    dnp3_tp_h   dnp3_tp;
    dnp3_app_h  dnp3_app;
}

/* ================================ metadata ===============================
 * PHV NOTE, and it is the one real allocation risk in this program:
 * phv_allocation_summary_0.log for the baseline shows MAU GROUP B0-15 at 16/16
 * CONTAINERS (116/128 bits), all ingress, while overall PHV is only 16.5% used.
 * The 8-bit ingress metadata group is CONTAINER-EXHAUSTED. That, not the overall
 * figure, is what breaks a new SALU's operand placement.
 *
 * Defense 3 therefore holds the 8-bit group FLAT:
 *      removed : meta.tag_ok, meta.ack_ok        (-2)
 *      added   : meta.verdict, meta.sess         (+2)
 * and every genuinely new value is 16- or 32-bit, landing in the empty H/W groups.
 *
 * CONSENSUS §4's pre-identified fix is APPLIED, not held in reserve: reg_ack_rel's
 * two SALU operands REUSE meta.tag_val (write) and meta.tag_diff (result). Both are
 * provably dead on exactly the two paths that touch reg_ack_rel — CLASS_RESP and
 * CLASS_ACK_REL both take the reg_tag `tag_read` arm, which has NO PHV input and
 * performs no write. This costs ZERO new PHV containers. It couples two registers'
 * liveness, so the coupling is spelled out at every site. */
struct ig_meta_t {
    /* ---- parser-computed classification ---- */
    bit<8>  role;          /* ROLE_*                                              */
    bit<8>  dir;           /* DIR_MASTER / DIR_OUT / DIR_RELAY                     */
    bit<9>  fwd_port;      /* transparent-forward peer port for this ingress port  */
    bit<8>  port_ok;       /* 1 if the ingress port is in the topology             */
    bit<8>  gen_in;        /* generation carried by this frame (PHV input 1 of reg_tag) */
    bit<8>  dequeued;      /* 1 if ingress_port == PORT_L                          */

    bit<32> ts32;          /* full-resolution ns, for the timestamp bank only      */
    bit<8>  budget_zero;   /* 1 if hdr.ib.seq == 0 as dequeued (fail-open watchdog)*/

    /* ---- level 0: packet-derived + runtime parameters ---- */
    bit<32> ts_m;          /* ts32 & TICK_MASK                                     */
    bit<32> seq_m;         /* D in ticks, from tbl_params (low byte zero)          */
    bit<32> read_len;      /* D3: master READ TCP payload length, from tbl_params  */
    bit<32> budget_init;   /* D3: fail-open pass budget B, from tbl_params         */
    bit<8>  sess;          /* D3: SESS_NONE / SESS_RELAY / SESS_MASTER             */
    bit<16> mport;         /* D3: the MASTER's ephemeral port as seen on this frame*/
    bit<16> sport_w;       /* D3: PHV input 2 of reg_session_port (0 = no write)   */
    bit<32> seq_w;         /* D3: value operand (PHV input 2) of reg_exp_relay_seq  */

    /* ---- level 1 ---- */
    bit<32> now_word;      /* ts_m | ARMED_MARK — the deadline-aligned "now"       */
    bit<8>  pkt_class;

    bit<8>  tag_val;       /* PHV input 2 of reg_tag (0 = no write) AND, on the
                            * CLASS_RESP / CLASS_ACK_REL paths ONLY, PHV input 2 of
                            * reg_ack_rel. See the PHV note above. */
    bit<32> exp_ack_cand;  /* D3: READ.tcp.seq_no + read_len = the EXP_ACK to store */

    /* ---- level 1/2: the trackers' SALU results ---- */
    bit<32> seq_diff;      /* D3: tcp.seq_no  - EXP_RELAY_SEQ  (0 == match)        */
    bit<16> sport_diff;    /* D3: mport       - session port   (0 == match)        */
    bit<32> ack_diff;      /* D3: tcp.ack_no  - EXP_ACK        (0 == match)        */

    /* ---- level 2 ---- */
    bit<32> dl_cand;       /* now_word + D = the armed word for this ACK           */
    bit<8>  tag_diff;      /* reg_tag SALU result: gen_in - stored. On CLASS_RESP /
                            * CLASS_ACK_REL it instead carries reg_ack_rel's result
                            * rel_diff = cur_gen - ack_release_gen. See the PHV note.*/
    bit<8>  cur_gen;       /* reg_tag raw read: the CURRENT stored generation byte  */

    /* ---- level 3 ---- */
    bit<32> dl_val;        /* PHV input 2 of reg_deadline (0 = do not write)       */
    bit<8>  verdict;       /* V_* — the single decode outcome                      */
    bit<8>  txn_active;    /* 1 = cur_gen is a 0xCn generation                     */

    /* ---- level 4 ---- */
    bit<32> age;           /* now_word - deadline_word, straight out of the SALU   */
    bit<32> dl_pre;        /* D3: the deadline word AS IT WAS before the ACK's
                            * arm-once attempt. == UNARMED_WORD <=> this ACK is the
                            * FIRST qualifying ACK and it armed the deadline.      */
    bit<8>  expired;       /* 1 = armed AND due (blocker path only)                */
    /* ---- Defense 4: mode + RESPONSE-deadline (reg_tresp), symmetric to the ACK side ---- */
    bit<8>  mode;          /* MODE_* from tbl_params                                */
    bit<32> da_dr;         /* precomputed (D_A + D_R) ticks from tbl_params (§ setup verifies) */
    bit<32> tresp_cand;    /* now_word + da_dr = the armed T_RESP word for this ACK */
    bit<32> dl_val_resp;   /* PHV input 2 of reg_tresp (DL_NO_WRITE = do not write) */
    bit<32> age_resp;      /* now_word - T_RESP_word, out of reg_tresp SALU         */
    bit<8>  expired_resp;  /* 1 = T_RESP armed AND due (RESP blocker path only)     */
    bit<8>  is_resp_blk;   /* 1 = dequeued token is a RESPONSE blocker (slot marker)*/

    /* timestamp event flags (each guards ONE ts-register call site) */
    bit<8>  ev_first_block;
    bit<8>  ev_ack_arm;
    bit<8>  ev_block_term;

    /* ---- request-triggered pktgen ---- */
    bit<8>     is_pktgen;    /* 1 = admitted from the pktgen source (dp68)              */
#ifdef D3_SYNTH_EVENTS
    /* 1 = a GENERATED SYNTHETIC EVENT (pktgen app 2). Zero-initialized in `start`
     * (under D3_SYNTH_EVENTS) and reassigned to 1 in parse_pktgen_event on that path.
     * Measured on bf-p4c 9.13.1, this start-init + later per-path reassign compiles
     * cleanly and clears uninitialized_out_param (§5.6 fix).
     *
     * It is NOT folded into meta.is_pktgen: is_pktgen == 1 diverts reg_tag to the
     * RAW tag_read arm, which would rob the synthetic ACK of the tag DIFFERENCE
     * that its dec_ack_arm / dec_ack_reject decode entries are keyed on. */
    bit<8>     is_synth;
#endif
    bit<32>    clone_tag;    /* the 4-byte recirc tag placed on the mirror clone        */
    MirrorId_t clone_ses;    /* the mirror session id for the clone (dp68)              */
}

/* ============================ ingress parser =============================
 * EVERY role decision is taken here; the MAU sees only meta.role / meta.dir /
 * meta.dequeued / meta.fwd_port / meta.port_ok / meta.gen_in. */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    /* the control plane loads this with the generated packets' leading byte,
     * = pktgen_recirc_header_t byte0 = 000 ++ pipe_id(2) ++ app_id(3). Programmed
     * with an EXACT 0xFF mask (a 0x1F mask aliases the 0xE1 clone marker). */
    value_set<bit<8>>(1) pgen_recirc;
#ifdef D3_INJECT
    /* ►► ADVERSARIAL INJECTOR (synthetic builds only). A THIRD leading-byte class for
     * from_pgen: a frame the generator emits that must be treated as a FRESH,
     * host-injected 0x88C1 blocker token -- is_pktgen = 0, dequeued = 0 -- carrying an
     * ATTACKER-CHOSEN generation and budget. It is the in-switch stand-in for a raw
     * 0x88C1 frame on a host port, which the lab cannot produce (no passwordless raw
     * socket on the master, no host on the relay leg). Leading byte = app 5 = 0x05.
     * Same EXACT 0xFF mask as pgen_recirc, for the same aliasing reason. */
    value_set<bit<8>>(1) pgen_inject;
#endif

#ifdef D3_SYNTH_EVENTS
    /* SYNTHETIC BUILD ONLY. The second generator application's leading byte,
     * = 000 ++ pipe_id(2) ++ app_id(3) = 0x02 for pipe 0 / app 2. A SEPARATE
     * value_set rather than a second entry in pgen_recirc, because the two apps
     * take DIFFERENT parser paths: a blocker token's 6-byte generator header is
     * ADVANCED over, while an event's is EXTRACTED so packet_id can be read.
     * Programmed with an EXACT 0xFF mask for the same reason pgen_recirc is. */
    /* SIZE 2, NOT 1 — one entry per EVENT APP.
     *
     * CHECK 2 (2026-07-29) measured that the Tofino-1 packet generator does not
     * start app 1's triggered blocker batch until the EVENT app's whole run has
     * finished, and that the wait equals the run SPAN: 1 batch of 3 at ipg 500 us
     * gave READ->first-blocker = 1 000 012 ns, at ipg 200 us gave 400 011 ns, and
     * 2 batches x 1 packet at ibg 500 us gave 500 010 ns (so it is the whole RUN,
     * not the batch). A single run therefore CANNOT hold both the READ and the ACK:
     * the reservoir would stand at READ + span + 1215 ns while the ACK is admitted
     * at or before READ + span. The events are split across TWO apps instead — the
     * READ alone (whose run ends immediately, leaving the generator free exactly as
     * production does) and the ACK/RESPONSE in a second app. */
    /* SIZE 3: app 2 (the READ), app 3 (ACK + RESPONSE), and app 4 -- a STALE-RESPONSE
     * injector that emits from a SECOND template whose tcp.seq belongs to the PREVIOUS
     * transaction. seq/ack is the TCP-POSITION key this design matches on (CONSENSUS 8.1;
     * NOT a DNP3 transaction-identity check -- the app-sequence nibble is not compared,
     * see §5.2), so a stale response can only be expressed with a second template; sharing one
     * template makes "stale" and "current" indistinguishable by construction. */
    value_set<bit<8>>(3) pgen_event;
#endif

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        /* NOTE (§5.6 fix) — the parser-classification fields role / dir / fwd_port /
         * port_ok / gen_in / dequeued (and is_pktgen / is_synth) are zero-initialized in
         * the block below together with the rest of meta, then reassigned on the paths
         * that reach a from_* / role state. This clears the uninitialized_out_param
         * warning WITHOUT suppressing it. The earlier claim that a start-init followed
         * by a later per-path reassignment is a hard compile error was NOT borne out:
         * measured on bf-p4c 9.13.1, that pattern compiles with 0 errors (constant and
         * header-sourced reassigns alike). Because every default written here equals the
         * compiler's own init_zero value, the change is behaviour-preserving and the MAU
         * is untouched. */
        meta.ts32            = 32w0;
        meta.budget_zero     = 8w0;
        meta.ts_m            = 32w0;
        meta.seq_m           = 32w0;
        meta.read_len        = 32w0;
        meta.budget_init     = 32w0;
        meta.sess            = SESS_NONE;
        meta.mport           = 16w0;
        meta.sport_w         = 16w0;
        meta.seq_w           = 32w0;
        meta.now_word        = 32w0;
        meta.pkt_class       = CLASS_OTHER;
        meta.tag_val         = TAG_NO_WRITE;
        meta.exp_ack_cand    = 32w0;
        meta.seq_diff        = 32w0;
        meta.sport_diff      = 16w0;
        meta.ack_diff        = 32w0;
        meta.dl_cand         = 32w0;
        meta.tag_diff        = 8w0;
        meta.cur_gen         = 8w0;
        meta.dl_val          = DL_NO_WRITE;
        meta.verdict         = V_NONE;
        meta.txn_active      = 8w0;
        meta.age             = 32w0;
        meta.mode            = MODE_D3_ACK;   /* default: the proven Defense 3 policy */
        meta.da_dr           = 32w0;
        meta.tresp_cand      = 32w0;
        meta.dl_val_resp     = DL_NO_WRITE;
        meta.age_resp        = 32w0;
        meta.expired_resp    = 8w0;
        meta.is_resp_blk     = 8w0;
        meta.dl_pre          = 32w0;
        meta.expired         = 8w0;
        meta.ev_first_block  = 8w0;
        meta.ev_ack_arm      = 8w0;
        meta.ev_block_term   = 8w0;
        meta.clone_tag       = 32w0;
        meta.clone_ses       = 10w0;
        /* §5.6 fix: EXPLICITLY zero the parser-classification fields (implicit init_zero
         * already made these the same values, so this is behaviour-preserving). Each is
         * reassigned exactly where it was before, on the from_* / role states. */
        meta.role            = ROLE_BYPASS;   /* 0 */
        meta.dir             = DIR_MASTER;    /* 0 */
        meta.fwd_port        = 9w0;
        meta.port_ok         = 8w0;
        meta.gen_in          = 8w0;
        meta.dequeued        = 8w0;
        meta.is_pktgen       = 8w0;
#ifdef D3_SYNTH_EVENTS
        meta.is_synth        = 8w0;
#endif
        transition select(ig_intr_md.ingress_port) {
            PORT_L      : from_loopback;
            PORT_RELAY  : from_relay;      /* D3: the LIVE relay leg gets DIR_RELAY */
#ifdef D3_REPLAY_ON_HULK
            /* PROBE/REPLAY BUILD ONLY. dp11 is not configured on the switch and the
             * live topology reaches the SEL-751 through dp64. Compile with
             * -DD3_REPLAY_ON_HULK to let a Hulk-side injector stand in for the relay
             * during synthetic gates; the live campaign build must NOT define it,
             * because CONSENSUS §8.1's first conjunct is `ingress_port == PORT_RELAY`. */
            PORT_HULK   : from_relay;
#else
            PORT_HULK   : from_outstation;
#endif
            PORT_VISION : from_master;
            PORT_PGEN   : from_pgen;       /* dp68 = generated tokens + recirc clones */
            default     : accept;          /* port_ok stays 0 -> dropped in the MAU   */
        }
    }

    /* the loopback carries only outstation-origin frames (the held ACK, the held
     * RESPONSE) and blocker tokens, so its transparent forward target is the master. */
    state from_loopback   { meta.dequeued = 8w1; meta.dir = DIR_OUT;    meta.fwd_port = PORT_VISION;
                            meta.port_ok  = 8w1; transition parse_eth; }
    /* D3: the live relay leg. DIR_RELAY is the "relay-facing ingress direction"
     * conjunct of CONSENSUS §8.1 / §8.2, carried as a parser field so the MAU never
     * re-reads ingress_port. */
    state from_relay      { meta.dir      = DIR_RELAY;  meta.fwd_port = PORT_VISION;
                            meta.port_ok  = 8w1; transition parse_eth; }
    state from_outstation { meta.dir      = DIR_OUT;    meta.fwd_port = PORT_VISION;
                            meta.port_ok  = 8w1; transition parse_eth; }
    state from_master     { meta.dir      = DIR_MASTER; meta.fwd_port = PORT_RELAY;
                            meta.port_ok  = 8w1; transition parse_eth; }

    /* dp68 carries exactly two things — a generated blocker token (leads with the
     * 6-byte pktgen_recirc header, first byte in pgen_recirc) or a recirculated tagged
     * clone (leads with the 0xE1 marker). The token is admitted; anything else falls
     * through with port_ok = 0 and is dropped in the MAU. */
    state from_pgen {
        transition select(pkt.lookahead<bit<8>>()) {
            pgen_recirc    : parse_pktgen_token;
#ifdef D3_SYNTH_EVENTS
            pgen_event     : parse_pktgen_event;
#endif
#ifdef D3_INJECT
            pgen_inject    : parse_pktgen_inject;
#endif
            CLONE_TAG_BYTE : parse_clone;   /* the trigger clone: expected, counted */
            default        : accept;        /* junk -> port_ok 0 -> BAD_PORT drop   */
        }
    }

    /* THE TAGGED CLONE, on the loopback that carried it into the generator's pattern
     * matcher. By the time the PARSER sees it the trigger has ALREADY happened —
     * pattern matching is done in the generator, ahead of the pipeline — so there is
     * nothing left to do but count it and drop it. It gets a role of its own for one
     * reason: with the old `default` fall-through it was charged to CF_BAD_PORT, and
     * BAD_PORT then read 1 on every armed transaction, so a real off-topology packet
     * was indistinguishable from correct operation.
     * Nothing after the tag is extracted — the frame is dropped, so the headers are
     * never needed, and NOT extracting keeps this state off the parser's critical
     * path. */
    state parse_clone {
        meta.role     = ROLE_CLONE;
        meta.port_ok  = 8w1;
        meta.dir      = DIR_OUT;
        meta.fwd_port = PORT_VISION;   /* never used: the ACT block drops it */
        transition accept;
    }
    state parse_pktgen_token {
        meta.is_pktgen = 8w1;
        meta.port_ok   = 8w1;
        meta.dir       = DIR_OUT;
        meta.fwd_port  = PORT_VISION;
        pkt.extract(hdr.pgen);        /* Defense 4: read packet_id to select the reservoir
                                       * (0..63 ACK/qid7, 64..127 RESP/qid5); NEVER emitted */
        transition parse_eth;
#ifdef D3_INJECT
    /* THE INJECTOR PATH. Identical to the token path EXCEPT is_pktgen is left 0, so
     * the frame is classified as a FRESH host-injected 0x88C1 rather than a generated
     * token: it reaches the legacy / R3 branch of the fresh ROLE_BLOCK arm rather than
     * the admission-stamp branch, and therefore KEEPS the generation and budget the
     * frame carries instead of having the current generation stamped over them. The
     * 0x88C1 body after the pktgen header is parsed by parse_token exactly as any
     * other 0x88C1 frame, so meta.gen_in comes from hdr.ib.gen and hdr.ib.seq is the
     * chosen budget. dequeued also stays 0 (this is not the dp8 loopback). */
    }
    state parse_pktgen_inject {
        meta.port_ok   = 8w1;
        meta.dir       = DIR_OUT;
        meta.fwd_port  = PORT_VISION;
        pkt.advance(PGEN_HDR_BITS);
        transition parse_eth;
#endif
    }

#ifdef D3_SYNTH_EVENTS
    /* SYNTHETIC BUILD ONLY — a generated event from app 2.
     *
     * `meta.dir = DIR_RELAY` IS THE ONE RELAXED CONJUNCT of this whole build.
     * CONSENSUS §8.1's first conjunct is `ingress_port == PORT_RELAY`, and a
     * generated packet necessarily arrives on dp68. Assigning DIR_RELAY here is
     * what lets the synthetic ACK and RESPONSE reach the REAL class driver, the
     * REAL decode table and the REAL hold, and it is exactly why the live
     * campaign build must not define D3_SYNTH_EVENTS. It is a single line, in one
     * place, in a state no live packet can ever enter.
     *
     * is_pktgen stays 0: an event is not a blocker token and must not take the
     * blocker admission path. */
    state parse_pktgen_event {
        meta.is_synth = 8w1;
        meta.port_ok  = 8w1;
        meta.dir      = DIR_RELAY;
        meta.fwd_port = PORT_VISION;
        pkt.extract(hdr.pgen);          /* consumed, never emitted */
        transition parse_eth;
    }
#endif

    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) {
            ETHERTYPE_IBSPG_TOKEN : parse_token;
            ETHERTYPE_IPV4        : parse_ipv4;
#ifdef D3_SYNTH_EVENTS
            /* the RELEASED synthetic frames coming back off the dp8 loopback.
             * The role was stamped into the ethertype on the enqueue pass because
             * the generator header — the only thing that distinguished the three
             * identical copies — was stripped by the ingress deparser. Nothing
             * after the ethernet header is extracted, so the rest of the frame
             * stays RESIDUAL and is re-emitted verbatim. */
            ETYPE_SYNTH_ACK       : synth_back_ack;
            ETYPE_SYNTH_RESP      : synth_back_resp;
            ETYPE_SYNTH_RESP_ALT  : synth_back_resp;   /* same return path, own tag */
#endif
            default               : accept;    /* ARP / IPv6 / ... -> ROLE_BYPASS */
        }
    }

#ifdef D3_SYNTH_EVENTS
    state synth_back_ack  { meta.role = ROLE_ACK;  transition accept; }
    state synth_back_resp { meta.role = ROLE_RESP; transition accept; }
#endif

    /* 0x88C1 is internal and can only ever be a blocker token: the role is FORCED
     * here, so no injected frame can talk its way onto a host port. */
    state parse_token {
        pkt.extract(hdr.ib);
        meta.role   = ROLE_BLOCK;
        meta.gen_in = hdr.ib.gen;
        /* Defense 4: is_resp_blk (from hdr.ib.slot) is computed in the MAU (the parser
         * has no comparison-to-flag); see the level-0 block where budget_zero is set. */
        transition accept;
    }

    /* D3 — CONSENSUS §8.1 conjunct "ipv4.ihl == 5 AND frag_offset == 0 AND MF == 0"
     * (NEW: the fragmentation test was never present in the baseline). The whole
     * flags+fragment-offset word is masked 0xBFFF against 0x0000, which rejects
     * every fragment and the reserved bit while tolerating DF. */
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol, hdr.ipv4.ihl, hdr.ipv4.flags_frag) {
            (IP_PROTO_TCP, 4w5, 16w0x0000 &&& 16w0xBFFF) : parse_tcp;
            default                                      : accept;
        }
    }

    /* GATE 1 — TCP flags and payload length. Range/exact-matched HERE (total_len
     * live-range = one state) because the TNA parser cannot compute, and matching
     * total_len in a downstream state ICEs.
     *
     *   D3 pure ACK    : (flags & 0x3F) == 0x10, total_len == 20 + 4*data_offset
     *                    The baseline mask 0x17 constrained only FIN/SYN/RST/ACK and
     *                    ADMITTED a zero-payload PSH|ACK (0x18) and a URG|ACK (0x30).
     *                    0x3F rejects PSH and URG too, while still tolerating ECE/CWR
     *                    so a future ECN deployment fails SAFE rather than open.
     *                    (Measured: this relay sets PSH on control segments — all 56
     *                    of its FIN frames are FIN|PSH|ACK.)
     *   D3 DNP3-capable: (flags & 0x27) == 0x10 — REQUIRE ACK, reject FIN/SYN/RST/URG,
     *                    ALLOW PSH (622/622 observed responses are flags 0x18).
     *                    The baseline's 0x00 &&& 0x07 did not even require ACK.
     * Anything else falls through to `accept` and is forwarded as ROLE_BYPASS. */
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.flags, hdr.tcp.data_offset, hdr.ipv4.total_len) {
            (8w0x10 &&& 8w0x3F, 4w5,  16w40) : set_role_ack;
            (8w0x10 &&& 8w0x3F, 4w6,  16w44) : set_role_ack;
            (8w0x10 &&& 8w0x3F, 4w7,  16w48) : set_role_ack;
            (8w0x10 &&& 8w0x3F, 4w8,  16w52) : set_role_ack;   /* Linux TS — the corpus case */
            (8w0x10 &&& 8w0x3F, 4w9,  16w56) : set_role_ack;
            (8w0x10 &&& 8w0x3F, 4w10, 16w60) : set_role_ack;
            (8w0x10 &&& 8w0x3F, 4w11, 16w64) : set_role_ack;
            (8w0x10 &&& 8w0x3F, 4w12, 16w68) : set_role_ack;
            (8w0x10 &&& 8w0x3F, 4w13, 16w72) : set_role_ack;
            (8w0x10 &&& 8w0x3F, 4w14, 16w76) : set_role_ack;
            (8w0x10 &&& 8w0x3F, 4w15, 16w80) : set_role_ack;
            (8w0x10 &&& 8w0x27, 4w5,  16w53 .. 16w65535) : parse_dnp3_dl;
            (8w0x10 &&& 8w0x27, 4w6,  16w57 .. 16w65535) : opt4;
            (8w0x10 &&& 8w0x27, 4w7,  16w61 .. 16w65535) : opt8;
            (8w0x10 &&& 8w0x27, 4w8,  16w65 .. 16w65535) : opt12;
            default                                      : accept;
        }
    }

    state opt4  { pkt.extract(hdr.tcp_opt4);  transition parse_dnp3_dl; }
    state opt8  { pkt.extract(hdr.tcp_opt8);  transition parse_dnp3_dl; }
    state opt12 { pkt.extract(hdr.tcp_opt12); transition parse_dnp3_dl; }

    state set_role_ack { meta.role = ROLE_ACK; transition accept; }

    /* GATE 2 — DNP3 link LEN. LEN counts ctrl+dst+src+user data, so LEN == 5 is a
     * well-formed LINK-ONLY frame (the LINK_STATUS exchange): valid, forwarded
     * transparently, never dropped. Transport(1) + application(2) need LEN >= 8. */
    state parse_dnp3_dl {
        pkt.extract(hdr.dnp3_dl);
        transition select(hdr.dnp3_dl.start, hdr.dnp3_dl.length) {
            (DNP3_START, 8w8 .. 8w255) : parse_dnp3_tp;
            default                    : accept;   /* LINK_OTHER or not DNP3 */
        }
    }

    /* GATE 3 (D3, NEW) — SINGLE TRANSPORT SEGMENT.  (tp_ctrl & 0xC0) == 0xC0, i.e.
     * FIR = 1 AND FIN = 1.  THE MASK MUST BE 0xC0: the low 6 bits are the transport
     * SEQUENCE counter and span 0x00-0x3F, so any wider mask silently rejects
     * legitimate frames. 622/622 of the corpus satisfies it.
     * The test is taken HERE, in the state that extracts tp_ctrl, rather than folded
     * into the next state's select — matching a field extracted in a PREVIOUS state
     * is the construct that ICEs this compiler. */
    state parse_dnp3_tp {
        pkt.extract(hdr.dnp3_tp);
        transition select(hdr.dnp3_tp.tp_ctrl) {
            (8w0xC0 &&& 8w0xC0) : parse_dnp3_app;
            default             : parse_dnp3_app_unsup;
        }
    }

    /* GATE 4 (D3, tightened) — SINGLE APPLICATION FRAGMENT, SOLICITED, NO CONFIRM.
     *   (app_control & 0xF0) == 0xC0  <=>  FIR = 1, FIN = 1, CON = 0, UNS = 0
     *   func_code == 129              <=>  solicited RESPONSE (130 = UNSOLICITED)
     * The baseline accepted ANY app_control on a RESPONSE (mask 0x00). 622/622 of the
     * corpus is 0xCn with func 129 and zero CON=1, zero FC 130. */
    state parse_dnp3_app {
        pkt.extract(hdr.dnp3_app);
        /* the DNP3 application control byte (FIR/FIN/CON/UNS + the 4-bit application
         * sequence, which increments per poll) is this transaction's generation.
         *
         * ►► CHECK 1 — NO ACTIVE GENERATION CAN EVER BE ZERO, and this is where it is
         * proven for the live build. gen_in is assigned here from app_control, and the
         * select immediately below admits ROLE_ARM only under (app_control & 0xF0) ==
         * 0xC0. ROLE_ARM is the ONLY role that reaches tag_arm, so every generation
         * that can be WRITTEN into reg_tag lies in 0xC0..0xCF. There is no generation
         * ARITHMETIC anywhere in the data plane — nothing increments and nothing can
         * wrap: the 4-bit DNP3 application sequence advances inside the LOW nibble
         * (0xCF -> 0xC0 at wrap) while the mask pins the high nibble to 0xC. So
         *     0x00 is unreachable as a generation, and reg_tag's domain is exactly
         *     {TAG_INACTIVE = 0x00} u {0xC0..0xCF},
         * which is what makes 0x00 usable as the "no transaction" marker.
         * gen_in is also assigned on the two non-ARM branches (unsupported response,
         * default accept) where it may be any byte; neither reaches tag_arm.
         * The SYNTHETIC build's generation is control-plane action data instead
         * (synth_read(gen)) and is range-checked in the control plane, because the P4
         * cannot check its own action data. */
        meta.gen_in = hdr.dnp3_app.app_control;
        transition select(hdr.dnp3_app.app_control, hdr.dnp3_app.func_code) {
            (8w0xC0 &&& 8w0xF0, DNP3_FC_RESPONSE) : set_role_resp;
            (8w0xC0 &&& 8w0xF0, DNP3_FC_READ)     : set_role_arm;
            (8w0x00 &&& 8w0x00, DNP3_FC_RESPONSE) : set_role_resp_unsup;
            default                               : accept;  /* DIRECT_OPERATE etc. */
        }
    }
    /* the transport layer said MULTI-SEGMENT. Still extract the application header so
     * the deparser's emit order is unchanged, then classify a RESPONSE as
     * UNSUPPORTED_SEGMENTATION (forwarded unprotected, counted). */
    state parse_dnp3_app_unsup {
        pkt.extract(hdr.dnp3_app);
        transition select(hdr.dnp3_app.func_code) {
            DNP3_FC_RESPONSE : set_role_resp_unsup;
            default          : accept;
        }
    }
    state set_role_resp       { meta.role = ROLE_RESP;       transition accept; }
    state set_role_resp_unsup { meta.role = ROLE_RESP_UNSUP; transition accept; }
    state set_role_arm        { meta.role = ROLE_ARM;        transition accept; }
}

/* ============================ ingress control =========================== */
control Ingress(inout headers_t hdr,
                inout ig_meta_t meta,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

    /* ================= state register 1: the TAG =========================
     * Packs generation and "active" into one byte.
     * PHV inputs across ALL THREE RegisterActions: meta.gen_in, meta.tag_val —
     * exactly 2, the SALU ceiling. Exactly one action runs per packet.
     *
     * INITIAL VALUE IS TAG_INACTIVE, not 0. That is what makes "idle" a single
     * encoding, which is what lets tag_arm below be a genuine compare-and-arm. */
    Register<bit<8>, bit<1>>(1, 0x00) reg_tag;   /* init == TAG_INACTIVE (0x00) */

    /* D3 — ARM-ONCE. Direction §7: a duplicate READ must not re-trigger, and a
     * CONCURRENT READ must NOT OVERWRITE ACTIVE STATE. The baseline's ARM took the
     * tag unconditionally; that cannot express "busy". The write is now conditional
     * INSIDE the SALU (the only place the decision can be made atomically, because
     * "busy" is only knowable from the register itself), and the returned difference
     * still distinguishes the three cases in the MAU:
     *
     *   stored v          rv = gen_in - v   meaning                decode entry
     *   ----------------------------------------------------------------------
     *   0x00 (idle)       0xC0..0xCF        FRESH, armed now       0xC0&&&0xF0
     *   0xCn (same gen)   0x00              duplicate READ         0x00&&&0xFF
     *   0xCm (m != n)     0x01..0x0F,
     *                     0xF1..0xFF        CONCURRENT, busy       default
     *
     * The three sets are DISJOINT because the parser pins gen_in to 0xC0..0xCF
     * (GATE 4) and the register domain to {0x00} u 0xC0..0xCF.
     *
     * ►► THE TABLE ABOVE IS THE 0x00 REGIME. Under the old 0xFF marker the idle row
     * read `0xFF (idle) -> 0xC1..0xD0`, which is why a `tag_diff == 0xD0 -> arm_fresh`
     * decode entry used to exist. It was REMOVED with this repair: under 0x00 no legal
     * state can produce 0xD0 (it needs stored in 0xF0..0xFF), so the only way to reach
     * it was reg_tag holding an OUT-OF-DOMAIN value — and in exactly that case the
     * write predicate `v == 0` is false, so the entry would have declared ARM_FRESH on
     * a transaction whose generation never committed. That is the F02 failure signature
     * itself, and leaving the entry in place would have kept a path to reproducing it
     * silently. The out-of-domain case is instead caught by the control plane's
     * clean-start assertion (`reg_tag == TAG_INACTIVE` before every trial). */
    /* ►► R2, THE SECOND-REGISTER REPAIR.
     *
     * THE DEFECT: a dequeued blocker with hdr.ib.seq == 0 used to set
     * meta.tag_val = TAG_INACTIVE and let tag_rmw commit it at level 2, guarded only by
     * "tag_val != TAG_NO_WRITE". The generation test lives in tbl_state_decode at level
     * 3, so a token of a FOREIGN generation retired whatever transaction was live, and
     * the action block's documented stale > deadline > budget priority could not undo a
     * write the SALU had already committed.
     *
     * WHY THE OBVIOUS REPAIRS DO NOT FIT, both MEASURED in
     * probe_failopen_qualification.p4: merging the arm-and-retire into one operation
     * needs three PHV operands and fails the stateful ALU's input crossbar; keeping them
     * separate needs a FIFTH RegisterAction on reg_tag, which is a hard error.
     *
     * ►► WHAT MAKES THE SECOND REGISTER WORK, and it is not just "somewhere else to
     * write". The fail-open write to reg_tag never released anything: the held ACK
     * leaves because the budget-zero token DROPS ITSELF, Q_BLOCK empties and Q_HOLD
     * becomes eligible. Its ONLY job was to let the NEXT READ arm. So the write does not
     * have to be generation-qualified at all -- the DECISION does. Move the note to its
     * own register and qualify it at the CONSUMER:
     *
     *   producer  a budget-zero token records the generation IT carries. Unconditional,
     *             and harmless whoever writes it: it is a note naming a generation, not
     *             a destructive write.
     *   consumer  the next READ arms if reg_tag is idle OR equals the noted generation.
     *             A FOREIGN token's note names a generation that is not the live one, so
     *             it can never authorise anything. That is the qualification, achieved
     *             by comparison at the consumer rather than at the producer.
     *
     * reg_failopen has its own four-action budget, so nothing is displaced, and tag_arm
     * gains one comparison rather than reg_tag gaining an operation.
     *
     * SINGLE-USE: the READ clears the note as it reads it, so one note can authorise at
     * most one arm.
     *
     * THE ONE RESIDUAL WINDOW, stated rather than hidden: generations wrap every 16
     * polls, so a note naming G could in principle authorise arming over a LIVE G that
     * armed later. For that the old token must reach budget zero (H = 30.8 ms) while a
     * generation 16 polls newer is live -- 3.2 s at the 200 ms poll rate. Two orders of
     * magnitude apart, and the note is cleared by the first READ after it is written. */
    Register<bit<8>, bit<1>>(1, 0) reg_failopen;
    /* producer: name my own generation. */
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_failopen) fo_note = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; v = meta.gen_in; }
    };
    /* consumer: read the note and clear it, so it is single-use. */
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_failopen) fo_take = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; v = TAG_INACTIVE; }
    };
    /* tag_arm, with the fail-open note as a SECOND way to be armable. One extra
     * comparison and one extra PHV operand; still four RegisterActions on reg_tag. */
    /* ►► THE NOTE RIDES ON meta.tag_val, AND THAT IS THE WHOLE TRICK.
     * reg_tag's stateful ALU has a budget of TWO PHV inputs SHARED ACROSS ALL FOUR of
     * its RegisterActions, and it is already full: meta.gen_in and meta.tag_val (the
     * source says so at the reg_tag declaration). Every attempt to feed the note in as
     * a THIRD source is rejected, and the compiler is explicit about which wall was hit:
     *   a separate byte      -> "meta.fo_gen ... not allocated in a valid region on the
     *                           input xbar to be a source of an ALU operation"
     *   a packed 16-bit pair -> "Ingress.reg_tag requires more than 2 PHV inputs"
     * So the note must arrive on an operand reg_tag ALREADY has. On the ARM path
     * meta.tag_val is dead -- tag_arm never referenced it, CLASS_ARM never executes
     * tag_rmw or tag_read_or_mark, and nothing downstream reads it for this class -- so
     * it carries the note at zero cost.
     *
     * When there is no note, fo_take returns TAG_INACTIVE (0x00), which makes the second
     * comparison identical to the first. 0x00 can never be a live generation, so a
     * "no note" value can never authorise anything by accident. */
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) tag_arm = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = meta.gen_in - v;
            if (v == TAG_INACTIVE || v == meta.tag_val) { v = meta.gen_in; }
        }
    };
    /* every other packet: the baseline read-modify-write. tag_val == TAG_NO_WRITE
     * makes it read-only, which is the case for the ACK, the blockers and bypass. */
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) tag_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = meta.gen_in - v;
            if (meta.tag_val != TAG_NO_WRITE) { v = meta.tag_val; }
        }
    };
    /* RAW read of the stored generation. Taken by an admitted pktgen token, by the
     * FRESH RESPONSE and by the RELEASED ACK.
     *
     * WHY THE RESPONSE MUST TAKE THIS ARM AND NOT tag_rmw (CONSENSUS §7 R7): the
     * response's generation test must NOT be built from its own app_control byte.
     * In the general case a solicited response sets CON (0xEn, not 0xCn) and the
     * difference gen_in - stored would then be non-zero on every single response —
     * a SILENT mis-fire. The response's generation binding is instead the tracked
     * session (seq/ack) plus txn_active on this RAW value. */
    /* ===================== E1: THE TWO PHASE TRANSITIONS =====================
     * ►► THE TARGET ALLOWS ONLY **4** RegisterActions PER REGISTER, and it is a hard
     * error, not a warning:
     *     error: Ingress.reg_tag: too many RegisterActions attached to the Register
     *     The target architecture limits the number ... to 4.
     * reg_tag already had tag_arm / tag_rmw / tag_read, so E1's two transitions would
     * have made five. tag_read is therefore FOLDED INTO the marker: a pure read is
     * just a mark with a delta of ZERO. The delta arrives in meta.tag_val, which is
     * provably dead on both paths that now use this arm — a fresh generated token
     * executes neither tag_rmw nor ack_rel_rmw, and the fresh RESPONSE no longer
     * executes ack_rel_rmw either (see the note there) — so this costs no new PHV.
     * Both return the PRE-state, which is what every downstream consumer already
     * expects from tag_read (cur_gen -> tbl_txn_active, and the token stamp), and
     * both take NO PHV input, so reg_tag's operand pair is unchanged and E1 costs
     * ZERO new PHV containers in the exhausted B0-15 group.
     *
     * ►► THE SIGN TEST MUST BE WRITTEN WITH AN EXPLICIT CAST. `v < 8w0` on a bit<8>
     * register compiles — with no error and no warning — to `lss.u lo, lo`, an
     * UNSIGNED less-than-zero, which is NEVER TRUE: a silently vacuous predicate, and
     * the same class of trap as the large-constant SALU comparison. `(int<8>)v < 8s0`
     * emits `lss.s lo, lo`. analysis/assert_salu_asm.py FAILS THE BUILD if the
     * load-bearing predicates do not read `lss.s`, so a future edit cannot regress
     * this silently. */
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) tag_read_or_mark = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;                          /* pre-state == cur_gen, as tag_read did */
            /* delta 0x50 on the first in-transaction RESPONSE (0xCn -> 0x1n);
             * delta 0x00 for a generated token, which makes the write a no-op and
             * leaves the arm a pure read. Predicated on the MSB, so it is ONE-SHOT:
             * marking clears the MSB, and a duplicate RESPONSE cannot mark again. */
            if ((int<8>)v < 8s0) { v = v + meta.tag_val; }
        }
    };
    /* THE GATE 4C REPAIR ITSELF. On the released ACK's commitment pass, retire the
     * transaction IFF no early RESPONSE is pending. MSB set == 0xC0..0xCF == nothing
     * pending == retire now; MSB clear == 0x10..0x1F == a RESPONSE is queued, so leave
     * the generation live and let the queued RESPONSE's release retire it, exactly as
     * it does today. The queued RESPONSE is therefore still the retirement event
     * whenever there IS one, and the ACK becomes the retirement event only when there
     * is not. */
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) tag_retire_if_unmarked = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            if ((int<8>)v < 8s0) { v = TAG_INACTIVE; }
        }
    };

    /* ================= state register 2: the DEADLINE ====================
     * 24 bits of 256 ns ticks in [31:8]; bit 0 is the ARMED MARKER, which is why
     * "deadline_valid" is NOT a register (CONSENSUS §4).
     * PHV inputs: meta.now_word, meta.dl_val — exactly 2. */
    Register<bit<32>, bit<1>>(1, 0) reg_deadline;
    /* every non-arming packet, INCLUDING the ARM (which disarms with
     * dl_val = UNARMED_WORD). Returns the AGE, which drives tbl_deadline_expiry. */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) deadline_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.now_word - v;
            if (meta.dl_val != DL_NO_WRITE) { v = meta.dl_val; }
        }
    };
    /* D3 — HOLD-ONCE, and the one-shot AWAITING_ACK state of CONSENSUS §8.1 in its
     * entirety. The armed word is written atomically ONLY when the stored word is
     * still the unarmed sentinel the ARM left behind.
     *
     * It returns the PRE-STATE rather than the age, because Defense 3 needs to know
     * something the baseline never asked: DID THIS ACK ARM? The held ACK never
     * consults `expired` (it is being held, not tested for expiry), so the age is of
     * no use to it, whereas
     *      dl_pre == UNARMED_WORD  <=>  this is the FIRST qualifying ACK
     * is exactly the discriminator between "arm and hold" and "duplicate: hold, but
     * do NOT push the deadline out". A full 32-bit whole-container compare against a
     * constant — no bit-slice, no gateway slice. */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) deadline_arm_once = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v;
            if (v == UNARMED_WORD) { v = meta.dl_val; }
        }
    };

    /* ================= Defense 4: reg_tresp — the RESPONSE deadline T_RESP ==========
     * Symmetric clone of reg_deadline. T_RESP = t_A + D_A + D_R, armed once at the
     * native ACK (same now_word as T_A, offset da_dr). tresp_rmw returns age_resp
     * (now_word - stored) for the RESP blocker's expiry test; tresp_arm_once writes the
     * armed word atomically only from the unarmed sentinel (one-shot, dup-ACK safe).
     * Two access sites (arm-once at the ACK, rmw-read on the RESP blocker loop); the
     * ARM (READ) disarms via dl_val_resp = UNARMED_WORD through tresp_rmw. PHV inputs:
     * meta.now_word, meta.dl_val_resp — exactly 2. */
    Register<bit<32>, bit<1>>(1, 0) reg_tresp;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_tresp) tresp_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.now_word - v;
            if (meta.dl_val_resp != DL_NO_WRITE) { v = meta.dl_val_resp; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_tresp) tresp_arm_once = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v;
            if (v == UNARMED_WORD) { v = meta.dl_val_resp; }
        }
    };

    /* Defense 4 D1 note: the D1 RESPONSE-observed event is NOT a new register. It is the
     * EXISTING reg_tag pending marker (0xCn -> 0x1n on RESPONSE hold): a live ACK blocker of
     * that generation then decodes tag_diff == 0xB0 -> V_BLOCK_PENDING, on which the D1 ACK
     * blocker terminates (generation-bound, so stale/rolled-over generations cannot release). */

    /* ================= D3: state register 3 — THE ACK-RELEASE GENERATION ==
     * THE ONE new register permitted by CONSENSUS §4.
     *
     * It stores a GENERATION (0xC0..0xCF) and is read as an 8-bit SALU DIFFERENCE:
     *      rel_diff = cur_gen - ack_release_gen
     *      rel_diff == 0  <=>  the ACK OF THIS GENERATION has already left Q_HOLD
     * It is deliberately NOT a boolean `ack_released = 1`. A boolean has no owner
     * responsible for clearing it, so it survives into the next generation and
     * (a) silently disables the hold and (b) lets a stale RESPONSE of generation N
     * be forwarded ahead of the held ACK of generation N+1 — inverting the one
     * ordering property Defense 3 claims, on the wire, in the exact scenario the
     * claim is about. The generation binding is what makes the state self-clearing:
     * a new generation N+1 automatically reads rel_diff != 0 with no reset.
     *
     * The comparison lives INSIDE the SALU (rv = cur_gen - v) rather than being a
     * store-then-MAU-compare, which saves one MAU level.
     *
     * PHV: reuses meta.cur_gen (already an operand of nothing else) and meta.tag_val.
     * meta.tag_val is provably DEAD on both paths that execute this register —
     * CLASS_RESP and CLASS_ACK_REL both take reg_tag's `tag_read` arm, which has no
     * PHV input and performs no write — so the reuse is safe and costs ZERO new PHV
     * containers in the exhausted B0-15 group. The result likewise lands in
     * meta.tag_diff, dead on the same two paths. This is CONSENSUS §4's
     * pre-identified fix, applied up front rather than after a placement failure. */
    Register<bit<8>, bit<1>>(1, 0) reg_ack_rel;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_ack_rel) ack_rel_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = meta.cur_gen - v;
            if (meta.tag_val != TAG_NO_WRITE) { v = meta.tag_val; }
        }
    };

    /* ================= D3: state registers 4-6 — THE SESSION TRACKERS =====
     * All three are learned IN THE DATA PLANE from the master's own frames; there is
     * no controller action per transaction or per connection (direction §2).
     *
     * reg_exp_relay_seq is the load-bearing one. MEASURED over 8 PCAPs:
     *   - the expected-ACKNOWLEDGMENT test accepts 61/61 of the relay's ~10.02 s
     *     TCP keepalives;
     *   - the expected-SEQUENCE test rejects 61/61 of them,
     *     and accepts 679/679 real relay pure ACKs and 622/622 responses.
     * A keepalive carries seq = SND.NXT - 1 (RFC 1122 4.2.3.6) and is otherwise
     * BYTE-IDENTICAL to a transaction ACK. Without this conjunct a keepalive parks a
     * live packet in Q_HOLD and installs a deadline already in the past, after which
     * the next real ACK finds the deadline armed and is never held — SILENT LOSS OF
     * PROTECTION with no drop, no reset and no counter.
     *
     * IT NEEDS NO ARITHMETIC:  EXP_RELAY_SEQ := (any master->relay frame).tcp.ack_no.
     * The master's ack_no is the relay's SND.NXT by definition, which is exactly the
     * seq the relay's next ACK and its RESPONSE will both carry. Seeded free by the
     * three-way-handshake ACK. No seq+len, no payload-length computation, no SALU add.
     *
     * reg_exp_ack is the defence-in-depth conjunct and is the ONLY place Defense 3
     * does arithmetic: EXP_ACK := READ.tcp.seq_no + read_len, one add against a
     * runtime immediate.
     *
     * reg_session_port pins the master's ephemeral port, which changes per connection.
     * reg_session_port and reg_exp_ack keep the 0 = no-write sentinel; reg_exp_relay_seq
     * uses a class-SELECTED writer/reader split instead (§5.5 fix — TCP seq 0 is a valid
     * value after wraparound and must not be read as "no write"). Each register still has
     * exactly 2 PHV inputs. */
    Register<bit<32>, bit<1>>(1, 0) reg_exp_relay_seq;
    /* ►► §5.5 FIX — WRITER/READER SPLIT (was a single value-sentinel RMW that skipped the
     * store when the candidate seq was 0, mistaking a legally wrapped seq for "no write").
     * The write-enable is now the packet CLASS, tested at the MAU gateway (see the apply
     * site), NOT the stored value, so seq 0 is stored correctly. The register's PHV-input
     * set is unchanged — {hdr.tcp.seq_no, meta.seq_w} = 2, the SALU ceiling — because the
     * selector lives in the MAU, not on the ALU input crossbar; RegisterActions go 1 -> 2
     * (register cap is 4). This mirrors reg_exp_ack's existing on-silicon w/r split. */
    /* writer: a master->relay session frame. UNCONDITIONAL store, so seq 0 lands. */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_exp_relay_seq) exp_seq_w = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = hdr.tcp.seq_no - v;
            v  = meta.seq_w;
        }
    };
    /* reader: every other frame — test only. */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_exp_relay_seq) exp_seq_r = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = hdr.tcp.seq_no - v;
        }
    };

    Register<bit<16>, bit<1>>(1, 0) reg_session_port;
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_session_port) sess_port_rmw = {
        void apply(inout bit<16> v, out bit<16> rv) {
            rv = meta.mport - v;
            if (meta.sport_w != 16w0) { v = meta.sport_w; }
        }
    };

    Register<bit<32>, bit<1>>(1, 0) reg_exp_ack;
    /* the READ installs the expected acknowledgment ... */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_exp_ack) exp_ack_w = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = hdr.tcp.ack_no - v;
            v  = meta.exp_ack_cand;
        }
    };
    /* ... every other frame only tests against it. Mutually exclusive per packet, so
     * one SALU access; 2 PHV inputs across both actions (ack_no, exp_ack_cand). */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_exp_ack) exp_ack_r = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = hdr.tcp.ack_no - v;
        }
    };

    /* ================= fixed-slot timestamp registers (4) =================
     * SPARSE latency capture, write-if-zero = first occurrence.
     *
     * DO NOT CUT THESE TO CHASE A STAGE COUNT. The ACK is held INSIDE the switch and
     * the dp64 relay leg is untappable, so Defense 3's headline observable — the ACK
     * left at t_ACK + D — is not visible on any external link. These registers are
     * the ONLY possible measurement of the hold.
     *
     *   hold duration   = reg_ts_ack_release - reg_ts_ack_arm
     *   deadline error  = hold - (D + K/rate_dp8)      <- score against D + 1.711 us,
     *                                                     NOT D. The release tail is a
     *                                                     deterministic K-proportional
     *                                                     BIAS, not jitter; misreading
     *                                                     it as spread is the default
     *                                                     failure of this measurement.
     *   reservoir standing = reg_ts_ack_arm - reg_ts_first_block   <- must be > 0, and
     *                                                     the ACK arrives min 0.400 ms
     *                                                     after the READ, ~4x sooner
     *                                                     than the packet Defense 2
     *                                                     held. A late reservoir is a
     *                                                     SILENT zero-hold.
     * All differences must be computed mod 2^32 by the analyzer: the 32-bit ns
     * counter wraps every ~4.3 s (~14x per 60 s run) and a signed subtraction
     * FABRICATES the headline number.
     *
     * TODO(silicon): THE RESERVOIR MUST BE STANDING BEFORE THE ACK ARRIVES. Defense 2
     *   held a packet that arrived ~2 ms after the READ; Defense 3 holds the ACK,
     *   which arrives at a MEASURED MINIMUM of 0.400 ms — roughly 4x sooner. If
     *   clone -> recirculation -> trigger -> 64 admissions has not completed, the ACK
     *   enters an unblocked Q_HOLD and leaves immediately: a SILENT ZERO-HOLD that
     *   reads as a successful run with a small measured delay.
     *   RESOLVING CHECK: after the first poll, (reg_ts_ack_arm - reg_ts_first_block)
     *   mod 2^32 must be > 0 AND < 100 us. Blocking gate; a run that cannot show it
     *   is not evidence of a hold.
     *
     * TODO(silicon): THE RELEASE INSTANT IS NOT THE DEADLINE INSTANT. They differ by
     *   a deterministic K-proportional bias, K/rate_dp8 = 1.711 us at K=64 / 25G
     *   (predicted; Part 12 measured 1.72 us with ~23 ns spread = one dp8 dequeue
     *   slot). Scoring the hold against D instead of D + K/rate reports a systematic
     *   1.7 us offset as if it were jitter, on every transaction.
     *   RESOLVING CHECK: (reg_ts_ack_release - reg_ts_ack_arm) mod 2^32 must centre
     *   on D + 1.711 us, not on D, with a spread of order tens of ns. If the spread
     *   is microseconds, the reservoir is not the thing gating the release. */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_block;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_block) ts_first_block_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_ack_arm;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_ack_arm) ts_ack_arm_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_block_term;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_block_term) ts_block_term_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    /* D3: RE-POINTED from the response release to the ACK RELEASE — the event this
     * defense is about. Its predicate (dequeued == 1 && role == ROLE_ACK) is entirely
     * PARSER-derived, so the register keeps the baseline's stage float and needs no
     * ev_* flag, i.e. it costs zero new PHV. */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_ack_release;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_ack_release) ts_ack_release_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };

#ifdef D3_TS_INTERNAL
    /* full-reservoir standing: WRITE-ALWAYS on the same guard as ts_first_block_w
     * (meta.ev_first_block is set on EVERY admitted token, the write-if-zero of
     * reg_ts_first_block being what selects the first), so after the burst it holds the
     * LAST admission. Admission runs exactly once per token, so a recirculating token
     * cannot overwrite it later. */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_last_block;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_last_block) ts_last_block_w = {
        void apply(inout bit<32> v) { v = meta.ts32; }
    };
    /* the FINAL blocker termination. reg_ts_block_term is write-if-zero and records the
     * FIRST; this one is write-always on the same guard and records the LAST, so the two
     * bracket the drain:  drain = last_term - first_term,
     *                     release tail = ack_release - last_term. */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_last_term;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_last_term) ts_last_term_w = {
        void apply(inout bit<32> v) { v = meta.ts32; }
    };
#endif

#ifdef D3_SYNTH_EVENTS
    /* ---- the two instruments §13 Gate 2 needs and the live build does not ----
     *
     * reg_ts_read closes CONSENSUS R2. R2 is stated as
     *     t_first_blocker_admitted - t_READ  <  100 us
     * and there is no t_READ anywhere in the live build — its four timestamps
     * measure the ACK, not the request. The live build's available surrogate is
     * (reg_ts_ack_arm - reg_ts_first_block) > 0, which only shows the reservoir
     * was standing BEFORE THIS ACK; it cannot show HOW LATE it was, and the ACK
     * arrives a MEASURED MINIMUM of 0.400 ms after the READ, ~4x sooner than the
     * packet Defense 2 held. A late reservoir is a SILENT ZERO-HOLD that reads as
     * a working run. The quantity R2 bounds — clone -> recirculation -> trigger
     * -> 64 admissions — is a property of the TRIGGER CHAIN, which is bit-for-bit
     * the same in both builds, so measuring it here bounds it there.
     *
     * reg_ts_resp_release makes the RELEASE ORDER a measurement rather than an
     * inference. ts_ack_release_w fires on (dequeued && ROLE_ACK) only, so
     * without this register a RESPONSE that somehow left first would leave no
     * trace at all — the ACK's timestamp would still be written, and the run
     * would read as a pass. The ordering test is then a signed 32-bit difference
     * t_resp_release - t_ack_release > 0, computed mod 2^32 by the analyzer.
     *
     * Both are write-if-zero, one call site each, and both are guarded by values
     * that already exist (meta.verdict, meta.role, meta.dequeued), so neither
     * costs a new PHV container. */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_read;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_read) ts_read_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_resp_release;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_resp_release) ts_resp_release_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };

    /* ---- CHECK 2 (direction, 2026-07-29): the two instants that decompose the
     * blocker-start latency, so the ~1 ms observed in the first working Gate 2 can be
     * attributed to a party rather than guessed at.
     *
     *   reg_ts_clone       t_pktgen_trigger. The instant the tagged clone re-entered
     *                      the pipe on dp68 — i.e. the instant the generator's pattern
     *                      matcher was fed. (t_clone - t_READ) is the CLONE CHAIN:
     *                      deparser -> mirror -> dp68 egress -> loopback -> parser.
     *                      (t_first_block - t_clone) is everything the GENERATOR itself
     *                      contributes. Those two numbers answer the direction's
     *                      question; the sum alone does not.
     *                      Predicate is meta.role == ROLE_CLONE, entirely
     *                      parser-derived, so like ts_ack_release_w it floats and costs
     *                      NO ev_* flag and NO new PHV container.
     *
     *   reg_ts_last_block  t_final_blocker_admitted, hence READ-to-FULL-RESERVOIR,
     *                      which is the quantity that actually has to beat the physical
     *                      ACK floor (~0.400 ms min / ~0.505 ms median) — the first
     *                      token only proves the reservoir STARTED.
     *                      WRITE-ALWAYS, deliberately: it is the same guard as
     *                      ts_first_block_w (meta.ev_first_block, which despite its
     *                      name is set on EVERY admitted token, the write-if-zero of
     *                      reg_ts_first_block being what selects the first), so after
     *                      the burst it holds the LAST one. No predicate at all, so no
     *                      immediate and nothing for the compiler to mis-lower.
     *                      Admission runs EXACTLY ONCE per token — the pktgen path is
     *                      taken on dp68 and the loops afterwards are dp8 dequeues — so
     *                      a recirculating token cannot overwrite it later. */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_clone;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_clone) ts_clone_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    /* the FINAL blocker termination, which the direction's Gate-2 measurement list
     * asks for separately from the first. reg_ts_block_term is write-if-zero and so
     * records the FIRST; this one is write-always on the same guard and so records
     * the LAST. Together they bracket the DRAIN: the reservoir empties between them,
     * and the held ACK is released at the end of it, so
     *     drain      = last_term  - first_term
     *     drain tail = ack_release - last_term
     * are both measurements rather than inferences. Same guard as ts_block_term_w,
     * so it shares the stage and costs no PHV. */
    /* ►► ORDERING INSTRUMENT for the duplicate-RESPONSE question. reg_ts_resp_release
     * is written on the DEQUEUED ROLE_RESP path, so a BYPASSED response — which is
     * forwarded straight out and never enters Q_HOLD — leaves no trace in it at all.
     * Without this register "did the duplicate overtake the held ACK?" cannot be
     * answered, only assumed. Write-if-zero, so it records the FIRST bypass. */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_resp_bypass;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_resp_bypass) ts_resp_bypass_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
#endif

    /* ================= counters (Stats ALU) =============================== */
    Counter<bit<64>, bit<8>>(32, CounterType_t.PACKETS) ctr_fresh;  /* CF_* slots */
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) ctr_deq;    /* CD_* slots */

    /* ================= TM actions =================
     * There is exactly ONE action that writes QID_HOLD and exactly ONE that writes
     * the master-facing port + qid 0. That single-site property is the structural
     * half of the ordering invariant, and it is checkable in pipe/context.json
     * action immediates rather than by reading this source. */
    action to_block() {                       /* enqueue Q_BLOCK on loopback dp8 */
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_BLOCK;
        ig_tm_md.bypass_egress     = 1w1;
    }
    /* D3: the HOLD queue. Reached by the qualifying ACK and by EVERY in-transaction
     * RESPONSE. One loopback pass for both — see the ordering invariant in the file
     * header, item (c). */
    action to_hold() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_HOLD;   /* = QID_ACK_HOLD (qid6): held original ACK */
        ig_tm_md.bypass_egress     = 1w1;
    }
    /* Defense 4: the RESPONSE hold queue (qid4) and the RESPONSE blocker reservoir (qid5).
     * Real RESPONSE stays queue-resident in qid4; only RESPONSE blocker tokens loop on qid5. */
    action to_resp_hold() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_RESP_HOLD;   /* qid4 */
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_resp_block() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_RESP_BLOCK;  /* qid5 */
        ig_tm_md.bypass_egress     = 1w1;
    }
    /* ================= THE INLINE LEVER =================================
     * D3_TO_FWD / D3_DROP are TEXTUAL macros, not P4 actions, and that is a
     * deliberate resource decision with a measured basis.
     *
     * A bare action CALL becomes its own logical table on Tofino-1 and will NOT
     * merge with the statement beside it, so `to_fwd(); ctr.count(x);` costs TWO
     * logical table IDs where the inlined form costs one. Defense 3's first compile
     * landed at 10 ingress stages with a critical path of 8 — i.e. purely
     * PLACEMENT-bound, with stages 6/7/8 all at 16/16 logical table IDs and 19 bare
     * action tables among them. Inlining these two bodies is the lever Panel A held
     * in reserve for exactly that outcome. It changes NO behaviour whatsoever.
     *
     * WHY A MACRO AND NOT COPY-PASTED STATEMENTS: the ordering invariant's item (d)
     * requires every master-facing packet to leave on the SAME dp9 qid. Keeping ONE
     * textual definition preserves that as a single-source property, so a typo at
     * one of the seven sites cannot silently break it. Every expansion writes the
     * same compile-time immediate QID_FWD, checkable in pipe/context.json.
     *
     * to_hold() and to_block() are deliberately NOT inlined: their single-site
     * property IS the evidence that nothing else can enqueue to Q_HOLD or Q_BLOCK,
     * and that evidence is worth more than the two table IDs it costs. */
    #define QID_FWD 5w0
#ifdef D3_EGRESS_MARKER
    #define D3_TO_FWD()  { ig_tm_md.ucast_egress_port = meta.fwd_port;  \
                           ig_tm_md.qid               = QID_FWD;        \
                           ig_tm_md.bypass_egress     = 1w0;            \
                           hdr.br.setValid();                           \
                           hdr.br.role                = meta.role; }
#else
    #define D3_TO_FWD()  { ig_tm_md.ucast_egress_port = meta.fwd_port;  \
                           ig_tm_md.qid               = QID_FWD;        \
                           ig_tm_md.bypass_egress     = 1w0; }
#endif
    #define D3_DROP()    { ig_dprsr_md.drop_ctl = 3w1; }

    /* request ONE I2E mirror (the clone) to dp68, on the FRESH-ARM path only. */
    action arm_clone() {
        ig_dprsr_md.mirror_type = MIRROR_TYPE_CLONE;
        meta.clone_ses          = CLONE_SESSION_ID;
        meta.clone_tag          = CLONE_TAG_MARKER | (bit<32>)meta.gen_in;
    }

    /* ================= level 0: the runtime parameter block ===============
     * D3: ONE keyless table carries all three runtime knobs, rewritten by the control
     * plane with default_entry_set. That is one logical table for what would
     * otherwise be three, and it is the Defense 2 `tbl_guard` idiom whose readback is
     * already proven on silicon.
     *   d_ticks   — D in 256 ns ticks, LOW BYTE MUST BE ZERO (the armed marker rides
     *               there and must survive now_word + d_ticks untouched)
     *   read_len  — the master READ's TCP payload length, for EXP_ACK
     *   budget    — the fail-open pass budget B; horizon H = B x K / rate_dp8 */
    /* Defense 4: d_ticks = D_A (ACK offset, T_A = t_A + D_A); da_dr = precomputed
     * (D_A + D_R) so T_RESP = t_A + D_A + D_R needs ONE MAU addition (setup verifies
     * da_dr == D_A + D_R and both satisfy the half-range < 2^31 timestamp clamp);
     * mode selects OFF/D1/D2/D3/D4/FAIL_OPEN. All statically installed, no per-txn action. */
    action set_params(bit<32> d_ticks, bit<32> read_len, bit<32> budget,
                      bit<8> mode, bit<32> da_dr) {
        meta.seq_m       = d_ticks;
        meta.read_len    = read_len;
        meta.budget_init = budget;
        meta.mode        = mode;
        meta.da_dr       = da_dr;
    }
    table tbl_params {
        actions = { set_params; }
        default_action = set_params(D_DEFAULT_TICKS, READ_LEN_DEFAULT, BUDGET_DEFAULT,
                                    MODE_D3_ACK, D_DEFAULT_TICKS);
        size = 1;
    }

    /* ================= level 0: D3 — the protected 5-tuple ================
     * CONSENSUS §8.1/§8.2 "reverse 5-tuple matches the learned session". The addresses
     * are NOT literals in the P4 (they are campaign parameters); the control plane
     * installs exactly two entries at calibration:
     *
     *   (RELAY_IP, MASTER_IP, sport 20000, dport *) -> sess_relay()
     *   (MASTER_IP, RELAY_IP, sport *, dport 20000) -> sess_master()
     *
     * The master's ephemeral port is the one field neither entry can pin at install
     * time, which is precisely what reg_session_port learns.
     *
     * sess_master() ALSO seeds both trackers, because every master->relay frame on the
     * session carries the same two facts: its ack_no is the relay's SND.NXT (the seq
     * the relay's next ACK and RESPONSE will carry), and its src_port is the master's
     * ephemeral port. Seeding at level 0 rather than from a later classification is
     * what lets reg_exp_relay_seq and reg_session_port execute one level earlier — it
     * is a stage, bought for nothing. */
    action sess_relay() {
        meta.sess  = SESS_RELAY;
        meta.mport = hdr.tcp.dst_port;
    }
    action sess_master() {
        meta.sess    = SESS_MASTER;
        meta.mport   = hdr.tcp.src_port;
        meta.sport_w = hdr.tcp.src_port;   /* learn the ephemeral port      */
        meta.seq_w   = hdr.tcp.ack_no;     /* EXP_RELAY_SEQ := relay SND.NXT */
    }
    action sess_none() { meta.sess = SESS_NONE; }
    table tbl_session {
        key = {
            hdr.ipv4.src_addr : ternary;
            hdr.ipv4.dst_addr : ternary;
            hdr.tcp.src_port  : ternary;
            hdr.tcp.dst_port  : ternary;
        }
        actions = { sess_relay; sess_master; sess_none; }
        default_action = sess_none();
        size = 4;
    }

#ifdef D3_SYNTH_EVENTS
    /* ============ level 0: SYNTHETIC-EVENT ROLE MAP (GATE 2 BUILD ONLY) ======
     * packet_id -> transaction role, installed by the control plane. A SCENARIO
     * IS EXACTLY (ipg, this map): swapping which packet_id is the ACK and which
     * is the RESPONSE is how an early-response or late-ack case is expressed,
     * with no recompile and no second P4 variant, and the generator's emission
     * order is untouched. The setup reads all three entries back into the trial
     * manifest, so what ran is recorded rather than assumed.
     *
     * It runs INSTEAD OF tbl_session, not beside it (the ACT-block dispatch just
     * below). Two reasons, in order of weight:
     *   1. all three events are copies of ONE relay->master template, so a
     *      5-tuple lookup necessarily returns the SAME session role for all
     *      three, while the READ needs SESS_MASTER and the other two SESS_RELAY;
     *   2. writing meta.sess from both tables would be a write-after-write on a
     *      level-0 field and would push the class driver — and therefore the
     *      whole pipeline — down a stage.
     * The actions reproduce sess_relay()/sess_master()'s writes exactly; what is
     * not exercised is the ternary lookup itself. Recorded in the ledger at the
     * top of this file.
     *
     * The two 32-bit trackers reg_exp_relay_seq and reg_session_port are NOT
     * seeded here. They are seeded by the CONTROL PLANE, because in the live
     * build they are learned from a master->relay frame on a real connection and
     * there is no such frame in this build. The comparisons they feed are real. */
    action synth_read(bit<8> gen) {
        meta.sess   = SESS_MASTER;         /* == sess_master()'s session role   */
        meta.mport  = hdr.tcp.dst_port;    /* master ephemeral port on a relay->master frame */
        meta.role   = ROLE_ARM;            /* NOT from the DNP3 parse chain     */
        meta.gen_in = gen;                 /* the transaction generation, 0xCn  */
    }
    action synth_ack() {
        meta.sess     = SESS_RELAY;        /* == sess_relay()                   */
        meta.mport    = hdr.tcp.dst_port;
        /* role stays ROLE_ACK, set by the REAL parse_tcp flags/length gate. */
        hdr.eth.etype = ETYPE_SYNTH_ACK;   /* survive the loopback              */
    }
    action synth_resp() {
        meta.sess     = SESS_RELAY;
        meta.mport    = hdr.tcp.dst_port;
        meta.role     = ROLE_RESP;         /* NOT from the DNP3 §8.2 gates      */
        hdr.eth.etype = ETYPE_SYNTH_RESP;
    }
    /* identical in every respect that the mechanism can see -- same session, same role,
     * same §8.2 treatment -- and different ONLY in the tag it carries out of the chip,
     * so the two RESPONSES of case F are separable on the wire. */
    action synth_resp_alt() {
        meta.sess     = SESS_RELAY;
        meta.mport    = hdr.tcp.dst_port;
        meta.role     = ROLE_RESP;
        hdr.eth.etype = ETYPE_SYNTH_RESP_ALT;
    }
    /* an unmapped packet_id: no session, no role change. It falls through the
     * class driver to ROLE_BYPASS and is forwarded and counted CF_BYPASS_FWD, so
     * a mis-sized batch shows up as a non-zero bypass count rather than as a
     * silently missing event. */
    action synth_none() { meta.sess = SESS_NONE; }
    table tbl_synth_role {
        /* KEYED ON (pipe_app, packet_id), not packet_id alone. With the events split
         * across two apps, packet_id is no longer unique: app 2's READ and app 3's
         * first packet are both packet_id 0. pipe_app is already parsed
         * (pad(3) ++ pipe_id(2) ++ app_id(3)) and is the app discriminator the
         * parser's value_set matches on, so this costs one more exact key field on a
         * table that was already exact-matched, and no new PHV. */
        key = { hdr.pgen.pipe_app  : exact;
                hdr.pgen.packet_id : exact; }
        actions = { synth_read; synth_ack; synth_resp; synth_resp_alt; synth_none; }
        default_action = synth_none();
        size = 16;
    }
#endif

    /* ---- level 1: build the deadline-aligned "now" ----
     * Constants only on the packing side. This must be an explicit table rather than
     * a plain statement beside the level-0 assignments: bf-p4c merges consecutive
     * unconditional statements into ONE action and then rejects the intra-action
     * dependency with "action spanning multiple stages" (measured on 9.13.1). */
    action build_now() { meta.now_word = meta.ts_m | ARMED_MARK; }
    table tbl_build_now {
        actions = { build_now; }
        const default_action = build_now();
        size = 1;
    }

    /* ---- level 1: D3 — the expected acknowledgment candidate ----
     * exp_ack_cand = this frame's tcp.seq_no + read_len. Computed UNCONDITIONALLY
     * (both operands are level-0), and consumed only by exp_ack_w, which the MAU
     * predicates on pkt_class == CLASS_ARM. Doing the gating with the SALU's MAU
     * predicate rather than with a metadata write is what keeps this at level 1 and
     * the register at level 2 — the alternative (gate the add on pkt_class) is a
     * level-1 -> level-1 dependency and costs a whole stage. */
    action build_exp_ack() { meta.exp_ack_cand = hdr.tcp.seq_no + meta.read_len; }
    table tbl_build_exp_ack {
        actions = { build_exp_ack; }
        const default_action = build_exp_ack();
        size = 1;
    }

    /* ---- level 2: the candidate armed word for an ACK ----
     * dl_cand = now_word + D: the low byte of the addend is zero, so the ARMED marker
     * survives the addition untouched and the tick fields add. */
    action build_cand() { meta.dl_cand = meta.now_word + meta.seq_m; }
    table tbl_build_cand {
        actions = { build_cand; }
        const default_action = build_cand();
        size = 1;
    }
    /* Defense 4: T_RESP candidate = now_word + (D_A + D_R) — ONE addition via the
     * precomputed da_dr param (bf-asm cannot PHV+PHV in the SALU; same idiom as build_cand). */
    action build_cand_resp() { meta.tresp_cand = meta.now_word + meta.da_dr; }
    table tbl_build_cand_resp {
        actions = { build_cand_resp; }
        const default_action = build_cand_resp();
        size = 1;
    }

    /* ================= the ONE decode table ==============================
     * Every §8 conjunct that is not already enforced by the parser or by the class
     * driver is resolved HERE, in one lookup, so the predicates cost ZERO additional
     * logical tables over the baseline. The match unit reads whole containers under a
     * TCAM mask — nothing is sliced.
     *
     * KEY, and which conjunct each field carries:
     *   pkt_class   exact    — direction + role + protected session (class driver)
     *   tag_diff    ternary  — generation state (see tag_arm's table above; and for a
     *                          pure ACK, gen_in == 0 so tag_diff == 0 - stored, which
     *                          is in {0x00, 0x01} exactly when NO transaction is live)
     *   seq_diff    ternary  — tcp.seq  == EXP_RELAY_SEQ   <- REJECTS 61/61 keepalives
     *   ack_diff    ternary  — tcp.ack  == EXP_ACK         <- defence in depth
     *   sport_diff  ternary  — tcp port == learned master ephemeral port
     *
     * ENTRY ORDER IS PRIORITY. A rejected ACK writes NOTHING, so it cannot move any
     * release time; it is forwarded unprotected and counted. */
    /* Defense 4: dl_val_resp mirrors dl_val for reg_tresp — the ARM disarms T_RESP,
     * the qualifying ACK arms it to tresp_cand; every other verdict leaves it. */
    action dec_arm_fresh()  { meta.dl_val = UNARMED_WORD; meta.dl_val_resp = UNARMED_WORD; meta.verdict = V_ARM_FRESH;  }
    action dec_arm_dup()    { meta.dl_val = DL_NO_WRITE;  meta.verdict = V_ARM_DUP;    }
    action dec_arm_busy()   { meta.dl_val = DL_NO_WRITE;  meta.verdict = V_ARM_BUSY;   }
    action dec_ack_arm()    { meta.dl_val = meta.dl_cand; meta.dl_val_resp = meta.tresp_cand; meta.verdict = V_ACK_ARM;    }
    action dec_ack_reject() { meta.dl_val = DL_NO_WRITE;  meta.verdict = V_ACK_REJECT; }
    action dec_block_live() { meta.dl_val = DL_NO_WRITE;  meta.verdict = V_BLOCK_LIVE; }
    /* Defense 4 D1: the live blocker whose generation's RESPONSE is pending (tag_diff 0xB0). */
    action dec_block_pending() { meta.dl_val = DL_NO_WRITE;  meta.verdict = V_BLOCK_PENDING; }
    action dec_resp()       { meta.dl_val = DL_NO_WRITE;  meta.verdict = V_RESP;       }
    action dec_resp_bypass(){ meta.dl_val = DL_NO_WRITE;  meta.verdict = V_RESP_BYPASS;}
    /* D3 — THE ACK RELEASE PASS. meta.tag_val is reg_ack_rel's write operand here
     * (see the PHV note on reg_ack_rel); assigning cur_gen records the release as a
     * GENERATION. reg_tag is untouched on this path (tag_read). */
    action dec_ack_rel()    { meta.dl_val = DL_NO_WRITE;  meta.tag_val = meta.cur_gen; }
    action dec_none()       { meta.dl_val = DL_NO_WRITE; }
    /* ►► R1. The RESPONSE's marker delta, authorised by the FULL 8.2 predicate.
     *
     * WHY THIS CAN BE DONE EARLY, and why it is not just moving the defect: the
     * RESPONSE rows of tbl_state_decode mask meta.tag_diff OUT entirely
     * (8w0x00 &&& 8w0x00), i.e. the RESPONSE verdict has NEVER depended on reg_tag. It
     * depends only on seq_diff / ack_diff / sport_diff, and all three are produced by
     * the session trackers BEFORE the tag access. So the same conjuncts can be resolved
     * one level earlier and used to gate the delta, leaving reg_tag's placement, its
     * four RegisterActions and every other class's ordering untouched.
     *
     * The one-shot property is unchanged: it is still enforced by the MSB test inside
     * tag_read_or_mark, so a duplicate RESPONSE that IS valid still cannot mark twice.
     * What changes is only that an INVALID response now carries delta 0 and the SALU
     * is a pure read for it, exactly as it is for a generated token. */
    action resp_authorise()   { meta.tag_val = TAG_PENDING_DELTA; }
    action resp_deauthorise() { meta.tag_val = 8w0; }   /* CLASS_RESP: delta 0 = read */
    action resp_untouched()   { }                       /* EVERYTHING ELSE: hands off */
    table tbl_resp_authorise {
        key = {
            meta.pkt_class  : exact;
            meta.seq_diff   : ternary;
            meta.ack_diff   : ternary;
            meta.sport_diff : ternary;
        }
        actions = { resp_authorise; resp_deauthorise; resp_untouched; }
        /* ►► THE DEFAULT MUST NOT TOUCH tag_val, AND THE FIRST VERSION OF THIS TABLE
         * DID. It defaulted to writing 0, which reaches every packet that is not a
         * RESPONSE -- and for those the tag arm is tag_rmw, whose write is guarded by
         * `tag_val != TAG_NO_WRITE`. Forcing 0 therefore turned every such packet into
         * an unconditional write of TAG_INACTIVE. GATE 2 CAUGHT IT IMMEDIATELY on
         * silicon: the READ armed (ARM_FRESH=1), the mirrored clone came back ~700 ns
         * later, took tag_rmw, and WIPED the generation, so all 64 tokens were rejected
         * (PKTGEN_ADMIT=0, PKTGEN_DROP=64), the ACK was refused (ACK_REJECT=1) and the
         * RESPONSE bypassed. tag_val's default of TAG_NO_WRITE is load-bearing for
         * every non-RESPONSE class and must survive this table. */
        const default_action = resp_untouched();
        const entries = {
            /* identical masks to tbl_state_decode's dec_resp row: full-width on all
             * three trackers. */
            (CLASS_RESP, 32w0 &&& 32w0xFFFFFFFF, 32w0 &&& 32w0xFFFFFFFF,
                         16w0 &&& 16w0xFFFF) : resp_authorise();
            /* a RESPONSE that failed any conjunct: explicitly made read-only. This is
             * a CLASS_RESP entry, NOT the table default, which is the whole fix. */
            (CLASS_RESP, 32w0 &&& 32w0, 32w0 &&& 32w0, 16w0 &&& 16w0)
                : resp_deauthorise();
        }
        size = 4;
    }

    table tbl_state_decode {
        key = {
            meta.pkt_class  : exact;
            meta.tag_diff   : ternary;
            meta.seq_diff   : ternary;
            meta.ack_diff   : ternary;
            meta.sport_diff : ternary;
        }
        actions = { dec_arm_fresh; dec_arm_dup; dec_arm_busy;
                    dec_ack_arm;   dec_ack_reject;
                    dec_block_live; dec_block_pending; dec_resp; dec_resp_bypass; dec_ack_rel; dec_none; }
        const default_action = dec_none();
        const entries = {
            /* ---- master READ. The session was already pinned by the class driver;
             * the seq/ack trackers are being INSTALLED here, not tested. ---- */
            (CLASS_ARM, 8w0x00 &&& 8w0xFF, 32w0 &&& 32w0, 32w0 &&& 32w0, 16w0 &&& 16w0)
                : dec_arm_dup();     /* stored == this generation: retransmitted READ */
            /* (the 0xFF-era `tag_diff == 0xD0 -> arm_fresh` entry was REMOVED here —
             * see the note on tag_arm. Under TAG_INACTIVE = 0x00 the single mask below
             * covers the whole idle set 0xC0..0xCF.) */
            (CLASS_ARM, 8w0xC0 &&& 8w0xF0, 32w0 &&& 32w0, 32w0 &&& 32w0, 16w0 &&& 16w0)
                : dec_arm_fresh();   /* idle: stored 0x00, so tag_diff == gen_in       */
            (CLASS_ARM, 8w0x00 &&& 8w0x00, 32w0 &&& 32w0, 32w0 &&& 32w0, 16w0 &&& 16w0)
                : dec_arm_busy();    /* a DIFFERENT generation is live: escape        */

            /* ---- relay pure ACK: EVERY remaining §8.1 conjunct, in priority order ---- */
            (CLASS_ACK, 8w0x00 &&& 8w0xFE, 32w0 &&& 32w0, 32w0 &&& 32w0, 16w0 &&& 16w0)
                : dec_ack_reject();  /* no live transaction at all                    */
            (CLASS_ACK, 8w0x00 &&& 8w0x00,
                        32w0 &&& 32w0xFFFFFFFF, 32w0 &&& 32w0xFFFFFFFF, 16w0 &&& 16w0xFFFF)
                : dec_ack_arm();     /* live AND seq AND ack AND port all match       */
            (CLASS_ACK, 8w0x00 &&& 8w0x00, 32w0 &&& 32w0, 32w0 &&& 32w0, 16w0 &&& 16w0)
                : dec_ack_reject();  /* keepalive / stale duplicate / wrong session   */

            /* ---- relay DNP3 RESPONSE: the §8.2 seq/ack/port conjuncts. The
             * generation binding is txn_active on the RAW stored value, tested in the
             * ACT block, NOT gen_in - stored (CONSENSUS §7 R7). ---- */
            (CLASS_RESP, 8w0x00 &&& 8w0x00,
                         32w0 &&& 32w0xFFFFFFFF, 32w0 &&& 32w0xFFFFFFFF, 16w0 &&& 16w0xFFFF)
                : dec_resp();
            (CLASS_RESP, 8w0x00 &&& 8w0x00, 32w0 &&& 32w0, 32w0 &&& 32w0, 16w0 &&& 16w0)
                : dec_resp_bypass(); /* stale generation / wrong session -> bypass     */

            /* ---- blocker token back from dp8: exact generation match ----
             * TWO values, both meaning "this token belongs to the CURRENT
             * transaction", because E1 puts the lifecycle phase in the same register
             * the token is compared against:
             *   tag_diff == 0x00  stored == carried            (no RESPONSE pending)
             *   tag_diff == 0xB0  stored == carried - 0xB0     (a RESPONSE is pending)
             * 0xB0 is EXACT and generation-INDEPENDENT: carried_gen - (gen - 0xB0) ==
             * 0xB0 for every one of the sixteen generations, so this is one entry, not
             * sixteen. It changes NOTHING about the blocker lifecycle — same
             * admission, same recirculation, same pass budget, same queue, same
             * deadline termination — it only teaches the liveness test the second
             * encoding of the same generation. Without it the tokens would read STALE
             * the instant an early RESPONSE was admitted and the reservoir would
             * collapse before D, which BLOCK_TERM_STALE and the hold measurement both
             * detect immediately.
             * A token of a DIFFERENT generation still reads stale: the differences a
             * foreign token can produce are gen_a - gen_b (mod 256) for distinct
             * generations, which lie in {0x01..0x0F, 0xF1..0xFF} against an unmarked
             * tag and {0xB1..0xBF, 0xA1..0xAF} against a marked one — 0xB0 is in
             * neither set. */
            (CLASS_BLOCK_DEQ, 8w0x00 &&& 8w0xFF, 32w0 &&& 32w0, 32w0 &&& 32w0, 16w0 &&& 16w0)
                : dec_block_live();
            (CLASS_BLOCK_DEQ, 8w0xB0 &&& 8w0xFF, 32w0 &&& 32w0, 32w0 &&& 32w0, 16w0 &&& 16w0)
                : dec_block_pending();   /* Defense 4 D1: current-gen RESPONSE observed */

            /* ---- the RELEASED ACK on its dp8 return pass ---- */
            (CLASS_ACK_REL, 8w0x00 &&& 8w0x00, 32w0 &&& 32w0, 32w0 &&& 32w0, 16w0 &&& 16w0)
                : dec_ack_rel();
        }
        size = 16;
    }

    /* ================= transaction-active check ===========================
     * reg_tag's raw value is provably in {0xC0..0xCF (a generation)} u {0x00 =
     * TAG_INACTIVE, i.e. idle or retired}; "active" == it is a 0xCn generation. Tested as a masked-equality
     * ternary on the whole container (NOT a magnitude compare, so no gateway/range
     * cost). Consumed by the pktgen admission AND by the RESPONSE's generation
     * binding. */
    action mark_txn_active()   { meta.txn_active = 8w1; }
    /* E1: LIVE, but a RESPONSE is already pending. A DISTINCT value, not a second
     * flag: every existing `txn_active == 8w1` test therefore keeps its exact meaning
     * ("live and nothing pending yet"), and the one-shot protection for a duplicate
     * RESPONSE falls out for free — the second RESPONSE reads txn_active == 2, misses
     * the hold branch, and is FORWARDED as a bypass rather than held or marked again.
     * No new PHV: meta.txn_active is already bit<8>. */
    action mark_txn_pending()  { meta.txn_active = 8w2; }
    action mark_txn_inactive() { meta.txn_active = 8w0; }
    table tbl_txn_active {
        key = { meta.cur_gen : ternary; }
        actions = { mark_txn_active; mark_txn_pending; mark_txn_inactive; }
        const default_action = mark_txn_inactive();
        const entries = {
            (8w0xC0 &&& 8w0xF0) : mark_txn_active();    /* 0xCn: live, none pending */
            (8w0x10 &&& 8w0xF0) : mark_txn_pending();   /* 0x1n: live, one pending  */
        }
        size = 4;
    }

    /* ================= deadline expiry =================================
     * expired <=> the deadline word is ARMED (low byte of the age is 0x00, which
     * happens only when the stored marker 0x01 cancelled the now-word marker with no
     * borrow) AND the 24-bit tick difference is non-negative (bit 31 clear). ONE
     * ternary entry tests both on a WHOLE CONTAINER; unarmed words can never read as
     * expired, which is why "deadline_valid" needs no state of its own.
     *
     * ONLY THE BLOCKER PATH AND THE RELEASED RESPONSE READ meta.expired. The ACK path
     * never does (it takes deadline_arm_once, which returns dl_pre into a different
     * field and leaves meta.age at its parser value), and the RESPONSE ADMISSION path
     * never does — see the ACT block. */
    action mark_expired()     { meta.expired = 8w1; }
    action mark_not_expired() { meta.expired = 8w0; }
    table tbl_deadline_expiry {
        key = { meta.age : ternary; }
        actions = { mark_expired; mark_not_expired; }
        const default_action = mark_not_expired();
        const entries = {
            (32w0x00000000 &&& 32w0x800000FF) : mark_expired();
        }
        size = 2;
    }
    /* Defense 4: RESPONSE-deadline expiry, symmetric (age_resp sign-bit, same mask). */
    action mark_expired_resp()     { meta.expired_resp = 8w1; }
    action mark_not_expired_resp() { meta.expired_resp = 8w0; }
    table tbl_tresp_expiry {
        key = { meta.age_resp : ternary; }
        actions = { mark_expired_resp; mark_not_expired_resp; }
        const default_action = mark_not_expired_resp();
        const entries = {
            (32w0x00000000 &&& 32w0x800000FF) : mark_expired_resp();
        }
        size = 2;
    }

    apply {
        if (meta.port_ok == 8w0) {
            /* isolate the pipeline: only dp8 / dp9 / dp11 / dp64 / dp68 are topology */
            ctr_fresh.count(CF_BAD_PORT);
            D3_DROP()
        } else {
            /* ---------- level 0: packet-derived only ---------- */
            meta.ts32 = ig_intr_md.ingress_mac_tstamp[31:0];
            meta.ts_m = ig_intr_md.ingress_mac_tstamp[31:0] & TICK_MASK;
            /* hdr.ib is valid ONLY on blocker tokens, so on every other frame this
             * compares a stale tagalong container and budget_zero is MEANINGLESS.
             * Safe because budget_zero has exactly two consumers and both sit inside
             * a ROLE_BLOCK branch. Do not read budget_zero outside a ROLE_BLOCK branch. */
            if (hdr.ib.seq == 32w0) { meta.budget_zero = 8w1; }  /* isolated 32b compare */
            /* Defense 4: RESP-blocker sub-role from the token slot (only read under
             * ROLE_BLOCK, where hdr.ib is valid — same tagalong discipline as budget_zero). */
            if (hdr.ib.slot == SLOT_RESP) { meta.is_resp_blk = 8w1; }
            tbl_params.apply();                                  /* D, read_len, B      */
            /* the 5-tuple lookup is gated on IPv4 validity so a blocker token's stale
             * tagalong containers can never match a session entry and corrupt a
             * tracker. Non-IP traffic keeps meta.sess = SESS_NONE and is bypassed. */
#ifdef D3_SYNTH_EVENTS
            /* SYNTHETIC BUILD ONLY. Mutually exclusive with the real lookup, so
             * both tables place in the SAME stage and the class driver below is
             * completely unchanged: a synthetic event traverses the identical
             * class driver, decode table, registers and ACT block as a live one. */
            if (meta.is_synth == 8w1)     { tbl_synth_role.apply(); }
            else if (hdr.ipv4.isValid())  { tbl_session.apply(); }
#else
            if (hdr.ipv4.isValid()) { tbl_session.apply(); }
#endif

            /* ---------- level 1: now-word, EXP_ACK candidate, class + write drivers ---- */
            tbl_build_now.apply();
            tbl_build_exp_ack.apply();

            if (meta.dequeued == 8w0) {
                /* FRESH from a host port (or the pktgen source dp68). The class driver
                 * carries the DIRECTION and PROTECTED-SESSION conjuncts of §8; the
                 * decode table carries the rest. */
                if (meta.is_pktgen == 8w1) {
                    /* ►► E1: A FRESH GENERATED TOKEN USES tag_read_or_mark AS A PURE
                     * READ, so its marker delta must be ZERO. The parser initialises
                     * meta.tag_val to TAG_NO_WRITE (0x01), and leaving it there makes
                     * the arm ADD ONE to the generation on every single token.
                     * MEASURED on silicon when this assignment was in the wrong branch:
                     * PKTGEN_ADMIT=16, PKTGEN_DROP=48, BLOCK_TERM_STALE=16 — because
                     * 0xC0 + 16 == 0xD0 leaves tbl_txn_active's domains exactly at
                     * token 17, so the first sixteen were admitted and then read stale.
                     *
                     * IT MUST BE IN THIS BRANCH. The ROLE_BLOCK arm below is in the
                     * `dequeued == 1` half of the class driver, so a FRESH token never
                     * reaches it; a fresh token matches none of the role tests here
                     * (role == ROLE_BLOCK, sess == SESS_NONE) and would otherwise leave
                     * this chain with tag_val untouched. Tested FIRST so there is
                     * exactly ONE write to tag_val per path — a second sequential write
                     * to a level-1 field is a write-after-write that costs a stage. */
                    meta.tag_val = 8w0;                /* delta 0 == read-only      */
                } else if (meta.role == ROLE_ARM && meta.sess == SESS_MASTER) {
                    meta.pkt_class = CLASS_ARM;
                } else if (meta.role == ROLE_ACK && meta.sess == SESS_RELAY
                                                 && meta.dir  == DIR_RELAY) {
                    meta.pkt_class = CLASS_ACK;
                } else if (meta.role == ROLE_RESP && meta.sess == SESS_RELAY
                                                  && meta.dir  == DIR_RELAY) {
                    meta.pkt_class = CLASS_RESP;
                }
                /* (a master->relay frame needs no class: tbl_session already set
                 *  meta.seq_w / meta.sport_w at level 0, which is the whole of the
                 *  session-learning path.) */
            } else if (meta.role == ROLE_BLOCK) {
                meta.pkt_class = CLASS_BLOCK_DEQ;
                if (meta.budget_zero == 8w1) {
                    /* R2: tag_val is deliberately LEFT ALONE here, so this packet's
                     * reg_tag access stays read-only. The note is written below. */
                }
            } else if (meta.role == ROLE_ACK) {
                meta.pkt_class = CLASS_ACK_REL;        /* D3: the released ACK      */
            } else if (meta.role == ROLE_RESP) {
                /* D3: the released RESPONSE completes the transaction. Retiring the
                 * generation HERE (and on fail-open) is what stops a later keepalive
                 * from finding a live generation. It cannot fire early: Q_HOLD is a
                 * FIFO and the ACK was enqueued first, so the RESPONSE can only
                 * dequeue after the ACK has already left. */
                meta.tag_val = TAG_INACTIVE;
            }

            /* ---------- R2: the fail-open note, one level BEFORE reg_tag ----------
             * reg_failopen must resolve before reg_tag, because tag_arm consumes
             * meta.fo_gen as an operand. The two accesses are mutually exclusive, so
             * exactly one runs per packet and the register takes one access per packet
             * exactly as reg_tag does. */
            if (meta.pkt_class == CLASS_ARM) {
                /* the note becomes tag_arm's second comparison operand. */
                /* C1: OFF / FAIL_OPEN never arm — tag_val = TAG_NO_WRITE so the reg_tag
                 * access below is a pure read (the transaction is never made active). */
                if (meta.mode == MODE_OFF || meta.mode == MODE_FAIL_OPEN) {
                    meta.tag_val = TAG_NO_WRITE;
                } else {
                    meta.tag_val = fo_take.execute(0);
                }
            } else if (meta.pkt_class == CLASS_BLOCK_DEQ && meta.budget_zero == 8w1) {
                fo_note.execute(0);                   /* name my own generation */
            }

            /* ---------- level 1/2: the session trackers ----------
             * All three are difference-returning. The two seeded from tbl_session's
             * level-0 action can execute at level 1; reg_exp_ack needs the level-1
             * exp_ack_cand and so sits at level 2. */
            /* §5.5: class-selected write-enable. exp_seq_w stores on a master->relay
             * session frame (meta.sess == SESS_MASTER); every other frame only tests.
             * In the synthetic build the tracker is control-plane-seeded and the synth
             * READ (also SESS_MASTER) must NOT clobber it, so is_synth gates the writer
             * off there — reproducing the old value-sentinel's no-write on that path. */
            if (meta.sess == SESS_MASTER
#ifdef D3_SYNTH_EVENTS
                    && meta.is_synth == 8w0
#endif
               ) { meta.seq_diff = exp_seq_w.execute(0); }
            else { meta.seq_diff = exp_seq_r.execute(0); }
            meta.sport_diff = sess_port_rmw.execute(0);
            if (meta.pkt_class == CLASS_ARM) {
                meta.ack_diff = exp_ack_w.execute(0);   /* install EXP_ACK */
            } else {
                meta.ack_diff = exp_ack_r.execute(0);   /* test  EXP_ACK   */
            }

            /* ►► R1: authorise the marker delta BEFORE the tag access. This runs after
             * the session trackers (which produce all three diffs) and before reg_tag,
             * so it costs one level of dependency on the RESPONSE path only. */
            tbl_resp_authorise.apply();

            /* ---------- level 2: tag access (+ the ACK candidate in parallel) ------
             * THREE mutually exclusive arms -> ONE SALU access on reg_tag per packet:
             *   CLASS_ARM                        -> tag_arm  (compare-and-arm-once)
             *   pktgen token / RESPONSE / ACK_REL-> tag_read (RAW stored generation)
             *   everything else                  -> tag_rmw  (the baseline difference)
             * The RESPONSE and the released ACK MUST take the raw arm: their
             * generation binding is the stored value, never their own app_control. */
            if (meta.pkt_class == CLASS_ARM &&
                meta.mode != MODE_OFF && meta.mode != MODE_FAIL_OPEN) {
                meta.tag_diff = tag_arm.execute(0);
            } else if (meta.pkt_class == CLASS_ARM) {
                /* C1 bypass: TAG_NO_WRITE above -> tag_rmw is a pure read, reg_tag stays
                 * INACTIVE, so no active transaction remains after an OFF/FAIL_OPEN READ. */
                meta.tag_diff = tag_rmw.execute(0);
            } else if (meta.pkt_class == CLASS_RESP || meta.is_pktgen == 8w1) {
                /* E1: ONE arm for both. The class driver set meta.tag_val to
                 * TAG_PENDING_DELTA for a RESPONSE (mark) and to 0 for a generated
                 * token (pure read); the PRE-state comes back as cur_gen either way,
                 * exactly as tag_read used to hand it over. */
                meta.cur_gen  = tag_read_or_mark.execute(0);
            } else if (meta.pkt_class == CLASS_ACK_REL) {
                /* E1: THE REPAIR. Retire iff nothing is pending. cur_gen is the
                 * PRE-state, so tbl_txn_active below reports WHICH branch ran:
                 * txn_active == 1 -> it retired; == 2 -> a RESPONSE is queued. */
                meta.cur_gen  = tag_retire_if_unmarked.execute(0);
            } else {
                meta.tag_diff = tag_rmw.execute(0);
            }
            tbl_build_cand.apply();
            tbl_build_cand_resp.apply();     /* Defense 4: T_RESP candidate (now_word + da_dr) */

            /* ---------- level 3: one decode for every remaining conjunct ---------- */
            tbl_state_decode.apply();
            tbl_txn_active.apply();

            /* ---------- level 4: deadline access + the ACK-release generation ------
             * The qualifying ACK arms hold-once and receives the PRE-state; every
             * other packet — including the ARM, which disarms via dl_val =
             * UNARMED_WORD — uses the unchanged deadline_rmw and receives the age.
             * Both are the same register; only one runs per packet.
             *
             * reg_ack_rel is executed ONLY on the two paths whose PHV operands are
             * provably dead (CLASS_RESP, CLASS_ACK_REL) and lands in the same stage,
             * in parallel with reg_deadline. */
            if (meta.verdict == V_ACK_ARM) {
                meta.dl_pre = deadline_arm_once.execute(0);
            } else {
                meta.age    = deadline_rmw.execute(0);
            }
            /* Defense 4: reg_tresp is the SYMMETRIC RESPONSE deadline. The qualifying ACK
             * arms T_RESP hold-once (parallel register, its own stage); every other packet
             * — including the ARM, which disarms via dl_val_resp = UNARMED_WORD — reads the
             * age_resp used by the RESP blocker's expiry test. Exactly one runs per packet. */
            if (meta.verdict == V_ACK_ARM) {
                tresp_arm_once.execute(0);
            } else {
                meta.age_resp = tresp_rmw.execute(0);
            }
            /* E1: CLASS_RESP NO LONGER executes this. Two reasons. (a) meta.tag_val
             * now carries the marker delta on that path, and ack_rel_rmw would write
             * it into reg_ack_rel as though it were a generation. (b) it is no longer
             * needed: under E1 a RESPONSE arriving after the ACK committed finds the
             * transaction already RETIRED, so it is classified by txn_active == 0 and
             * bypassed, and the early/late question never reaches rel_diff. reg_ack_rel
             * is now purely the ACK-release generation record. */
            if (meta.pkt_class == CLASS_ACK_REL) {
                meta.tag_diff = ack_rel_rmw.execute(0);   /* == rel_diff; see PHV note */
            }

            /* ---------- level 5: expiry (blocker + released-response paths) ------- */
            tbl_deadline_expiry.apply();
            tbl_tresp_expiry.apply();        /* Defense 4: expired_resp from age_resp */

            /* ================= ACT (flat, no early returns) ================= */
            if (meta.dequeued == 8w0) {
                /* ----- FRESH from a host port (or the pktgen source dp68) ----- */
                if (meta.role == ROLE_CLONE) {
                    /* the trigger clone, tested FIRST so it cannot fall into any other
                     * arm. Counted as itself and dropped. Its ingress timestamp is the
                     * instant the generator's pattern matcher was fed — i.e.
                     * t_pktgen_trigger — which is why the synthetic build records it. */
                    D3_DROP()
                    ctr_fresh.count(CF_CLONE_SEEN);

                } else if (meta.role == ROLE_BLOCK) {
                    if (meta.is_pktgen == 8w1) {
                        /* PKTGEN admission: admit only while a transaction is active;
                         * STAMP the current generation + the runtime fail-open budget
                         * so the token matches on its first dp8 loop, then enqueue
                         * Q_BLOCK. Stamping from reg_tag (not the template) means a
                         * token generated a hair after a new READ still gets the live
                         * generation, and a stale-generation token self-terminates on
                         * its first loop. to_block() is the ONLY egress a token can
                         * reach. */
                        if (meta.txn_active == 8w1 && hdr.pgen.packet_id[15:7] != 9w0) {
                            /* Defense 4: invalid packet_id (>= 128) — drop before admission. */
                            D3_DROP()
                            ctr_fresh.count(CF_PKTGEN_DROP);
                        } else if (meta.txn_active == 8w1 && hdr.pgen.packet_id[6:6] == 1w0) {
                            /* Defense 4: packet_id 0..63 -> ACK blocker, first-enqueue qid7. */
                            hdr.ib.role = ROLE_BLOCK;
                            hdr.ib.slot = SLOT_ACK;
                            hdr.ib.gen  = meta.cur_gen;       /* CURRENT generation    */
                            hdr.ib.seq  = meta.budget_init;   /* runtime budget B      */
                            to_block();                        /* qid7 ACK reservoir    */
                            ctr_fresh.count(CF_PKTGEN_ADMIT);
                            meta.ev_first_block = 8w1;
                        } else if (meta.txn_active == 8w1) {
                            /* Defense 4: packet_id 64..127 -> RESPONSE blocker, first-enqueue qid5. */
                            hdr.ib.role = ROLE_BLOCK;
                            hdr.ib.slot = SLOT_RESP;
                            hdr.ib.gen  = meta.cur_gen;
                            hdr.ib.seq  = meta.budget_init;
                            to_resp_block();                   /* qid5 RESPONSE reservoir */
                            ctr_fresh.count(CF_PKTGEN_ADMIT);
                            meta.ev_first_block = 8w1;
                        } else {
                            D3_DROP()                       /* no active txn         */
                            ctr_fresh.count(CF_PKTGEN_DROP);
                        }
                    } else {
                        /* ►► R3. A FRESH 0x88C1 frame that did NOT come from the packet
                         * generator can only have arrived on a host-facing port, because
                         * the parser forces that EtherType to ROLE_BLOCK from ANY port in
                         * the topology and every topology port sets port_ok = 1. The
                         * shipped code enqueued it into Q_BLOCK -- the STRICT-PRIORITY
                         * queue -- carrying an attacker-chosen generation and budget.
                         *
                         * This is the ADMISSION defect R3 closes: a fresh injected token
                         * reaches Q_BLOCK carrying an attacker-chosen generation and budget.
                         * NOTE ON THE CLOBBER (corrected after the K-sweep): the injected
                         * token itself did NOT clobber reg_tag -- forging it through the
                         * legacy is_pktgen=0 path with seq==0 does not traverse a native
                         * token's budget-zero write, so that was a harness artifact. The
                         * destructive fail-open write of defect 2 is reproduced by the
                         * NATIVE reservoir at K=1 (§7.8 K-sweep), not by this injected frame.
                         * R3 still closes the injection ADMISSION path regardless; combined
                         * with R2 (which removes the destructive write) the practical route
                         * is shut. Closing it here costs one action and no state.
                         *
                         * The threat model is passive, so this is outside the modelled
                         * adversary -- but a production build should not ship a known
                         * injection path for the sake of an A/B rollback that the
                         * in-switch generator has made unnecessary. */
                        /* ►► COUNTER FIX. A frame dropped here was NEVER enqueued, so it
                         * must not increment CF_BLOCK_ENQ -- that counter is read
                         * elsewhere as evidence of residence in Q_BLOCK. Count a distinct
                         * CF_BLOCK_REJECT so R3's rejection is visible and unambiguous. */
                        D3_DROP()
                        ctr_fresh.count(CF_BLOCK_REJECT);
                    }

                } else if (meta.pkt_class == CLASS_RESP) {
                    /* ============ D3: THE RESPONSE PATH ============
                     * EVERY in-transaction RESPONSE goes to Q_HOLD, UNCONDITIONALLY.
                     * There is NO `expired` test and NO deadline term anywhere in this
                     * branch, by design and not by omission:
                     *   - `if (expired) to_fwd()` races the measured 1,736 ns release
                     *     tail. A RESPONSE arriving inside that window would take ZERO
                     *     loopback passes while the held ACK still has up to 1.711 us
                     *     to run, and would be enqueued at dp9 AHEAD of it — inverting
                     *     the one ordering property Defense 3 claims.
                     *   - unconditional hold makes the pass count EQUAL for the ACK
                     *     and for the RESPONSE in every case, which is the ordering
                     *     invariant's item (c). If the deadline has already passed,
                     *     Q_BLOCK is empty and the cost is one 408 ns traversal.
                     * rel_diff is used ONLY to attribute the case (early vs late) and
                     * never to route. */
                    /* E1: txn_active == 1 means the tag was in 0xC0..0xCF, i.e. the
                     * ACK has NOT been released (it would have retired the tag) and no
                     * RESPONSE is pending yet. So a held RESPONSE is EARLY by
                     * construction, and tag_read_or_mark has just marked the tag.
                     * txn_active == 2 (a DUPLICATE, tag already 0x1n) and txn_active ==
                     * 0 (retired: a LATE or stale RESPONSE) both fall to the bypass
                     * arm — forwarded exactly once, never held, never re-marked.
                     * CF_RESP_HOLD_LATE is consequently UNREACHABLE under E1 and is
                     * retained only so a non-zero value would be a loud alarm. */
                    if (meta.verdict == V_RESP && meta.txn_active == 8w1 &&
                        (meta.mode == MODE_OFF || meta.mode == MODE_FAIL_OPEN)) {
                        /* OFF / FAIL_OPEN: forward the RESPONSE immediately (bypass). */
                        D3_TO_FWD()
                        ctr_fresh.count(CF_RESP_HOLD_EARLY);
                    } else if (meta.verdict == V_RESP && meta.txn_active == 8w1) {
                        /* Defense 4: EVERY protected RESPONSE enters qid4 (its own hold
                         * queue), starved by the qid5 RESPONSE blocker reservoir until
                         * T_RESP AND ACK commitment (D1/D2/D3/D4). Defense 3 held it on
                         * the shared ACK queue; Defense 4 separates the two originals. */
                        to_resp_hold();
                        /* D1_EVENT: no explicit write here — holding the RESPONSE already
                         * marks reg_tag 0xCn -> 0x1n (the E1 pending marker), which the D1
                         * ACK blocker reads as V_BLOCK_PENDING to release the ACK on the event. */
                        ctr_fresh.count(CF_RESP_HOLD_EARLY);
                    } else if (meta.verdict == V_RESP && meta.txn_active == 8w2) {
                        /* ►► DUPLICATE SUPPRESSION. An EXACT retransmission of the
                         * RESPONSE already held for THIS generation. Forwarding it is
                         * not an option: the bypass arm goes straight to the master
                         * while the ACK is still in Q_HOLD, and it was MEASURED
                         * overtaking the ACK by 1.0014 ms — inverting the one ordering
                         * property Defense 3 claims. Enqueuing a second copy is not an
                         * option either: the dequeued ROLE_RESP path retires
                         * unconditionally, so a second copy could clear a LATER
                         * generation. So it is dropped, and counted as its own event.
                         *
                         * WHAT "EXACT" MEANS HERE, conjunct by conjunct. verdict ==
                         * V_RESP is the decode entry whose seq / ack / port masks are
                         * all FULL-WIDTH, so:
                         *   tcp.seq                == EXP_RELAY_SEQ   (byte position)
                         *   tcp.ack_no             == EXP_ACK         (ack relation)
                         *   master ephemeral port  == the learned port
                         * and CLASS_RESP additionally required the §8.2 DNP3 gates —
                         * relay-facing, tracked session, FIR|FIN set with CON=0 UNS=0,
                         * func 129, single transport segment — which is the DNP3
                         * transaction identity. txn_active == 2 is the generation
                         * conjunct: reg_tag is in THIS generation's pending domain.
                         *
                         * ►► NOT independently compared: payload LENGTH. The held
                         * RESPONSE's length is not stored anywhere and storing it would
                         * mean new persistent state. tcp.seq pins the byte position and
                         * the DNP3 gates pin the framing, so a same-seq retransmission
                         * of a DIFFERENT length is the one case this cannot tell apart.
                         * Stated rather than papered over.
                         *
                         * Once the queued RESPONSE releases and retires the
                         * transaction, txn_active reads 0 and a later retransmission
                         * falls to the bypass arm below and forwards normally. */
                        D3_DROP()
                        ctr_fresh.count(CF_RESP_DUP_SUPP);
                    } else {
                        /* stale generation, wrong session, seq/ack mismatch, or no
                         * active transaction: forward unprotected, NEVER drop, and
                         * never hold — a stale RESPONSE must not enter Q_HOLD behind
                         * the NEXT transaction's ACK. */
                        D3_TO_FWD()
                        ctr_fresh.count(CF_RESP_BYPASS);
                    }

                } else if (meta.pkt_class == CLASS_ACK) {
                    /* ============ THE ACK PATH ============ */
                    if (meta.verdict == V_ACK_ARM &&
                        (meta.mode == MODE_OFF || meta.mode == MODE_FAIL_OPEN)) {
                        /* OFF / FAIL_OPEN: forward the ACK immediately, no hold (bypass). */
                        D3_TO_FWD()
                        ctr_fresh.count(CF_ACK_REJECT);
                    } else if (meta.verdict == V_ACK_ARM) {
                        to_hold();
                        if (meta.dl_pre == UNARMED_WORD) {
                            /* the FIRST qualifying ACK: it armed d_ACK = t_ACK + D */
                            ctr_fresh.count(CF_ACK_HOLD);
                            meta.ev_ack_arm = 8w1;
                        } else {
                            /* a SECOND qualifying ACK. The one-shot rejected the
                             * ARMING (deadline_arm_once did not write), NOT the
                             * packet. It is still delivered, through Q_HOLD, so it
                             * keeps the same pass count and cannot overtake the
                             * original — forwarding it directly here would both
                             * invert the order and leak the native ACK timing. */
                            ctr_fresh.count(CF_ACK_DUP_HOLD);
                        }
                    } else {
                        /* failed a §8.1 conjunct — keepalive (seq == SND.NXT-1), no
                         * live transaction, wrong session or wrong acknowledgment.
                         * Forwarded unprotected and counted; NOTHING was written, so a
                         * rejected ACK cannot move any release time. */
                        D3_TO_FWD()
                        ctr_fresh.count(CF_ACK_REJECT);
                    }

                } else if (meta.pkt_class == CLASS_ARM) {
                    /* a real DNP3 READ: it must reach the outstation, so it is
                     * forwarded byte-identically on every arm of the branch. The clone
                     * is a separate mirror copy and never perturbs this one. */
                    D3_TO_FWD()
                    if (meta.verdict == V_ARM_FRESH &&
                        meta.mode != MODE_OFF && meta.mode != MODE_FAIL_OPEN) {
                        /* C1: OFF / FAIL_OPEN are TRUE bypass — no K=64 blocker burst, so
                         * no blocker state is ever created for the transaction. */
                        arm_clone();                  /* exactly ONE K=64 burst */
                        ctr_fresh.count(CF_ARM_FRESH);
                    } else if (meta.verdict == V_ARM_DUP) {
                        ctr_fresh.count(CF_ARM_DUP);  /* retransmitted READ: no burst */
                    } else {
                        /* CONCURRENT_TRANSACTION_ESCAPE (direction §7): a different
                         * eligible READ arrived while a transaction is active. It is
                         * forwarded normally and UNPROTECTED; tag_arm did not write,
                         * so the active state is intact and no second reservoir was
                         * generated. This is a SCOPE LIMIT (one active transaction),
                         * so it is counted and reported, never suppressed. */
                        ctr_fresh.count(CF_ARM_BUSY);
                    }

                } else if (meta.role == ROLE_RESP_UNSUP) {
                    /* UNSUPPORTED_SEGMENTATION: multi-segment transport, multi-fragment
                     * application, or CON = 1. Forwarded transparently and counted. NO
                     * claim of multi-segment support is made anywhere. */
                    D3_TO_FWD()
                    ctr_fresh.count(CF_UNSUP_SEG);

                } else {
                    D3_TO_FWD()                         /* ROLE_BYPASS: transparent */
                    ctr_fresh.count(CF_BYPASS_FWD);
                }

            } else {
                /* ----- DEQUEUED (looped back from dp8) ----- */
                if (meta.role == ROLE_BLOCK && meta.is_resp_blk == 8w1) {
                    /* Defense 4: the RESPONSE blocker (qid5). SYMMETRIC to the ACK
                     * blocker below, but gated on the RESPONSE deadline (expired_resp,
                     * from reg_tresp = t_A + D_A + D_R) and re-enqueued to qid5. Release
                     * of the held RESPONSE (qid4) happens when this reservoir drains at
                     * T_RESP; the four-queue strict priority (qid6 ACK_HOLD > qid4
                     * RESP_HOLD) plus T_RESP >= T_A guarantees the ACK is served first,
                     * i.e. ACK commitment precedes RESPONSE release (no extra register).
                     * Termination priority stale > deadline > budget, as the ACK side.
                     * V_BLOCK_PENDING (this generation's RESPONSE marked) is still LIVE for
                     * the RESP blocker — it keeps holding the RESPONSE until T_RESP. */
                    if (meta.verdict != V_BLOCK_LIVE && meta.verdict != V_BLOCK_PENDING) {
                        D3_DROP()
                        ctr_deq.count(CD_BLOCK_TERM_STALE);
                        meta.ev_block_term = 8w1;
                    } else if (meta.expired_resp == 8w1) {
                        D3_DROP()                            /* T_RESP reached: drain -> release RESP */
                        ctr_deq.count(CD_BLOCK_TERM_DL);
                        meta.ev_block_term = 8w1;
                    } else if (meta.budget_zero == 8w1) {
                        D3_DROP()                            /* RESP_MISSING / fail-open horizon */
                        ctr_deq.count(CD_BLOCK_TERM_TMO);
                        meta.ev_block_term = 8w1;
                    } else {
                        hdr.ib.seq = hdr.ib.seq - 32w1;
                        to_resp_block();                     /* re-enqueue qid5 */
                        ctr_deq.count(CD_BLOCK_LOOP);
                    }

                } else if (meta.role == ROLE_BLOCK) {
                    /* ACK blocker (qid7). Two live states: V_BLOCK_LIVE (no RESP yet) and
                     * V_BLOCK_PENDING (this generation's RESPONSE OBSERVED — the D1 event,
                     * from the existing reg_tag 0x1n marker; no reg_resp_seen). Termination:
                     *   any other verdict          -> STALE (not this generation)
                     *   D1_EVENT: V_BLOCK_PENDING   -> release ACK on the RESPONSE event; the
                     *             ordinary deadline `expired` is NOT tested in D1; budget is
                     *             the only other terminator (missing-RESPONSE fail-open).
                     *   D2/D3/D4: expired (T_A)     -> deadline; then budget. */
                    if (meta.verdict != V_BLOCK_LIVE && meta.verdict != V_BLOCK_PENDING) {
                        D3_DROP()
                        ctr_deq.count(CD_BLOCK_TERM_STALE);
                        meta.ev_block_term = 8w1;
                    } else if (meta.mode == MODE_D1_EVENT) {
                        /* D1: event OR budget only — never the ordinary ACK deadline. */
                        if (meta.verdict == V_BLOCK_PENDING) {
                            D3_DROP()                        /* RESP observed -> release ACK  */
                            ctr_deq.count(CD_BLOCK_TERM_DL);
                            meta.ev_block_term = 8w1;
                        } else if (meta.budget_zero == 8w1) {
                            D3_DROP()                        /* missing RESPONSE fail-open    */
                            ctr_deq.count(CD_BLOCK_TERM_TMO);
                            meta.ev_block_term = 8w1;
                        } else {
                            hdr.ib.seq = hdr.ib.seq - 32w1;
                            to_block();                      /* keep holding the ACK          */
                            ctr_deq.count(CD_BLOCK_LOOP);
                        }
                    } else if (meta.expired == 8w1) {
                        D3_DROP()                            /* D2/D3/D4: ACK deadline T_A    */
                        ctr_deq.count(CD_BLOCK_TERM_DL);
                        meta.ev_block_term = 8w1;
                    } else if (meta.budget_zero == 8w1) {
                        D3_DROP()
                        ctr_deq.count(CD_BLOCK_TERM_TMO);   /* ACK_MISSING_FAIL_OPEN */
                        meta.ev_block_term = 8w1;
                    } else {
                        /* LOOP: consume one budget unit, re-enqueue Q_BLOCK */
                        hdr.ib.seq = hdr.ib.seq - 32w1;
                        to_block();
                        ctr_deq.count(CD_BLOCK_LOOP);
                    }

                } else if (meta.role == ROLE_ACK) {
                    /* ============ D3: THE ACK RELEASE PASS ============
                     * The reservoir drained, Q_HOLD became eligible and the ACK is
                     * back on dp8. Assign the master-facing port and the NORMAL final
                     * FIFO (to_fwd -> dp9 qid 0, the same single action every other
                     * egress path uses — ordering invariant item (d)), and forward it
                     * BYTE-IDENTICALLY.
                     *
                     * The release was already recorded as a GENERATION by
                     * ack_rel_rmw two levels above, on this same packet, on this same
                     * pass, with NO predicate between the write and this forward.
                     *
                     * "Prevent the ACK from being held again" needs no state: the
                     * CLASS_ACK assignment lives inside `if (dequeued == 0)`, so a
                     * released ACK can never be re-classified as a holdable ACK. */
                    D3_TO_FWD()
                    /* E1: ONE ctr_deq access, TWO slots that partition the ACK
                     * releases by which retirement path ran. txn_active came from the
                     * PRE-state of tag_retire_if_unmarked, so this is a direct readout
                     * of the SALU's own decision rather than an inference. */
                    if (meta.txn_active == 8w1) {
                        ctr_deq.count(CD_ACK_REL_RETIRE);  /* nothing pending: RETIRED */
                    } else {
                        ctr_deq.count(CD_ACK_RELEASE);     /* a RESPONSE is queued     */
                    }

                } else if (meta.role == ROLE_RESP) {
                    /* RELEASED RESPONSE: forward to the master, byte-identical, behind
                     * the ACK by FIFO order. The release cause is attributed by the
                     * deadline state at dequeue: expired => the reservoir drained on
                     * the deadline; not-expired => it drained early on its pass budget.
                     * The two causes partition the releases, so this packet touches
                     * ctr_deq exactly once and the total is their sum. */
                    D3_TO_FWD()
                    /* Defense 4: the RELEASED RESPONSE is attributed by its OWN deadline
                     * (expired_resp, from reg_tresp = T_RESP), not the ACK-side expired. */
                    if (meta.expired_resp == 8w1) { ctr_deq.count(CD_RELEASE_DEADLINE); }
                    else                          { ctr_deq.count(CD_RELEASE_FAILOPEN); }

                } else {
                    D3_DROP()   /* nothing else may loop back */
                }
            }

            /* ================= SPARSE latency capture (single call site each) ===
             * Each register is pinned to the stage AFTER whatever writes its flag.
             * ts_ack_release's predicate is entirely PARSER-derived, so it floats to
             * an early stage and needs no flag at all. */
            if (meta.ev_first_block == 8w1) { ts_first_block_w.execute(0); }
            if (meta.ev_ack_arm     == 8w1) { ts_ack_arm_w.execute(0); }
            if (meta.ev_block_term  == 8w1) { ts_block_term_w.execute(0); }
            if (meta.dequeued == 8w1 && meta.role == ROLE_ACK) { ts_ack_release_w.execute(0); }
#ifdef D3_TS_INTERNAL
            if (meta.ev_first_block == 8w1) { ts_last_block_w.execute(0); }
            if (meta.ev_block_term  == 8w1) { ts_last_term_w.execute(0); }
#endif
#ifdef D3_SYNTH_EVENTS
            if (meta.verdict == V_ARM_FRESH) { ts_read_w.execute(0); }
            if (meta.dequeued == 8w1 && meta.role == ROLE_RESP) { ts_resp_release_w.execute(0); }
            /* CHECK 2 instruments. ts_last_block_w shares ev_first_block's guard, so it
             * shares the stage; ts_clone_w's guard is parser-derived and floats. */
            if (meta.role == ROLE_CLONE)    { ts_clone_w.execute(0); }
            /* the ORDERING instrument: a fresh RESPONSE that took the bypass arm. The
             * predicate is (dequeued == 0 && pkt_class == CLASS_RESP && not held), and
             * "not held" is exactly txn_active != 1 on a V_RESP packet. */
            /* ONLY the arm that actually FORWARDS. The three RESPONSE dispositions
             * are: held (V_RESP && txn_active == 1), SUPPRESSED (V_RESP &&
             * txn_active == 2 — dropped, so it commits nowhere), and bypassed
             * (everything else). The first version of this predicate was
             * `txn_active != 1`, which fired on the SUPPRESSED copy too and made the
             * ordering test fail against a packet that had been dropped. */
            if (meta.dequeued == 8w0 && meta.pkt_class == CLASS_RESP
                    && (meta.verdict != V_RESP || meta.txn_active == 8w0)) {
                ts_resp_bypass_w.execute(0);
            }
#endif
        }
    }
}

/* ============================ ingress deparser ==========================
 * Emission order == extraction order, so every forwarded frame is byte-identical.
 * Exactly one of {ib} / {ipv4 ...} is valid; unextracted bytes stay residual and are
 * emitted automatically. */
control IgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    ig_meta_t meta,
                   in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    /* no-arg Mirror() (the typed ctor errors "Inconsistent mirror selectors" on TF1). */
    Mirror() clone_mirror;
    apply {
        /* on the fresh-ARM path arm_clone() set mirror_type = CLONE and
         * meta.clone_ses/clone_tag. emit prepends the 4-byte recirc tag to the MIRROR
         * copy only (session -> dp68 via $mirror.cfg); the main forwarded copy below is
         * untouched. Formatting the tag here costs ZERO egress stages. */
        if (ig_dprsr_md.mirror_type == MIRROR_TYPE_CLONE) {
            clone_mirror.emit<recirc_tag_h>(meta.clone_ses, { meta.clone_tag });
        }
#ifdef D3_EGRESS_MARKER
        pkt.emit(hdr.br);      /* PROBE VARIANTS B/C ONLY — stripped again in egress */
#endif
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ib);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.tcp_opt4);
        pkt.emit(hdr.tcp_opt8);
        pkt.emit(hdr.tcp_opt12);
        pkt.emit(hdr.dnp3_dl);
        pkt.emit(hdr.dnp3_tp);
        pkt.emit(hdr.dnp3_app);
    }
}

/* ============================ egress ====================================
 * VARIANT A (the pre-registered selection, direction §10): a BYTE-PRESERVING
 * PASS-THROUGH. Egress extracts only ethernet: everything after it is residual and
 * is re-emitted verbatim, so the frame is byte-identical to what the ingress
 * deparser produced. No field is modified anywhere in egress. Blocker tokens and
 * held packets set bypass_egress = 1 and never arrive here, so the hold mechanism
 * cannot be perturbed by this gress.
 *
 * WHY NOTHING MOVED HERE (Panel A, adopted by CONSENSUS §3): there is no internal
 * marker to clean up (the parser RE-DERIVES role on the loopback pass, and blockers
 * never reach egress); queue selection cannot move because the TM consumes it before
 * egress; an egress release counter cannot identify the released ACK without bridged
 * metadata on a byte-preserving pass; and an egress release TIMESTAMP is strictly
 * WORSE than the ingress one, because the true dequeue instant is the loopback pass's
 * ingress_mac_tstamp. Variants B and C exist only to produce the numbers §10 asks for.
 */
struct eg_meta_t { }

parser EgParser(packet_in pkt,
                out headers_t hdr,
                out eg_meta_t meta,
                out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
#ifdef D3_EGRESS_MARKER
        pkt.extract(hdr.br);       /* consumed here and NOT re-emitted -> byte identity */
#endif
        transition parse_eth;
    }
    state parse_eth {
        pkt.extract(hdr.eth);
        transition accept;
    }
}
control Egress(inout headers_t hdr,
               inout eg_meta_t meta,
               in    egress_intrinsic_metadata_t                 eg_intr_md,
               in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
#ifdef D3_EGRESS_MARKER
    /* PROBE VARIANT B: the release-path counter §10 asks about. It needs the bridged
     * role byte to tell a released ACK from ordinary forwarded traffic, because all of
     * it leaves via dp9 with bypass_egress = 0. */
    Counter<bit<64>, bit<8>>(8, CounterType_t.PACKETS) ctr_eg;
    action eg_count(bit<8> slot) { ctr_eg.count(slot); }
    table tbl_eg_release {
        key = { hdr.br.role : exact; }
        actions = { eg_count; }
        default_action = eg_count(8w0);
        size = 8;
    }
#endif
#ifdef D3_EGRESS_TS
    /* PROBE VARIANT C: the measurement-only egress release timestamp. Recorded here
     * ONLY to price it; it is strictly worse than the ingress instrument. */
    Register<bit<32>, bit<1>>(1, 0) reg_eg_ts;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_eg_ts) eg_ts_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = eg_prsr_md.global_tstamp[31:0]; } }
    };
#endif
    apply {
#ifdef D3_EGRESS_MARKER
        tbl_eg_release.apply();
#endif
#ifdef D3_EGRESS_TS
        if (hdr.br.role == 8w7) { eg_ts_w.execute(0); }
#endif
    }
}
control EgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    eg_meta_t meta,
                   in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        pkt.emit(hdr.eth);
    }
}

/* ============================ pipeline ================================== */
Pipeline(IgParser(), Ingress(), IgDeparser(),
         EgParser(), Egress(), EgDeparser()) pipe;

Switch(pipe) main;

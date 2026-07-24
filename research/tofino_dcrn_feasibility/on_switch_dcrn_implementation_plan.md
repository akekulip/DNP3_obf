# On-Switch DNP3 ACK-Delay (DCRN) — Tofino-1 Implementation Plan

*Authored by p4-dataplane-engineer (2026-07-18), main-session verified against the tofino-p4 skill
references. Design/planning only — nothing compiled, loaded, or run; no SSH to the switch. This is the
code-level build spec that operationalizes `on_switch_implementation_map.md`.*

**Readiness statement.** A P4 author can start coding from this spec today. Every load-bearing P4 shape
below is copied from working lab code on this chip: the DNP3 parse, the `tcp_data_offset_overhead`
payload-length table, and per-tuple `Hash` instances come from `a reference DNP3-parsing program`; the
runtime-indexed `Register` / two-`RegisterAction`-per-register / constructor-seed patterns come from
`a reference register/SALU program`; the `ucast_egress_port = 68` recirculation-hold, the bridge encap/decap
byte-preservation geometry, and the exact TM/recirc bfrt calls come from `a co-resident program's P4 source`
+ `the co-resident bring-up script`. Two things are **not** exercised anywhere in lab code and are the only
genuine unknowns, both resolved by the **first `bf-p4c` compile on SDE 9.13.2** and the **M2 hardware
probe**: (1) that the deadline compare against a runtime PHV operand fits a single Tofino-1 SALU
predicate, and (2) that `ig_prsr_md.global_tstamp` is re-taken when a frame re-enters ingress from the
recirc port. Both have concrete fallbacks. Every stage/SALU/PHV count is inference `[I]` until that
first compile prints a resource report. Byte-preservation and fail-open are non-negotiable invariants.

Evidence tags: **[L]** confirmed from working lab code cited inline · **[V]** TNA/vendor header/doc ·
**[M]** measured on the Phase-04B two-host rig · **[I]** inference on this unbuilt design · **[H]** hypothesis.

---

## Part 1 — Objective, invariants, scope

**What the ACK-delay does.** For each eligible DNP3 transaction, DCRN records the request arrival time
`t0` at ingress and selects a **class-independent** absolute deadline `T = t0 + Di` from a public
transaction-class profile identical across SEL-751-, AB1400-, and ION7550-derived traffic. It delays
the *existing* reverse-direction packet(s) so the visible request→response and request→ACK→response
timing no longer reflects the outstation's device-dependent processing time. It handles **both** native
TCP structures:

- **COMBINED** (AB1400/ION7550): `request → ACK-bearing DNP3 RESPONSE`. Hold the single response to `T`.
- **SEPARATE** (SEL-751): `request → pure TCP ACK → DNP3 RESPONSE`. Hold **both** the existing pure ACK
  and the existing response, release them back-to-back in FIFO order (pure ACK first) around the common
  target `T`, using a small common guard-delta on the response to guarantee ordering.

The hold is realized on-switch by a **self-clocked recirculation loop** on internal port dp68: an
eligible reverse frame is recirculated (byte-carried, with an internal bridge header) and released to
Vision only when a wall-clock deadline compare fires.

**Hard invariants (never traded for fit).**
1. **Byte-preserving.** Only the departure time changes. No DNP3 field/length edit, no CRC recompute,
   no padding, no TCP seq/ack rewrite, no packet synthesis. Byte-identity is asserted at the
   **dp8→Vision egress boundary**: IP header and everything above leaves bit-for-bit identical. The
   internal recirc frame carries an extra bridge header, **stripped before release** (a co-resident program's
   encap→decap discipline [L]); only the L2 FCS is recomputed by the MAC, as on any store-and-forward hop.
2. **Fail-open.** Every guard's default is **forward, never drop**, and **never hold beyond the
   RTO-safe cap**. A dropped or RTO-overshot DNP3 response is the loudest tell (trips a passive Zeek
   `dnp3` IDS). Detaching the controller or program leaves forwarding transparent.
3. **BOUNDED, not FIXED.** Target drawn from one common bounded distribution `[Dlow, Dhigh]` with a
   deterministic seed. FIXED left a device-correlated ~0.19 ms scheduler-guard residual on the host rig
   [M]; BOUNDED drove the timing attacker to chance. The residual reappears on-switch as recirc
   quantization, so BOUNDED is the operating policy.

**In scope:** request→ACK and request→response *timing* normalization, dual-case, fail-open, telemetry.
**Out of scope (separate primitives, never claimed here):** ACK **mode** (a passive switch cannot
synthesize/suppress the ACK split — mode_only stays ~0.667 [M]); response **size** (still leaks
~14.6 B/CROB [M]); packet count; full device anonymity.

---

## Part 2 — The P4 program (code-skeleton form, real TNA syntax)

Program name `dcrn`. One `Pipeline`, pipe 0, bump-in-the-wire dp8↔dp9. All hold logic in **ingress**
(the recirc loop re-enters ingress each pass); egress carries telemetry only.

### 2.1 Headers and types
```p4
#include <core.p4>
#include <tna.p4>

const bit<16> ETHERTYPE_IPV4  = 0x0800;
const bit<16> ETHERTYPE_DCRN  = 0x88B6;   // private recirc-bridge ethertype (distinct from a co-resident program 0x88B5)
const bit<8>  IP_PROTO_TCP     = 6;
const bit<16> DNP3_PORT        = 20000;
const bit<8>  DNP3_START_0      = 0x05;
const bit<8>  DNP3_START_1      = 0x64;

const PortId_t PORT_VISION = 9w8;    // master  (run_master.py)          [L testbed.md]
const PortId_t PORT_HULK   = 9w9;    // outstation / split_server.py     [L]
const PortId_t PORT_RECIRC = 9w68;   // pipe-0 internal recirc port       [L the co-resident bring-up script]

// tuning constants (promote to a 1-entry config table for runtime tuning if desired)
const bit<32> GUARD_TICKS = 32w4;      // ~0.26 ms at 65.5 us/tick; >= one recirc pass and >= host ~0.19 ms [M-derived]
const bit<16> MAX_PASS    = 16w4096;   // hard loop cap → fail-open release
const bit<32> HELD_MAX    = 32w256;    // recirc-occupancy watermark → new responses bypass

header ethernet_h { bit<48> dst_addr; bit<48> src_addr; bit<16> ether_type; }

// Internal recirc-only bridge. Pushed on hold-enter, popped on release. NEVER reaches Vision.
header dcrn_bridge_h {
    bit<16> original_ethertype;   // 0x0800, restored on release
    bit<16> flow_id;              // register index, carried so recirc passes need no re-hash
    bit<16> pass_count;           // recirc laps (max-pass guard)
    bit<8>  guard_apply;          // 1 = separate-case response (subtract GUARD); 0 = ACK/combined  (Class 3)
    bit<8>  _pad;
}
header ipv4_h {
    bit<4> version; bit<4> ihl; bit<8> diffserv; bit<16> total_len;
    bit<16> identification; bit<3> flags; bit<13> frag_offset;
    bit<8> ttl; bit<8> protocol; bit<16> hdr_checksum;
    bit<32> src_addr; bit<32> dst_addr;
}
header tcp_h {
    bit<16> src_port; bit<16> dst_port; bit<32> seq_no; bit<32> ack_no;
    bit<4> data_offset; bit<4> res; bit<8> flags; bit<16> window;
    bit<16> checksum; bit<16> urgent_ptr;
}
header dnp3_dl_h {   // first bytes of the DNP3 data-link header
    bit<8> start_0; bit<8> start_1; bit<8> length; bit<8> ctrl;
    bit<16> dst_addr; bit<16> src_addr; bit<16> crc;
}
header dnp3_tp_h  { bit<1> fin; bit<1> fir; bit<6> seq; }
header dnp3_app_h { bit<8> app_control; bit<8> func_code; bit<8> obj_group; bit<8> obj_variation; }

struct headers_t {
    ethernet_h ethernet; dcrn_bridge_h bridge; ipv4_h ipv4; tcp_h tcp;
    dnp3_dl_h dnp3_dl; dnp3_tp_h dnp3_tp; dnp3_app_h dnp3_app;
}
```
`ipv4_h`/`tcp_h`/`dnp3_*` are copied verbatim from `a reference DNP3 parser` [L]. The bridge header mirrors
a co-resident program's `a co-resident bridge header` role [L]: internal-only, added/removed inside the switch so the wire frame
toward Vision is byte-identical.

### 2.2 Ingress metadata struct
```p4
struct metadata_t {
    bit<8>  dir;              // 0=from Vision(dp8), 1=from Hulk(dp9), 2=from recirc(dp68)   (Class 3)
    bit<8>  is_dnp3; bit<8> is_request; bit<8> is_response; bit<8> is_pure_ack; bit<8> fc_ok;
    bit<16> payload_len;      // total_len - (ip+tcp overhead)  [a reference DNP3 parser idiom]
    bit<16> flow_id;          // Hash index (canonical bidirectional key)
    bit<32> now_tick;         // global_tstamp[47:16], 65.5 us tick
    bit<32> now_eff;          // now_tick, or now_tick - GUARD_TICKS for separate-case responses
    bit<32> di;               // selected class-independent delay (ticks)
    bit<32> deadline;         // now_tick + di
    bit<8>  released; bit<8> over_watermark; bit<8> guard_apply;
}
```
All flags `bit<8>` even for one meaningful bit — **Class 3** (byte-align next to 32-bit register
outputs), as another lab program's `r1_fired…r6_fired` and a reference register/SALU program's 1-bit flags are widened [L].

### 2.3 Parser (parse to TCP + DNP3 FC; payload stays residual)
```p4
parser DcrnIngressParser(packet_in pkt, out headers_t hdr, out metadata_t meta,
                         out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md); pkt.advance(PORT_METADATA_SIZE);
        meta = { 0,0,0,0,0,0, 0,0, 0,0,0,0, 0,0,0 };
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_DCRN : parse_bridge;    // arrived on recirc port — strip bridge, continue
            ETHERTYPE_IPV4 : parse_ipv4;
            default        : accept;          // ARP/other → transparent forward
        }
    }
    state parse_bridge { pkt.extract(hdr.bridge); transition parse_ipv4; }   // a co-resident program decap [L]
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.ihl) { 4w5 : parse_tcp; default : accept; }   // no-option IPv4 only [L]
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.dst_port, hdr.tcp.src_port, hdr.tcp.flags[1:1]) {
            (DNP3_PORT, _, 1w0) : skip_tcp_options;
            (_, DNP3_PORT, 1w0) : skip_tcp_options;
            default             : accept;      // pure ACK parsed to TCP; DNP3 layers stay invalid
        }
    }
    state skip_tcp_options {                   // constant-advance option skip — verbatim a reference DNP3 parser [L]
        transition select(hdr.tcp.data_offset) {
            5:parse_dnp3_dl; 6:opt4; 7:opt8; 8:opt12; 9:opt16; 10:opt20;
            11:opt24; 12:opt28; 13:opt32; 14:opt36; 15:opt40; default:accept;
        }
    }
    state opt4 {pkt.advance(32); transition parse_dnp3_dl;}   state opt8 {pkt.advance(64); transition parse_dnp3_dl;}
    state opt12{pkt.advance(96); transition parse_dnp3_dl;}   state opt16{pkt.advance(128);transition parse_dnp3_dl;}
    state opt20{pkt.advance(160);transition parse_dnp3_dl;}   state opt24{pkt.advance(192);transition parse_dnp3_dl;}
    state opt28{pkt.advance(224);transition parse_dnp3_dl;}   state opt32{pkt.advance(256);transition parse_dnp3_dl;}
    state opt36{pkt.advance(288);transition parse_dnp3_dl;}   state opt40{pkt.advance(320);transition parse_dnp3_dl;}
    state parse_dnp3_dl {
        pkt.extract(hdr.dnp3_dl);
        transition select(hdr.dnp3_dl.start_0, hdr.dnp3_dl.start_1) {
            (DNP3_START_0, DNP3_START_1) : parse_dnp3_tp;
            default                      : accept;
        }
    }
    state parse_dnp3_tp  { pkt.extract(hdr.dnp3_tp);  transition parse_dnp3_app; }
    state parse_dnp3_app { pkt.extract(hdr.dnp3_app); transition accept; }   // FC at fixed offset; body residual
}
```
A **pure ACK** (payload 0) reaches `parse_tcp` and stops — `dnp3_*` stay invalid, which is exactly how
we classify it later (`payload_len == 0`).

### 2.4 Ingress control — full logic flow
```p4
control DcrnIngress(inout headers_t hdr, inout metadata_t meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action drop() { ig_dprsr_md.drop_ctl = 1; }          // only for malformed L2; NEVER a DNP3 frame

    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_armed;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_held;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_released;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_deadline_miss;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_bypass;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_passthru;

    Hash<bit<16>>(HashAlgorithm_t.CRC16) flow_hash;        // ONE instance, ONE tuple shape (Class 7)  [L a reference register/SALU program]

    Register<bit<32>, bit<16>>(65536, 0) reg_deadline;     // absolute deadline tick per flow (0 = unarmed/past → release now)
    Register<bit<32>, bit<16>>(65536, 0) reg_req_tstamp;   // t0 tick (telemetry/wrap)
    Register<bit<8>,  bit<16>>(65536, 0) reg_ack_seen;     // separate-case: pure ACK observed
    Register<bit<32>, bit<1>>(1, 0)      reg_txn;          // global txn counter → BOUNDED index
    Register<bit<32>, bit<1>>(1, 0)      reg_held_count;   // global recirc-occupancy watermark

    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_deadline) arm_deadline = {
        void apply(inout bit<32> dl, out bit<32> rv) { dl = meta.deadline; rv = dl; }
    };
    RegisterAction<bit<32>, bit<16>, bit<8>>(reg_deadline) check_deadline = {
        void apply(inout bit<32> dl, out bit<8> released) {
            if (meta.now_eff >= dl) { released = 1; } else { released = 0; }   // the one compile-critical shape (Q1)
        }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_req_tstamp) store_t0 = {
        void apply(inout bit<32> t, out bit<32> rv) { t = meta.now_tick; rv = t; }
    };
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_ack_seen) set_ack_seen = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 1; rv = 1; }
    };
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_ack_seen) get_ack_seen = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_txn) next_txn = {
        void apply(inout bit<32> v, out bit<32> rv) { v = v + 1; rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<8>>(reg_held_count) held_check_inc = {
        void apply(inout bit<32> v, out bit<8> over) {
            if (v >= HELD_MAX) { over = 1; } else { v = v + 1; over = 0; }     // a reference register/SALU program inc+threshold idiom [L]
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_held_count) held_dec = {
        void apply(inout bit<32> v, out bit<32> rv) { if (v > 0) { v = v - 1; } rv = v; }
    };

    action set_overhead(bit<16> ov) { meta.payload_len = hdr.ipv4.total_len - ov; }   // PHV − const, single stage (Class 5)
    table tcp_overhead {                                   // verbatim from a reference DNP3 parser [L]
        key = { hdr.tcp.data_offset : exact; }
        actions = { set_overhead; }
        const entries = {
            (4w5):set_overhead(16w40); (4w6):set_overhead(16w44); (4w7):set_overhead(16w48);
            (4w8):set_overhead(16w52); (4w9):set_overhead(16w56); (4w10):set_overhead(16w60);
            (4w11):set_overhead(16w64);(4w12):set_overhead(16w68);(4w13):set_overhead(16w72);
            (4w14):set_overhead(16w76);(4w15):set_overhead(16w80);
        }
        default_action = set_overhead(16w40); size = 16;
    }
    action fc_allow() { meta.fc_ok = 1; }
    table fc_allowlist {                                   // controller installs READ (0x01) only initially
        key = { hdr.dnp3_app.func_code : exact; }
        actions = { fc_allow; NoAction; }
        default_action = NoAction();                       // miss → fc_ok 0 → bypass (fail-open)
        size = 32;
    }
    action set_deadline(bit<32> di) { meta.di = di; meta.deadline = meta.now_tick + di; }  // di = action data, single stage (Class 5)
    table bounded_target {                                 // controller pre-samples 256 Di (deterministic seed)
        key = { meta.di : exact; }                         // key = low-8 txn index staged into meta.di
        actions = { set_deadline; }
        default_action = set_deadline(32w0);               // policy-absent → deadline in past → release now (fail-open)
        size = 256;
    }

    apply {
        if (!hdr.ethernet.isValid()) { drop(); return; }
        meta.now_tick = ig_prsr_md.global_tstamp[47:16];   // [V tna.p4] — refresh-on-recirc is probe (a)
        if      (ig_intr_md.ingress_port == PORT_VISION) { meta.dir = 0; }
        else if (ig_intr_md.ingress_port == PORT_HULK)   { meta.dir = 1; }
        else if (ig_intr_md.ingress_port == PORT_RECIRC) { meta.dir = 2; }
        else { drop(); return; }

        // ===== A. RECIRC LOOP (frames already held) =====
        if (hdr.bridge.isValid()) {
            meta.flow_id     = hdr.bridge.flow_id;
            meta.guard_apply = hdr.bridge.guard_apply;
            meta.now_eff     = (hdr.bridge.guard_apply == 1) ? (meta.now_tick - GUARD_TICKS) : meta.now_tick;
            meta.released    = check_deadline.execute(meta.flow_id);
            hdr.bridge.pass_count = hdr.bridge.pass_count + 1;
            if (meta.released == 1 || hdr.bridge.pass_count >= MAX_PASS) {
                hdr.ethernet.ether_type = hdr.bridge.original_ethertype;  // restore, byte-identical
                hdr.bridge.setInvalid();
                held_dec.execute(0);
                ig_tm_md.ucast_egress_port = PORT_VISION;
                ctr_released.count(0);
            } else {
                ig_tm_md.ucast_egress_port = PORT_RECIRC;                 // keep looping (self-clock) [L a co-resident program]
            }
            return;
        }

        // ===== B. FIRST ARRIVAL (native frames) =====
        if (hdr.tcp.isValid() && (hdr.tcp.dst_port == DNP3_PORT || hdr.tcp.src_port == DNP3_PORT)) {
            meta.is_dnp3 = 1;
        }
        if (meta.is_dnp3 == 0) {                                          // transparent bump-in-the-wire
            ig_tm_md.ucast_egress_port = (meta.dir == 0) ? PORT_HULK : PORT_VISION;
            ctr_passthru.count(0); return;
        }
        tcp_overhead.apply();                                            // meta.payload_len
        bit<32> client_ip; bit<16> client_port; bit<32> server_ip;
        if (meta.dir == 0) { client_ip=hdr.ipv4.src_addr; client_port=hdr.tcp.src_port; server_ip=hdr.ipv4.dst_addr; }
        else               { client_ip=hdr.ipv4.dst_addr; client_port=hdr.tcp.dst_port; server_ip=hdr.ipv4.src_addr; }
        meta.flow_id = flow_hash.get({ client_ip, server_ip, client_port });   // ONE tuple shape (Class 7)

        // B1. REQUEST path (dp8, dst 20000, payload>0)
        if (meta.dir == 0 && hdr.tcp.dst_port == DNP3_PORT && meta.payload_len > 0 && hdr.dnp3_app.isValid()) {
            fc_allowlist.apply();
            if (meta.fc_ok == 1) {
                bit<32> txn = next_txn.execute(0);
                meta.di = (bit<32>)(txn[7:0]);                           // stage 8-bit index
                bounded_target.apply();                                  // meta.deadline = now_tick + Di
                arm_deadline.execute(meta.flow_id);
                store_t0.execute(meta.flow_id);
                ctr_armed.count(0);
            }
            ig_tm_md.ucast_egress_port = PORT_HULK;                      // forward request UNCHANGED
            return;
        }

        // B2. RESPONSE / pure-ACK path (dp9, src 20000)
        if (meta.dir == 1 && hdr.tcp.src_port == DNP3_PORT) {
            meta.over_watermark = held_check_inc.execute(0);
            if (meta.over_watermark == 1) {                              // recirc saturated → bypass (fail-open)
                ig_tm_md.ucast_egress_port = PORT_VISION; ctr_bypass.count(0); return;
            }
            if (meta.payload_len == 0) {                                 // PURE ACK (separate case)
                set_ack_seen.execute(meta.flow_id);
                meta.guard_apply = 0; meta.now_eff = meta.now_tick;      // ACK releases at T
            } else {                                                     // ACK-BEARING RESPONSE
                bit<8> seen = get_ack_seen.execute(meta.flow_id);
                meta.guard_apply = seen;                                 // 1 if a pure ACK preceded (separate)
                meta.now_eff = (seen == 1) ? (meta.now_tick - GUARD_TICKS) : meta.now_tick;
            }
            meta.released = check_deadline.execute(meta.flow_id);
            if (meta.released == 1) {                                    // at/after deadline (or unarmed=0) → release now
                held_dec.execute(0);
                ig_tm_md.ucast_egress_port = PORT_VISION;
                ctr_deadline_miss.count(0);
            } else {                                                     // ENTER HOLD: push bridge, recirc via dp68
                hdr.bridge.setValid();
                hdr.bridge.original_ethertype = hdr.ethernet.ether_type; // 0x0800
                hdr.bridge.flow_id = meta.flow_id; hdr.bridge.pass_count = 0;
                hdr.bridge.guard_apply = meta.guard_apply; hdr.bridge._pad = 0;
                hdr.ethernet.ether_type = ETHERTYPE_DCRN;                // 0x88B6 recirc-only
                ig_tm_md.ucast_egress_port = PORT_RECIRC;
                ctr_held.count(0);
            }
            return;
        }
        ig_tm_md.ucast_egress_port = (meta.dir == 0) ? PORT_HULK : PORT_VISION;   // other DNP3-ish → transparent
        ctr_passthru.count(0);
    }
}
```
**Fail-open guards** (all forward, never drop): RTO cap (controller guarantees every installed
`Di ≤ rto_cap_ticks` → zero data-plane cost); watermark (`held_check_inc` → bypass); max-pass
(`pass_count >= MAX_PASS` → force release); policy-absent / non-allowlist (`bounded_target` default
`set_deadline(0)` and `fc_allowlist` miss → deadline 0 → `now_eff >= 0` always true → immediate
release); unarmed response (`reg_deadline` seeded 0 → same). No path calls `drop()` on a DNP3 frame.

### 2.5 Deparser, egress, pipeline
```p4
control DcrnIngressDeparser(packet_out pkt, inout headers_t hdr, in metadata_t meta,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.bridge);      // emitted only while valid (recirc loop); popped before release → not on Vision wire
        pkt.emit(hdr.ipv4); pkt.emit(hdr.tcp);
        pkt.emit(hdr.dnp3_dl); pkt.emit(hdr.dnp3_tp); pkt.emit(hdr.dnp3_app);
        // NO Checksum() extern: we never modify any IP/TCP/DNP3 byte → nothing to recompute (Class 6 unreachable).
    }
}
```
Egress is pass-through carrying optional telemetry (per-flow pass-count histogram, release/miss
counters) — structurally the co-resident lab programs empty egress [L]; add reads here only if M1's resource
report shows ingress running tight. Pipeline assembly is the standard `Pipeline(...); Switch(pipe) main;` [L].

### 2.6 Constraint-class pin-down
| Element | bf-p4c class | Preemptive workaround | Grounding |
|---|---|---|---|
| `check_deadline`: `now_eff >= dl` | **1 + 2** | 32-bit **SALU predicate**, not a gateway (32-bit magnitude compare burns >44 bits) nor a range key (≤20-bit); `now_eff` sliced from `global_tstamp[47:16]` | `[I]` — the one compile-critical unknown |
| `set_deadline`: `now_tick + di` | **5** | `di` = **action data** (per-entry const) → single-stage add | `[L]` a reference DNP3 parser |
| `set_overhead`: `total_len − ov` | **5** | `ov` action data → single-stage subtract | `[L]` a reference DNP3 parser |
| all metadata flags `bit<8>` | **3** | widened even for one bit | `[L]` a reference register/SALU program / another lab program |
| `flow_hash` one tuple | **7** | canonicalize both directions to one tuple; one `Hash` | `[L]` a reference single-hash idiom |
| `reg_deadline` seeded 0, branch `>=` | **8** | constructor seed; never in-SALU `==0`; unarmed→immediate-release from `now>=0` | `[L]` a reference register/SALU program |
| bridge push/pop = byte-preservation | — | a co-resident program encap/decap; strip before release; no CRC extern | `[L]` a co-resident program |
| recirc via `ucast_egress_port=68` | — | pipe-0 internal recirc-hold | `[L]` a co-resident program |

Class-6 (silent ICE) unreachable — no end-around-carry checksum is computed (we recompute nothing).

---

## Part 3 — Registers + tables
| Name | Type | Width/index | Purpose | Seeded (Class 8)? |
|---|---|---|---|---|
| `reg_deadline` | `Register<bit<32>,bit<16>>` | 65536×32b, idx=flow_id | absolute `t0+Di` tick; **0 = unarmed/past → release now** | Yes (ctor 0; re-seed per trial) |
| `reg_req_tstamp` | `Register<bit<32>,bit<16>>` | 65536×32b | `t0` tick (telemetry/wrap) | Yes (0) |
| `reg_ack_seen` | `Register<bit<8>,bit<16>>` | 65536×8b | separate-case pure ACK observed | Yes (0) |
| `reg_txn` | `Register<bit<32>,bit<1>>` | 1×32b | txn counter → BOUNDED index `[7:0]` | Yes (0) |
| `reg_held_count` | `Register<bit<32>,bit<1>>` | 1×32b | recirc-occupancy watermark | Yes (0) |
| `tcp_overhead` | exact table | key=data_offset, 16 | payload_len overhead (const) | const entries |
| `fc_allowlist` | exact table | key=func_code, 32 | READ only initially; miss→bypass | **controller** |
| `bounded_target` | exact table | key=txn[7:0], 256 | `Di` action-data const (FIXED/BOUNDED) | **controller** |
| `flow_hash` | `Hash<bit<16>>` | 1 instance, 1 tuple | canonical bidirectional key | — |
| pass_count | bridge header field | 16b, recirc metadata | max-pass guard | — |

Every register is seeded at load by its P4 constructor initial value (a reference register/SALU program's proven pattern [L]);
the two policy tables are the only controller-installed match tables. RTO cap enforced purely at install.

---

## Part 4 — Recirculation self-clock mechanics
On hold-enter the frame gets an internal `dcrn_bridge_h` and `ucast_egress_port = 68`. dp68 is the
pipe-0 internal recirc port; a frame egressed there re-enters the **ingress** parser of the same pipe
[L `the co-resident bring-up script` enables `recirculation_enable=True` on dp68]. Byte-carried: IP/TCP/DNP3
untouched; only the L2 ethertype is temporarily 0x88B6 and the bridge rides ahead of IPv4 — both
removed on release. `hdr.bridge.pass_count` increments each lap (bridge field, not a register) and
drives the max-pass guard. Each lap runs `check_deadline` → when `now_eff >= reg_deadline[flow_id]` (or
max-pass), restore ethertype, invalidate bridge, egress to dp8 byte-identical.

**TM `max_rate` shaper paces the loop** (mirrors `the co-resident bring-up script` with the corrected table names):
```python
tgt0    = gc.Target(device_id=0, pipe_id=0)                 # TM tables are pipe-specific
q_shape = bi.table_get("tf1.tm.queue.sched_shaping")
q_cfg   = bi.table_get("tf1.tm.queue.sched_cfg")
PG_ID, PG_PORT_NR, QID_HOLD = 17, 0, 5                       # dp68's PG_ID/PG_PORT_NR from a co-resident program
pgq = PG_PORT_NR * 8 + QID_HOLD
HOLD_LOOP_PPS = 10000                                        # ~100 us/pass (a co-resident program caps at 100000 = ~10 us/pass)
q_shape.entry_mod(tgt0,
    [q_shape.make_key([gc.KeyTuple("pg_id", PG_ID), gc.KeyTuple("pg_queue", pgq)])],
    [q_shape.make_data([gc.DataTuple("unit", str_val="PPS"), gc.DataTuple("provisioning", str_val="UPPER"),
                        gc.DataTuple("max_rate", val=HOLD_LOOP_PPS), gc.DataTuple("max_burst_size", val=16384)])])
q_cfg.entry_mod(tgt0,
    [q_cfg.make_key([gc.KeyTuple("pg_id", PG_ID), gc.KeyTuple("pg_queue", pgq)])],
    [q_cfg.make_data([gc.DataTuple("scheduling_enable", bool_val=True), gc.DataTuple("max_rate_enable", bool_val=True)])])
```
(**Correction over the map:** the real tables are `tf1.tm.queue.sched_shaping` + `tf1.tm.queue.sched_cfg`,
keyed `pg_id`/`pg_queue`, not `tf1.tm.port.sched_shaping` [L].)

**Two open probes + fallbacks:**
- **(a) Does `ig_prsr_md.global_tstamp` refresh on recirc re-entry?** The only correctness-critical
  probe. If it refreshes → design works as written. **Fallback (a):** pass-count self-clock — replace
  the compare with `pass_count >= release_passes[flow]`, controller-computed as
  `Di_ticks · (tick_ns / measured_pass_ns)`, installed via an extra `bounded_target` action-data field;
  needs no refreshing clock. Second fallback: move the compare to egress against
  `eg_prsr_md.global_tstamp` and bridge the decision back (heavier; reserve).
- **(b) Does a sparse frame get paced by the burst-1 shaper?** **Under wall-clock release this is
  bandwidth-only, not correctness:** even if an idle-queue shaper releases the lone frame immediately
  (line-rate recirc ~0.3–1 µs/pass), the wall clock still holds it the correct duration; it merely burns
  ~4.8 Gbps for that one frame (<0.1% of the ~1.6 Tbps recirc budget) — "purely churn control,"
  a co-resident program's own words [L]. **Fallback (b)** (only if the pass-count clock is in use *and* pacing is
  non-uniform): a low-rate metronome recirc frame (a co-resident program's pktgen tick proves it feasible), or
  measured-latency margin.

---

## Part 5 — Control plane (bfrt_python)
Startup sequence (mirrors `the co-resident bring-up script` [L] + `bfrt_starter.py` [L]; run on the switch after
the gated `bf_switchd` start of the `dcrn` conf):
```python
import sys; SDE_PY = "/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"
sys.path.insert(0, SDE_PY + "/tofino"); sys.path.insert(0, SDE_PY)
import bfrt_grpc.client as gc

iface = gc.ClientInterface("localhost:50052", client_id=2, device_id=0, notifications=None)   # [L]
iface.bind_pipeline_config("dcrn")
bi   = iface.bfrt_info_get("dcrn")
tgt  = gc.Target(device_id=0, pipe_id=0xffff)
tgt0 = gc.Target(device_id=0, pipe_id=0)

# 1. host ports up: dp8 Vision, dp9 Hulk (exact $PORT fields from a co-resident program) [L]
port = bi.table_get("$PORT")
for dp in (8, 9):
    k = [port.make_key([gc.KeyTuple("$DEV_PORT", dp)])]
    d = [port.make_data([gc.DataTuple("$SPEED", str_val="BF_SPEED_25G"),
                         gc.DataTuple("$FEC", str_val="BF_FEC_TYP_RS"),
                         gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_DEFAULT"),
                         gc.DataTuple("$LOOPBACK_MODE", str_val="BF_LPBK_NONE"),
                         gc.DataTuple("$PORT_ENABLE", bool_val=True)])]
    try: port.entry_add(tgt, k, d)
    except Exception: port.entry_mod(tgt, k, d)

# 2. enable recirculation on dp68 (NO pktgen — DCRN never synthesizes packets) [L]
pc = bi.table_dict["tf1.pktgen.port_cfg"]
pc.entry_mod(tgt, [pc.make_key([gc.KeyTuple("dev_port", 68)])],
             [pc.make_data([gc.DataTuple("recirculation_enable", bool_val=True)])])

# 3. dp68 hold-loop shaper — see Part 4 (tf1.tm.queue.sched_shaping / sched_cfg, tgt0)

# 4. seed registers to 0 (constructor covers cold init; re-seed per trial via $REGISTER_INDEX loop).
#    Register-table data-field name is the one 9.13.2 idiom to confirm at M0 [I].

# 5. FC allowlist — READ (0x01) only initially; everything else bypasses (fail-open)
fca = bi.table_get("pipe.DcrnIngress.fc_allowlist")
fca.entry_add(tgt, [fca.make_key([gc.KeyTuple("hdr.dnp3_app.func_code", 0x01)])],
                   [fca.make_data([], "DcrnIngress.fc_allow")])

# 6. BOUNDED distribution — 256 Di (ticks), deterministic seed, all <= rto_cap_ticks (RTO cap enforced HERE)
import numpy as np
TICK_NS = 65536; rto_cap_ticks = int(150e6 / TICK_NS)                 # 150 ms cap → ~2289 ticks
Dlow_t, Dhigh_t = int(32e6/TICK_NS), int(42e6/TICK_NS)               # 32–42 ms → 488..641 ticks
rng = np.random.default_rng(20260718)                                # deterministic, NOT reset per device/session
bt  = bi.table_get("pipe.DcrnIngress.bounded_target")
for i in range(256):
    di = int(rng.integers(Dlow_t, Dhigh_t + 1))                      # P2_BOUNDED; P1_FIXED = single const
    assert di <= rto_cap_ticks                                       # RTO cap guaranteed at install → zero dataplane cost
    bt.entry_add(tgt, [bt.make_key([gc.KeyTuple("meta.di", i)])],
                      [bt.make_data([gc.DataTuple("di", di)], "DcrnIngress.set_deadline")])
```
Policy switch (no recompile): **P0_NATIVE** = empty `fc_allowlist`; **P1_FIXED** = 256 identical `Di`;
**P2_BOUNDED** = the sampled distribution. The register-table data-field name is the one bfrt idiom to
confirm against 9.13.2 at M0 [I].

---

## Part 6 — BOUNDED target calibration procedure
**Inputs (host-side, from the authoritative native captures — mostly already from Phase-04B).** Per
transaction class: count, min, median, p90/p95/p99/p99.9, max of request→response readiness; first vs
non-first; scheduler precision from a calibration run; and the **effective Vision-side TCP RTO**
(re-measured on kernel-6.8 Vision at M5 preflight — ~211 ms [M] is from the prior host, must be re-confirmed).
**Target region:** `Dlow ≥ p99.9 readiness + scheduler guard`, `Dhigh < effective_RTO − safety guard`.
From the rig: native median ~16.8 ms [M] → band **~32–42 ms**, RTO-safe cap **~150 ms** (well under
~211 ms). Tails above `Dlow` retained + counted as deadline misses, never discarded. If no safe sub-RTO
target exists for a class → mark unsupported, bypass (never invent a target).
**Tick conversion:** `tick = 65.536 µs`; `Di_ticks = round(Di_ms·1000/65.536)` (32 ms→488, 42 ms→641,
150 ms→2289); fits `bit<32>` with ~78 h span before wrap.
**Deterministic seed:** one `numpy.random.default_rng(SEED)` draws 256 `Di`, converted to ticks,
installed into `bounded_target[0..255]`, indexed at runtime by `reg_txn[7:0]`. **Never reset** per
device/capture/session/rep → device-independent + reproducible off-chip; the on-chip `Random<>` extern
is avoided (can't reproduce the host seed the leakage-safety argument depends on).
**Guard-delta (dual-case FIFO):** `GUARD_TICKS = max(one recirc pass, host guard ~0.19 ms)`; one pass
~100 µs ≈ 1.5 ticks, host guard ~2.9 ticks → take **4 ticks (~0.26 ms)**. Common constant across all
separate transactions, device-independent, reported as a residual.

---

## Part 7 — Build & deploy runbook (GATED)
Every `sudo`/`bf_switchd` line is **gated — run only with explicit approval** via the `!` prefix.
```bash
# 0. Preflight (M0): switch reachable; connectivity map current; ~/.lab_env sourced
ssh decps@10.10.54.81                                   # key-based [L testbed.md]
# 1. Compile on the SWITCH SDE 9.13.2 (never the 9.13.1 laptop copy) [L build-deploy.md]
source /home/decps/Downloads/bf-sde-9.13.2/bf-sde-env.sh
cmake $SDE/p4studio -DCMAKE_INSTALL_PREFIX=$SDE_INSTALL -DCMAKE_MODULE_PATH=$SDE/cmake \
      -DP4_NAME=dcrn -DP4_PATH=/home/decps/dcrn/dcrn.p4
make -j4 dcrn && make install
# On any opaque/empty error → constraints.md (Class 6 silent-ICE first), NOT the SDE manual.
# 2. [GATED] take the chip from a co-resident program
sudo systemctl stop the co-resident auto-load service; sudo systemctl mask the co-resident auto-load service; pkill -f the co-resident launch script
# 3. [GATED] load DCRN — bf_switchd cold restart (needs Philip's approval); stdin open, under tmux
export SDE=/home/decps/Downloads/bf-sde-9.13.2; export SDE_INSTALL=$SDE/install
export LD_LIBRARY_PATH=$SDE_INSTALL/lib:$LD_LIBRARY_PATH
tail -f /dev/null | "$SDE_INSTALL/bin/bf_switchd" --install-dir "$SDE_INSTALL" \
    --conf-file /home/decps/dcrn/dcrn.conf --init-mode=cold --status-port 7777
# 4. enable ports 8+9, recirc dp68, shaper, seed registers, install fc_allowlist + bounded_target,
#    THEN start the controller (after register init, else transient coarse_time floods)
python3.8 /home/decps/dcrn/dcrn_setup.py
# 5. [GATED] hand the chip back when done
sudo systemctl unmask the co-resident auto-load service && sudo systemctl start the co-resident auto-load service
```
Symptom that step 2 was skipped: `Failed to find BfRtInfo for program dcrn` + `coarse_time write failed`
floods. The controller is freely restartable — bounce it, never `bf_switchd`, when iterating [L].

---

## Part 8 — Milestone plan (M0→M5)
| Milestone | Code deliverable | Acceptance test |
|---|---|---|
| **M0 — Preflight + ports/self-clock** | `dcrn.conf`; controller skeleton enabling dp8/dp9, recirc on dp68, the `tf1.tm.queue.sched_shaping`/`sched_cfg` shaper; confirm the 9.13.2 register-table data-field name | dp8/dp9 `UP / BF_SPEED_25G`; dp68 recirc enabled; shaper installs w/o error |
| **M1 — Compile-only classify + arm** | Full parser; ingress classify + `flow_id` + arm `reg_deadline`/`reg_req_tstamp` on a dp8 request, **forward everything unchanged (no hold)**; controller installs tables, seeds regs | `bf-p4c` **compiles clean on switch SDE** + `make install`; resource report shows the **32-bit `check_deadline` fits an SALU predicate**, ingress ≤ ~7 stages (upgrades [I]→fact); dp8↔dp9 forwarding byte-identical. **Resolves Q1.** |
| **M2 — Recirc-hold, single frame (combined) + probes** | Recirc loop, bridge push/pop, deadline compare, pass-count; combined response only | One combined txn: Vision capture req→response **flattens to target** (~16.8→~32–42 ms); **byte-identical (SHA-256)**, 0 retrans/reset. **Probe (a)** clock-refresh (else pass-count fallback). **Probe (b)** dp68 pass counts (bandwidth-only). |
| **M3 — Dual-case + BOUNDED** | Pure-ACK path, `reg_ack_seen`, guard-delta bias, `now_eff`; wire `reg_txn`→`bounded_target` | SEL-751 separate: ACK + response both move to target, **ACK egresses first** (FIFO, 0 dup-ACK/reorder), gap → ~one pass. BOUNDED reproduces from the seed |
| **M4 — Fail-open guards** | Watermark, max-pass, policy-absent/non-allowlist bypass; RTO cap at install | Fault-inject each guard → **forwarded, never dropped, never held past RTO cap**; kill controller → transparent |
| **M5 — Two-host rig campaign** | Full harness across P0_NATIVE/P1_FIXED/P2_BOUNDED × 3 profiles | (1) timing flattens, distributions overlap across profiles; (2) timing-only balanced acc → **chance 0.333** under BOUNDED (match host 0.289 [M]); (3) byte-identical, 0 retrans/reset/dup/reorder; (4) fail-open forwards-never-drops; (5) residuals confirmed (size ~14.6 B/CROB, ACK mode unchanged). Re-measure Vision RTO (kernel 6.8). **Resolves Q6.** |

---

## Part 9 — Test / validation plan
**Rig run (reuses the DCRN harness).** `run_master.py` on Vision (10.10.54.19, dp8) → outstation
replay (`split_server.py`/`run_outstation.py`) on Hulk (10.10.54.158, dp9) **through the switch**;
capture at **`enp59s0f0np0` on Vision** [L testbed.md]. Paired conditions on the same source
transactions/order/seeds/bytes/hosts/sockets/capture-point: **A NATIVE / B (old app-scheduler baseline)
/ C DCRN_FIXED / D DCRN_COMMON_BOUNDED**, across SEL-751 (separate), AB1400 + ION7550 (combined). No
combining with splitting, padding, or Phase-05 coalescing.
**Metrics.** Timing flattening per profile (request→ACK-event, request→response, separate ACK→response
gap, scheduler target error, release distribution, tails, deadline-miss/bypass rate; n/min/median/mean/
std/p90-p99/max + CIs, Wasserstein, KS) — success = req→response + req→ACK-event distributions overlap
across all three profiles, separate gap collapses to the fixed guard/serialization residual.
Byte-identity (received==source SHA-256, IP-and-above, 100% for completed). Transport health (0 retrans/
reset/dup-ACK/reorder attributable to DCRN; no ACK-after-response; separate pre-connection SYN/RST from
session resets). Fail-open (fault-inject → forwards, never drops/overshoots; detach → transparent).
Attacker eval (leakage-safe grouped splits by run/session/source-txn; families mode_only, ack_event_timing,
response_timing, timing_all, size, all; balanced accuracy w/ repeated grouped-CV mean/std/bootstrap 95%
CI, exact seeds, uniform baseline 0.333, majority baseline) — **success = pure-timing balanced acc →
chance 0.333 under BOUNDED** matching software-rig 0.289 [M]; mode_only ~0.667 and size unchanged are
expected residuals, NOT failures — never claim full anonymity or ACK-mode/size removal by DCRN.

---

## Part 10 — Open risks / what only the first compile or a probe resolves
| # | Open item | Resolved by | Fallback |
|---|---|---|---|
| Q1 | **Stage/SALU/PHV fit** — ingress ≤ ~7 stages; the 32-bit `check_deadline` compare vs a **runtime PHV operand** fits a single SALU predicate (lab SALUs only compare vs constants — the one unproven shape). All counts [I]. | **M1 compile + resource report** | telemetry fully to egress; two-RegisterAction constant-biased form; coarsen tick + range table (Class 2) last |
| Q2 | **Recirc-refreshed clock** — does `ig_prsr_md.global_tstamp` re-take on recirc re-entry? | **M2 single-frame probe** | pass-count self-clock (`pass_count >= release_passes`); or egress compare bridged back |
| Q3 | **Sparse-frame pacing** — burst-1 `max_rate` spacing a lone frame | **M2 pass-count read** | **bandwidth-only under wall-clock** — correctness unaffected; metronome frame or latency margin |
| Q4 | **True per-pass latency + recirc bandwidth** | **M2 measurement** | affects headroom only (DNP3 <0.1% budget), not correctness |
| Q5 | **a co-resident program coexistence** — clean stop/mask, ports reset | **M0/M5 on switch** | documented gated restart (Part 7); controller re-seed clears floods |
| Q6 | **Vision RTO re-measurement** (kernel 6.8; ~150 ms cap rests on ~211 ms [M] prior host) | **M5 preflight** | lower installed `Di` cap; mark no-safe-target classes unsupported/bypass |
| Q7 | **Register-table bfrt data-field name** on 9.13.2 | **M0 read on switch** | constructor cold-seeds; controller re-seed is per-trial convenience |

**Two invariants across every milestone, never traded for fit:** byte-preservation (recirc frame
stripped of bridge before dp8 egress; IP-and-above bit-identical; no CRC/field edit; no `Checksum()` on
any path) and fail-open (every guard forwards, never drops, never overshoots the RTO cap; controller/
program detach → transparent). A `bf-p4c` compile on 9.13.2 is the only proof the Part-2 stage/SALU/PHV
sketch fits; until M1 runs, those counts are honest inference.

### Files a P4 author starts from
This spec · `on_switch_implementation_map.md` (note the TM-table correction: `tf1.tm.queue.sched_shaping`
/`sched_cfg`, not `tf1.tm.port.*`) · `corrective.md` (DCRN spec) · `a co-resident program's P4 source` +
`the co-resident bring-up script` (recirc-hold loop, bridge encap/decap, TM/recirc bfrt patterns) ·
`a reference DNP3-parsing program` (DNP3 parse, `tcp_data_offset_overhead`, per-tuple Hash, single-stage
action-data arithmetic) · `a reference register/SALU program` (runtime-indexed Register, two-RegisterAction-per-
register, constructor seed, in-SALU inc+threshold) · `tools/bfrt_starter.py` (controller boilerplate) ·
`~/.claude/skills/tofino-p4/references/{constraints,build-deploy,testbed}.md`.

<!-- Deliverable authored by Agent F (P4/Tofino) for the split/pad/timing combined-policy study (2026-07-13), grounded in GROUNDING.md + measured_evidence.md, building on the prior ack_timing_normalization package, and integrated by the synthesizing lead. Research/design only — no source code changed. Citations merged into paper_matrix.csv (new works) + bibliography.bib. Reviewed in the Agent-J skeptical pass; surviving caveats in research_gaps_and_novelty.md. -->

<!-- Agent F (P4/Tofino data-plane) deliverable for the split_pad_timing_policy study, 2026-07-13.
Design/literature only — NO harness or P4 source was written, compiled, or run. This EXTENDS
research/ack_timing_normalization/hardware_design.md + agent_E_hardware.md (the platform×mechanism
feasibility half) into a concrete STAGED Tofino-1 (TNA) pipeline. Grounded in GROUNDING.md +
measured_evidence.md. Evidence labels per GROUNDING §17: [M] measured-rig · [S] standard ·
[V] vendor-doc · [P] paper-reported · [I] inference · [H] hypothesis. -->

# Agent F — A Staged Tofino 1 (TNA) Design for DNP3 Split / Pace / Timing Obfuscation

_This is the P4 half of the study. It does not re-derive Agent E's platform comparison; it takes
Agent E's finding — that pacing/IPG are native on Tofino, absolute first-packet delay is not, and
the recirculation workaround is affordable for DNP3 — and turns it into a concrete pipeline with
metadata, tables, registers, counters, queue assignments, a control plane, a quantified resource/
latency/recirc budget, failure behavior, and a Hulk/Vision test plan. Two build points are given:
a **minimal ASIC build (Stage 1 + Stage 2)** that is in-phase and buildable today, and a
**future-advanced build (Stage 3)** that is an UNBUILT recirculation-hold design whose costs are
inference. Stage 4 (protocol-modifying) is placed off-ASIC by construction._

---

## 0. The one-paragraph answer, and the caveat that dominates everything

On Tofino 1 the switch can, in-phase and byte-preserving, (1) **classify** DNP3 direction / ACK-
bearing responses / READ-vs-SELECT/OPERATE by shallow parse, (2) **measure** per-flow timing, size,
gap, and packet/byte counts at line rate with ns-precision timestamps, and (3) **pace** already-
created split chunks through a shaped egress queue so their inter-chunk gaps are normalized. What it
**cannot** do natively is impose an **absolute first-response delay** — the mechanism that actually
erases the request→response processing-time fingerprint — and it cannot **create** the split or
**pad** without leaving the byte-preserving phase. Absolute delay is reachable only through an
unbuilt recirculation-hold loop, which is affordable here purely because DNP3 is single-digit kbps
and small-frame. **The caveat that dominates the whole design:** the strongest measured fingerprint,
CROB count, leaks on the **size** channel (14.6 B/CROB, R²=0.9999 [M — n=1 per N-level, one device;
a 10-point line, not a replicated law]) even more cleanly than on timing (0.179–0.214 ms/CROB [M, same
n=1/N caveat]). Nothing Tofino can do in-phase touches size — split preserves
total bytes [M] and no safe DNP3 padding exists [M]. So **even a perfect Tofino timing hold does not
hide CROB count.** The Tofino contribution is necessary-but-not-sufficient: it closes the timing
axis and reshapes the segmentation axis; the residual size axis is a Stage-4, off-ASIC, protocol-
modifying problem.

_Plain language: the switch is excellent at watching the clock and at smoothing out the spacing
between packets it is handed, but it cannot secretly hold the very first reply without an unusual
loop, and it cannot make a small reply look like a big one. And the thing that gives the device away
most — how many control points were operated — shows up in the reply's size, which the switch cannot
change without breaking the rules we set for this phase._

---

## 1. Deployment model and what the switch actually sees

The Tofino is a **bump-in-the-wire** between the DNP3 master and outstation. On the lab rig the two
hosts and ports are fixed [V, from testbed map + project memory]:

| Role in obfuscation | Host | dev_port | data IP | Notes |
|---|---|---|---|---|
| Master (DNP3 client) | Vision | **8** | 10.0.1.10 | issues READ / SELECT / OPERATE |
| Outstation (server) / split server | Hulk | **9** | 10.0.2.10 | emits responses (or `split_server.py` in its place) |
| Recirc / loopback source (pipe 0) | — | **68** | — | on-chip pktgen/recirc port, not front-panel |

DNP3 rides TCP port **20000** [S]. The two directions are trivially separable at L3/L4:

- **Request** (master→outstation): ingress_port 8, TCP dst==20000.
- **Response** (outstation→master): ingress_port 9, TCP src==20000; per measured evidence the DNP3
  response is **piggybacked on the ACK, 9/9** [M], so an "ACK-bearing response" is a segment with
  src port 20000, ACK set, and TCP payload length > 0.

Nothing in the payload has to be modified for Stages 1–3; the byte-preservation invariant
(`join(chunks) == original`) is upheld because the switch only reads, counts, times, queues, and
(Stage 3) holds whole frames — it never rewrites DNP3 or TCP bytes.

_Plain language: the switch sits in the middle of the master–outstation link. Just from the port a
packet came in on and its TCP port number, the switch already knows whether it is a request or a
reply and whether the reply carries data — without opening the DNP3 message at all._

---

## 2. Shallow parse — what is parseable at line rate, and its cost

For **direction and ACK-bearing detection** the switch needs only Ethernet + IPv4 + TCP — all
fixed-offset, zero risk [V].

For **READ vs SELECT/OPERATE** it needs the DNP3 application **function code (FC)**. DNP3 framing
inside the TCP payload is fixed-offset once the (variable) TCP options are skipped [S]:

```
TCP payload byte:  0    1    2     3      4-5   6-7   8-9    10         11         12
DNP3 field:       0x05 0x64  LEN  CTRL   DEST  SRC   CRC   TRANSPORT  APP_CTRL  FUNCTION_CODE
```

So `FUNCTION_CODE` sits at a **fixed offset 12** of the TCP payload. The only variable part upstream
is the TCP options length, handled by one runtime-valued `pkt.advance((tcp.dataOffset - 5) << 5)` in
the parser — the same idiom used for options skipping [V/I]. The measured captures carry
`NOP-NOP-Timestamp` options [M], so this advance is exercised in practice.

FC values we key on [S]: `0x01` READ, `0x03` SELECT, `0x04` OPERATE, `0x05` DIRECT_OPERATE,
`0x81` RESPONSE, `0x82` UNSOLICITED_RESPONSE.

**Parseability verdict [I]:** direction + ACK-bearing = free (L3/L4). FC extraction = feasible at
line rate at the cost of a handful of parser states, one runtime `advance`, and ~13 bytes of DNP3
header lifted into PHV. Objects are **not** parsed (shallow only) — object counts / values are never
needed and parsing them would be deep and PHV-hungry. A response's FC is only `0x81/0x82`; to learn
whether that response *answered* a READ or a SELECT/OPERATE, the switch correlates it to the last
request FC on the same flow (a per-flow register, §4), because DNP3 responses do not restate the
request type.

_Plain language: the switch can cheaply read the one DNP3 byte that says "this is a read / select /
operate," but only for requests. For a reply it remembers what the matching request was. It never
digs into the actual data objects — that would be slow and is not needed._

---

## 3. Stage architecture at a glance

```
                 INGRESS pipeline (≤12 MAU stages)                    TM            EGRESS
  ┌───────────────────────────────────────────────────────┐   ┌────────────┐   ┌──────────┐
  │ parse  → S1: classify dir/ack/fc  → txn_class          │   │ UC0 default│   │ (Stage 3 │
  │ (shallow)  per-flow tstamp/gap/req regs  counters mirror│──▶│ UC1 shaped │──▶│  deadline│──▶ port 8
  │        → S2: pick qid (pace)                            │   │  (paced)   │   │  compare │
  │        → S3*: compute deadline, do_hold?  (future)      │   │ + recirc   │   │  emit /  │
  └───────────────────────────────────────────────────────┘   │  loopback  │   │  recirc) │
        ▲ recirc frames re-enter here ────────────────────────┘◀──port 68◀──────┘  (Stage 3)
  S1+S2 = MINIMAL ASIC BUILD (in-phase, buildable today)
  S3*   = FUTURE-ADVANCED BUILD (unbuilt recirc-hold; costs are [I])
  S4    = OFF-ASIC (padding / payload reconstruction / ACK decoupling) — DPU/FPGA, out of phase
```

- **Stage 1 — Classify & telemetry** (ingress): every deliverable's evidence source.
- **Stage 2 — Split-chunk pacing** (ingress qid assignment + TM shaper): normalizes inter-chunk gaps
  of chunks the switch did **not** create.
- **Stage 3 — First-response absolute timing** (ingress deadline compute + recirc loop + egress
  compare): the unbuilt hold.
- **Stage 4 — Protocol-modifying** (padding, payload reconstruction, ACK/seq decoupling): off-ASIC.

_Plain language: the design is layered. The first two layers are safe and build today; they watch and
smooth traffic. The third layer, which actually delays the first reply, needs a special loop and is
only sketched. The fourth layer — making replies bigger or faking TCP — is not something this chip
should do at all._

---

## 4. Stage 1 — Classification & telemetry (the MINIMAL build, part 1)

### 4.1 Metadata (kept small; flags widened to `bit<8>` per bf-p4c Class 3)

```p4
struct ig_md_t {
    bit<8>  is_dnp3;         // 1 if TCP port 20000 flow
    bit<8>  dir;             // 0 = request (master->outstation), 1 = response
    bit<8>  is_ack_bearing;  // 1 if response + ACK + payload>0
    bit<8>  dnp3_fc;         // application function code (requests); 0x81/0x82 for responses
    bit<8>  txn_class;       // 0 monitor,1 event,2 control,3 critical,4 unknown,5 unsupported
    bit<16> flow_id;         // canonical bidirectional flow hash index
    bit<16> tcp_payload_len; // ipv4.total_len - ihl*4 - dataOffset*4
    bit<32> now_tick;        // global_tstamp[47:16]  -> 65.5us tick, 32-bit, ~78h span
    bit<32> req_tick;        // request time recalled from reg_req_tstamp
    bit<32> ipg_tick;        // now_tick - last_tick  (inter-packet gap, this flow)
    bit<8>  do_hold;         // Stage 3: 1 = needs absolute-delay hold
    bit<32> deadline_tick;   // Stage 3: req_tick + target_delay_tick
}
```

Every one-bit signal is a `bit<8>` on purpose — sub-byte flags next to 32-bit register outputs
trigger `invalid SuperCluster` (Class 3) [V, lab constraint doc]. The timestamp is sliced to
`global_tstamp[47:16]`: a **32-bit tick at 65.5 µs resolution spanning ~78 h**, which keeps every
later magnitude compare inside a 32-bit SALU word (§6) while staying far finer than the ms-scale
holds we need.

### 4.2 Canonical bidirectional flow key

Requests and responses have swapped src/dst, but both must index the **same** per-flow slot. Since
exactly one side is always port 20000, canonicalize on {master_ip, outstation_ip, master_ephemeral_
port} and feed a single `Hash` instance (one tuple shape → one `Hash`, avoiding Class 7) [I]:

```p4
Hash<bit<16>>(HashAlgorithm_t.CRC16) flow_hash;   // one instance, one tuple shape
// action canon_key(): if tcp.src_port==20000 { ephem=tcp.dst_port } else { ephem=tcp.src_port }
// flow_id = flow_hash.get({ ip_lo, ip_hi, ephem });   // ip_lo/ip_hi = sorted pair
```

### 4.3 Tables and registers

| Object | Type | Key | Purpose | ALU/stage cost |
|---|---|---|---|---|
| `tbl_classify` | exact | `{ingress_port, l4_dst==20000, l4_src==20000}` | set `is_dnp3`, `dir` | tiny, 1 stage |
| `tbl_txn_class` | exact | `dnp3_fc` | FC → `txn_class` (**operator allowlist**) | tiny, 1 stage |
| `reg_last_tstamp` | Register`<bit<32>,bit<16>>` | `flow_id` | RegisterAction: `ipg = now - v; v = now` | 1 SALU |
| `reg_req_tstamp` | Register`<bit<32>,bit<16>>` | `flow_id` | request: write `now`; response: read → `req_tick` | 1 SALU |
| `reg_req_fc` | Register`<bit<8>,bit<16>>` | `flow_id` | remember last request FC for the response | 1 SALU |
| `ctr_class` | Counter`<bit<32>,bit<16>>` PKTS_AND_BYTES | `flow_id` or `txn_class` | per-class packet/byte telemetry | statistics ALU (cheap) |

`tbl_txn_class` is where the **safety allowlist** lives (GROUNDING: DNP3 fields reveal operation
*type* but never physical *criticality*, so criticality must be operator-supplied) [M/S]. Counters use
**statistics ALUs**, not the general SALUs, so they stay cheap even under stage pressure [V, memory].
Registers replicate per pipe; a flow lives in one pipe, so the controller reads and takes the max
across pipes [I, memory].

### 4.4 Mirror / sample for offline analysis

Set an ingress mirror session on a sampled subset (e.g. all ACK-bearing responses, or 1-in-N via a
`Random<bit<8>>` predicate) to a collector/CPU port. The mirror engine copies whole frames off-path;
the forward path is untouched, so this is byte-preserving and adds no MAU stage beyond a session-id
assignment [V/I]. This feeds the attacker-ladder evaluation (A1–A8) with real on-path samples rather
than host pcaps.

### 4.5 What Stage 1 produces per transaction (mapped to the study's three axes)

- **Axis 1 (size/shape):** `tcp_payload_len`, `ctr_class` bytes, packet counts, and — because chunks
  arrive as separate frames — link-frame / segment counts by counting frames per flow. Directly
  observes the CROB-count **size** leak (14.6 B/CROB [M]) and the READ point-count leak (5.7 B/pt
  [M]).
- **Axis 2 (timing):** `ipg_tick` (inter-packet gap), and req→response = `now_tick − req_tick` on the
  response — the on-chip measurement of the crown-jewel processing-time leak (1.01 ms mean, linear in
  CROB count, R²>0.99 [M]).
- **Axis 3 (semantics/safety):** `txn_class` via the FC allowlist.

_Plain language: Stage 1 is the switch's instrument panel. For every DNP3 exchange it records how big
the reply was, how long the outstation took to answer, the gaps between packets, and what kind of
operation it was — all in hardware, at line rate, without changing a byte. It can also copy a sample
of traffic to a side port for deeper offline study._

---

## 5. Stage 2 — Split-chunk pacing (the MINIMAL build, part 2)

### 5.1 The switch paces chunks; it does not create them

Creating the CRC-boundary split (one large response → many small segments) requires emitting new TCP
segments with **recomputed seq/len/checksums** — that is TCP segmentation / payload reconstruction,
which the phase rule forbids and which Tofino cannot do without becoming a proxy [I]. So **the split
is created upstream** (the software `split_server.py` today; a DPU in future). Tofino's in-phase job
is to **pace the chunks it is handed**: mark response-direction chunk frames to a shaped egress queue
so their spacing is regularized, preserving order.

### 5.2 Queue assignment and the shaper

```p4
// in ingress, after classify:
// if dir==RESPONSE (and is_dnp3):  ig_intr_md_for_tm.qid = UC1;   // shaped
// else:                            ig_intr_md_for_tm.qid = UC0;   // default, unshaped
```

- **UC0** — default/best-effort: requests, non-DNP3, handshakes.
- **UC1** — shaped: response chunks. The control plane configures UC1's shaper on the master-facing
  port (dev_port 8) to a rate that yields the target inter-chunk gap.

Tofino 1 commonly exposes **8 unicast queues/port (UC0–UC7)**; the TM is "configurable but not
programmable," shaped in **bps or pps** [V]. One flow → **one** queue (never spread a response's
chunks across queues, which would reorder them) [I]. Ordering within a single FIFO shaped queue is
preserved by construction.

### 5.3 Confirming the brief: TM shaping bounds RATE, not first-packet latency

**Confirmed [I], and it is a load-bearing seam of the whole design.** A max-rate shaper is a leaky/
token-bucket regulator: it delays a frame only when enough backlog is already queued that draining at
the shaped rate pushes this frame's turn into the future. Therefore:

- Chunks **2..N** of a burst *are* paced — each waits behind the previous one at the shaped rate, so
  their inter-chunk gaps are normalized to `frame_bytes / rate`. This is genuine **IPG normalization**
  (Agent E mechanism 2), and it pairs exactly with the existing CRC-split primitive (the gaps are
  defined on frames splitting already produced).
- Chunk **1** (or any lone response frame arriving at an idle, token-replenished queue — which it
  always is at ~1 s poll spacing) leaves **essentially immediately**. Shaping does **not** set the
  absolute wall-clock time the first frame departs.

So Stage 2 normalizes the *segmentation/gap* observables but leaves the *req→first-response* delay —
the crown-jewel timing leak — untouched. That is precisely why absolute first-frame delay is a
separate, harder Stage 3, and why the two must not be conflated.

**Quantization note [V, memory]:** in PACKETS mode the requested CIR is stored mantissa/exponent, so
the achieved rate ≠ requested (e.g. requested 1000 pps quantizes to 945; CIR=1 quantizes to 0 = total
block). The controller must **read back** `$METER_SPEC_CIR_*` and report the quantized value; the
same applies to queue shapers. Do not assume the requested gap is the achieved gap.

### 5.4 No controller fast-path dependence

The pace decision is a static table (`dir/txn_class → qid`) and a pre-configured shaper. The
controller sets policy at config time and is never in the per-packet path. If the controller dies,
Stage 2 keeps pacing with the last-installed policy [I].

_Plain language: the switch cannot cut a reply into pieces itself — that would mean rewriting TCP,
which we forbid. What it does is take the pieces the upstream server already made and feed them through
a "metering" queue so the gaps between them are even. But the very first piece still shoots out
immediately — a rate limiter smooths spacing, it does not hold the first packet back. Holding the
first packet is a different, harder job (Stage 3)._

---

## 6. Stage 3 — First-response absolute timing (the FUTURE-ADVANCED build; UNBUILT, costs are [I])

This is the mechanism that erases the timing fingerprint, and it is the part Agent E flagged as
"absent as a primitive on Tofino 1, reachable only via recirculation." Below is the concrete design
plus the quantities the brief asked for. **It is a design, not a built artifact — the phase rule
forbids writing/loading P4 now, so every cost here is inference.**

### 6.1 The recirculation-hold loop

```
Request passes (dir=0):     reg_req_tstamp[flow] = now_tick             (stamp arrival)
Response 1st frame (dir=1): req_tick = reg_req_tstamp[flow]
                            deadline_tick = req_tick + target_delay_tick(txn_class)
                            if (now_tick >= deadline_tick) -> forward now      (already slow enough)
                            else -> mark do_hold, carry deadline_tick, send to recirc port 68
Each recirc pass:           if (now_tick >= deadline_tick) -> emit to egress port 8
                            else -> recirculate again
```

`target_delay_tick` is a per-class constant the controller installs (the "timing bucket"); a
class-independent target is the honest goal (class-dependent targets leak class). The compare
`now_tick >= deadline_tick` is done inside a SALU RegisterAction so it is a stateful predicate, not a
gateway (§6.3).

### 6.2 Timestamp width, resolution, and wraparound — quantified

- **Width / span [V+I]:** `global_tstamp` and `ingress_mac_tstamp` are **48-bit ns** [V]. Full-width
  span = 2⁴⁸ ns ≈ **78.2 h** before wrap. We instead carry `now_tick = global_tstamp[47:16]`: a
  **32-bit** value, **tick = 2¹⁶ ns ≈ 65.5 µs**, same ~78 h span. (Choose the slice to trade
  resolution for compare width: `[47:20]` → 1.05 ms tick, 28-bit; `[47:16]` → 65.5 µs, 32-bit. Both
  are finer than needed.)
- **Resolution needed:** holds are ms-scale and bounded by the master's effective TCP RTO (≈200 ms
  Linux floor, **measure on Vision** — GROUNDING) [M/S]. 65.5 µs resolution is ~3000× finer than a
  200 ms budget. Ample.
- **Wraparound handling [I]:** `deadline = req + target` can overflow the 32-bit tick once per ~78 h
  for a ~200 ms window. Detect it (`deadline_tick < req_tick` ⇒ overflow) and **fail open** (forward
  immediately) for that single frame rather than risk an inverted compare. A once-per-78-h single-
  frame no-op is invisible; a broken compare is not.

### 6.3 The deadline-compare tax (bf-p4c Classes 1–2, and the SALU width limit)

A magnitude compare of a wide timestamp is **not free** — this is the single most important
implementation constraint:

- **Gateway (Class 1):** gateway predicate input ≤ **44 bits**, and a magnitude compare burns the
  field width. A 48-bit (even 32-bit combined with other predicates) `>=` **cannot** live in a
  gateway [V].
- **SALU operand width:** the Tofino 1 stateful ALU works on register words **≤ 32 bits** [I,
  well-established]. A 48-bit compare cannot be one SALU op either. This is **why** we pre-slice to a
  32-bit `now_tick`/`deadline_tick` — the compare then fits one SALU predicate.
- **Range-match alternative (Class 2):** if the compare is moved to a TCAM range table, the range key
  is ≤ **20 bits** (5 nibble pairs) [V] — so one would slice further (`[43:24]`, ~1 ms tick, 20-bit)
  and match a range. Viable but coarser; the SALU-predicate path at 32-bit is preferred.

Net: **pre-slice the timestamp so the deadline compare is a 32-bit SALU predicate.** Budget this up
front — a naive `bit<48>` compare will fail to fit and is the first thing to get wrong.

### 6.4 Max recirculation passes, self-clock, and recirc load — quantified

- **Per-pass latency L [P/I]:** a bare on-chip loopback pass is ~0.3–1 µs; on-chip recirc budget
  ≈ **1.6 Tbps**, ~2× faster than off-chip [P, Wu 2019].
- **Passes per held frame [I]:** hold H ÷ L. At L = 1 µs, H = 200 ms ⇒ **200,000 passes** — a lot of
  pipeline re-entries for one frame. To cut this, **shape the loopback port** so each pass takes
  ~100 µs; because a continuously-recirculating frame keeps that port busy, passes 2..N *are* paced
  (the empty-queue exemption of §5.3 applies only to the very first pass). Then 200 ms / 100 µs ≈
  **2,000 passes**. A per-frame **max-pass counter** (carried in recirc metadata) caps this and
  force-emits a stuck frame (§6.6).
- **Recirc bandwidth per held frame [I]:** `frame_bytes / L`. 200 B at L=100 µs ⇒ **16 Mbps**; at
  L=1 µs ⇒ **1.6 Gbps**.
- **Concurrency [I]:** poll spacing ≥ 1 s, hold ≤ 200 ms ⇒ **< 1 frame held per outstation** at any
  instant. Even ~10 simultaneously-held frames at the 100 µs self-clock ≈ 160 Mbps ≈ **0.16 % of a
  100 G pipe** against a 1.6 Tbps recirc budget. **Negligible** — this is the affordability inversion:
  a technique prohibitive for datacenter TCP is cheap for low-rate small-frame OT/SCADA.

### 6.5 Register / held-frame table sizing

- `reg_req_tstamp`, `reg_req_fc` (Stage 1) already index by `flow_id` (`bit<16>` → up to 65,536, size
  to the substation's outstation count, typ. 256–4096) [I].
- `reg_held_count` (global, `bit<32>`): concurrently-held-frame watermark for fail-open (§6.6).
- Register memory is scarce and statically partitioned per stage (NetVRM) [P], so hold state is sized
  in the hundreds–thousands, not millions — **ample** for a substation, and the reason this does not
  generalize to 10⁵⁺ concurrent flows without controller assistance.

### 6.6 Failure behavior — fail-open is mandatory

The switch must **never** drop a DNP3 response and **never** overshoot the master's TCP RTO (a
spurious retransmit is the loudest possible tell to a passive observer *and* triggers a Zeek `dnp3`
IDS — GROUNDING) [M/S]. Fail **open** (forward immediately) on any of:

1. **RTO cap:** `deadline − req > rto_cap_ticks` (controller-set, below the measured Vision RTO
   floor) → do not hold this long.
2. **Watermark:** `reg_held_count > held_max` → stop holding new frames (overload / burst / attack).
3. **Max-pass:** per-frame pass counter exceeded → force-emit (stuck-frame guard).
4. **Wrap:** deadline overflow detected (§6.2).
5. **Controller death / policy absent:** default action forwards. No fast-path controller dependence.

Disabling the hold table reverts cleanly to the Stage 1+2 pass-through. All four guards are cheap
SALU/gateway checks. **Do not rely on an in-SALU `v==0` sentinel** for "empty slot" — bf-p4c flattens
that branch (Class 8); seed register slots from the controller at startup and branch on a real
condition [V].

### 6.7 Alternatives to recirc, and why they are weaker on Tofino 1

- **Queue gating / Time-Aware Shaper (802.1Qbv):** open/close an egress queue on a cyclic schedule so
  a held frame leaves at the next gate window. This gives *time-quantized cyclic* release, not
  arbitrary per-frame absolute delay, and P4-TAS demonstrates it on **Tofino 2** via an internally
  generated control-frame stream [P, preprint]. On **Tofino 1** a per-queue time-gate hold is **not**
  an exposed primitive, so this is controller-assisted and coarser. Attractive only if the policy is a
  fixed cadence rather than a per-frame deadline. [I/H]
- **pktgen-assisted scheduling:** the on-chip packet generator has one-shot/periodic/port-down/recirc
  timer triggers [V], but it emits **new** packets from its buffer — it cannot re-emit a specific
  held frame's exact bytes unless those bytes were copied into the pktgen buffer, which is payload
  storage (Mechanism 5, impractical on Tofino, §7). pktgen's real roles here are (a) a periodic tick
  that clocks a control loop and (b) cover-traffic generation (Stage 4) — **not** first-frame hold.
  [I]
- **Deadline-ordered scheduling (PIFO/SP-PIFO):** programmable schedulers can release in deadline
  order on Tofino queues [P], but they order *relative* release; they do not impose an *absolute*
  wall-clock hold. Useful as the release discipline once frames are held, not as the hold itself. [I]

**Stage 3 verdict:** absolute first-response delay on Tofino 1 is realistic **only** via the
recirc-hold; it is **not** a native primitive; and it is affordable for DNP3 specifically. Every
number above is inference on an unbuilt design — the honest status is "affordable, plausible,
unbuilt, and paying a real deadline-compare/recirc-tuning tax." Do **not** describe this as "the
switch sleeps the packet" — there is no packet-sleep primitive; the hold is a self-clocked loop.

_Plain language: to actually hold the first reply until a fixed target time, the switch has to keep
bouncing that one frame around an internal loop, checking a clock each lap, until the target passes,
then let it out. For DNP3 this is cheap because replies are tiny and rare, so at most a fraction of
one frame is ever looping. The tricky parts are: the clock comparison has to be trimmed to 32 bits to
fit the hardware, the loop laps must be paced so it is thousands not hundreds-of-thousands of laps,
and if anything goes wrong — too many frames, a stuck frame, a clock wrap, or a target longer than the
master will wait — the switch must just let the reply go rather than drop it or trip a retransmit._

---

## 7. Stage 4 — Protocol-modifying (padding, reconstruction, ACK decoupling): OFF-ASIC

Explicitly out of the byte-preserving phase and off Tofino by construction [I], consistent with Agent
E:

- **Padding** (make a small response resemble a larger one): requires adding DNP3 objects / bytes and
  recomputing CRCs and TCP/IP length+checksum — byte modification, and the only DNP3 padding tested
  is a **negative result** (invalid-index CROBs → OUT_OF_RANGE, not insertable) [M]. This is what the
  residual **size** leak (CROB count, 14.6 B/CROB [M]) would need — and it has no safe in-phase form.
- **Payload buffering / reconstruction** (store-and-rebuild for fused split+timing or reorder):
  Tofino's ~20–22 MB TM buffer is **transient egress buffering, not random-access storage** [V];
  holding an existing frame in flight is fine, storing/reconstructing a payload is not. Belongs on a
  DPU (up to 32 GB DDR + Arm cores) or FPGA [V].
- **ACK generation / TCP seq-ack rewrite** (decouple ACK from a held response): no TCP stack on
  Tofino; rewriting seq/ack is proxy/MITM territory the phase rule forbids and a passive IDS would
  flag [V/I]. If ever authorized, its home is the BlueField DPU (full TCP proxy in Arm/DOCA), never
  the ASIC.

_Plain language: making replies bigger, rebuilding their contents, or faking TCP acknowledgements are
all off-limits for this phase and, even later, belong on a smart NIC or FPGA that has real memory and
a TCP stack — not on the switch chip._

---

## 8. Control-plane policy (bfrt_python, config-time only)

```python
# 1. Operator FC->class allowlist (Axis-3 safety; criticality is operator-supplied, not DNP3-derived)
tbl_txn_class.add(dnp3_fc=0x01, txn_class=CLASS_MONITOR)   # READ
tbl_txn_class.add(dnp3_fc=0x03, txn_class=CLASS_CONTROL)   # SELECT
tbl_txn_class.add(dnp3_fc=0x04, txn_class=CLASS_CONTROL)   # OPERATE
# ... critical/protection points flagged per operator table, never inferred from the FC alone

# 2. Stage-2 pacing: response chunks -> shaped queue UC1
tbl_pace_qid.add(dir=RESP, txn_class=ANY, qid=UC1)

# 3. Configure the UC1 shaper on the master-facing port (dev_port 8), THEN read back the quantized rate
port_sched.mod(dev_port=8, qid=UC1, max_rate_pps=REQ_RATE)
achieved = port_sched.get(dev_port=8, qid=UC1)   # report quantized rate beside requested (mantissa/exp)

# 4. Stage-3 timing buckets + guards (future build)
tbl_target_delay.add(txn_class=ANY, target_delay_tick=TARGET)   # class-independent target (honest)
reg_rto_cap.set(rto_cap_ticks=RTO_CAP)   # below the MEASURED Vision TCP RTO floor
reg_held_max.set(held_max=HELD_MAX)
# 5. Seed all per-flow / hold registers to known values (Class 8 — no in-SALU ==0 sentinels)
seed_registers()
# 6. Telemetry read loop (offline, not fast-path): counters ($COUNTER_SPEC_*), regs (from_hw, max across pipes)
```

The controller touches the chip only at config time and for telemetry reads; it is never in the
per-packet path (no fast-path dependence). Digests, if used for sampling, are matched by **instance
name** not struct type [V, lab caveat].

_Plain language: the controller just loads the policy once — which function codes mean what, which
queue paces replies, how long to hold and never longer than the master will tolerate — then steps back
and only reads meters. It never has to be consulted packet-by-packet._

---

## 9. Resource budget, latency, recirc load (summary)

| Dimension | Minimal build (S1+S2) | +Future build (S3) |
|---|---|---|
| **MAU stages (ingress)** | ~4–5 of 12 (classify, txn_class, 3 SALUs, qid) [I] | +2–3 (deadline compute, SALU compare, guards) [I] |
| **SALUs** | 3 (last_tstamp, req_tstamp, req_fc) | +2 (deadline compare, held_count) |
| **Statistics ALUs** | 1–2 (`ctr_class`) | same |
| **TCAM** | ~0–1 (mostly exact-match) | +1 if range-match compare chosen (Class 2) |
| **Registers** | 3 arrays × (256–4096) × ≤32-bit | + deadline reuse + 1 global watermark |
| **Queues** | 2 UC (UC0 default, UC1 shaped) | + 1 loopback/recirc port (dev_port 68) |
| **Hash** | 1 instance (one tuple shape) | same |
| **Latency added** | ~switch baseline (100s of ns); chunks 2..N spaced at shaper rate; chunk 1 immediate | held frames + up to `target_delay` (≤ RTO cap, e.g. ≤~150 ms); non-held frames unchanged |
| **Recirc load** | none | 16 Mbps–1.6 Gbps **per held frame**; <1 frame held ⇒ ≤~1.6 Gbps peak ≈ ≤0.1 % of 1.6 Tbps [I] |

**Co-residency flag [I, memory]:** a generative sibling like `decoy_switch_tna` already fills all 12
ingress stages, so this program cannot co-exist with such a sibling — it needs its own program load.
The minimal build alone is light (~4–5 stages) and leaves headroom; Stage 3 stays within 12 stages
standalone. The `bit<16>` flow index caps per-flow state at 65,536; a `bit<8>` variant caps at 255
(matches the meter-index cap seen on the friction build).

_Plain language: the safe build is small — about a third of the switch's stages, two queues, three
counters-with-memory. The future hold layer adds a couple more stages and one internal loop port. It
comfortably fits on its own, but not on top of a program that already uses the whole pipeline._

---

## 10. Hardware test plan (Hulk / Vision / Tofino)

Preflight [V, memory]: consult the port map; mask `gc-switchd` before loading a different program
(`systemctl stop/mask gc-switchd`); enable ports **8 + 9**; **never restart `bf_switchd` without
approval** (only the Python controller is freely restartable). Traffic crosses dev_port 8 (Vision/
master) ↔ dev_port 9 (Hulk/outstation or `split_server.py`).

1. **Stage 1 — classification & telemetry.** Run `run_master.py` on Vision against `run_outstation.py`
   on Hulk through the switch. Verify: `ctr_class` packet/byte counts match the expected DNP3 exchange;
   `reg_last_tstamp` yields sane gaps; req→response = `now_tick − req_tick` on responses tracks the
   measured ~1 ms and rises with CROB count (reproduces the timing leak on-chip); mirror samples arrive
   at the collector; `tcpdump` on Vision shows **byte-identical** payloads (invariant intact).
2. **Stage 2 — pacing.** Drive `split_server.py --delivery crc-boundary` from Hulk (the 2407 B →
   141/71/36/18-chunk cases [M]). Capture on Vision; measure inter-chunk gaps → chunks 2..N normalized
   to the UC1 shaper rate, chunk 1 immediate (**confirms TM bounds rate, not first-frame latency**).
   Confirm **0 TCP retransmits / 0 resets** and master still delivers 800 measurements + CONFIRM (the
   rig success bar). Read back the **quantized** shaper rate and report it beside the requested rate.
3. **Stage 3 — absolute timing (future build).** With hold enabled, measure req→first-response on the
   Vision capture across a CROB sweep → the delay should **flatten to `target_delay` independent of
   CROB count** (timing axis closed). Confirm **0 spurious retransmits** (hold stayed under the
   measured Vision RTO). Read `reg_held_count` watermark and per-frame pass counts. **Then explicitly
   confirm the residual:** the response **size** still rises 14.6 B/CROB — timing normalized, size not.
   Fault-injection: force `held_count > held_max` and a `target > rto_cap` and verify **fail-open**
   (frames forwarded, never dropped, no retransmit).

Observability primitives [V, memory]: port counters `$FramesReceivedOK`/`$FramesTransmittedOK`
(`from_hw=True`); register reads `from_hw=True`, max across pipes; meter/shaper CIR readback (report
quantized). offered = Δ(port 9 RX), passed = Δ(port 8 TX).

_Plain language: prove it in three steps on the real rig — first that the switch measures the DNP3
exchange correctly without altering bytes, then that it evens out the gaps between reply chunks while
the first chunk still leaves at once, and finally (future) that holding the first reply flattens the
timing tell across control-count sweeps without ever tripping a TCP retransmit — while openly showing
that the reply's size still gives the control count away._

---

## 11. How this extends Agent E (not a redo)

Agent E answered *which platform supports which of six mechanisms*. This report converts the Tofino
column into an implementable pipeline and supplies the numbers Agent E flagged as "needed": the exact
timestamp slice that makes the deadline compare fit a 32-bit SALU (`global_tstamp[47:16]`, 65.5 µs,
78 h span); the bf-p4c tax on that compare (gateway ≤44-bit / SALU ≤32-bit / range ≤20-bit,
Classes 1–2); wraparound handling and its fail-open; the pass-count/self-clock tradeoff (200k vs 2k
passes) and per-held-frame recirc bandwidth (16 Mbps–1.6 Gbps); register sizing and the four fail-open
guards; concrete queue assignments (UC0/UC1 + loopback 68); a config-time-only control plane; and a
three-stage rig test. It also **sharpens the study's core asymmetry into a Tofino statement**: the
switch can close the timing axis and reshape the segmentation axis in-phase, but the strongest
fingerprint (CROB count) lives on the size axis, which Tofino cannot touch without Stage-4 padding —
off-ASIC and, in DNP3, so far a proven dead end.

---


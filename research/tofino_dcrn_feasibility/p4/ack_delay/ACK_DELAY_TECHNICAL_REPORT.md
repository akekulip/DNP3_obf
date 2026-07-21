# ACK-Delay Timing Obfuscation for DNP3 — Technical Report (software → Tofino-1)

**Scope.** End-to-end technical account of the ACK-delay work: the timing side-channel it defends,
the two defense policies, the **software prototypes** (eBPF earliest-departure-time + a socket-side
scheduler), the **executable reference model**, and the **Tofino-1 P4 implementation** (both cases),
with real code, the constraints solved on the ASIC, the resource cost, and the measured results.
Everything below is quoted from the actual sources in
`research/tofino_dcrn_feasibility/p4/ack_delay/` and `dnp3_split_harness/`.

Authority: `test_cases.md` (Dr. Lin's ACK-centric CLRT control). Companion specs:
`ACK_DELAY_POLICY.md`, `ACK_DELAY_STATE_MACHINE.md`, `ACK_DELAY_DEFENSE2_DESIGN.md`, `COMPILE_FACTS.md`.

---

## 1. The signal we defend — CLRT

Formby et al. (NDSS 2016, *"Who's in Control of Your Control System? Device Fingerprinting for
CPS"*) showed that an industrial device can be identified by its **cross-layer response time**:

```
CLRT = t(DNP3 application response) − t(pure TCP ACK)      [separate-ACK transactions only]
```

In a *separate-ACK* transaction the outstation's kernel emits a **prompt pure TCP ACK** for the
poll, then its application emits the DNP3 response some milliseconds later:

```
master request (t_req)  →  outstation pure ACK (t_ack)  →  outstation DNP3 response (t_resp)
G_native = t_resp − t_ack
```

`G_native` is stable and device-specific (it reflects the outstation's kernel-vs-application timing
split), so a passive observer can fingerprint the device from it. **Measured ground truth** (this
project, from `Traffic Trace/`, Zeek-confirmed Class-0 READ→RESPONSE, in `ACK_DELAY_POLICY.md §4`):

| Device | ACK mode | Native CLRT (ACK→resp) | req→resp |
|---|---|---|---|
| **SEL-751** (10.0.0.1) | **separate** (299/299) | **median 12.9 ms** (p10–p90 11.6–15.9) | 17.0 ms |
| AB1400 (10.0.0.12) | combined (0 pure ACKs) | undefined | 16.6 ms |
| ION7550 (10.0.0.11) | combined (0 pure ACKs) | undefined | 16.1 ms |

**Honest scoping (load-bearing).** On this corpus only SEL-751 is separate-ACK; the other two
piggyback the ACK on the response (*combined* mode, CLRT undefined). So the dominant cross-device
signal is actually **ACK mode**, which neither defense here touches. Every efficacy claim is scoped
to *"collapsing the within-separate-mode CLRT sub-channel,"* never *"hiding device identity."* This
is stated up front, not discovered by a reviewer (`ACK_DELAY_POLICY.md §5`).

---

## 2. The two defense policies

Both are **byte-preserving** (no DNP3/TCP/IP field edited, no seq/ack rewrite, no CRC recompute),
**non-cooperative** (the legacy RTU is unmodified), and act **inline** on the outstation→master
direction where the ACK and response originate.

### Case A — `ACK_DELAY_REDUCE_CLRT` (primary / headline)
Hold **only the pure ACK** until the response is ready; release the ACK first, then the response
after the smallest hardware-safe ordering guard `δ`:

```
t_ack_out  ≈ t_resp_ready
t_resp_out = t_ack_out + δ
G_reduce   = t_resp_out − t_ack_out ≈ δ   (small, common to every device)
```

The ACK→response gap collapses to `δ`. **Event-governed:** the release fires on the *arrival of the
response*, so it needs no wall-clock — which makes Case A immune to the recirculation-clock question
that gates deadline holds (see §5.2).

### Case B — `RESPONSE_DELAY_INCREASE_CLRT`
Forward the pure ACK immediately; hold the **response** to an **ACK-relative** deadline:

```
deadline    = t_ack + G_i          (G_i drawn from a common, device-independent bounded distribution)
t_resp_out  = max(t_resp_ready, deadline)
```

The ACK→response gap becomes a constant `G_i`, identical for every device. **Deadline-governed:** it
needs a per-pass-refreshing clock (see §5.4). `G_i` is loaded at runtime (not compiled in) in two
modes: **B1_FIXED** (one `G_i` for all) and **B2_COMMON_BOUNDED** (a device-independent band).

### The tradeoff, and what each case actually conceals
- **Case A is cheap but relocates the signal:** with `t_ack_out ≈ t_resp_ready`, the *request→ACK*
  time now equals the device's processing time — the exact quantity CLRT measured. Against Formby's
  literal CLRT feature it works; against an adversary who reads *request→ACK* it is near-theatre.
- **Case B is costly but normalises** the response-readiness quantity itself.
- The publishable story is the **latency–concealment tradeoff**, and the attacker evaluation must
  include a *request→ACK* and a joint *(req→ACK, ACK→resp, size)* classifier, not CLRT alone.

### Combined-mode & grid-safety bypass (non-negotiable)
A payload-bearing response with **no** preceding pure ACK is **combined mode** → CLRT is undefined →
**bypass unchanged** (never synthesise, suppress, split, or rewrite an ACK). Controls, unsolicited
event reports, SELECT/OPERATE, handshake, retransmits, dup-ACKs, SACK, out-of-order, and fragments
are all **forwarded unchanged, never dropped** (fail-open). Only idempotent Class-0 monitoring polls
are ever held, by tens of ms — operationally invisible, since protection executes locally in the
relay and never traverses this path (`ACK_DELAY_POLICY.md §6`).

---

## 3. Software side (host prototypes)

### 3.1 eBPF earliest-departure-time (`ack_edt.c`)
The first mechanism proof: a tc/eBPF program that **stamps departure times on packets that already
exist** and lets the `fq` qdisc enforce them — no packet is forged, no byte edited. It records the
request as it egresses, then schedules the reverse ACK and response to per-flow target times.

```c
/* dnp3_split_harness/reports/phases/phase_04/ebpf_prototype/ack_edt.c */
#define ACK_TARGET_NS  20000000ULL   /* request -> pure ACK = 20 ms */
#define RESP_TARGET_NS 40000000ULL   /* request -> response = 40 ms */

SEC("tc")
int ack_edt(struct __sk_buff *skb) {
    ...
    /* Request egressing (master->server, has payload): record its arrival. */
    if (dport == SERVER_PORT && plen > 0) {
        __u64 key = ((__u64)saddr << 16) | sport;
        struct flow_state st = { .req_arrival_ns = bpf_ktime_get_ns() };
        bpf_map_update_elem(&flows, &key, &st, BPF_ANY);
        return TC_ACT_OK;
    }
    /* Reverse packet egressing (server->master): schedule its EDT release. */
    if (sport == SERVER_PORT) {
        __u64 key = ((__u64)daddr << 16) | dport;
        struct flow_state *st = bpf_map_lookup_elem(&flows, &key);
        if (!st) return TC_ACT_OK;                    /* FAIL OPEN: unknown / combined-mode */
        __u64 target = st->req_arrival_ns + (plen == 0 ? ACK_TARGET_NS : RESP_TARGET_NS);
        skb->tstamp = target;                          /* EDT; fq enforces. No byte edited. */
        return TC_ACT_OK;
    }
    return TC_ACT_OK;
}
```

- **Byte-preserving:** the only mutation is `skb->tstamp` (a scheduling hint), never a header.
- **Invariant by construction:** `ack_release (20 ms) < response_release (40 ms)`.
- **Fail-open:** a reverse packet with no recorded request (unknown/combined) is left native.
- **Result:** proven on the wire (PI-run) — the ACK and response left at their scheduled times.

**Why the host approach is not the endpoint.**
1. **Off-path.** eBPF-EDT paces the *host's own transmit*. To reshape a **third-party outstation's**
   outstation→observer timing, the delay must sit **on the path** between them. On the single-host
   loopback the host *is* on the path (both endpoints local), so it is a valid mechanism proof — but
   a real deployment would need the host to be a forwarding bump-in-the-wire.
2. **Privilege.** Loading the program needs `CAP_BPF`/root — restricted on the rig
   (`unprivileged_bpf_disabled=2`; the load is PI-sudo only).
3. **Split path.** A real inline deployment needs a tc-**ingress**(record request) + tc-**egress**
   (schedule reverse) split, not one egress program.

These three gaps are exactly what an **on-path** hold (Tofino, or a SmartNIC) closes.

### 3.2 Socket-side scheduler (`timing_policy.py`)
Used by the replay/split server (which **owns the socket**, so it can legitimately decide *when* it
sends the response it already holds). It is a **pure decision function** — no clock reads, no
sleeps — hence deterministic and unit-tested (byte-identity preserved; 22/22 tests):

```
target_delay   = sample from a common, class-INDEPENDENT bounded distribution
desired_release = request_received + target_delay
actual_release  = max(response_ready, desired_release)      # never send early
```

Key properties (`dnp3_split_harness/timing_policy.py`): the target distribution does **not** depend
on CROB count, response size, request size, native readiness, or device identity (normalisation, not
additive jitter); a Phase-2 helper `plan_ack_response_release()` reschedules an existing ACK+response
pair and **strictly enforces `ack_release ≤ response_release`**; and an RTO-safety guard fails open
when no RTO-safe bound is known (`RTO_UNKNOWN_STRICT`). Measured master RTO on the rig ≈ 207–211 ms,
so every hold target is bounded well below it to avoid triggering a retransmit.

---

## 4. The executable reference model

Before any silicon, the state machines are pinned as pass-based Python models with invariant tests
(`refmodel/defense1_state_machine.py`, `refmodel/defense2_state_machine.py`; `tests/`). The Case-B model
proves six properties that gate hardware authorization (`tests/test_defense2.py`, 10/10):

1. ACK forwarded immediately; 2. response held until the **ACK-relative** deadline; 3. released
unchanged (byte-preserving); 4. state returns to IDLE; 5. **zero reordering** (ACK egresses before
response); 6. `MAX_PASS` used **only** as fail-open (normal release is the deadline). Plus: the
deadline is ACK-relative (not request-relative), CLRT collapses to a constant `G_i` independent of
readiness, and the honest `max(ready, deadline)` edge (readiness > `G_i` leaks at readiness).

---

## 5. Tofino-1 implementation

Two **separate compile-time binaries** (never one runtime `policy_mode` program — stacked they blow
the 12-stage limit): `dcrn_defense1.p4` (event-governed) and `dcrn_defense2.p4` (deadline-governed). They
share the parser, deparser, prologue, bridge geometry, and register idioms; only the release logic
differs. Target: Tofino-1 (TNA), bf-p4c 9.13.1 local / 9.13.2 on-switch.

### 5.1 Dataflow
```
                 ┌──────────────── ingress pipeline ───────────────┐
 Vision(dp8) ───▶│ parse → prologue → ARM / classify / hold-decide │───▶ Hulk(dp9)  [request, unchanged]
 Hulk(dp9)   ───▶│                                                 │───▶ Vision(dp8) [release, byte-identical]
                 │            hold ↕ (push bridge, recirc)          │
                 └──────────────── dp68 recirc port ───────────────┘───▶ egress: restamp clock / strip bridge
```
A held frame is parked on the **dp68 recirculation port** carrying an internal `dcrn_bridge_h`
header (never seen by Vision). Each lap re-enters ingress; the release decision runs per pass. On
release the frame is sent to `PORT_VISION` and egress **strips the bridge** → the frame reaching
Vision is IP-and-above bit-identical.

### 5.2 Parser — the payload-length gate (a real-HW showstopper fixed)
The parser must **not** descend into DNP3 for a zero-payload frame (a pure ACK to dst:20000), or
`extract(dnp3_dl)` reads past end-of-packet → parser error → the frame is **dropped** → retransmit
storm. Because the parser cannot do arithmetic, the gate is a **range-match on `total_len` per
`data_offset`**:

```p4
// dcrn_defense1.p4 parse_tcp  (descend into DNP3 only when long enough to hold a DNP3 link header:
//   total_len >= 20 (IP) + 4*data_offset (TCP) + 10 (DNP3 link) = 30 + 4*data_offset)
transition select(hdr.tcp.flags[1:1], hdr.tcp.data_offset, hdr.ipv4.total_len) {
    (1w0, 4w5,  16w50 .. 16w65535) : parse_tcp_options;   // no options
    (1w0, 4w8,  16w62 .. 16w65535) : parse_tcp_options;   // Linux TCP timestamps — common case
    ...
    default                        : accept;              // pure ACK / short / SYN -> forward
}
```

### 5.3 Prologue — shared, parallel, per-frame
Runs on every path (`dcrn_defense1.p4` apply): capture the 65.5 µs clock tick, direction, TCP payload
length (via a **negate-and-add** table, since the MAU can't subtract in one stage), the **canonical
bidirectional flow key** (identical for request, response, and recirc frame → one hash), and the
TCP-flag classification used to qualify a *pure* ACK:

```p4
meta.now_tick   = ig_prsr_md.global_tstamp[47:16];
tcp_overhead.apply();                             // meta.payload_len = total_len + (-overhead)
meta.exp_addend = (bit<32>)meta.payload_len;      // FIX1: widen HERE so the arm-time add is clean 32+32
meta.flow_id    = flow_hash.get({ client_ip, server_ip, client_port });
if ((hdr.tcp.flags & 8w0x17) == 8w0x10) { meta.flags_ok  = 1; }  // pure ACK: ACK=1, SYN=RST=FIN=0
if ((hdr.tcp.flags & 8w0x05) == 0)      { meta.not_abort = 1; }  // no FIN, no RST
```

### 5.4 Per-flow state (hardened registers)
Separate `bit<8>` flag registers (no single enumerated-state register; controller cold-seeds — Class
8), indexed by `flow_id`, each ≤2 pipeline phases:

| Register | Role (Case A) |
|---|---|
| `reg_armed` | active txn: set@arm, read(+abort-clear)@response |
| `reg_expected_ack` | **FIX1** request end-seq (`seq + payload_len`); compared *in-SALU* vs `tcp.ack_no` at the ACK |
| `flow_has_held_ack` | **FIX4** binary ACK occupancy + **one-shot** hold latch (rejects dup-ACKs) |
| `reg_resp_seen` | response entered the pipeline — the **Case-A event trigger** |
| `reg_ack_gone` | the held ACK has been released — the **ordering latch** |

### 5.5 Case A — arm → hold → **event** release, and the zero-inversion invariant

**Arm** on an eligible request (dp8, dst 20000, FC-allowlisted), forward it to Hulk unchanged:
```p4
meta.exp_ack = hdr.tcp.seq_no + meta.exp_addend;  // the ACK we later hold must ack exactly this
if (meta.fc_ok == 1) {
    armed_set.execute(meta.flow_id);              // active txn
    expack_set.execute(meta.flow_id);             // store request end-seq (FIX1)
    fha_clr.execute(meta.flow_id);                // fresh occupancy (FIX4)
}
ig_tm_md.ucast_egress_port = PORT_HULK;           // byte-identical, incl. TCP options
```

**Qualify + hold** the first genuine pure ACK — exact match, one-shot:
```p4
bit<8> armed  = armed_get_absclr.execute(meta.flow_id);   // FIX2: clears armed on FIN/RST abort
bit<8> amatch = expack_match.execute(meta.flow_id);       // reg_expected_ack == tcp.ack_no ? (in-SALU)
if (armed == 1 && meta.flags_ok == 1 && amatch == 1) {    // rejects keepalives, window-updates, FIN/RST
    bit<8> already = fha_tas.execute(meta.flow_id);       // one-shot: hold only the FIRST qualifying ACK
    if (already == 0) {
        hdr.bridge.setValid(); hdr.ethernet.ether_type = ETHERTYPE_DCRN;   // push bridge, recirc
        hdr.bridge.role = ROLE_ACK; hdr.bridge.pass_count = 0;
        ig_tm_md.ucast_egress_port = PORT_RECIRC; ig_tm_md.qid = QID_HOLD;
    }
}
```

**Admit the response** (past the arming watermark — completing a hold, not arming a new one) and set
the trigger:
```p4
bit<8> held = fha_getclr.execute(meta.flow_id);           // separate-mode? + release occupancy
if (held == 1 && meta.not_abort == 1) { respseen_set.execute(meta.flow_id); }  // Case-A trigger
// ... push ROLE_RESP bridge, recirc on QID_HOLD ...
```

**Event-governed release on the recirc loop** — the held ACK polls `reg_resp_seen`; the response
releases only after `reg_ack_gone`:
```p4
if (hdr.bridge.role == ROLE_ACK) {
    bit<8> rs = respseen_getclr.execute(meta.flow_id);    // atomic poll + self-clear
    bit<8> ack_release = rs;
    if (hdr.bridge.pass_count >= ACK_MAX_PASS) { ack_release = 1; ack_alarm = 1; }  // fail-open only
    if (ack_release == 1) {
        ackgone_set.execute(meta.flow_id);                // set on the SAME pass we go to Vision
        ig_tm_md.ucast_egress_port = PORT_VISION;         // qid 0 (shared FIFO)
    } else { ig_tm_md.ucast_egress_port = PORT_RECIRC; ig_tm_md.qid = QID_HOLD; }
}
else {   // admitted response: release only on ack_gone==1 (+ guard passes)
    if (hdr.bridge.pass_count >= GUARD_PASSES) { ag = ackgone_getclr.execute(meta.flow_id); }
    if (ag == 1 || pass_count >= RESP_MAX_PASS) { ig_tm_md.ucast_egress_port = PORT_VISION; }
    else { ig_tm_md.ucast_egress_port = PORT_RECIRC; ig_tm_md.qid = QID_HOLD; }
}
```

**The zero-inversion invariant (the crux).** A response is directed to `PORT_VISION` *only* on a pass
where it reads `reg_ack_gone == 1`; the ACK sets `reg_ack_gone := 1` on the pass it is itself directed
to `PORT_VISION`. Because **register writes are visible only to strictly-later passes**, the
response's release pass is strictly later than the ACK's, and since both leave on the **same
`PORT_VISION` FIFO queue** (both at qid 0, never `QID_HOLD`), the ACK dequeues first. Non-same-cycle
visibility can only *delay* the response's read (adds guard), never advance it → **cannot invert.**
This rests on two hardware facts asserted on-silicon: monotone register visibility, and ACK+response
sharing one egress queue.

### 5.6 Case B — the ACK-anchored deadline
Case B forwards the ACK immediately, but at that moment records `reg_deadline = now_tick + G_i`, and
holds the response until a per-pass clock reaches it. `G_i` comes from a controller-installed
**bounded-target table** walked by a global counter (device-independent):

```p4
// dcrn_defense2.p4 — the deadline is ACK-anchored, loaded at runtime
action set_deadline(bit<32> gi) { meta.deadline = meta.now_tick + gi; }   // single-stage add (Class 5)
table bounded_target {                       // 256 entries; B1_FIXED = all same, B2 = a distribution
    key = { meta.bkt_idx : exact; } actions = { set_deadline; }
    default_action = set_deadline(32w0);     // policy-absent -> deadline in the past -> immediate release
    size = 256;
}
RegisterAction<...>(reg_deadline) arm_deadline = {                     // the ONLY deadline write, @ACK
    void apply(inout bit<32> dl, out bit<32> rv) { dl = meta.deadline; rv = dl; }
};
RegisterAction<...>(reg_deadline) check_deadline = {                   // THE single deadline compare
    void apply(inout bit<32> dl, out bit<8> released) {
        if (meta.now_eff >= dl) { released = 1; } else { released = 0; }   // runtime-operand magnitude cmp
    }
};
```

The clock `now_eff` is the first-arrival `now_tick`, or on the recirc loop the **egress-refreshed**
`bridge.tstamp_tick`:
```p4
if (is_recirc == 1) { meta.now_eff = hdr.bridge.tstamp_tick; }   // refreshed each pass in egress
else                { meta.now_eff = meta.now_tick; }
meta.released = check_deadline.execute(meta.flow_id);            // 1 = now_eff >= deadline -> release
```
Egress re-stamps the bridge clock every lap (`hdr.bridge.tstamp_tick = eg_prsr_md.global_tstamp[47:16]`)
— this is the refreshing time source the ingress deadline compare reads, and the reason Case B (unlike
Case A) depends on the recirc clock.

### 5.7 Byte-preservation
The deparser emits every header and there is **no `Checksum()` extern** — no IP/TCP/DNP3 byte is ever
recomputed. The internal `dcrn_bridge_h` is valid only on the recirc loop; egress restores the
original ethertype and `setInvalid()`s the bridge before the frame reaches Vision:
```p4
hdr.ethernet.ether_type = hdr.bridge.original_ethertype;   // restore 0x0800
hdr.bridge.setInvalid();                                    // deparser drops it -> byte-preserved
```
Verified on hardware: **26/26 response payloads byte-identical** P0 (native) vs P1 (defended).

### 5.8 Tofino-1 constraints solved (why the code looks non-idiomatic)
Each of these cost real compile iterations and is applied preemptively (`references/constraints.md`):
- **No parser arithmetic** → the payload gate is a `total_len` range-match per `data_offset` (§5.2).
- **Single-stage action arithmetic** → `payload_len` via a **negate-and-add** overhead table; the
  `exp_ack` add is kept a clean 32+32 by widening `payload_len` to 32 bits in the prologue
  (**FIX1 `exp_addend`**, dodging the widened-narrow-add `BIT_COLLISION`).
- **Sub-byte fields next to 32-bit outputs** → all flags are `bit<8>` even when only the LSB matters.
- **No `if v==0` SALU sentinel** → registers are controller cold-seeded; branch on other conditions.
- **Magnitude compares out of gateways** → `pass_count`/deadline compares are isolated 32-bit
  compares so the placer runs them in parallel, not chained.
- **One register touched at one depth** → the reliable event tallies were **moved to egress** so the
  ingress release blocks stay shallow and place ≤12 stages.

### 5.9 Control plane & rig
- **`defense1_setup.py` / `defense2_setup.py`** (bfrt): bring up ports (dp8/dp9/dp68), the `QID_HOLD=5`
  shaper on the recirc port, seed registers, and install the FC allowlist (READ 0x01 only). Case B
  additionally installs the 256-entry `bounded_target` (B1_FIXED = uniform `G_i`; B2 = a sampled
  device-independent band).
- **Single-host loopback rig (Hulk):** one host plays **both** DNP3 roles in two network namespaces
  (VEPA macvlans `10.0.1.10` master / `10.0.2.10` outstation) with a `dp8` MAC-near loopback
  hairpin, so a real pydnp3 master↔outstation transaction runs **through the switch**. Requires
  `i40e disable-source-pruning on`. Captures are taken on the physical NIC (see the pcap note below).

---

## 6. Compile facts & resource usage (bf-p4c 9.13.1; `COMPILE_FACTS.md`)

| Resource — used / total | Case A | Case B |
|---|---|---|
| **MAU ingress stages** | **12 / 12** | **10 / 12** |
| Egress stages | 1 | 1 |
| Critical path (dep. chain) | 7 | 8 |
| Parser range-match rows | 171 / 256 | 166 / 256 |
| SRAM (unit-RAM blocks) | 62 / 960 | 63 / 960 |
| **TCAM** | **0 / 288** | **0 / 288** |
| Map RAM | 60 / 576 | 60 / 576 |
| Stateful/meter ALUs | 9 / 48 | 6 / 48 |
| Gateways | 35 / 192 | 34 / 192 |
| PHV 32-bit | 13 / 64 | 22 / 64 |

**Headline:** both programs are **stage-bound and parser-bound, not memory-bound** (SRAM ≤7%, TCAM
0%, PHV ≤34%). The as-shipped **hardened** Case A fills all 12 ingress stages
(`evidence/defense1_9.13.1_hardened/`); the FIX1+2+4 hardening added the 12th stage over the
pre-hardening 11-stage build. There are **no stages left** for size-padding or split — the direct
reason all three obfuscation primitives cannot co-reside on one Tofino pipeline, and the motivation
for a run-to-completion SmartNIC (§8).

---

## 7. Results (single-transaction, from the captures in `evidence/pcap_clean/`)

Passive-observer ACK→response gap, one transaction (Src 10.0.2.10 = device, 10.0.1.10 = master):

| Condition | ACK arrival | Response arrival | **CLRT gap** |
|---|---|---|---|
| **Before** (native) | 0.324 ms | 16.786 ms | **16.5 ms** |
| **Case A** (hold ACK) | 25.274 ms (held) | 25.298 ms | **0.02 ms** ✅ collapsed |
| **Case B** (hold response) | 0.259 ms (immediate) | 81.660 ms (held) | **81.4 ms** ✅ fixed |

Also verified on hardware: byte-preservation perfect (26/26 payloads identical), 0 retransmits/resets
under the clean single-txn runs. Case A is **device-independent** (collapses to the guard floor for
any readiness); Case B fixes CLRT to a common constant. Full before/after captures:
`evidence/pcap_before_after.png`; raw + clean pcaps: `evidence/pcap_raw/`, `evidence/pcap_clean/`.

**Known Case-B mechanism limit (honest).** On silicon the recirc hold hit a ~2.87 ms cap when
`ig_tm_md.qid` was left default on the recirc paths (bare recirc reached `MAX_PASS`), and the earlier
bounded-distribution runs showed a ~47 ms drain offset from the shaper mapping — both are Tofino
timing-mechanism artifacts (not fundamental), and reinforce the SmartNIC case where a memory-ring +
timer thread replaces the recirc+shaper hack (M2 next step: set `qid=5` on the recirc paths + confirm
the shaper paces a lone frame).

---

## 8. Limitations & the next step

1. **Case A relocates rather than removes** the signal (request→ACK now carries it) — the attacker
   eval must read request→ACK and the joint feature, not CLRT alone.
2. **ACK mode is the dominant cross-device signal** and neither case touches it (that is the phase-05
   socket-side coalescing line, separate from this ACK-*delay* work).
3. **Multi-segment responses** need per-segment ordering (single-flag machine is single-segment
   scope; gated to a later size sweep).
4. **Timing + size + split cannot co-reside** on Tofino (Case A already 12/12 stages). The fix is a
   run-to-completion **SmartNIC** (Netronome NFP-4000 confirmed on Vision): no 12-stage wall, GBs of
   memory, and a natural memory-ring + timer-thread hold (no recirc, no drain offset). See
   `netronome_vision_onbox_inspection.md`.

---

## 9. File map

| Path | What |
|---|---|
| `ACK_DELAY_POLICY.md` | policy spec (CLRT, two cases, bypass, grid safety, prohibited list) |
| `ACK_DELAY_STATE_MACHINE.md` | Case A/B state machines, zero-inversion, clock-fix design |
| `ACK_DELAY_DEFENSE2_DESIGN.md` | Case B off-switch design + local compile/resource report |
| `dcrn_defense1.p4` / `dcrn_defense2.p4` | the two Tofino binaries (event- / deadline-governed) |
| `refmodel/`, `tests/` | executable state-machine models + invariant tests |
| `defense1_setup.py` / `defense2_setup.py` / `defense1_read.py` | bfrt control plane + register readback |
| `dnp3_split_harness/.../ack_edt.c` | eBPF earliest-departure-time prototype |
| `dnp3_split_harness/timing_policy.py` | socket-side pure-decision release scheduler |
| `COMPILE_FACTS.md` | reconciled bf-p4c resource facts (this report §6) |
| `evidence/pcap_clean/`, `evidence/pcap_raw/`, `evidence/visualization/` | captures + figures |

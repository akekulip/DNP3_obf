# Panel memo C — TCP and DNP3 protocol engineer

**Task:** exact, implementable READ / pure-ACK / RESPONSE / retransmission / keepalive predicates for
DEFENSE 3 (predetermined ACK-delay release, `d_ACK = t_ACK + D`, D ∈ {1,2,3} ms), Case A only.
**Authority:** `meeting_direction.md` §7 (transaction lifecycle) and §8 (exact packet classification).
**Branch:** `research/case-a-defense3-fixed-ack-delay`. **Analysis only** — no code changed, no hardware touched.

**Evidence base.** Every number tagged `[M]` was re-derived from repo PCAPs in this session with
`tshark` + the research Python; `[R]` is quoted from a repo report and not re-measured; `[U]` is
unverified. Corpus: the seven
`evidence/corrected_v2/cwi/pcaps/{C1,C2,C3,C4_idle1s,C4_idle5s,C4_idle15s,C4_idle30s}.pcap` cells and
`research/physical_sel751/clrt_300poll_20260723T152242/evidence/clrt_300poll_20260723T152242.pcap` —
**8 PCAPs, 622 complete transactions, 56 TCP connections**. All are read-only polls of the physical
SEL-751 at `192.168.10.7:20000` from master `192.168.10.1`.
Baseline code inspected: `research/defense2_pktgen/p4/dnp3_timing_normalizer_pktgen.p4` (frozen; not modified).

---

## 0. Findings first

1. **The keepalive is separable, exactly, by one field.** Across 61 keepalives, `tcp.seq == SND.NXT − 1`
   in 61/61, while `tcp.seq == SND.NXT` holds for **679/679 relay non-keepalive pure ACKs** and
   `RESP.seq == ACK.seq` for 622/622 responses. `[M]` The keepalive is retrograde by exactly one octet.
   **The expected-*acknowledgment* test does not separate them: 61/61 keepalives carry the correct
   `EXP_ACK` of the last READ and pass it.** `[M]` §8's `expected relay TCP sequence` conjunct is the
   load-bearing one, not `expected TCP acknowledgment number`.
2. **`EXP_RELAY_SEQ` needs no arithmetic.** Set it from the *master's* pure ACK: `EXP_RELAY_SEQ :=
   master_pure_ack.tcp.ack_no`. Validated over 8 PCAPs: 679/679 relay non-keepalive pure ACKs and 622/622
   responses match the tracker, 0 mismatches, 61/61 keepalives rejected. `[M]` (The 679 are the 622
   transaction ACKs plus 57 handshake / teardown / `LINK_STATUS` ACKs; those extras pass the
   sequence test and are rejected by the acknowledgment test A6.) It is seeded free by the
   three-way-handshake ACK and needs no `seq + len` add, no payload-length computation, and no SALU
   arithmetic. This is the single cheapest way to satisfy §8.
3. **The flags mask must be `0x3F`, not `0x17`.** `0x17` (`FIN|SYN|RST|ACK`) admits a zero-payload
   `PSH|ACK` and a `URG|ACK`. `[M]` from source read of the baseline parser, lines 486–496.
4. **The observed Class-0 response is one TCP segment, one transport segment, one application
   fragment — 622/622.** `[M]` `tp_ctrl & 0xC0 == 0xC0` and `app_control & 0xF0 == 0xC0` (FIR=1, FIN=1,
   CON=0, UNS=0) on every response in the corpus. Everything else must bypass and count
   `UNSUPPORTED_SEGMENTATION`. Multi-segment is **not** supported and must not be implied.
5. **TCP correctness at D ≤ 3 ms is not close to any binding timer.** The binding constraint is the
   master's RTO on the outstanding READ; at the Linux 200 ms floor that is ≥ 66× D=3 ms. Fast
   retransmit is structurally unreachable. Delayed-ACK is never engaged (master ACKs the response in
   median 37.3 µs `[M]`). Risk becomes real only above ~40–50 ms (see §4.6).
6. **Two defects inherited from the baseline must be fixed before any D is swept**, both already named
   in `research/case_a_fixed_ack_delay/design/CASE_A_MECHANISM_STUDY.md` §5 and both confirmed here:
   the keepalive silently disarms the defense, and `expired → forward RESPONSE` lets the response
   overtake the held ACK inside the measured 1,736 ns release tail `[R]`.
7. **New gap not previously recorded:** the baseline never tests IP fragmentation
   (`ipv4.flags.MF`, `ipv4.frag_offset`) `[M]` source read. Add it to both predicates; it is one extra
   parser select field.

---

## 1. The protected ACK predicate

### 1.1 Constants (control-plane parameters, not literals in P4)

| Symbol | Campaign value | Source |
|---|---|---|
| `RELAY_IP` | `192.168.10.7` | corpus `[M]` |
| `MASTER_IP` | `192.168.10.1` | corpus `[M]` |
| `DNP3_PORT` | `20000` | corpus `[M]` |
| `PORT_RELAY` | `dp64` live inline / `dp11` replay | baseline P4 lines 165–172 `[M]` |
| `PORT_VISION` | `dp9` (master side) | baseline P4 line 166 `[M]` |
| `PORT_L` | `dp8` (internal loopback) | baseline P4 line 165 `[M]` |
| `D` | 1 / 2 / 3 ms, as a multiple of 256 ns | direction §14; tick constraint `[R]` |

### 1.2 Conjuncts — all must hold

| # | §8 conjunct | Concrete field test | Where |
|---|---|---|---|
| **A1** | relay-facing ingress direction | `ig_intr_md.ingress_port == PORT_RELAY` (i.e. parser `meta.dir == DIR_OUT` **and** `meta.dequeued == 0`) | parser select on ingress port |
| **A2** | valid IPv4 structure | `hdr.eth.ether_type == 16w0x0800` ∧ `hdr.ipv4.version == 4w4` ∧ `hdr.ipv4.ihl == 4w5` ∧ `hdr.ipv4.protocol == 8w6` ∧ **`hdr.ipv4.frag_offset == 13w0`** ∧ **`(hdr.ipv4.flags & 3w0b001) == 0`** (MF clear) | parser `parse_ipv4` select |
| **A3** | protected 5-tuple | `ipv4.src_addr == RELAY_IP` ∧ `ipv4.dst_addr == MASTER_IP` ∧ `tcp.src_port == 16w20000` ∧ `tcp.dst_port == reg_session_port` | 1-entry exact table + 1 register |
| **A4** | ACK-only flags | **`(hdr.tcp.flags & 8w0x3F) == 8w0x10`** | parser select (replaces `&&& 8w0x17`) |
| **A5** | zero TCP payload | `hdr.ipv4.total_len == 16w(20 + 4·data_offset)`, i.e. the exact pairs `(4w5,16w40) … (4w15,16w80)` | parser select — **keep the baseline entries verbatim**, they are correct |
| **A6** | expected TCP ack number | `hdr.tcp.ack_no == reg_exp_ack` | MAU exact/ternary on a 32-bit container |
| **A7** | **expected relay TCP sequence** | **`hdr.tcp.seq_no == reg_exp_relay_seq`** | MAU exact/ternary on a 32-bit container |
| **A8** | active current generation | `tag_diff ∉ {8w0x00, 8w0x01}` — i.e. the ternary reject entry `(CLASS_ACK, 8w0x00 &&& 8w0xFE) → dec_none()` already in the baseline (line 799). A pure ACK carries `gen_in = 0`, so `tag_diff = 0 − stored`; `stored = 0x00` (never armed) → `0x00`, `stored = 0xFF` (retired) → `0x01`, `stored = 0xCn` (live) → `0x40−n`. The mask therefore means exactly "a transaction is live". | existing `tbl_state_decode` |
| **A9** | one-shot `AWAITING_ACK` | `txn_state == AWAITING_ACK`; the arming SALU must be write-once (`deadline_arm_once`, baseline line 922) **and** the state must advance to `ACK_HELD` in the same pass | packed state register |

**Session learning (required, because A7's tracker is load-bearing).** `reg_session_port` and
`reg_exp_relay_seq` are both learned in the data plane, with no controller action:

```
on master→relay SYN      ((flags & 0x3F) == 0x02, dst_port == 20000, IP pair matches):
        reg_session_port  := hdr.tcp.src_port          // master ephemeral (54055 in C3 [M])
        reg_exp_relay_seq := 0 ; state := IDLE          // reset the whole machine
on master→relay pure ACK ((flags & 0x3F) == 0x10, 5-tuple matches):
        reg_exp_relay_seq := hdr.tcp.ack_no             // == relay SND.NXT, always
```
The handshake ACK seeds the tracker with `SYN-ACK.ISN + 1` for free; every later master ACK refreshes
it after the response is consumed. Verified 679/679 + 622/622, 0 mismatches, 8 PCAPs `[M]`.

### 1.3 Rejection matrix — which conjunct kills what

| Must reject | Observed encoding | Killed by | Corpus check |
|---|---|---|---|
| SYN-ACK | `flags 0x12`, `data_offset 11`, `total_len 64` | **A4** (also A7: `seq = ISN`) | 56 in corpus, all rejected `[M]` |
| FIN,PSH,ACK from relay | `flags 0x19` — **this relay always sets PSH with FIN, 56/56** | **A4** | 56 in corpus `[M]` |
| FIN-ACK from master | `flags 0x11` | **A4** (also A1: wrong direction) | 56 in corpus `[M]` |
| RST | `flags 0x04` / `0x14` | **A4** | 0 in this corpus; 7 relay RSTs in the connectivity probe `[R]` |
| PSH/data | `flags 0x18`, `total_len > 20+4·off` | **A4** (PSH) ∧ **A5** (payload) | 622 responses `[M]` |
| zero-payload `PSH\|ACK` | `flags 0x18`, `total_len == 20+4·off` | **A4 only** — `0x17` would admit it | none observed; latent |
| `URG\|ACK` | `flags 0x30` | **A4 only** — `0x17` would admit it | none observed; latent |
| **keepalive** | `flags 0x10`, `len 0`, `data_offset 8`, `seq = SND.NXT−1`, `ack = EXP_ACK` | **A7 only** | **61/61 rejected by A7; 61/61 pass A6** `[M]` |
| duplicate ACK (pre-response) | identical `seq`/`ack` to the armed ACK | **A9** (tracker has not moved yet, so A6/A7 still pass) | constructed case |
| duplicate ACK (post-response) | `seq` now behind the tracker | **A7** ∧ **A9** | constructed case |
| ACK outside an active transaction | any | **A8** ∧ **A9** | 3 keepalives/idle cycle `[M]` |
| unrelated TCP flow | any | **A3** | — |
| IP fragment overlaying a fake TCP header | `frag_offset ≠ 0` | **A2** (new) | latent; not tested in baseline `[M]` |
| internal blocker token | `eth.type 0x88C1` | forced `ROLE_BLOCK` in the parser | baseline invariant `[M]` |

### 1.4 The keepalive — decisive discriminator, and why A6 is not enough

Measured on `cwi_C4_idle30s.pcap` (frames 13–20, ground truth for the whole class):

```
f13  relay→master  flags 0x10  len 0   seq 4076395653  ack 4087653111   <- TRANSACTION ACK
f14  relay→master  flags 0x18  len 54  seq 4076395653  ack 4087653111   <- RESPONSE  (SND.NXT = 4076395707)
f16  relay→master  flags 0x10  len 0   seq 4076395706  ack 4087653111   <- keepalive  t = 10.832 s
f18  relay→master  flags 0x10  len 0   seq 4076395706  ack 4087653111   <- keepalive  t = 20.854 s
f20  relay→master  flags 0x10  len 0   seq 4076395706  ack 4087653111   <- keepalive  t = 30.874 s
```

* **Direction, 5-tuple, IP/TCP structure, flags, payload length and acknowledgment number are
  byte-identical between the transaction ACK and the keepalive.** A1–A6 cannot tell them apart; the
  keepalive is generated by the same stack, on the same session, echoing the same `EXP_ACK`.
* The only difference is `tcp.seq`: `4076395653` (= `SND.NXT` at that moment) versus `4076395706`
  (= `SND.NXT − 1` after the response advanced `SND.NXT` to `4076395707`). This is RFC 1122 §4.2.3.6
  keepalive-probe behaviour — the probe deliberately carries `SEG.SEQ = SND.NXT − 1` so the peer is
  forced to emit an ACK without any new data being delivered.
* Interval: median **10.020 s**, and a second population at **14.999 s** in the 15 s idle cell `[M]`.
  61 keepalives across the two idle cells. Real integrity-poll cadences (15 s – 15 min) meet this
  constantly.

**Why A6 alone is insufficient, stated as a measurement, not an argument:** applying only the
expected-ack test to the 61 keepalives accepts **61/61**. Applying the expected-relay-seq test rejects
**61/61**. `[M]`

**Failure mode if A7 is omitted.** In Defense 2 the keepalive is rejected only by arm-once idempotence
— an accident, because Defense 2 never *holds* the ACK. In Defense 3 a qualifying pure ACK enqueues a
packet into `Q_HOLD` and installs `ack_deadline`. A keepalive arriving between transactions therefore
(a) parks a live packet in `Q_HOLD` with no blockers standing, and (b) leaves a valid deadline already
in the past, so the next real ACK finds `deadline_valid == 1` and is never held. That is **silent loss
of protection**: no drop, no crash, no counter, and a measured D that looks small instead of absent.
Any Defense 3 campaign run without A7 at a poll period above ~10 s is unreproducible by construction.

**Necessary companion:** retire `reg_tag` on the *successful* ACK-release / response-release pass, not
only on fail-open. The baseline retires it only on fail-open (line 897) `[M]`, so a keepalive between
polls still sees a live generation and passes A8.

**Honest limit.** There is no purely header-field predicate that separates the transaction ACK from a
*window update* — a window update is also `flags 0x10`, `len 0`, `seq == SND.NXT`, `ack == EXP_ACK`.
The relay's advertised window does move (7230 – 8688 across the corpus `[M]`), so window updates are
possible in principle; none appeared in the corpus. All **740** relay pure ACKs are fully accounted for
as 622 transaction ACKs + 57 handshake / teardown / `LINK_STATUS` ACKs + 61 keepalives — **zero
residue** `[M]`. The one-shot `AWAITING_ACK` state (A9) is what covers this case, and it cannot be
engineered away: transaction state is load-bearing.

### 1.5 The flags mask: `0x17` → `0x3F`

TCP flag byte: `CWR 0x80 | ECE 0x40 | URG 0x20 | ACK 0x10 | PSH 0x08 | RST 0x04 | SYN 0x02 | FIN 0x01`.

* Baseline `(flags & 0x17) == 0x10` constrains only FIN, SYN, RST and ACK. It **admits** a zero-payload
  `PSH|ACK` (0x18) and a `URG|ACK` (0x30). Both are legal TCP, both carry different semantics from a
  pure ACK, and `URG` is a standard evasion primitive (RFC 6093 explicitly deprecates urgent-pointer
  reliance for exactly this reason). PSH is not hypothetical on this device: **every one of its 56 FIN
  frames in the corpus is `FIN|PSH|ACK` (0x19)** `[M]`, so the relay's stack does set PSH on control
  segments.
* **Use `(flags & 8w0x3F) == 8w0x10`.** This rejects FIN, SYN, RST, PSH and URG while remaining
  tolerant of ECE/CWR, which do not change "this is a pure acknowledgment". Failing *open* on an
  ECN-marked ACK would lose protection for no correctness gain.
* `0xFF` would also work on this path today — ECN is not negotiated (master SYN `flags 0x0002`, relay
  SYN-ACK `flags 0x0012`, no ECE/CWR `[M]`) — but `0x3F` is the semantically correct mask and does not
  silently break if ECN is ever enabled upstream.
* The change is free: it is the same parser `select` keyset, with the mask constant edited on 11 lines
  (baseline lines 486–496). It does not add a parser match register or a state.
* Note A5 already excludes payload-bearing PSH via `total_len == 20 + 4·data_offset`; the mask change
  closes only the **zero-payload** PSH/URG hole. Both are needed.

---

## 2. The protected RESPONSE predicate

| # | §8 conjunct | Concrete field test | Corpus check |
|---|---|---|---|
| **R1** | relay-facing ingress | `ingress_port == PORT_RELAY` ∧ `meta.dequeued == 0` | — |
| **R2** | valid IPv4/TCP | identical to A2, including the new `frag_offset == 0` ∧ `MF == 0` | — |
| **R3** | protected reverse session | `src == RELAY_IP` ∧ `dst == MASTER_IP` ∧ `tcp.src_port == 20000` ∧ `tcp.dst_port == reg_session_port` | — |
| **R4** | flags | **`(hdr.tcp.flags & 8w0x27) == 8w0x10`** — require ACK, reject FIN/SYN/RST/URG, **allow PSH** | 622/622 observed `flags == 0x18` `[M]` |
| **R5** | payload present, supported size class | exact-match `tbl_resp_shape` on `(ipv4.total_len, tcp.data_offset)`, installed at calibration; miss → bypass + `UNSUPPORTED_SEGMENTATION` | 2 shapes in corpus: `(16w186, 4w8)` and `(16w106, 4w8)` `[M]` |
| **R6a** | expected TCP sequence | `hdr.tcp.seq_no == reg_exp_relay_seq` | **622/622** `[M]` |
| **R6b** | expected TCP acknowledgment | `hdr.tcp.ack_no == reg_exp_ack` | **622/622** `[M]` |
| **R7** | DNP3 link layer | `dnp3_dl.start == 16w0x0564` ∧ `dnp3_dl.length ≥ 8w8` ∧ `dnp3_dl.dst_addr == 16w0x0100` ∧ `dnp3_dl.src_addr == 16w0x0000` ∧ `(dnp3_dl.ctrl & 8w0x80) == 0` (DIR = 0, from outstation) | 622/622; link ctrl always `0x44` `[M]` |
| **R8** | single transport segment | **`(dnp3_tp.tp_ctrl & 8w0xC0) == 8w0xC0`** (FIR = 1 ∧ FIN = 1) | 622/622; low 6 bits are the transport sequence and span `0x00–0x3F`, so the mask **must** be `0xC0` `[M]` |
| **R9** | **solicited** RESPONSE, single application fragment | `func_code == 8w129` ∧ **`(app_control & 8w0xF0) == 8w0xC0`** (FIR = 1, FIN = 1, CON = 0, UNS = 0) | 622/622 `[M]` |
| **R10** | active current generation | `app_control == reg_gen`, i.e. `tag_diff == 0` with `gen_in = hdr.dnp3_app.app_control` (baseline line 528) | READ and RESPONSE app-control bytes match per transaction `[M]` |
| **R11** | one-shot response state | `txn_state ∈ {ACK_HELD, ACK_RELEASED}` ∧ `response_seen == 0`; set `response_seen = 1` on admission | — |

### 2.1 Identifying a *solicited* response

Three independent, all-cheap indicators; require all three (they share one parser `select` keyset with
the existing ARM entry, so the cost is one extra const entry):

1. **Function code 129** (`RESPONSE`). IEEE 1815-2012 clause 4 (application layer), function-code
   table: FC 129 is the solicited response and FC **130** (`UNSOLICITED_RESPONSE`) the unsolicited one.
   `[U]` on the exact sub-clause number — verify against the standard before it appears in a paper. FC 130 is a distinct value
   and is rejected by the exact match.
2. **`UNS = 0`** — application-control bit 4. IEEE 1815 requires UNS = 1 in every unsolicited response;
   the pair (FC 129, UNS 0) is redundant by design and catches a non-conforming stack that reuses
   FC 129.
3. **Generation match `app_control == reg_gen`** — the low nibble is the application sequence number,
   which an outstation must echo from the request it is answering (IEEE 1815-2012 clause 4, application
   sequence-number rules). Unsolicited
   responses use an *independent* sequence counter, so a stray unsolicited fragment will almost
   certainly fail R10 as well.

Corpus support: 622/622 responses are FC 129 with `app_control ∈ {0xC0…0xCF}`; **zero FC 130 and zero
CON = 1 in the entire corpus (622 responses, 8 PCAPs)** `[M]`. Unsolicited is disabled on this relay for these campaigns; the
predicate does not depend on that remaining true, because R9 rejects FC 130 explicitly.

### 2.2 The response overtaking the held ACK — do not implement §7 CASE 2 literally

`meeting_direction.md` §7 LATE RESPONSE says "forward it normally". Implemented as `if (expired)
to_fwd()`, this is a race: `expired` flips at the deadline, but the ACK does not physically leave until
deadline + the measured **1,736 ns release tail** `[R]`
(`research/ibspg_dnp3_replay/END_TO_END_RESULT.md`). A RESPONSE arriving inside that ~1.7 µs window is
forwarded directly to the master while the ACK is still queued — **inverting the order on the wire**,
which is the one thing Defense 3 claims to preserve.

**Fix, which is also a simplification:** route *every* in-transaction RESPONSE to `Q_HOLD`
unconditionally, with no `expired` test on the response path. If the deadline has already passed,
`Q_BLOCK` is empty, so the response dequeues immediately at a cost of one dp8 loopback traversal
(408 ns `[R]`). This satisfies §7 CASE 2's intent to within 0.4 µs, removes a branch, and removes the
race. Direction §13 GATE 4-A aims squarely at this window; keep the test, drop the racy code path.

**Retransmitted RESPONSE.** None observed (`tcp.analysis.flags` empty across `cwi_C3.pcap` — 0
retransmissions, 0 duplicate ACKs, 0 reorder `[M]`). If one occurs it carries the same `tcp.seq`, so
R6a still matches; **R11 (`response_seen == 1`)** rejects it. It must then be **forwarded, never
dropped and never re-held** — dropping a retransmission would be the only way this design could cause
a real TCP failure.

---

## 3. Segmentation scope — single-segment only, enforced and counted

**Confirmed from repo evidence:** the observed Class-0 / Group-30 response is a single TCP segment
carrying a single DNP3 link frame, a single transport segment and a single application fragment, in
**622/622** responses across eight PCAPs and two independent campaigns `[M]`:

| Campaign | n | TCP payload | wire frame | `dnp3_dl.length` | `tp_ctrl & 0xC0` | `app_control & 0xF0` |
|---|---:|---:|---:|---:|:--|:--|
| `clrt_300poll` (Class-0 integrity, `3c 01 06`) | 300 | **134 B** | 200 B | 115 | `0xC0` (100 %) | `0xC0` (100 %) |
| `cwi_C1/C2/C3/C4` (Group 30 Var 3, idx 1–7) | 322 | **54 B** | 120 B | 43 | `0xC0` (100 %) | `0xC0` (100 %) |

Arithmetic check on the 134 B case: `LEN = 115` → 110 B user data → `⌈110/16⌉ = 7` data blocks →
14 CRC octets → `10 + 110 + 14 = 134 B`. Exactly the observed TCP payload — one link frame, nothing
trailing. This also cross-validates
`research/physical_sel751/size_inventory_20260724/SIZE_INVENTORY_REPORT.md` (200 B wire / 134 B TCP
payload / 115 B DNP3 length, 300 responses, 1 distinct wire size) `[R]`.

A DNP3 link frame is capped at 292 B — LEN is a single octet, so at most 250 B of user data →
`10 + 250 + 32 = 292 B` (IEEE 1815-2012 clause 9, data-link frame format) — far below the negotiated
MSS 1460 `[M]`, so a *single* link frame can never be TCP-segmented on this path. Segmentation can only
arise from the layers above.

**Bypass path (`UNSUPPORTED_SEGMENTATION`).** Any relay→master DNP3 frame on the protected session that
fails one of the following is forwarded transparently as `ROLE_BYPASS`, increments
`UNSUPPORTED_SEGMENTATION`, and — if a transaction is active — triggers the clean fail-open path
(retire `reg_tag`, terminate blockers, release anything in `Q_HOLD`, invalidate the generation):

| Trigger | Test | Meaning |
|---|---|---|
| multi-segment transport | `(tp_ctrl & 0xC0) != 0xC0` | FIR/FIN not both set → the response spans several transport segments |
| multi-fragment application | `(app_control & 0xC0) != 0xC0` | not a single application fragment |
| confirm-requesting response | `(app_control & 0x20) != 0` (CON = 1) | adds a master APPLICATION CONFIRM, a 4th packet — outside the Case A `READ → ACK → RESPONSE` model |
| unsolicited | `func_code != 129` | FC 130 or anything else |
| unknown size class | `tbl_resp_shape` miss on `(ipv4.total_len, data_offset)` | a shape never seen during calibration; also catches a TCP segment carrying **two** link frames, which the parser cannot see past the first |
| link-only frame | `dnp3_dl.length < 8` | the `LINK_STATUS` exchange at connection start (relay `REQUEST_LINK_STATUS` ctrl `0x49`, master reply ctrl `0x8b`, LEN = 5; one such exchange in the corpus, in the 300-poll campaign `[M]`) — already bypassed by the baseline GATE 2 |

**Claim boundary (state it in the report verbatim):** Defense 3 protects the single-segment,
single-fragment, `CON = 0` solicited Class-0 response observed on this SEL-751. Multi-segment and
multi-fragment responses are **detected and bypassed unprotected**, not handled. Nothing in this design
supports them, and no claim of support may be made from these campaigns.

---

## 4. TCP correctness of holding the ACK by D

### 4.1 What is actually being delayed

The held packet is the relay's pure ACK of the master's READ, travelling **relay → master**. Holding it
does not touch the relay's own send window or its retransmission state. It delays only when the *master*
learns its READ was received. In the early-response case (`CLRT < D`) the RESPONSE is also held, which
does put a hold on the relay's own retransmission timer — the second-order effect quantified in §4.6.

**Both packets travel the same direction**, so there is no cross-direction reordering to reason about;
the only ordering question is intra-queue, which §2.2 resolves by routing every in-transaction RESPONSE
through `Q_HOLD`.

### 4.2 Master RTT / RTO

Measured on the corpus `[M]`:

| Quantity | `cwi_C3` (n = 100) | `clrt_300poll` (n = 300) |
|---|---|---|
| READ → ACK | min 0.400, med **0.505**, p95 1.519, max 2.138 ms | min 0.415, med **0.563**, p95 3.205, max 5.150 ms |
| CLRT (ACK → RESPONSE) | min 1.021, med **1.401**, p95 7.452, max 21.695 ms | min 0.905, med **1.899**, p95 7.435, max **15.649** ms |
| master ACK-of-RESPONSE | min 25.9, med **37.3**, max 38.3 µs | not measured |
| master READ interval | med 400.001 ms, sd 0.028 ms (absolute monotonic) | not measured |
| `tcp.analysis.flags` events | **0** (no retransmit / dupack / reorder) | not measured |
| **early RESPONSE, also held** (`CLRT < D`) | D=1: 0/100 · D=2: **61/100** · D=3: **84/100** | D=1: 1/300 · D=2: **179/300** · D=3: **224/300** |

The last row matters for §4.1: at the prescribed D = 2–3 ms the RESPONSE is held too in **60–75 %** of
transactions `[M]`, so the relay's own retransmission timer is in scope, not only the master's. The hold
applied to the RESPONSE is `D − CLRT ≤ D`, i.e. at most 3 ms, which is why §4.6 still clears every
plausible relay `RTO_min` by ≥ 33×.

TCP timestamps are negotiated in both directions (`NOP,NOP,TSopt`, `data_offset == 8` on every data and
ACK frame `[M]`), so the master takes an RTT sample from every transaction. SRTT ≈ 0.5 ms, RTTVAR
sub-millisecond ⇒ `RTO = max(RTO_min, SRTT + 4·RTTVAR)` is pinned at the **Linux `TCP_RTO_MIN` floor of
200 ms** (`HZ/5`). The repo's measured **≈ 211 ms** `[R]` is consistent with that floor, but it was
**measured on loopback** and is flagged as such in
`research/tofino_dcrn_feasibility/on_switch_implementation_map.md` Q6 `[R]`. **Treat 200 ms as the
design floor and re-measure the wire RTO on Vision (kernel 6.8) before publishing any RTO-derived
bound.** `[U]` for the on-wire value.

Adding a *constant* D raises SRTT by D and leaves RTTVAR essentially unchanged (a constant offset adds
no variance once the EWMA settles; there is a transient RTTVAR bump on the first few samples after D
changes). RTO therefore does not move at all for D ≤ ~40 ms, because it stays clamped at the floor.

### 4.3 Delayed ACK

Not engaged, in either direction:

* **Relay → master:** the relay ACKs the READ in median 0.505–0.563 ms `[M]`, far inside any
  delayed-ACK timer (typically 40–200 ms). It is not a delayed ACK to begin with, so holding it does not
  interact with a delayed-ACK timer — the switch simply reschedules a packet the relay already emitted.
* **Master → relay:** the master ACKs the RESPONSE in median 37.3 µs `[M]` — immediate, i.e. Linux
  quickack, not the 40 ms delayed-ACK path. Defense 3 never delays this ACK (wrong direction), and it
  shifts in time by exactly (D − CLRT) in the early-response case.

One consequence worth recording: because the master's ACK is immediate and Defense 3 shifts it, the
tracker refresh (`reg_exp_relay_seq := master_ack.ack_no`) also shifts by the same amount. It still
lands well before the next READ (400 ms poll period vs ≤ D + ~0.1 ms), so the next transaction always
starts with a valid tracker.

### 4.4 Nagle

**Verified by source read this session**, not inherited: `opendnp3` sets no `tcp::no_delay` option
anywhere in `cpp/` — the only `set_option` calls in `~/Projects/opendnp3-community/cpp/lib/src/channel/`
are serial-port parameters and `reuse_address` on the acceptor `[M]`. **Nagle is therefore active on the
master's DNP3 socket.**

Inert for Case A as scoped: the master has at most one 18–22 B READ outstanding, `SND.UNA == SND.NXT`
when it writes, so RFC 896 permits an immediate send. Confirmed by the poll schedule — READs leave on an
exact 400 ms cadence with 0.028 ms standard deviation, i.e. never delayed by Nagle `[M]`.

**It stops being inert if** the master pipelines requests, if a response becomes multi-fragment with
`CON = 1` (the master's CONFIRM would be a small write while data is outstanding), or if D grows large
enough that a READ is issued while the previous ACK is still held. All three are outside the current
scope; the third is a reason to bound D well below the poll period (§4.6).

### 4.5 Duplicate ACKs and fast retransmit

Fast retransmit requires **three duplicate ACKs while data is outstanding** (`packets_out > 0`,
RFC 5681 §3.2). Structurally unreachable here:

* The master has exactly one small segment outstanding per 400 ms, and it is acknowledged by the
  relay's single pure ACK — or, if that ACK were lost, cumulatively by the RESPONSE's own `ack_no`
  (R6b: the RESPONSE carries the same `EXP_ACK`, 622/622 `[M]`). There is never a second data segment to
  generate a duplicate.
* The relay emits exactly one ACK per READ; Defense 3 does not duplicate it, only reschedules it.
* Measured: **0 duplicate ACKs and 0 retransmissions** in `cwi_C3.pcap` `[M]`.

The one way Defense 3 could manufacture a duplicate ACK is the §2.2 race — releasing the RESPONSE first
so that its cumulative `ack_no` already covers the READ, after which the held pure ACK arrives as a
stale ACK (`SEG.ACK ≤ SND.UNA`). Linux would classify it as a duplicate but not act on it
(`tcp_fastretrans_alert` is not entered with `packets_out == 0`), so it is harmless to TCP — but it is a
**visible artifact and an order inversion**, which is precisely why the unconditional-hold fix is
mandatory rather than cosmetic.

### 4.6 Where the risk actually starts

Ordered by how binding each limit is, with the margin at D = 3 ms:

| Limit | Value | Binding at D ≈ | Margin at D = 3 ms |
|---|---|---:|---:|
| Master RTO on the outstanding READ | **200 ms** floor (`[R]` 211 ms measured, loopback `[U]` on wire) | **≥ 200 ms** | **67×** |
| Poll period (transaction overlap → `CONCURRENT_TRANSACTION_ESCAPE`) | 400 ms `[M]` | ≥ ~40 ms (10 %) | 133× |
| Relay RTO on the *held* early RESPONSE | **never measured** `[U]`; ≥ 200 ms on any conventional stack, RFC 6298 §2.4 recommends ≥ 1 s | ≥ ~100 ms even under a pessimistic embedded `RTO_min` | ≥ 33× |
| DNP3 application response timeout (master) | 5 s in the connectivity probe `[R]` | ≥ ~5 s | ≥ 1600× |
| Fail-open blocker budget horizon | 100 000 passes ≈ 171 ms `[R]` | — | see below |

**Verdict: risk becomes real at D ≳ 40 ms** (poll-period overlap, the first limit reached), and
*dangerous* at D ≳ 200 ms (master READ retransmission). The prescribed sweep D ∈ {1, 2, 3} ms sits
1.5–2 orders of magnitude below the nearest limit, and even the mechanism study's extended sweep to
D = 22 ms `[R]` stays below the overlap threshold. **Recommend a hard control-plane clamp at
D ≤ 40 ms**, enforced in `setup/`, so a typo cannot reach the RTO region.

**Resize the fail-open budget.** The inherited 100 000-pass budget gives a ~171 ms horizon `[R]`,
sized for Defense 2's G = 25 ms and uncomfortably close to the 200 ms RTO — a fail-open that fires late
would collide with the master's retransmission rather than pre-empt it. For D ≤ 3 ms a horizon of
~10 × D (≈ 30 ms, ≈ 18 000 passes `[R]`) is ample. Make it a runtime parameter alongside D so it sweeps
without recompiling.

### 4.7 Residual protocol-layer leaks that D cannot close (disclose, do not fix)

1. **TCP timestamps.** `TSecr`/`TSval` are the relay's own clock and Defense 3 does not rewrite bytes,
   so `TSval(RESPONSE) − TSval(ACK)` survives the hold untouched. Measured `[R]`
   (`research/case_a_fixed_ack_delay/evidence/tcp_timestamp_leak_result.txt`): effective granularity
   ≈ 316.8 ms, `ΔTSval ∈ {0 (74 ×), 30 (26 ×)}`, `MI(ΔTSval; CLRT) = 0.144` bits = **6.1 % of the CLRT
   entropy**. Small, but it is a channel the mechanism structurally cannot reach.
2. **Master SRTT inflation.** The master's own RTT estimate rises by exactly D; anything that exports
   SRTT (a diagnostic, an SNMP counter, a second observer inside the master) reveals D directly.
3. **Poll-schedule coupling.** Against a master that schedules the next poll *relative to the last
   response*, the inter-poll interval lengthens by the added delay, revealing both the presence and the
   parameter. Mitigation is experimental, not architectural: **run every campaign on an absolute
   monotonic schedule** — the existing poller already does (sd 0.028 ms `[M]`).

---

## 5. Relay safety

### 5.1 Nothing in read-only Class-0 polling can reach a protection function — confirmed

Verified across the whole corpus (623 DNP3 frames each way: 622 `fc = 1` READs from the master and
622 `fc = 129` RESPONSEs from the relay, plus one link-only `LINK_STATUS` frame in each direction)
`[M]`:

* **Master → relay: function code 1 (`READ`) only.** Zero `SELECT` (3), `OPERATE` (4),
  `DIRECT_OPERATE` (5/6), `WRITE` (2), `COLD_RESTART` (13), `WARM_RESTART` (14), `ENABLE_UNSOLICITED`
  (20), `DISABLE_UNSOLICITED` (21), time-sync or any CROB object.
* **Relay → master: function code 129 (`RESPONSE`) only.** Zero FC 130, in 622/622.
* Link-layer control is `0xC4` (master) / `0x44` (relay) in every DNP3 frame: PRM = 1, **FC = 4
  `UNCONFIRMED_USER_DATA`**, FCV = 0 `[M]`. An unconfirmed user-data frame starts **no link-layer
  confirm timer** (IEEE 1815-2012 clause 9, primary-to-secondary function codes), so there is no link
  timer for D to interact with. Contrast FC 3 `CONFIRMED_USER_DATA`, which does — it is absent here.
* Application `CON = 0` in 622/622, so **no application CONFIRM** and no application confirm timer
  either.
* Link addressing: outstation **0**, master **1** on the physical relay (`dnp3_dl.dst_addr` bytes
  `00 00` / `src_addr` bytes `01 00` on the READ, reversed on the RESPONSE) `[M]`. Note for the P4:
  extracted as big-endian `bit<16>` these are `0x0000` and `0x0100` — **do not** write `16w1`.
* IEEE 1815-2012 treats the TCP connection as an opaque byte stream (clause 11, IP networking); Defense 3 modifies **no byte**, only egress time.
  The DNP3 application layer cannot observe the difference except as latency.
* The relay's DNP3 configuration is never touched: Defense 3 requires no settings change, and
  `meeting_direction.md` §17 already stops the work if one is ever required.

### 5.2 The real operational hazards, ranked

1. **Being inline at all.** The Tofino sits in the protection relay's SCADA path. A pipeline reload, a
   `bf_switchd` restart, a port flap or a queue-config error black-holes the poll. Mitigations already
   mandated by direction §17 (pre-run snapshot, trap-based restore, exactly one `bf_switchd`
   verification, explicit Defense 2 restoration) are the right ones; add a **fail-open watchdog on
   `Q_HOLD` itself** so a stuck blocker reservoir cannot strand a real ACK indefinitely.
2. **Reconnect storm on master timeout.** Demonstrated on this relay: opendnp3's default `ChannelRetry`
   produced **434 SYNs in ~7.9 s ≈ 55 connections/s** when the relay closed sessions
   (`research/physical_sel751/SEL751_DIRECT_CONNECTIVITY_REPORT.md`) `[R]`. If Defense 3 ever drops or
   strands a packet long enough for the master's channel to fail, this is the failure mode — a
   connection flood at a protection relay, not a millisecond of latency. **Use a no-retry / long-minimum
   `ChannelRetry` in every Defense 3 campaign poller**, and count `SYN` rate as a run-abort gate.
3. **Session-state desynchronization.** The `reg_exp_relay_seq` tracker is now load-bearing. If the
   master reconnects and the switch misses the SYN (mirrored, dropped, arriving during a reload), the
   tracker holds a stale value and **every** ACK fails A7 → the defense is silently absent. Mitigate
   with a counter `ACK_SEQ_MISMATCH` and a run-abort gate at > 0 outside the keepalive class, plus the
   SYN-triggered reset in §1.2.
4. **Silent zero-hold (risk R1 from the mechanism study).** Defense 2 held the RESPONSE ~2 ms after the
   READ, so the K = 64 reservoir always had time to stand up. Defense 3 holds the **ACK**, which arrives
   after the READ at median 0.505 ms (C3) / 0.563 ms (300-poll) and **minimum 0.400 ms** `[M]` —
   roughly 4× sooner than the packet Defense 2 held. If clone → recirculation → trigger
   → 64 admissions has not completed, the ACK enters an unblocked `Q_HOLD` and leaves immediately —
   a run that looks successful with a small measured delay. **Free check, no new code:** after the first
   poll require `(reg_ts_ack_arm − reg_ts_first_block) mod 2³² > 0` `[R]`. This is a protocol-timing
   constraint on Panel B's reservoir, so I flag it here: **the reservoir must be standing within
   400 µs of the READ**, not 2 ms.
5. **Connection-cold first poll.** The first poll on a new connection has median CLRT 25.25 ms and
   max 87.7 ms `[R]` (`evidence/corrected_v2/COLD_WARM_IDLE_CHARACTERIZATION.md`), i.e. `CLRT ≫ D` for
   every D in the sweep. It is unprotected by construction and must be reported separately, never
   pooled. It is also the best in-vivo falsification probe for the "predetermined, not
   response-triggered" claim — a predetermined deadline gives ACK hold = D there too.
6. **Not a hazard, worth stating:** nothing about Defense 3 is unsafe to the *relay*. The relay never
   sees a modified byte, never sees a delayed packet in the master→relay direction, and never has a
   timer engaged. The exposure is availability of the SCADA path, not integrity of the device.

---

## 6. Model and assumptions

| Item | Assumption | Status |
|---|---|---|
| Device | one physical SEL-751, separate-ACK (Case A) | measured `[M]` |
| Traffic | sequential read-only Class-0 / Group-30 polls, one TCP session, absolute monotonic 400 ms schedule | measured `[M]` |
| Response shape | single TCP segment, single transport segment, single application fragment, CON = 0 | 622/622 `[M]` |
| Master stack | Linux, TS + SACK + WS negotiated, quickack, `RTO_min` 200 ms, Nagle **enabled** (opendnp3 sets no `TCP_NODELAY`) | `[M]` source + PCAP |
| Master RTO on the wire | ≈ 211 ms measured on **loopback** | `[U]` — re-measure on Vision |
| Relay `RTO_min` | never measured | `[U]` |
| Relay keepalive | ~10.02 s (also 14.999 s seen), `seq = SND.NXT − 1` | 61/61 `[M]` |
| ECN | not negotiated on this path | `[M]` |
| Window updates from relay | possible (window 7230–8688) but never observed as a distinct pure ACK | `[M]` |
| Release tail | 1,736 ns on-chip; dp8 loop RTT 408 ns | `[R]` |
| Multi-segment / multi-fragment | **not supported**; detected and bypassed | design decision |

---

## 7. Recommendations, with the clauses that back them

1. **Add `tcp.seq == reg_exp_relay_seq` (A7) to the ACK predicate, maintained from the master's pure
   ACK.** This is the decisive keepalive discriminator (61/61 vs 61/61), needs no arithmetic, and is
   the direct implementation of `meeting_direction.md` §8 "expected relay TCP sequence". Rationale for
   the keepalive's shape: RFC 1122 §4.2.3.6.
2. **Tighten the pure-ACK flags mask from `0x17` to `0x3F`** on baseline lines 486–496. Rejects
   zero-payload `PSH|ACK` and `URG|ACK`; tolerates ECE/CWR so a future ECN deployment fails safe rather
   than open. RFC 6093 on urgent-pointer semantics; §8 "ACK-only flags".
3. **Add `frag_offset == 0` and `MF == 0` to `parse_ipv4`** in both predicates — one extra select field,
   closes an untested path (RFC 1858 class of overlap attack). §8 "IPv4/TCP structure valid".
4. **Learn `reg_session_port` and reset all state on the master's SYN.** Makes the 5-tuple conjunct
   complete without any controller action (§2 "no per-transaction controller action" is respected — this
   is per-session and in-data-plane), and gives the tracker a clean reset point.
5. **Retire `reg_tag` on the successful ACK-release / response-release pass**, not only on fail-open.
   Without it a keepalive still passes A8. §7 "invalidate the generation safely"; baseline line 897.
6. **Route every in-transaction RESPONSE to `Q_HOLD` unconditionally** — no `expired` test on the
   response path. Removes the 1.7 µs overtake race, removes a branch, and satisfies §7 CASE 2 to within
   0.4 µs. Direction §13 GATE 4-A stays as the test.
7. **Gate the RESPONSE on `(tp_ctrl & 0xC0) == 0xC0`, `(app_control & 0xF0) == 0xC0`, `func_code == 129`
   and a calibrated `(total_len, data_offset)` shape table.** Anything else bypasses and counts
   `UNSUPPORTED_SEGMENTATION`. IEEE 1815-2012 clause 4 (application sequence echo; FC 129 vs 130)
   and clause 9 (LEN ≤ 255). §8 "state the response-segmentation scope explicitly".
8. **Forward, never drop, a retransmitted RESPONSE or a second qualifying ACK.** One-shot state rejects
   the *hold*, not the *packet*. This is the only path by which Defense 3 could cause a real TCP failure.
9. **Clamp D ≤ 40 ms in the control plane** and resize the fail-open budget from ~171 ms to ~10 × D
   (≈ 30 ms, ≈ 18 000 passes). §4.6.
10. **Re-measure the master RTO on the wire** (Vision, kernel 6.8) before any RTO-derived bound appears
    in the report; the 211 ms figure is loopback-measured `[U]`.
11. **Add three microbenchmarks the direction's §13 list does not cover:** a qualifying pure ACK with no
    active transaction; a keepalive arriving mid-hold; a keepalive arriving between ACK release and
    RESPONSE arrival. All three are naturally generated by the device every ~10 s — they are not
    synthetic.
12. **Report as residual leaks, not as fixed:** `ΔTSval` (0.144 bits, 6.1 % of CLRT entropy), master
    SRTT inflation by D, and poll-schedule coupling. §16 forbids claiming indistinguishability, and
    these are the concrete reasons.

---

### Appendix — reproduction

All `[M]` figures come from `tshark` over the PCAPs named at the top, paired by DNP3 function code
(READ = 1, RESPONSE = 129) rather than by packet order; pairing by order alone produces a spurious
389.6 ms "CLRT" in the 300-poll capture by matching the `LINK_STATUS` ACK to the first Class-0 response.
Under strict function-code pairing the 300-poll campaign gives n = 300, CLRT median 1.899 ms,
max 15.649 ms. Analysis scripts were run in the session scratchpad and are not committed; they are ~40
lines of `tshark` field extraction and can be regenerated from the predicates above.

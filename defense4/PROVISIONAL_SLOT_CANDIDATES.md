# Defense 4 — PROVISIONAL slot-pattern candidates (for review, NOT frozen)

**2026-08-04. Output of the offline transaction oracle (`defense4/analysis/txn_oracle.py`) run on the
corrected corpus. Per directive §7/§8 these candidates are PROVISIONAL — presented for your review
before any freeze. Nothing here is committed as the public slot pattern.**

Evidence base (all read-only, no switch, no SEL actuation):
- SBO corpus: `defense4/evidence/sbo_corpus/multicrob_n{1,2,4,8,16,17,32}.pcapng`
- READ corpus: `defense3/evidence/pure_defense3/20260804T155605Z/pure_defense3_D16ms.pcap` (60 reads)
- Frozen annotation: `defense4/evidence/oracle/annotated_corpus.json` (98.6 kB, machine-readable)

---

## 1. What the oracle actually observed (measured, this session)

### READ transaction — physical SEL-751, **Case A / separate ACK**, Defense-3 protected
60 identical transactions, 4 observable units:

| slot | dir | role | inner frame_len (excl FCS) | tcp payload | timing from prev |
|---|---|---|---|---|---|
| 0 | M→O | READ | 84 B | 18 B | — |
| 1 | O→M | **separate ACK** (pure TCP ACK) | 66 B | 0 B | **16.517 ms median** (= D hold) |
| 2 | O→M | RESPONSE | 200 B | 134 B | 0.032 ms (residual CLRT) |
| 3 | M→O | ACK-back (pure TCP ACK) | 66 B | 0 B | 0.024 ms |

The 16.5 ms READ→ACK gap **is** the Defense-3 predetermined hold D=16 ms; the residual ACK→RESPONSE
interval is **32 µs** (the CLRT content Defense 3 compressed away). READ and RESPONSE sizes are
**constant** across all 60 reads (0-bit size channel on the READ line, consistent with E0).

### SBO transaction — Hulk emulator, **Case B / piggybacked ACK**
6 observable units (N = 1..16, the successful envelope):

| slot | dir | role | inner frame_len N=1 → N=16 | tcp payload N=1 → N=16 |
|---|---|---|---|---|
| 0 | M→O | SELECT | 101 → 320 B | 35 → 254 B |
| 1 | O→M | SELECT-RESPONSE (piggyback ACK) | 103 → 322 B | 37 → 256 B |
| 2 | M→O | ACK | 66 B | 0 B |
| 3 | M→O | OPERATE | 101 → 320 B | 35 → 254 B |
| 4 | O→M | OPERATE-RESPONSE (piggyback ACK) | 103 → 322 B | 37 → 256 B |
| 5 | M→O | ACK | 66 B | 0 B |

Size grows **14.6 B / CROB** on both request and response (the real SBO size channel). **N ≥ 17 is
rejected** by the outstation: the oracle sees `SELECT → RESPONSE → ACK → ACK` with **no OPERATE**
(N=17), and `N=32` additionally shows TCP-segmentation of the oversized SELECT (an undissected
`tcp_only` 292 B segment). Rejected transactions are held as a separate corpus, not mixed into the
public envelope.

### The three ACK modes the template must survive (directive §7)
The oracle explicitly separates them, and all three appear in the corpus:
- **separate/pure ACK** — READ line, unit 1 (the CLRT-bearing ACK; the whole Defense 1/2/3 target)
- **piggybacked ACK** — SBO line, the RESPONSE frames carry PSH+ACK on data
- **missing ACK** — N=17 rejected line ends on bare ACKs with no OPERATE/second RESPONSE

---

## 2. The hard constraint the candidates must resolve

READ and SBO are **not the same shape**: 4 units vs 6 units, separate-ACK vs piggyback-ACK, and — a
real corpus limitation — they were measured on **different devices** (physical Case-A relay vs Case-B
emulator). To make `Obs(READ) ≈ Obs(SBO)` an observer must see the **same slot grid** for both: same
slot count, same per-slot public sizes, same slot times, with filler slots padding the shorter
operation up to the longer one. The candidates below differ in how aggressively they normalize.

Public **outer** wire sizes are derived, not observed: `wire = inner_frame_len + OUTER_HDR + FCS`,
clamped to `[64, 1500]`. Using a provisional 8-byte Defense-4 outer shim (`dir1+tag2+slot1+realfill1+
size2`, rounded 7→8) and the 4-byte FCS convention:

| logical slot | inner target | public outer wire |
|---|---|---|
| request (pad to N=16) | 320 B | **332 B** |
| response (pad to N=16) | 322 B | **334 B** |
| READ request | 84 B | 96 B |
| READ response | 200 B | 212 B |
| pure ACK | 66 B | 78 B |

*(N=17's 335 B SELECT is excluded — it is a rejected transaction; the request ceiling is the N=16
success boundary, 320 B. Flag for review: if Defense 4 must also hide rejected attempts, raise the
request ceiling.)*

---

## 3. PROVISIONAL candidates

### Candidate A — **6-slot unified grid, size-and-time normalized** (recommended)
Both operations occupy a fixed **6-slot** grid on the slot clock. READ fills slots 0–3 with real
units and slots 4–5 with **filler** (pure-ACK-shaped or minimum-size cells); SBO fills all 6. Every
request slot is padded to the 332 B public size, every response slot to 334 B, every ACK slot to
78 B — so CROB count (14.6 B/CROB) and READ-vs-SBO unit count are both erased at the measurement
boundary. Slot **times** come from the Defense-3 grid: the first O→M release lands at D on the slot
clock; subsequent slots at fixed grid offsets.

- Hides: CROB count, READ-vs-SBO distinction, separate-vs-piggyback ACK mode, CLRT.
- Cost: READ pays 2 filler slots + pads 84→332 / 200→334; every transaction pays the response pad.
- Residual: total transaction *duration* still bounded by D grid; k=1 (one flow) so no anonymity claim.

### Candidate B — **role-typed slots, size normalized only** (cheaper, weaker)
Keep each operation's real unit count (READ=4, SBO=6) but normalize **sizes** per role so a SELECT and
a READ request are indistinguishable by length, likewise responses. Does **not** equalize unit count,
so an observer still separates READ (4 units) from SBO (6 units) by counting.
- Hides: CROB count, per-role size. Does **not** hide operation type.
- Use only if unit-count leakage is deemed acceptable — it is a strictly weaker `Obs` guarantee.

### Candidate C — **max-envelope single super-slot** (simplest, most expensive)
Every transaction is emitted as one fixed 6-slot, fixed-size, fixed-time cell regardless of content;
filler pads everything to the SBO N=16 ceiling.
- Hides: everything the others do, plus transaction *type* fully.
- Cost: every READ pays the full SBO envelope (6×, up to 334 B/slot) — heaviest overhead; likely
  violates DNP3 poll-rate timing budgets. Listed for completeness.

---

## 4. Recommendation for review

**Candidate A** is the one that matches the Defense 4 objective (`Obs(READ) ≈ Obs(SBO)`) at the lowest
cost that still equalizes both axes. Before it can be frozen, three things must close (directive §7/§9):

1. **Same-device co-measurement.** READ (Case A relay) and SBO (Case B emulator) were captured on
   different devices. A defensible `Obs(READ) ≈ Obs(SBO)` needs both operations measured on **one**
   device/path, or an explicit argument that the grid is device-independent (E0 is a falsifier for
   that, not proof).
2. **The size data path (MB-8 offline gate).** Exact outer format, real padding bytes, encoder/decoder
   ports, padding removal, byte-identical restoration, real/filler discrimination, MTU/oversize
   handling — none proven yet. MB-1 proved only that the outer-field *assignment* is cheap.
3. **Filler semantics.** Candidate A's filler slots must be indistinguishable from real ACK slots at
   the boundary and must carry no DNP3 object (no decoy CROBs — safety boundary held).

Once you pick a candidate, the oracle re-runs on the pass-gate-validated corpus (task #19) and the
chosen pattern is frozen with its envelope table.

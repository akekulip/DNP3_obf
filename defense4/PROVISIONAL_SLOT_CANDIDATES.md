# Defense 4 — PROVISIONAL slot-pattern candidates (for review, NOT frozen)

**2026-08-04, corrected after review. Output of the offline transaction oracle
(`defense4/analysis/txn_oracle.py`, v2) on the corrected corpus. Per directive §7/§8 these are
PROVISIONAL — presented for review before any freeze. Nothing here is committed. Candidate **A2**
supersedes the earlier Candidate A, which had a direction-mapping error (see §5).**

Evidence base (read-only; no switch, no SEL actuation):
- READ corpus: `defense3/evidence/pure_defense3/20260804T155605Z/pure_defense3_D16ms.pcap` — **60
  transactions, all four units** (closure bug fixed; was reported as "60 identical" but the parser had
  left one six-unit record).
- SBO corpus: `dnp3_multicrob_harness/captures/sweep/multicrob_n{1..16}.pcapng` — the **full 16-count
  successful range** (not just powers of two); rejected N=17/32 kept separate.
- Frozen annotation: `defense4/evidence/oracle/annotated_corpus.json` (78 txns: 60 READ + 16 SBO
  success + 2 rejected). Each unit now carries **txn_id, phase, ack_assoc, fragment, outer_len,
  expected_slot**.

---

## 1. FROZEN wire format (chosen so sizes can be computed) — format (b)

The size numbers cannot be derived until one encapsulation format is fixed. **Frozen choice: outer
Ethernet + Defense-4 header + complete inner Ethernet frame** — the only option that yields a valid
Ethernet wire layout *and* trivial byte-identical restoration:

```
[ outer Ethernet 14 B ][ D4 header 8 B ][ complete inner frame = frame_len ][ outer FCS 4 B ]
```

- **Decode** = strip outer Ethernet + D4 header → the inner frame is byte-identical (no inner-checksum
  recompute). Padding bytes live after the inner frame; the D4 header carries the true inner length so
  the decoder removes them exactly.
- **Overhead** `OUTER_OVERHEAD = 14 + 8 + 4 = 26 B`, added to every inner `frame_len` to get the
  public on-wire `outer_len`.
- Rejected: the current MB-1 P4 prepends a 6-byte shim *before* Ethernet — not a valid wire frame, no
  decode path, `realfill` visible in clear. **MB-8 must implement format (b) precisely** (real padding
  bytes, encoder/decoder ports, padding removal, byte-identical restore, hidden real/filler); until
  MB-8 runs, all `outer_len` values below are provisional.
- **Overflow rule (corrected):** a unit whose inner `frame_len` exceeds its slot's public target, or
  whose `outer_len` would exceed the link **MTU 1500**, **FAILS OPEN (bypasses, unshaped)** — it is
  never silently clamped to a smaller size. (No unit in this corpus overflows; max `outer_len` = 348.)

---

## 2. What the oracle observed (corrected)

### READ — physical SEL-751, Case A / separate ACK, Defense-3 protected (60 txns, all 4 units)
| slot | dir | phase | inner frame_len | outer_len | measured time from slot 0 |
|---|---|---|---|---|---|
| 0 | M→O | read_req | 84 B | 110 B | 0 ms |
| 1 | O→M | **separate ACK** | 66 B | 92 B | **16.517 ms median** (= D hold) |
| 4 | O→M | read_resp | 200 B | 226 B | 16.548 ms (≈ ACK + 31 µs) |
| 5 | M→O | final ACK | 66 B | 92 B | 16.573 ms |

READ uses slots **0, 1, 4, 5**; slots 2, 3 are **filler** for READ.

### SBO — Hulk emulator, Case B / piggyback ACK (16 counts, all 6 units)
| slot | dir | phase | inner frame_len N=1 → N=16 | measured time (N=8) |
|---|---|---|---|---|
| 0 | M→O | select | 101 → 320 B | 0 ms |
| 1 | O→M | select_resp | 103 → 322 B | 3.367 ms |
| 2 | M→O | sbo_ack | 66 B | 3.568 ms |
| 3 | M→O | operate | 101 → 320 B | 3.845 ms |
| 4 | O→M | operate_resp | 103 → 322 B | 7.218 ms |
| 5 | M→O | final ACK | 66 B | 12.991 ms |

14.6 B/CROB on requests and responses, confirmed across the full N=1..16 (not just powers). SBO timing
is raw emulator (ungridded). N≥17 rejects: `SELECT → RESPONSE → ACK`, no OPERATE (`maxControlsPerRequest
=16`); N=32 additionally shows a `tcp_frag` segment (oracle flags `fragment=true`).

---

## 3. Candidate A2 — corrected 6-slot unified grid (recommended)

Both operations occupy the **same** six public slots. Each slot has a fixed **(direction, public size,
time τ)**. READ maps its four real units to slots 0/1/4/5 and the switch emits **filler** at slots 2/3;
SBO fills all six. Every real unit is padded UP to its slot's public size — so **slot 1 exposes ONE
size (348 B) for both the READ separate-ACK and the SBO SELECT-response**, which is the property the
earlier Candidate A violated.

| slot | direction | public inner target | **public outer_len** | READ content | SBO content | provisional τ |
|---|---|---|---|---|---|---|
| 0 | M→O | 320 B | **346 B** | read_req (pad 84→320) | select | τ0 = 0 |
| 1 | O→M | 322 B | **348 B** | **sep ACK (pad 66→322)** | select_resp | τ1 = D |
| 2 | M→O | 66 B | **92 B** | **filler** | sbo_ack | τ2 = D + Δ |
| 3 | M→O | 320 B | **346 B** | **filler** | operate | τ3 = D + 2Δ |
| 4 | O→M | 322 B | **348 B** | read_resp (pad 200→322) | operate_resp | τ4 = D + 3Δ |
| 5 | M→O | 66 B | **92 B** | final ACK | final ACK | τ5 = D + 4Δ |

**Public inner target per slot = max inner frame_len over both operations at that slot; public outer =
inner + 26.** Direction and size are now fixed and identical for READ and SBO at every slot — the
requirement the review named ("a public timing pattern is not derived until each slot has a fixed
direction, size and time").

### Provisional slot times τ (grid parameters, NOT frozen)
τ is a **linear grid**: `τ0 = 0`, `τ_i = D + (i−1)·Δ` for i≥1. The first O→M unit (READ's separate ACK
/ SBO's SELECT-response) is released at the deadline **D**; each later slot is one grid tick **Δ**
after. Example from the measured data: **D ≈ 16 ms** (the Defense-3 value) and **Δ** a grid tick chosen
in the low-ms range. Admissibility bounds the grid, not the reverse:
- `τ5 = D + 4Δ < RTO_min − margin` (RTO_min ≈ 200 ms → ample room);
- SELECT→OPERATE gap `τ3 − τ1 = 2Δ` must fit the SEL-751 `selectTimeout` budget (device value BLOCKED
  — must be read before any live SBO);
- causality holds: τ3 (OPERATE) > τ1 (SELECT-response), so the master has the SELECT-response before
  the grid emits OPERATE.

τ0..τ5 stay **provisional** until the size data path (MB-8) and the four-level-priority + grid
microbench (MB-3) run. They cannot be frozen from READ+SBO traces alone because READ was Defense-3
timed and SBO was ungridded on a different device (see §5 caveat).

---

## 4. Alternatives (unchanged in spirit, corrected mapping)
- **Candidate B2 — role-typed, size-normalized only:** keep each operation's real unit count (READ=4,
  SBO=6) and normalize only per-slot size. Cheaper, but an observer still separates READ from SBO by
  unit count — a strictly weaker `Obs` guarantee. Use only if unit-count leakage is acceptable.
- **Candidate C2 — max-envelope single super-slot:** every transaction emitted as one fixed 6-slot,
  fixed-size, fixed-time cell padded to the SBO ceiling. Hides transaction type fully; heaviest
  overhead (every READ pays the full SBO envelope) and likely violates poll-rate budgets.

---

## 5. What still blocks a freeze (review-driven)

1. **Same-device co-measurement.** READ (Case-A physical relay, Defense-3 timed) and SBO (Case-B
   emulator, ungridded) are on **different devices with different ACK modes**. The τ vector and the
   slot-1 size unification are *designed*, not co-measured; a defensible `Obs(READ) ≈ Obs(SBO)` needs
   both operations on one device/path (or an explicit device-independence argument).
2. **MB-8 (size data path).** Format (b) must be implemented and proven offline: real padding, exact
   `outer_len` per slot, encode/decode ports, padding removal, byte-identical restore, hidden
   real/filler, MTU/oversize fail-open. The `outer_len` numbers here are provisional until then.
3. **MB-1 v2 (semantically complete ingress core) — RESOLVED.** The complete core (flow-keyed state,
   internal generation not app_control, SELECT-response-preserving FSM, ack_gone, universal fail-open,
   epoch cleanup, working slot state, 4 QIDs, exact match+cleanup) compiles at **10/12 ingress, CP 8**
   (`mb1_v2_unified_core.p4`, verified). Ingress resource feasibility is no longer a blocker; the
   remaining blockers are (1) same-device co-measurement, (2) MB-8 size data path, (4) filler semantics.
4. **Filler semantics.** Slots 2/3 filler (Candidate A2) must be indistinguishable from real ACK/OPERATE
   cells at the boundary and carry **no DNP3 object** (no decoy CROBs — safety boundary held).

**Candidate A2 is the right direction, but it is not ready to select or freeze until (1)–(4) close.**

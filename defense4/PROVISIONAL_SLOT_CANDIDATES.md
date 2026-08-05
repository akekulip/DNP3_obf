# Defense 4 — PROVISIONAL slot-pattern candidates (Candidate A3, for review, NOT frozen)

**2026-08-04, corrected again after review. Output of the offline transaction oracle
(`defense4/analysis/txn_oracle.py`, v3) on the corrected corpus + a persistent-connection SBO rerun.
Per directive §7/§8 these are PROVISIONAL. Candidate **A3** supersedes A2 (A2's slot-5 was derived from
per-transaction-teardown traces where the SBO terminal ACK was masked by a FIN).**

Evidence (read-only; no switch, no SEL actuation):
- READ: `defense3/evidence/pure_defense3/…/pure_defense3_D16ms.pcap` — 60 txns, persistent connection,
  **slot-5 is a real final ACK (60/60)**.
- SBO (persistent): `defense4/evidence/sbo_corpus_persistent/multicrob_persist_n{1,8,16}.pcapng` — captured
  with the new `run_master.py --hold-open-ms 300`, so the kernel emits a standalone pure ACK of the
  OPERATE-response before teardown. **slot-5 is a real final ACK (3/3)**.
- SBO (original per-txn teardown): `dnp3_multicrob_harness/captures/sweep/multicrob_n{1..16}` — retained
  to document the LEAK: every one closes by TCP teardown, slot-5 absent (0/16).
- Frozen annotation: `defense4/evidence/oracle/annotated_corpus.json`.

---

## 1. The connection-lifecycle correction (review-driven)

The oracle v2 labelled the SBO's slot-5 a `final_ack`, but a decode of the committed N=8 capture showed
that unit is the **third TCP-teardown packet** (Master ACK of the outstation's FIN) — its own JSON had
`acks_phase: null`. The v2 harness opened a **new TCP connection per transaction and tore it down**
(FIN/FIN/ACK) after each SBO, so the OPERATE-response's ACK was carried on the FIN and there was no clean
DNP3 final ACK.

Two fixes, both applied:
1. **Oracle (v3):** SYN/FIN/RST are connection-control, never DNP3 units; a pure ACK is resolved against
   the data it acknowledges (`tcp.ack == seq+len`); piggyback-ACK detection uses the **ACK flag**, not
   PSH; a transaction closes only on an ACK acknowledging the terminal response, else on teardown with
   **slot-5 marked ABSENT**. Result on the old traces: SBO closed_by=teardown, slot-5 absent (16/16) —
   the leak is now surfaced, not mislabelled.
2. **Harness (`--hold-open-ms`) + persistent rerun:** holding the connection open 300 ms after the SBO
   makes the kernel emit the standalone pure ACK of the OPERATE-response before teardown. **Result: SBO
   slot-5 becomes a real final ACK (N=1/8/16), identical to READ.**

**Answer to the review's question — is SBO slot-5 a real terminal ACK or filler? It is a REAL terminal
ACK.** The per-transaction teardown was masking it. Candidate A3 therefore uses a **real** ACK at slot 5
for both operations, and records the connection-lifecycle finding below.

**Connection-lifecycle finding (a leak Defense 4 must handle):** a per-transaction TCP teardown is itself
a strong observable (SYN/FIN/RST pattern + connection count). Defense 4 must either (a) assume a
**persistent** master↔outstation connection (as the physical READ path already is), or (b) normalize
connection-control packets into the slot grid as their own cells. A3 assumes (a); (b) is noted as an
alternative for MB-8.

---

## 2. FROZEN wire format — format (b), 8-byte D4 header with inner_len

```
[ outer Ethernet 14 B ][ D4 header 8 B ][ complete inner frame = frame_len ][ outer FCS 4 B ]
```
- The **8-byte D4 header carries the true inner length** (`inner_len`, 16-bit) so the decoder removes
  padding byte-exactly, plus {direction, txn_tag, slot_id, realfill} and pad to 8 B. (MB-1 v3 must
  materialize this exact 8-byte header — v2's 6-byte header without `inner_len` is a defect being fixed.)
- **Overhead** `OUTER_OVERHEAD = 14 + 8 + 4 = 26 B`; public `outer_len = frame_len + 26`.
- **Decode** = strip outer Ethernet + D4 header, truncate to `inner_len` → inner frame byte-identical.
- **Ethernet size terminology (corrected):** the payload **MTU is 1500 B**; the maximum standard frame is
  **1514 B excluding FCS / 1518 B including FCS**. A unit whose inner `frame_len` exceeds its slot's
  public target, or whose outer frame would exceed the max frame size, **FAILS OPEN (bypasses,
  unshaped)** — never silently clamped. (Max `outer_len` in this corpus = 384 B, well within range.)
- Implementation/verification of this data path is **MB-8**, not yet run; all `outer_len` below are
  provisional until then.

---

## 3. Candidate A3 — corrected 6-slot unified grid (recommended)

Both operations occupy the same six public slots; each slot has a fixed **(direction, public size, time
τ)**. READ maps its four real units to slots 0/1/4/5 with **filler** at 2/3; SBO fills all six. **Slot 5
is a real terminal ACK for both** (persistent connection). Every real unit is padded UP to its slot's
public size, so slot 1 exposes one size for the READ separate-ACK and the SBO SELECT-response, and slot 5
one size for both final ACKs.

| slot | direction | public inner target | **public outer_len** | READ content | SBO content | provisional τ |
|---|---|---|---|---|---|---|
| 0 | M→O | 320 B | **346 B** | read_req (pad 84→320) | select | τ0 = 0 |
| 1 | O→M | 322 B | **348 B** | sep ACK (pad 66→322) | select_resp | τ1 = D |
| 2 | M→O | 66 B  | **92 B**  | **filler** | sbo_ack | τ2 = D + Δ |
| 3 | M→O | 320 B | **346 B** | **filler** | operate | τ3 = D + 2Δ |
| 4 | O→M | 322 B | **348 B** | read_resp (pad 200→322) | operate_resp | τ4 = D + 3Δ |
| 5 | M→O | 66 B  | **92 B**  | **final ACK (real)** | **final ACK (real)** | τ5 = D + 4Δ |

Direction, public size, and slot time are now fixed and identical for READ and SBO at every slot — and
slot 5 is a real ACK in both, not a teardown artifact.

### Provisional slot times τ (grid parameters, NOT frozen)
Linear grid `τ0 = 0`, `τ_i = D + (i−1)·Δ`. The first O→M unit is released at the deadline **D**; each
later slot one grid tick **Δ** later. Example: **D ≈ 16 ms** (the Defense-3 value), **Δ** in the low-ms
range. Bounds: `τ5 = D + 4Δ < RTO_min − margin`; SELECT→OPERATE gap `τ3 − τ1 = 2Δ` must fit the SEL-751
`selectTimeout` (BLOCKED until read); causality `τ3 > τ1`. τ stays provisional until MB-8 + the grid
microbench (MB-3).

---

## 4. Alternatives
- **Candidate B3 — size-normalized, unit counts kept** (READ=4, SBO=6): cheaper; leaks operation type by
  unit count. Strictly weaker.
- **Candidate C3 — max-envelope super-slot:** hides type fully; heaviest overhead; likely breaks poll-rate
  budgets.

---

## 5. What still blocks a freeze
1. **Same-device co-measurement.** READ = Case-A physical relay (separate ACK, Defense-3 timed); SBO =
   Case-B emulator (persistent now, but a different device with piggyback ACKs). A defensible
   `Obs(READ) ≈ Obs(SBO)` needs both on one device/path or an explicit device-independence argument.
2. **MB-8 (size data path).** Format (b) with the 8-byte inner_len header must be implemented + proven
   offline (real padding, exact outer_len, encode/decode ports, byte-identical restore, hidden
   real/filler, fail-open on oversize).
3. **MB-1 v3 (ingress core).** MB-1 v2 had fatal logic defects (directional flow key, dead pktgen blocker
   path, generation-parity validity, missing response reservoir, incomplete cleanup, wildcard
   slot-occupancy match, 6-byte header, missing MODE_FAIL_OPEN release, uninitialized metadata). Being
   rebuilt as **MB-1 v3**; the "Unified ingress core = GO" verdict is **withdrawn** until v3 fits ≤12 with
   raw compiler evidence committed.
4. **Connection lifecycle.** A3 assumes a persistent connection; if a deployment uses per-transaction
   connections, the SYN/FIN/RST pattern is a residual leak to normalize (MB-8 option (b)).

**Candidate A3 is the right design family, but not ready to select or freeze until (1)–(4) close.**

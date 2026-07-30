# Physical D-sweep campaign — Case A Defense 3 vs a real SEL-751

**480 attempted transactions, 480 responded, 0 unanswered.** 6 arms × 4 interleaved rounds
× 20 polls, one TCP connection per block, D changed on the **runtime** path (no reload).
Arms **interleaved round by round**, and every comparison made **within the session**,
because native-vs-native drift on this relay has reached AUROC 0.985 *across* sessions.

Raw: `dsweep_blocks.jsonl` (24 blocks, per-transaction wire rows), `dsweep_analysis.json`.
Reproduce: `run/campaign.sh out.jsonl 4 20 0.2` with `run/setarm.py`, `run/block.py`.

## Results

Observed CLRT = ACK→RESPONSE **on the wire at the master**, which is where a passive
observer sits. Separability = AUROC folded to [0.5, 1.0], since an adversary may invert
its rule. **Native-vs-native separability (the drift floor) = 0.530.**

| arm | D (ms) | att | resp | CLRT med | CLRT p95 | CLRT max | CLRT sd | collapsed <0.1 ms | READ→ACK med | **sep vs native** |
|---|---|---|---|---|---|---|---|---|---|---|
| native | — | 80 | 80 | 2.828 | 12.222 | 13.175 | 2.854 | **0/80** | 0.453 | — (floor 0.530) |
| **d1** (null control) | 1 | 80 | 80 | 1.799 | 10.563 | 15.465 | 3.331 | **0/80** | 1.514 | **0.649** |
| d2 | 2 | 80 | 80 | 0.823 | 11.350 | 18.356 | 3.952 | **20/80** | 2.515 | **0.719** |
| d4 | 4 | 80 | 80 | **0.032** | 2.084 | 7.888 | 1.129 | **63/80** | 4.508 | **0.966** |
| d8 | 8 | 80 | 80 | **0.032** | 0.043 | 1.264 | 0.153 | **78/80** | 8.519 | **1.000** |
| d16 | 16 | 80 | 80 | **0.032** | 0.043 | 0.047 | 0.012 | **80/80** | 16.509 | **1.000** |

**The hold tracks D exactly on real traffic:** READ→ACK median = D + 0.51 ms at every D
(1.514, 2.515, 4.508, 8.519, 16.509), against 0.453 ms native. **Ordering invariant:
480/480 transactions committed the ACK before the RESPONSE.**

## The central result, and it is a negative one

**Concealment and detectability rise together.** At D = 16 ms every one of 80 transactions
has its CLRT collapsed to 32 µs — the CLRT magnitude is perfectly concealed — and the
separability from native is **1.000**: the adversary tells protected from native *perfectly*.
The same holds at D = 8. CONSENSUS §10 predicted exactly this and said to state it head-on
rather than in limitations, and the campaign confirms it on the physical relay.

The mechanism of the leak is visible in the table: concealment moves the information out
of the CLRT and into **READ→ACK**, which becomes `D + 0.51 ms` — a near-constant that
native never produces. The residual CLRT floor of **0.032 ms** (the release tail) is itself
a constant fingerprint: native's CLRT sd is 2.854 ms, D=16's is **0.012 ms**.

**D = 1 ms behaves as its pre-registration says, and the distinction matters.** It conceals
**nothing** (0/80 collapsed, CLRT median still 1.799 ms) — so it is a valid null for
*concealment*. But it is **not** a null for *detectability*: it still delays the ACK by
~1 ms and its separability is 0.649, above the 0.530 drift floor. A null control for one
axis is not a null control for the other.

## Mechanism — per-arm counter deltas

| arm | PKTGEN_ADMIT | ARM_FRESH | TERM_DL | STALE | TMO | FAILOPEN | DROP | BUSY | DUP_SUPP | q drops |
|---|---|---|---|---|---|---|---|---|---|---|
| d1 | **5120** | **80** | **5120** | 0 | 0 | **0** | 0 | 0 | 0 | 0 |
| d2 | 5120 | 80 | 5120 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| d4 | 5120 | 80 | 5120 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| d8 | 5120 | 80 | 5120 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| d16 | 5120 | 80 | 5120 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

`5120 = 64 × 80` — **exactly K=64 blockers per transaction**, every one terminating on the
**deadline**. Zero stale terminations, zero budget expiry, **zero fail-open**, zero admission
drops, zero concurrent-transaction escapes, zero duplicate suppressions (no real
retransmission occurred in 480 transactions), zero queue drops.

**Both E1 retirement branches partition exactly, 400 times:**

| arm | RESP_HOLD_EARLY | RESP_BYPASS | ACK_RELEASE | ACK_REL_RETIRE |
|---|---|---|---|---|
| d1 | 0 | 80 | 0 | **80** |
| d2 | 18 | 62 | 18 | 62 |
| d4 | 62 | 18 | 62 | 18 |
| d8 | 78 | 2 | 78 | 2 |
| d16 | 79 | 1 | 79 | 1 |

`EARLY + BYPASS = 80` in every arm, `ACK_RELEASE = EARLY` and `ACK_REL_RETIRE = BYPASS`
identically. As D grows past the relay's CLRT the RESPONSE moves from arriving *after* the
ACK committed (retire-at-ACK) to arriving *inside* the window (queue behind, retire on the
RESPONSE) — the E1 lifecycle sweeping across its own boundary on real traffic.

## Negative evidence and limits

- ⚠ **The native arm's counter delta is unusable.** Counters were never zeroed before the
  campaign and my per-block zeroing in `setarm.py` failed silently, so the printed
  mechanism totals were cumulative snapshots I then summed. The per-arm figures above are
  recovered as *differences* of consecutive snapshots, which is valid for d1–d16 but not
  for the first block, whose delta absorbs all pre-campaign history — hence native's
  nonsensical `ADMIT = 11904, ARM_FRESH = 307`. The wire is unambiguous that native was
  unheld (READ→ACK 0.453 ms, 0/80 collapsed), so the arm is sound; only its counters are
  not. Fix before the next campaign: verify the zeroing readback instead of `try/except`.
- **Native here is "reservoir disarmed", not "defense absent".** The pipeline still parses,
  classifies and forwards; only the hold is inactive.
- **One relay, one session, one poll rate** (200 ms). CLRT depends on relay load and
  connection state; no steady-state CLRT claim is made, and the native median of 2.828 ms
  with p95 12.222 ms is this session's distribution, not the device's.
- **No classifier evaluation.** Separability here is a single-feature AUROC on the raw CLRT.
  A real adversary gets READ→ACK, packet counts and ACK mode too — and READ→ACK alone is
  trivially separable at every D ≥ 2.
- **No binned entropy anywhere**, deliberately: a proven bijection once raised it 0.260
  bits. AUROC on the raw feature also avoids the KDE-degeneracy trap in which a fully
  clamped feature returns accuracy 1.000 through density degeneracy rather than information.
- **No iso-latency Defense 2 arm was run**, so no Defense 2 vs Defense 3 comparison is made.
  D ≤ 3 ms against G = 25 ms would be uninterpretable in both directions.

## State

Switch left with the 10/12 instrumented live Defense 3 loaded, reservoir **armed**,
D = 16 ms as the last arm set. Defense 2 not restored. Read-only throughout: no SELECT,
OPERATE, DIRECT OPERATE, write or setting change was sent in 480 transactions.

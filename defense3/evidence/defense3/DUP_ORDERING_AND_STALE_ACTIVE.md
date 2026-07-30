# Two pre-physical closures: duplicate-RESPONSE ordering, and a stale RESPONSE during an active transaction

Base `73d562f`. Defense 3 **left loaded**. Both issues closed; full regression green.

## 1. Duplicate early RESPONSE ordering — the invariant WAS violated

`reg_ts_resp_release` is written only on the dequeued `ROLE_RESP` path, so a **bypassed**
response left no trace at all and the ordering question could not be answered. Added
`reg_ts_resp_bypass` (write-if-zero, on the forwarding arm) and measured, three
repetitions, both responses inside D:

| rep | `t_ack_release` | `t_resp_bypass` | bypass − ACK | verdict |
|---|---|---|---|---|
| 1 | 150 365 630 | 149 364 181 | **−1 001 449 ns** | duplicate committed **BEFORE** the ACK |
| 2 | 1 370 251 194 | 1 369 249 853 | **−1 001 341 ns** | **BEFORE** |
| 3 | 2 591 179 962 | 2 590 178 541 | **−1 001 421 ns** | **BEFORE** |

The bypass arm forwards straight to the master while the ACK is still in `Q_HOLD`, so the
duplicate **overtook the packet the whole defense exists to delay, by 1.0014 ms**. Note
Gate 4 had reported PASS: my case-D rubric never tested ordering. Found by measuring, not
by the rubric.

### The repair

While `reg_tag` is in the current generation's **pending** domain, an exact
retransmission is **suppressed** (dropped) and counted in its own slot,
`CF_RESP_DUP_SUPP`:

```p4
if (verdict == V_RESP && txn_active == 1) { to_hold();  count RESP_HOLD_EARLY; }
else if (verdict == V_RESP && txn_active == 2) { D3_DROP() count RESP_DUP_SUPP; }
else { D3_TO_FWD() count RESP_BYPASS; }
```

**What "exact" means, conjunct by conjunct.** `verdict == V_RESP` is the decode entry
whose seq / ack / port masks are all full-width, giving `tcp.seq == EXP_RELAY_SEQ` (byte
position), `tcp.ack_no == EXP_ACK` (acknowledgment relation) and the learned master
ephemeral port. `CLASS_RESP` additionally required the §8.2 DNP3 gates — relay-facing,
tracked session, FIR|FIN with CON=0 UNS=0, func 129, single transport segment — which is
the DNP3 transaction identity. `txn_active == 2` is the generation conjunct.

**⚠ Payload length is NOT independently compared.** The held RESPONSE's length is stored
nowhere, and storing it would mean new persistent state. `tcp.seq` pins the byte position
and the DNP3 gates pin the framing, so the one case this cannot distinguish is a
same-sequence retransmission of a *different* length. Stated rather than papered over.

A second copy was **not** enqueued into `Q_HOLD`: the dequeued `ROLE_RESP` path retires
unconditionally, so a second copy could clear a later generation. Exact safety against
that was not proven, so the direction's precondition for enqueuing is not met.

After the queued RESPONSE releases and retires, `txn_active` reads 0 and later
retransmissions fall to the bypass arm and **forward normally** — unchanged.

### Result — 3/3 PASS

| rep | EARLY | DUP_SUPP | BYPASS | ACK_REL | RETIRE | ADMIT | DL | STALE | `t_resp_bypass` | post tag | hold |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1 | **1** | **0** | 1 | 0 | 64 | 64 | 0 | **0 (never written)** | 0x00 | 2 001 426 |
| 2 | 1 | **1** | **0** | 1 | 0 | 64 | 64 | 0 | **0** | 0x00 | 2 001 397 |
| 3 | 1 | **1** | **0** | 1 | 0 | 64 | 64 | 0 | **0** | 0x00 | 2 001 453 |

`t_resp_bypass = 0` means nothing was forwarded early: **no RESPONSE copy commits before
the ACK.** `ACK_REL=1 / RETIRE=0` still proves the marker was applied exactly once.

★ A second instrument bug of mine, caught the same way: the first bypass-timestamp
predicate was `txn_active != 1`, which fired on the **suppressed** copy too — a packet
that had been dropped and committed nowhere. Corrected to fire only on the arm that
actually forwards.

## 2. Stale RESPONSE during a NEW ACTIVE transaction — 3/3 PASS

seq/ack **is** the transaction identity in this design, and both the ACK and the RESPONSE
test it against the same register, so one template cannot express "stale RESPONSE with a
valid ACK". A third generator app (app 4) with its **own packet buffer** was added, its
`tcp.seq` offset by `--stale-seq-delta` (0x1000) from the trackers the transaction seeds.
It fires 800 µs after the READ — reservoir standing, deadline armed, N+1's own RESPONSE
still to come.

| rep | gen | EARLY | DUP_SUPP | BYPASS | ACK_REL | RETIRE | ADMIT | DL | STALE | post tag | hold |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 0xC4 | 1 | **0** | **1** | 1 | 0 | 64 | 64 | **0** | 0x00 | 2 001 563 |
| 2 | 0xC6 | 1 | **0** | **1** | 1 | 0 | 64 | 64 | **0** | 0x00 | 2 001 508 |
| 3 | 0xC8 | 1 | **0** | **1** | 1 | 0 | 64 | 64 | **0** | 0x00 | 2 001 612 |

- `reg_tag` for N+1 unchanged — `ACK_REL=1 / RETIRE=0` proves the ACK still found the
  pending marker, so the stale copy neither cleared nor set it.
- deadline unchanged — the hold is 2 001 5xx ns, i.e. `D + drain + tail`; a premature
  retirement would have collapsed it.
- pending marker unchanged; `DUP_SUPP = 0` — correctly **not** suppressed, because it is a
  different identity and must take the bypass path.
- blocker counts unchanged: 64 admitted, 64 deadline-terminated, **STALE = 0**.
- not held as N+1's RESPONSE (`EARLY = 1` is N+1's *own* RESPONSE, still held normally),
  and it could not retire N+1 (`post tag = 0x00` came from N+1's own RESPONSE release).

The stale copy commits 1 501 5xx ns **before** the ACK. That is correct and deliberate: it
belongs to a **completed** transaction, so holding it would be wrong. The ordering
invariant scopes to copies of the *current* transaction's RESPONSE, which is why case F is
scored on `score_common` plus its own isolation requirements rather than on the
normal-transaction rubric that forbids any bypass.

## 3. Compile and resources

| | ingress | egress | critical path | errors |
|---|---|---|---|---|
| BF-SDE 9.13.1 synthetic | **9 / 12** | **0** | 8 | 0 |
| BF-SDE 9.13.1 live | **9 / 12** | **0** | 8 | 0 |
| BF-SDE 9.13.2 synthetic (loaded) | **9 / 12** | **0** | 8 | 0 |

Deltas: `+1` ctr_fresh slot (`CF_RESP_DUP_SUPP`), `+1` SYNTH-only timestamp register
(`reg_ts_resp_bypass`, an instrument), `pgen_event` value_set 2→3, `+1` suppression branch.
**No change** to the state encoding, blocker lifecycle, deadline, queues, K=64 or the
synthetic schedule. `assert_salu_asm.py` and `test_tag_domain.py` (2 256 assertions) both
pass on every build.

## 4. Required regression — all green

| | verdict |
|---|---|
| Gate 3 — five consecutive normal transactions | **PASS 5/5**, 18/18 each |
| Gate 4A — just before the deadline | **PASS 3/3** |
| Gate 4B — after the ACK release | **PASS 3/3** |
| Gate 4C — missing RESPONSE **+ immediate recovery** | **PASS 3/3 + 3/3** |
| Case D — duplicate early RESPONSE | **PASS 3/3** |
| Case E — stale RESPONSE, idle | **PASS 3/3** |
| Case F — stale RESPONSE, active N+1 | **PASS 3/3** |

Gate 3 timing, unchanged from pre-repair: drain **1 691 – 1 695** (spread 4), release tail
26 – 28, reservoir standing 1 193 – 1 195, hold 2 001 427 – 2 001 586.

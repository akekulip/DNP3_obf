# Panel memo F — safety and verification engineer

**Scope:** cleanup, fail-open, stale-generation handling, transaction ordering, switch loading and
restoration for DEFENSE 3 (predetermined ACK-delay release, `d_ACK = t_ACK + D`, two queues
`Q_BLOCK(high) > Q_HOLD(low FIFO)`, one deadline, one request-triggered K=64 blocker class).

**Authority:** `meeting_direction.md` §7 (lifecycle / fail-open / cleanup), §13 (gates), §17
(hardware run requirements). Baseline and carried-forward measured facts:
`design/DEFENSE3_BASELINE.md`.

**Position of this memo in one line:** Defense 3's headline observable — *the ACK left at
`t_ACK + D` and the RESPONSE never preceded it* — is **not visible on any external link**, because
the ACK is held inside the switch and the dp64 relay leg is untappable. Every claim therefore rests
on on-chip state. On-chip state is exactly where this project has previously been wrong. So the
verification burden here is unusually high and must be discharged by construction, not by
inspection after the fact.

**Read-only confirmation taken while writing this memo** (per the standing rule: read `ps`, do not
trust the record):

```
decps@10.10.54.81:  pgrep -cx bf_switchd -> 1     pid 475438
  --conf-file /home/decps/defense2_pktgen_compile/pktgen_abs.conf
  program-name = dnp3_timing_normalizer_pktgen
```

That is the restore target. It matches `DEFENSE3_BASELINE.md`. Confirm it again by the same method
at the start of every hardware run; do not carry this line forward as a fact.

---

## 1. The clean-start assertion

### 1.1 `usage_cells` cannot participate

`usage_cells` is a **live, writable gauge that reads 0 on dp8 queues even when packets are
demonstrably queued** — measured across five shaper settings, including one that leaked. Two
consequences, both absolute:

- it may **never** be a gate predicate, a precondition, or a drain proof;
- because it is writable, "zero it and read back zero" certifies nothing at all. A cleanup that
  zeroes it before draining would certify a switch that is still holding traffic.

It may be recorded in the snapshot as a raw field for the record. It may not be reasoned from.

`watermark_cells` is latched and is a **one-way** diagnostic: `watermark > 0` proves a queue *was*
occupied; it can never prove a queue is *now* empty. Use it to prove the hold happened, never to
prove the drain happened.

### 1.2 Emptiness is proven by conservation, not by a gauge

The only sound drain test is **token conservation**, per generation *g*:

```
admitted(g)  ==  term_deadline(g) + term_budget(g) + term_stale(g)
admitted(g)  ==  64                                    (exactly one burst, K=64)
```

with, in the same window, `drop_count_packets` delta == 0 on both queues, and zero
`eth.type == 0x88C1` observed externally. Conservation plus zero drops plus zero escapes is the
drain proof. Nothing else is.

### 1.3 Facts a trial must READ before it starts

All read from the switch, none from any script's belief about what it configured:

| # | Fact | Source | Required value |
|---|---|---|---|
| 1 | `pgrep -cx bf_switchd` | switch | exactly `1` |
| 2 | `p4_name` | `--conf-file` parsed out of `/proc/$(pgrep -ox bf_switchd)/cmdline`, then `p4_devices[0].p4_programs[0].program-name` | the Defense 3 program under test |
| 3 | `reg_tag` | register read | `TAG_INACTIVE` — no live generation |
| 4 | deadline word | register read | unarmed (marker byte says invalid) |
| 5 | pktgen `app_enable` and `pkt_counter` | `tf1.pktgen.*` | `false`; counter delta since the previous trial `== 0` |
| 6 | previous trial's conservation | counter readback | balanced per §1.2 |
| 7 | `drop_count_packets`, both queues | `tf1.tm.counter.queue` | recorded as the delta base — **never assumed zero** |
| 8 | `watermark_cells`, both queues | same | explicitly reset to 0 **and the reset read back as 0** |
| 9 | escape gate | on-chip dequeue counter | `total_dequeues_before_release == 0` |
| 10 | external internal-token count | Vision capture + dp64 port counter | `0` since the previous trial |
| 11 | configured `D` word | register readback | equals the intended `D`, low byte within the armed-marker allowance |
| 12 | all assertion counters | readback | stored as a base; assertions are on **deltas**, never on absolutes |

Item 11 is not bookkeeping. `D` rides in the same 32-bit word as the armed marker, so `D` must be a
multiple of 256 ns; a silently truncated or mis-scaled `D` produces a plausible-looking headline
number that is simply wrong. Read it back and compare before the campaign, not after.

### 1.4 What makes a start DIRTY

Any one of: an active `reg_tag`; an armed deadline; a nonzero pktgen counter delta; the previous
trial's tokens unbalanced; a nonzero queue drop delta; a refused or unverified `watermark` reset;
a nonzero pre-release escape count; **or the trial being the first trial after a program load.**

The last one is measured, not hypothetical. Across three independent runs the first trial after a
fresh load leaked 4, 5 and 6 packets respectively, and every subsequent trial leaked exactly zero
(`FOUR_QUEUE_DEQUEUE_ORACLE_RESULT.md`). The first trial after any load is discarded or repeated —
it is never a data point.

### 1.5 Required handling

- A dirty start makes the trial **INVALID**, not FAIL, with a **distinct exit code** (the proven
  idiom is `3`). An INVALID trial never established its preconditions, so it is not a verdict about
  ordering or timing and must never be reported as one.
- A trial **refuses to start dirty.** It does not "clean and continue" silently — cleaning is
  logged, and the trial that follows a clean-up is marked as such.
- Cleanup runs from a `finally`, unconditionally. This is measured, not stylistic: a trial that
  ended INVALID without release left its backlog behind and **124 leftover packets were consumed by
  the following trial**, corrupting it.
- Cleanup ORDER is load-bearing and fixed:
  `disable pktgen → restore line rate → drain → verify conservation → only then reset counters`.
  Resetting before draining certifies a switch that is still holding traffic.

---

## 2. Fail-open

### 2.1 Budget sizing from the measured pass time

Measured: **1.715 µs per token pass at K=64** (Defense 2 gate f: 100 000 passes → fail-open at
171.5 ms). A previous program's comment assumed 10 µs and was ~6× wrong; do not re-derive from
Mpps figures, use the measured number.

Horizon `H = B × 1.715 µs`. Because all 64 tokens are stamped with the budget at admission within
one burst, the first token to reach zero invalidates the tag and the remaining 63 terminate as
stale within one further revolution (~1.715 µs). The drain is therefore effectively instantaneous
relative to `H` — but that is an inference from the code path and belongs in §6 as an item to
check, not a fact to assume.

| D | `D / 1.715 µs` (absolute floor) | Recommended `B` | Horizon `H` | `H / D` | `H` vs 211 ms RTO |
|---|---|---|---|---|---|
| 1 ms | 583 passes | 18 000 | 30.87 ms | 30.9× | 6.8× below |
| 2 ms | 1 166 passes | 18 000 | 30.87 ms | 15.4× | 6.8× below |
| 3 ms | 1 749 passes | 18 000 | 30.87 ms | 10.3× | 6.8× below |

**One budget of `B = 18 000` covers all three D values** with ≥10× margin over the largest D and
~6.8× clearance below the master's RTO. The inherited `B = 100 000` gives `H = 171.5 ms = 0.81 × RTO`
— sized for G = 25 ms and far too close. It must be changed before any Defense 3 hardware run: at
that horizon a single mis-sized deadline turns a logic bug into a retransmission storm on the
master rather than into a clean fail-open.

`B` must be a **runtime parameter alongside `D`**, so the horizon can be swept without a recompile,
and the report must state the horizon in **milliseconds**, not in passes.

**The relay side is the unmeasured half.** In the early-response case the hold sits on the *relay's*
retransmit timer too (~60% of transactions at D = 2 ms), and the SEL-751's `RTO_min` has never been
measured. The horizon must be sized against the lower of the two RTOs; since one is unknown, size
conservatively at `H ≤ ~31 ms` and state the limitation explicitly rather than implying the
211 ms figure bounds both. The 211 ms itself was measured on loopback and is not a wire measurement.

### 2.2 Release-cause purity — a gate, not telemetry

In a valid Defense 3 trial the ACK's release cause must be **DEADLINE**, never FAILOPEN:

```
ACK_RELEASE_FAILOPEN == 0   for every valid trial
```

A fail-open release means the budget was mis-sized for the configured `D`, and **the timing number
from that trial is void** — it measures the budget, not `D`. This must be an automatic
per-trial gate in the analyzer, not a line in a report.

### 2.3 `ACK_MISSING_FAIL_OPEN` must not absorb classification failures

`ACK_MISSING_FAIL_OPEN` is the correct terminal for *no qualifying ACK arrived*. It must be
strictly distinguishable from *an ACK arrived and the predicate rejected it*. If one counter serves
both, a keepalive-predicate bug is indistinguishable from a silent relay — which is precisely the
failure mode §5 of the mechanism study describes as "no crash, no counter, a result that does not
replicate".

Required: `ACK_MISSING_FAIL_OPEN` (budget exhausted with `awaiting_ack` still 1) as one counter,
and a **separate rejection counter per reason** (seq mismatch, ack-number mismatch, flags, nonzero
payload, generation mismatch, not-awaiting). Verification: craft one packet per rejection reason and
assert **exactly one** counter moves for each.

### 2.4 What must never hold a packet indefinitely

**Rule.** Every hold must be released by a condition that is a function of TIME, or of a
monotonically decreasing COUNT owned by the held path itself. **Never by the arrival of another
packet.**

- ACK release ← deadline (time) **or** budget exhaustion (count). Both bounded.
- Early RESPONSE release ← `Q_BLOCK` empty ← all tokens terminated ← (stale | deadline | budget).
  Bounded transitively; the RESPONSE holds no timer of its own, which is why §6 forbids `d_RESP`.
- **Prohibited by construction:** releasing the ACK on RESPONSE arrival (that is Defense 1, and it
  reinstates the leak Defense 3 exists to remove); any controller fast-path release (out of scope,
  §2); a second response deadline (§6).

**Corollary for review:** if any code path can hold a packet and is not covered by a watchdog whose
expiry is `≤ H`, that is a defect *regardless of whether any test failed*. The test for this is not
a run, it is an enumeration: list every enqueue-to-`Q_HOLD` site and name the bounded release
condition for each. A site with no named bound does not ship.

---

## 3. Stale-generation handling

§7 mandates `ack_release_gen == current_generation` and explicitly forbids a boolean
`ack_released = 1`. This is correct, and the reason is worth stating precisely because it is the
single most likely place for Defense 3 to fail silently.

### 3.1 What a stale boolean breaks

1. **Silent loss of protection.** A boolean is set on release and has no owner responsible for
   clearing it. If it survives into generation *N+1*, that transaction's ACK reads "already
   released" and is forwarded immediately. The defense is off. No drop, no error, no counter — and
   the CLRT it was meant to hide reappears in `READ→ACK`.
2. **Ordering inversion across generations.** The boolean cannot express *whose* release it
   records. A RESPONSE from generation *N* arriving during generation *N+1*'s hold window would
   take the post-release path and be forwarded to the master **ahead of the held ACK of *N+1***.
   That inverts the one ordering property Defense 3 claims, on the wire, in the exact scenario the
   claim is about.
3. **Two sources of truth.** `reg_tag` already carries the generation. A boolean adds a second,
   independently clocked piece of state that can disagree with it. The disagreement window is
   whatever gap exists between the generation advance and the boolean clear — and any such gap is a
   bug that no amount of testing at one poll rate will reliably expose.
4. **Cause attribution collapses.** "Released by deadline in generation N" and "released by
   fail-open in generation N" cannot both be recorded by one bit, so §2.2's release-cause purity
   gate becomes unimplementable.

### 3.2 The test that proves the binding works

A positive test alone is insufficient — a boolean implementation passes the ordinary
five-transaction gate. The binding must be proven by a test that a boolean **fails**.

**T-GEN-1 — cross-generation stale RESPONSE (the discriminating test).**

1. Transaction *N*: inject `READ_N`, `ACK_N`; let the ACK release at `t_ACK + D`; **withhold**
   `RESPONSE_N`.
2. Start transaction *N+1*: `READ_{N+1}`, `ACK_{N+1}`. `ACK_{N+1}` is now held.
3. **Inside** *N+1*'s hold window, inject the stale `RESPONSE_N`.

Required, all four:
- `RESPONSE_N` is classified stale on generation mismatch, counted as `STALE_RESPONSE_BYPASS`, and
  **does not enter `Q_HOLD`**;
- `ack_release_gen` reads *N+1*'s generation at that moment (register readback in the trial record,
  not inferred);
- `ACK_{N+1}` still leaves at `t_ACK + D`;
- **on the Vision capture**, the order is `ACK_{N+1}` then `RESPONSE_{N+1}`, with `RESPONSE_N`
  either before `ACK_{N+1}` as a bypass or absent — but never between them and never displacing
  the ACK.

**Why this is the discriminating observable:** with a boolean, step 3 takes the post-release path
and `RESPONSE_N` appears on the master link **before** `ACK_{N+1}`. The failure is visible on the
external capture, so this test does not depend on trusting on-chip state.

**T-GEN-2 — negative control.** Run T-GEN-1 with the stale-generation check deliberately disabled
in a scratch build and confirm the inversion *does* occur. A safety test that has never been
observed to fail is not evidence that it can detect anything. (Scratch build only; not loaded on
the campaign program.)

**T-GEN-3 — generation-wrap argument, checked numerically.** The generation is a small field and
wraps. The safety argument is that a token cannot survive a wrap: maximum token lifetime is
`H = 30.87 ms`, one generation consumes at least the poll interval (≥ 1 s), so 16 generations span
≥ 16 s — a factor of ~500. **State this ratio with the measured `H` and the measured poll interval
in the report.** It is an argument, and arguments about wrap have to be arithmetic on measured
numbers, not adjectives. If the poll interval is ever driven below `16 × H`, the argument is void
and the wrap must be tested directly.

---

## 4. Terminal states

### 4.1 One definition of CLEAN, applied identically everywhere

`CLEAN(g)` holds iff **all** of:

1. `reg_tag` reads `TAG_INACTIVE`; `transaction_active == 0`, `awaiting_ack == 0`,
   `deadline_valid == 0`, `response_queued == 0`;
2. token conservation balances for *g*: `admitted == term_deadline + term_budget + term_stale`, and
   `admitted == 64`;
3. `drop_count_packets` delta `== 0` on `Q_BLOCK` and `Q_HOLD`;
4. zero `eth.type == 0x88C1` externally — Vision capture **and** the dp64 relay-leg port counter
   (dp64 has no tap, so a port/queue counter is the only observable there);
5. exactly one ACK release attributed to *g*, and at most one RESPONSE release;
6. no packet of *g* remains referenced by any hold-path state.

Every row below means *this* CLEAN, plus the row's own extra condition. No row gets a softer
definition.

### 4.2 The states

| Terminal state | Trigger | Counted | "Clean" additionally means |
|---|---|---|---|
| **NORMAL — late RESPONSE** | RESPONSE after the ACK release pass | `ACK_RELEASE_DEADLINE` +1, `RESPONSE_AFTER_ACK_RELEASE` +1 | wire order ACK→RESPONSE on Vision; on-chip hold duration `= D ± release tail`; RESPONSE not re-held |
| **NORMAL — early RESPONSE** | RESPONSE before ACK release | `ACK_RELEASE_DEADLINE` +1, `RESP_ENQ_HOLD` +1 | ACK dequeued **strictly before** RESPONSE; RESPONSE added delay `≈ D − CLRT_native`; single FIFO, no reorder |
| **Missing RESPONSE** | no RESPONSE within the watchdog | `ACK_RELEASE_DEADLINE` +1, `RESPONSE_MISSING_WATCHDOG` +1 | ACK still left at `D`; watchdog retired the generation; no held packet remains |
| **Missing ACK** | no qualifying ACK before budget exhaustion | `ACK_MISSING_FAIL_OPEN` +1, `term_budget == 64` | `Q_HOLD` never received a packet; a later ACK is bypassed as `ACK_OUTSIDE_TXN`; horizon observed `≈ H`, not `≈ D` |
| **Duplicate / retransmitted READ** | second READ, same session, while active | `ARM_DUP` +1, **no** pktgen trigger | `admitted` still exactly 64; generation **not** advanced; READ forwarded byte-identically |
| **Concurrent READ** | a different eligible READ while active | `CONCURRENT_TRANSACTION_ESCAPE` +1 | forwarded normally and **unprotected**; active state unchanged; still exactly one reservoir. This is a scope limit (§2: one active transaction), so it must be *counted and reported*, never treated as an error to suppress |
| **Duplicate ACK** | second ACK-shaped packet during or after the hold | `ACK_DUP_BYPASS` +1 | not enqueued, not re-held; deadline byte-unchanged; **forwarded, not dropped** — it is a legitimate TCP segment |
| **Keepalive** | pure ACK with retrograde seq (`seq = SND.NXT − 1`, ~every 10.02 s) | `KEEPALIVE_REJECT` +1 | forwarded; deadline register **byte-unchanged**; `awaiting_ack` unchanged. See §6 item 6 — this is the highest-severity silent-failure path in the design |
| **FIN / FIN-ACK / RST** | teardown on the protected session | `SESSION_TEARDOWN` +1 | any held ACK is released **before** the FIN is forwarded (a FIN reaching the master ahead of the ACK it follows is a protocol violation); blockers forced to terminate; generation retired; expected-seq state invalidated so the next SYN reseeds |
| **Unsupported segmentation** | RESPONSE is not the single observed Class-0 segment | `UNSUPPORTED_SEGMENTATION` +1 | **all** segments of that response bypass; a partial response is never held; generation retired. §8 forbids silently claiming multi-segment support |
| **Timestamp wrap** | 32-bit ns counter wraps inside a hold (~every 4.3 s; ~14× per 60 s run) | analysis-side flag | durations computed as `(release − arm) & 0xFFFFFFFF`, values `> 2³¹` treated as wrap corrections. A plain signed subtraction here **fabricates** the headline number rather than measuring it |

Two consequences worth stating plainly:

- **Missing ACK and rejected ACK must never share a terminal.** They differ by whether the relay
  spoke. Merging them makes a classifier bug look like a device fault.
- **FIN/RST is the only state where the hold is cut short deliberately.** It therefore needs its own
  test; it cannot be inferred from the missing-RESPONSE watchdog test.

---

## 5. Hardware run protocol (§17)

### 5.1 Pre-run snapshot — contents

Taken **before anything is touched**, written to `evidence/defense3/<runid>/snapshot.json`:

- `pgrep -cx bf_switchd` and `pgrep -ox bf_switchd`;
- the `--conf-file` parsed out of `/proc/<pid>/cmdline`, and `program-name` read from that JSON.
  **This is the authoritative program identity** — not what a setup script believes, and not
  project memory (memory was wrong about the restore target once);
- dp8 / dp9 / dp64 port state: oper status, speed, FEC, autoneg;
- dp8 shaper, **all five fields**: `max_rate_enable`, `max_rate`, `unit`, `max_burst_size`,
  `scheduling_speed`;
- queue scheduling for every qid Defense 3 will touch: `max_priority`, `min_priority`, DWRR weight;
- pktgen app state: `app_enable`, batch/packet counts, pattern value and mask,
  `pipe_local_source_port`, `increment_source_port`;
- per-queue `watermark_cells` and `drop_count_packets` as delta bases;
- SDE version, P4 build hash, git commit of the P4, the setup script and the runner;
- UTC timestamp.

`usage_cells` may be recorded but is **not** a snapshot fact anything compares against.

### 5.2 Isolated test configuration

- No host-injected tokens (§2). The only internal resources touched are the pktgen app, ethertype
  `0x88C1`, the dp8 loopback and the two queues.
- Read-only Class-0 polls only. Any action that could operate or reconfigure the SEL-751 is a
  §17 stop condition, not a judgement call.
- Internal tokens must never appear externally: verified on the Vision capture **and** by a dp64
  port counter, because the relay leg cannot be tapped.
- The runner runs under `tmux`, so an SSH drop cannot kill it mid-configuration and strand the
  switch half-configured; the EXIT trap must be able to fire.
- Defense 3 is loaded from its own conf/build directory. Defense 2's
  `/home/decps/defense2_pktgen_compile/` is read-only for this work.

### 5.3 Trap-based restoration

- `EXIT`, `INT`, `TERM`, `HUP` all routed through **one idempotent** `restore()` guarded by a
  `RESTORE_DONE` flag; signal handlers `exit` so the EXIT trap runs exactly once.
- Restoration **converges to known-good** — it re-asserts and verifies rather than always
  restarting, so it is safe to run against a healthy switch. The proven path is
  `research/case_a_read_anchored_dual_release/run/run_four_queue_oracle.sh --restore-only`
  (exercised repeatedly, including from real failures). Defense 3's runner may wrap it, but must
  not reimplement it.
- **Order is fixed:** disable pktgen → restore line rate → drain → verify conservation → reset.
- Three environmental traps, all previously measured, all mandatory:
  - **`pgrep -f bf_switchd` overcounts — it returned 3 for a single daemon**, because the launcher
    command line and the invoking shell both carry the string. Count with **`pgrep -cx bf_switchd`**.
    The `[b]racket` trick fixes only the invoking shell and is **not** a fix.
  - **`set -u` with an unset `LD_LIBRARY_PATH` aborted a program swap after the old program had
    already been stopped**, briefly leaving the switch with nothing loaded. Every export must be
    `${LD_LIBRARY_PATH:-}`. Enforce mechanically: `grep -n 'LD_LIBRARY_PATH' run/* setup/*` must
    show **zero** bare `$LD_LIBRARY_PATH`, checked before each run.
  - **`pkill` as `decps` cannot kill the root-owned `bf_switchd`.** Any stop step must use `sudo`
    *on the switch*, and its success is established by re-reading `pgrep -cx`, never by `pkill`'s
    exit code.
- Restoration is never claimed from a command's exit status. It is claimed from a readback.

### 5.4 PASS list required after every hardware run

All eleven, printed and written to the restore log. Any FAIL means the switch is not to be left in
that state; re-run `--restore-only`.

| # | Fact | Required |
|---|---|---|
| 1 | `p4_name` | `dnp3_timing_normalizer_pktgen` |
| 2 | `strict_priority_verified` | `true` |
| 3 | `app_enable` | `false` |
| 4 | `pgrep -cx bf_switchd` | `1` |
| 5 | dp8 shaping restored — all five fields byte-equal to the snapshot | `true`, `n_fail == 0` (a partial restore reports FAIL, never PASS) |
| 6 | queue `max_priority` / `min_priority` restored for every qid touched | equal to snapshot |
| 7 | token conservation, every generation in the run | balanced; `admitted == 64 × n_txn` |
| 8 | TM drops on `Q_BLOCK` and `Q_HOLD` | delta `== 0` |
| 9 | `eth.type == 0x88C1` externally — Vision capture and dp64 counter | `0` |
| 10 | first-trial-after-load discarded; no trial started dirty | `true` |
| 11 | snapshot-vs-post-run diff | empty except for counters explicitly reset, each named |

Items 1–5 are the proven five from the existing runner. **6–11 are Defense 3 additions** and are
what make the run's *data* trustworthy rather than merely the switch's *state*.

### 5.5 Preserved evidence

Under `evidence/defense3/<runid>/`, never appended to a prior run's files (§14): snapshot JSON;
restore log; full stdout/stderr of every remote command; pre/post register and counter readbacks;
Vision PCAP; on-chip trace dumps; both compile logs (9.13.1 and 9.13.2) with their resource
reports; the git commit of P4, setup, runner and analyzer. A failure additionally produces the §12
failure packet.

---

## 6. Verification-versus-assumption audit

Each row is something this project has at some point asserted without proof, or is about to. The
right-hand column is the check that converts it into a fact.

| # | Assumption | Why it is not yet a fact | Check that establishes it |
|---|---|---|---|
| 1 | "the switch is running program X" | taken from project memory, which was **wrong about the restore target once** | parse `--conf-file` from `/proc/$(pgrep -ox bf_switchd)/cmdline`, read `program-name` from that JSON. Done for this memo: `dnp3_timing_normalizer_pktgen` |
| 2 | "exactly one `bf_switchd` is running" | `pgrep -f` **returned 3 for one daemon** | `pgrep -cx bf_switchd` |
| 3 | "the queue drained / the hold worked", from `usage_cells` | reads **0 on dp8 queues while packets are demonstrably queued**, across five shaper settings including one that leaked; and it is writable | token conservation + zero drops + zero external `0x88C1`; `watermark_cells` as a one-way diagnostic only |
| 4 | "the trial started clean" | the 2026-07-28 pilot was contaminated by a prior INVALID trial — **124 leftover packets consumed by the next trial**; the first trial after a load leaked 4, 5, 6 across three runs | the §1.3 twelve-fact precondition read; refuse a dirty start; discard the first trial after any load; cleanup from `finally` |
| 5 | "per-token pass time is ~10 µs" | a previous program's comment; measured **1.715 µs**, ~6× wrong | re-measure **on the Defense 3 program**: withhold the ACK, time READ → `ACK_MISSING_FAIL_OPEN`, divide by the configured `B`. The queue configuration differs from Defense 2's, so the Defense 2 number is a prior, not a result |
| 6 | "the classifier matches only the transaction ACK" | the relay's ~10.02 s keepalive satisfies **every** condition of the current classifier; today it is rejected only by arm-once idempotence, which Defense 3 removes. Silent loss of protection: no crash, no counter | idle the session ≥ 10.02 s **inside** a live transaction and again **inside** the hold window; assert `KEEPALIVE_REJECT` increments and the deadline register is byte-unchanged. Predicate must include `tcp.seq == EXP_RELAY_SEQ` — the decisive discriminator |
| 7 | "the ACK always precedes the RESPONSE" | the `expired → forward response` branch lets a RESPONSE overtake the ACK inside the **~1.72 µs release tail** | route every in-transaction RESPONSE to `Q_HOLD` unconditionally (removes the race and a branch); verify by **wire order on the Vision capture**, not by counters, with the RESPONSE deliberately placed inside the tail |
| 8 | "strict priority holds for `Q_BLOCK > Q_HOLD`" | the earlier IBSPG failure's root cause was that `max_priority` was **never set** — only inert `min_priority` was. Proven for the four-queue set, not for this two-queue set | causal reversal control in the **Defense 3 configuration**: reverse only `max_priority` and confirm the dequeue order reverses. A readback of the field is not evidence |
| 9 | "the hold lasted D" | unobservable externally — the ACK is held and dp64 is untappable | on-chip arm/release timestamp pair with `(release − arm) & 0xFFFFFFFF` wrap handling; the 32-bit ns counter wraps ~14× per 60 s run and a signed subtraction would fabricate the number |
| 10 | "K=64 is safe here" | validated for **Defense 2's** queue configuration | re-run the empty-gap / zero-escape-before-release check in the two-queue configuration before any timing claim. §6 already forbids claiming 64 is minimal; also do not claim it is *sufficient* here until re-checked |
| 11 | "the master's RTO is 211 ms" | measured on **loopback**, not on the wire | measure on the Vision↔relay path before publishing it as a bound |
| 12 | "the relay tolerates the early-response hold" | the relay's `RTO_min` has **never been measured**, and the early-response case puts the hold on its retransmit timer (~60% of transactions at D = 2 ms) | measure the relay's retransmit behaviour, or size `H` conservatively (≤ ~31 ms) and state the limitation. Do not omit it |
| 13 | "all 64 tokens terminate within one revolution of the first" | inferred from the tag-invalidation code path, not measured | assert the READ→drain wall time in the missing-ACK trial is `≈ H + 1.715 µs`, not `≈ H + 64 × 1.715 µs`; conservation alone does not distinguish these |
| 14 | "9.13.1 pass implies 9.13.2 pass" | no drift has ever been observed on this line — an absence of counterexamples, not a proof | §13 Gate 1 requires both; run both, archive both resource reports, diff them |
| 15 | "restoration succeeded" from an exit code | the existing runner already treats this as insufficient | read the eleven §5.4 facts back; a partial dp8 restore reports FAIL |

---

## 7. Position

The mechanism is buildable and the safety envelope is wide — at D ∈ {1, 2, 3} ms there is roughly
two orders of magnitude of margin against every binding TCP timer. The risk in Defense 3 is not
that it breaks loudly; it is that it **stops protecting silently**, in three specific ways, all of
which have a cheap deterministic test:

1. a keepalive installs a stale deadline and the next real ACK is never held (§6 item 6);
2. a stale-generation boolean forwards the next transaction's ACK immediately (§3);
3. a mis-sized budget releases on fail-open and the trial measures `B` instead of `D` (§2.2).

None of the three produces a drop, a reset or an error. Each produces a plausible number. The three
gates that catch them — keepalive rejection with a byte-unchanged deadline, the cross-generation
stale-RESPONSE test (T-GEN-1) validated by its own negative control (T-GEN-2), and
`ACK_RELEASE_FAILOPEN == 0` — should be treated as **blocking for every hardware campaign**, not as
part of the §13 "after the core lifecycle works" tail.

Nothing in this memo has been executed against hardware beyond the read-only state check quoted at
the top. No file other than this memo was modified.

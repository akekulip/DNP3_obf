# Claims and limitations — timing

What the timing evidence supports, stated so that each claim can be checked against a named
artifact, and what it does not support, stated so that no reader has to infer the boundary.

Evidence: one physical Tofino-1 between a master and a physical SEL-751 relay, six
master-facing captures taken in one session on 2026-08-13.

---

## Terminology: the two arms

The two experimental arms are named for what actually differed between them.

* **Timing OFF** (also written *Timing OFF, shaping active*) — the unified switch binary
  running with the timing mechanism disabled.
* **Obfuscated** (the public-facing name Dr. Lin asked for; the extractor and CSV file names keep the internal word "defended") — the same binary with the timing mechanism
  enabled.

They are deliberately **not** called "native" and "defended". In the `final_read_sbo` dataset both
arms ran the same unified binary with the size-shaping datapath active, so the Timing OFF arm of
that dataset is not an unmodified SEL-751 baseline and must not be presented as one. In
`campaign_v1` the carve is off in both arms, so that caveat does not apply there. Because shaping was on in both arms it is
a held constant rather than a difference between them, so the comparison isolates the
timing-mode change within one binary. It is not a pure timing-only binary and not a pure
native-versus-defended experiment. An unmodified device baseline would require a separate
campaign with `shape_enable=0`.

---

## Claims

### C1 — CLRT normalization

With the timing mode off, command-to-link response time varies with transaction type and
spans roughly 1 to 18 ms. With it on, READ and the SELECT phase of SBO both settle at a
median of 4.001 ms with a standard deviation of about 0.02 ms.

| arm and class | n | median | std | max | above 12 ms |
|---|---|---|---|---|---|
| Timing OFF, READ | 999 | 1.272 ms | 1.354 ms | 12.275 ms | 2 |
| Timing OFF, SELECT | 488 | 2.107 ms | 2.530 ms | 18.178 ms | 11 |
| Obfuscated, READ | 599 | 4.001 ms | 0.022 ms | 4.098 ms | 0 |
| Obfuscated, SELECT | 499 | 4.001 ms | 0.021 ms | 4.124 ms | 0 |

Counts are after excluding the first transaction of each TCP connection. Figures 1 and 2.

The rule that produces the 4.001 ms is anchored to the relay's own TCP ACK, not to the request:
the switch releases the held ACK at `t_A + D_A` and the held response at `t_A + D_A + D_R`,
where `t_A` is the ACK's arrival at the switch, `D_A` = 20 ms and `D_R` = 4 ms (setup defaults,
corroborated by the wire, no readback archived). CLRT is therefore pinned to `D_R`. The
master-visible request-to-ACK interval is shifted to about `D_A` plus the relay's own ACK latency
(0.5 to 0.6 ms median, sub-millisecond spread) and is not itself normalized to a constant. The
control path is the one anchored to the request; see C3. Full derivation:
`paper/rewrite/pipeline/reports/EVENT_SEMANTICS_TRUTH_TABLE.md`.

### C2 — Timing-feature overlap

The two features a passive observer can measure master-facing — request-to-ACK latency and
CLRT — separate READ from SELECT with the timing mode off and stop separating them once it is on. Figure 3.

### C3 — The echo-to-ACK interval does not reveal the hold

Across configured holds of J = 2, 6 and 12 ms, the master-visible echo-to-ACK interval stays
at about 4.00 ms: 4.001, 4.002 and 4.003 ms respectively, 30 OPERATE transactions per
condition. An observer who subtracts the two timestamps available to it learns nothing about
J. Figure 4.

The OPERATE path is anchored to the request: the switch arms the ACK release at `T0 + A` and the
echo release at `T0 + R` when the OPERATE arrives (`T0`), forwards the OPERATE to the relay at
`T0 + J`, and the relay's later ACK cannot re-anchor the deadlines. The observable is `R − A`
with `J` absent. The absolute delays A and R sit about 1 ms above their configured 20 ms and
24 ms, a master-facing path and capture offset that cancels in the difference.

### C4 — Transaction-class timing-feature suppression

A classifier trained on Timing OFF CLRT to tell READ from the SELECT phase of SBO reaches
0.592 balanced accuracy and falls to 0.500 — chance — when applied unchanged to Obfuscated
traffic. Mutual information between transaction class and CLRT falls from 0.424 bits, far
above its permutation null, to below 0.003 bits, inside its null. Figure 5.

---

## Limitations

These bound the claims above. None is a caveat added for form.

### L1 — Size processing was active during every timing capture of the `final_read_sbo` dataset

**Scope.** This limitation describes the `final_read_sbo` evidence only. It does **not** apply to
the `campaign_v1` dataset (`evidence/campaign_v1/`, collected 2026-08-27 and 2026-08-28), which
was captured with `shape_enable = 0` in both arms and therefore is a timing-only measurement.
The requirement recorded at the end of this limitation has since been met; see the closing note.

For `final_read_sbo`, the switch was running the combined program with the size carve enabled,
in **both** the Timing OFF and the Obfuscated arm. Every response in every timing capture of that
dataset arrives as two TCP payloads of 28 and 21 bytes; a capture with the carve off shows a
single 49-byte payload.

Because it was on in both arms it is a held constant and not a confound between them, so the
Timing OFF to Obfuscated change in CLRT is attributable to the mode toggle. But the
Timing OFF figures
in C1 are the relay's CLRT **through the shaping datapath**, not an unmodified device
baseline.
No capture in the `final_read_sbo` evidence has both interventions off.

**Requirement met (2026-08-28).** The clean timing-only campaign that this limitation called for,
and that `EVIDENCE_AUDIT.md` §9 specified, was collected as `evidence/campaign_v1/`: 22 sessions,
132 captures, 63,360 transactions, `shape_enable = 0` verified in both arms by the control-plane
readback and on the wire, where every response is a single 49-byte payload and every capture holds
exactly 1,448 frames and 130,708 bytes in both arms. Which dataset the manuscript reports is a
separate decision; the two disagree on the Timing OFF CLRT precisely because one measures the
relay through the shaping datapath and the other does not.

### L2 — J was never observed relay-facing

J is the configured codebook value that sets the switch-internal release delay toward the
relay. It was not measured on the wire: dp68 is an internal pktgen/recirculation port with
no host-capturable tap. C3 is a statement about what the master sees. Relay-facing timing at
T0+J is not evidence in this package.

### L3 — Exactly-once release is not demonstrated

The master issued one OPERATE per transaction. Release multiplicity toward the relay was not
observable for the same reason as L2. Nothing here shows that exactly one OPERATE reached
the relay.

### L4 — One device, therefore signature replacement

The testbed has a single SEL-751. What is shown is that this relay's timing signature under
Timing OFF is replaced by a policy signature under Obfuscated. Indistinguishability across devices is a different claim
and is not tested. This is not device fingerprinting and not a device-identification result.

### L5 — The classifier is a transaction-class classifier

C4 concerns telling READ from SELECT. It is not device identification. The split is
transaction-disjoint but **not session-disjoint**: all transactions come from one capture
session, so a classifier could in principle exploit session-specific structure. A
session-disjoint evaluation would be stronger and was not run.

### L6 — The defended mutual-information estimate is unstable at the fourth decimal

The predeclared bin grid places an edge at exactly 4.000 ms and 18 percent of Obfuscated
observations fall within a microsecond of it, so the point estimate moves between roughly
0.000 and 0.002 bits with sub-microsecond rounding and with grid phase. Quote it as "below
0.003 bits and inside the permutation null", not to four significant figures. The Timing OFF estimate is unaffected. `EVIDENCE_AUDIT.md` §11.

### L7 — The configuration proof is partial

`readbacks/hw_config_readback.txt` reports one failed assertion while showing none. The
failing check cannot be identified from anything archived. The parameters the timing claims
depend on — A, R, the J codebook, tick quantization, TCP-timestamp policy — all appear as
passing rows matched verbatim to a configure-all run that passed with zero failures, and
`shape_enable` is established from the captures rather than from any log. The unidentified
failure is not explained away. `EVIDENCE_AUDIT.md` §6.

### L8 — Driver invocations were not logged

No per-run driver log survives for the E-phase captures, so the expected request count for
each capture is not independently recorded. What was actually received is counted from the
captures themselves, and every request in all six has both an ACK and a response.

### L9 — The loaded binary was not read back at capture time

Two documents written that day record binary `33fa3a77` as loaded, and they agree. No
readback was taken alongside the captures. `EVIDENCE_AUDIT.md` §8.

### L10 — Scope

READ, the SELECT phase of SBO, and OPERATE, on one relay, in one session, master-facing.
Size obfuscation is outside the timing claims entirely: it is not evaluated here, no size
figure is produced here, and L1 states the one way size processing bears on these results.

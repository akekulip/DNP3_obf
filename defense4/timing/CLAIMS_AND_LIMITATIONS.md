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
* **Timing ON** (also written *Defended timing*) — the same binary with the timing mechanism
  enabled.

They are deliberately **not** called "native" and "defended". Both arms ran the same unified
binary with the size-shaping datapath active, so the Timing OFF arm is not an unmodified
SEL-751 baseline and must not be presented as one. Because shaping was on in both arms it is
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
| Timing ON, READ | 599 | 4.001 ms | 0.022 ms | 4.098 ms | 0 |
| Timing ON, SELECT | 499 | 4.001 ms | 0.021 ms | 4.124 ms | 0 |

Counts are after excluding the first transaction of each TCP connection. Figures 1 and 2.

### C2 — Timing-feature overlap

The two features a passive observer can measure master-facing — request-to-ACK latency and
CLRT — separate READ from SELECT with the timing mode off and stop separating them once it is on. Figure 3.

### C3 — The echo-to-ACK interval does not reveal the hold

Across configured holds of J = 2, 6 and 12 ms, the master-visible echo-to-ACK interval stays
at about 4.00 ms: 4.001, 4.002 and 4.003 ms respectively, 30 OPERATE transactions per
condition. An observer who subtracts the two timestamps available to it learns nothing about
J. Figure 4.

The absolute delays A and R sit about 1 ms above their configured 20 ms and 24 ms, a
master-facing path and capture offset that cancels in the difference.

### C4 — Transaction-class timing-feature suppression

A classifier trained on Timing OFF CLRT to tell READ from the SELECT phase of SBO reaches
0.592 balanced accuracy and falls to 0.500 — chance — when applied unchanged to Timing ON
traffic. Mutual information between transaction class and CLRT falls from 0.424 bits, far
above its permutation null, to below 0.003 bits, inside its null. Figure 5.

---

## Limitations

These bound the claims above. None is a caveat added for form.

### L1 — Size processing was active during every timing capture

The switch was running the combined program with the size carve enabled, in **both** the
Timing OFF and the Timing ON arm. Every response in every timing capture arrives as two TCP
payloads of 28 and 21 bytes; a capture with the carve off shows a single 49-byte payload.

Because it was on in both arms it is a held constant and not a confound between them, so the
Timing OFF to Timing ON change in CLRT is attributable to the mode toggle. But the
Timing OFF figures
in C1 are the relay's CLRT **through the shaping datapath**, not an unmodified device
baseline.
No capture in the evidence has both interventions off. A clean timing-only measurement would
need a new campaign; the requirement is written out in `EVIDENCE_AUDIT.md` §9 and no
hardware action has been taken.

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
Timing OFF is replaced by a policy signature under Timing ON. Indistinguishability across devices is a different claim
and is not tested. This is not device fingerprinting and not a device-identification result.

### L5 — The classifier is a transaction-class classifier

C4 concerns telling READ from SELECT. It is not device identification. The split is
transaction-disjoint but **not session-disjoint**: all transactions come from one capture
session, so a classifier could in principle exploit session-specific structure. A
session-disjoint evaluation would be stronger and was not run.

### L6 — The defended mutual-information estimate is unstable at the fourth decimal

The predeclared bin grid places an edge at exactly 4.000 ms and 18 percent of Timing ON
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

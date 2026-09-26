# Randomized deadline candidate

The exact source has been compiled with the switch's SDE 9.13.2 and loaded on
physical Tofino. A repeat baseline pilot, with the random table empty, completed
60 primary exchanges across Timing OFF and D4. This proves a bounded baseline
check, not randomized timing behavior or classifier resistance. Randomized
acquisition has not yet completed.

## Implementation

The optional `pipe.Ingress.tbl_random_deadlines` is applied only to fresh,
master-session ROLE_ARM packets. Its range key is `meta.rand8`, with no operation
code in the key. Each of 16 disjoint ranges supplies the ACK and response offsets
for the existing read and OPERATE deadline paths. Existing registers retain the
selected deadlines. No register was added. The empty table's default is
`NoAction`, preserving the fixed parameters.

The gap-only policy has 16 equally spaced levels centered on one configured gap.
The joint policy is a 4-by-4 Cartesian product of D_A and gap levels for one
center and amplitude. Every possible selected pair must pass the original
admission constraints, stay positive on the 256 ns grid, and have total offset
below 30 ms. A policy with any invalid pair is rejected entirely. The current
enumeration contains 33 valid policies and 23 exclusions. The 2 ms native-time
value in the admission check is a configured assumption, not a measured
worst-case bound.

The same PRNG byte also selects the unchanged BOR J codebook. Thus J and the
selected deadlines may be correlated. No cryptographic randomness or independence
across transactions is claimed. A joint policy's Cartesian mapping gives separate
D_A and gap levels if its buckets are sampled uniformly; actual draws must be
reported from the telemetry.

A 32-byte digest carries the TCP source port and sequence, operation, ingress
timestamps, PRNG byte and four selected offset words. It is emitted only for
accepted fresh outcomes, never loopback packets. Digest metadata is initialized
and cleared outside those outcomes. The generated learn object is
`pipe.IgDeparser.random_deadline_digest` (id 2388186329). Packet bytes and the
forwarding path are unchanged by the digest export.

## Exact build and baseline hardware evidence

- Source SHA256: `8e6d0ad983acfceadae447aa7b5b4614193604b6cd87b902b1d567eaa5696478`.
- Compiler: `p4c 9.13.2 (SHA: 1baf055)`.
- Seven ingress match-action stages, zero egress match-action stages, critical
  path seven, 76 allocated tables.
- Remote immutable build:
  `/home/decps/dnp3_latency_random_20260926/build_digest_init_sde9132`.
- Retained manifest, BFRT schema and placement report:
  `../evidence/randomized_sde9132/`.
- Preload recovery commit: `6857f455`.
- Loaded process identity, setup checks and rollback snapshot:
  `../evidence/random_preflight_20260926/`.
- Completed baseline pilot: `pilot_20260926T180007Z`; summary:
  `../results/noaction_pilot_20260926T180007Z/`.

The baseline pilot passed all 60 application exchanges and packet-pair checks,
with no reported capture drops or flagged TCP retransmissions. D4 median
response-minus-ACK gaps were 3.999--4.000 ms for all three operations. This is a
functional pilot, not a full equivalence test. The inherited retransmission and
native-arrival limitations remain.

## Control-plane lifecycle and telemetry acceptance

BFRT binding is exclusive on this switch. Install and read back all configuration
before starting the listener; wait for its ready event before traffic; wait for
its complete records and stream teardown before the next BFRT configuration.
All listener and setter exit paths now close their stream. An initial diagnostic
omitted listener teardown and blocked the next configuration; it was stopped and
the original configuration restored. Its partial acquisition is preserved and
excluded from the completed baseline pilot.

Use the existing authorization gate and guarded runner. An accepted randomized
block requires one matching digest per captured request, including both safety
polls, no duplicates or missing records, and exact selected-value agreement with
the installed table. Capture-derived timings, configured offsets and observed
selected offsets are distinct evidence. No randomized protection claim is
supported by compilation, the baseline pilot or the listener-ready event alone.

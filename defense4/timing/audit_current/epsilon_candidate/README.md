# Epsilon candidate: a patch, not a build

`epsilon_candidate.patch` applies to the frozen P4 and nothing else is modified. It is
**uncompiled and unverified**, and it has not been loaded.

| | sha256 |
|---|---|
| base, `implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4` | `7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861` |
| candidate after applying | `dacd80021a879cfaa6cdfbe57bc3413880028a022540dae26740a1a3c6931cfa` |
| the patch itself | `8633811c24d6729202c4111cbe185766a92b9d6bb528c9b1524153d584369676` |

Verified here only in the one way it can be offline: applying the patch to the base reproduces
the candidate byte for byte.

## What it adds, and why it is this small

Three registers, each indexed by lane, 0 for the ACK lane and 1 for the RESPONSE lane:

* `reg_ep_expiry_first[slot]` — write-if-zero, so the first token to observe its deadline passed
  wins and later tokens cannot overwrite it;
* `reg_ep_block_last[slot]` — write-always, so the last blocking action wins;
* `reg_ep_valid[slot]` — a flag, so a missing measurement reads as invalid rather than as an
  elapsed time of zero.

`epsilon = reg_ep_block_last - deadline` and `detection = reg_ep_expiry_first - deadline`, both
modular on 32-bit nanoseconds; a difference above the half-range means the clock wrapped and the
sample is discarded rather than reported.

**No new predicate is introduced.** `meta.expired` and `meta.expired_resp` already mark the two
lanes' expiry, so the writes ride the existing `mark_expired` and `mark_expired_resp` actions.
Because each of those actions *is* one lane, the register index is a compile-time constant, which
also avoids narrowing `hdr.ibspg.slot` at runtime.

The lanes are indexed rather than pooled because they share dp8 and one priority scheduler. A
single dp8 counter sums them, which is why the 2026-09-15 blocker figures could not separate them.

## What it still cannot answer

The held packet's actual departure. Ingress sees a packet arrive, not leave, and this program has
no egress-side timestamp register, so epsilon here ends at the last blocking action rather than at
the wire. Anything beyond that needs egress instrumentation, which is a larger change.

## The expected failure

The program already occupies all twelve ingress match-action stages. Three registers with their
stateful ALUs, two of them on the blocker path, may not fit. That is a compile-time failure and a
real result: it would mean epsilon cannot be measured this way on this program without
restructuring it.

`bf-p4c` exists only on the switch, which this work does not access; `/usr/bin/p4c` here is the
open-source compiler and cannot target Tofino. The procedure, the required evidence and the
failure criteria are in `../EPSILON_MEASUREMENT_PLAN.md`.

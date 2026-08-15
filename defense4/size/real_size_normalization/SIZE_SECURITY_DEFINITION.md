# Size Security Definition

Gate: S0

Status: reviewed S0 definition
Authority: `defense4/CODEX_NEXT_PHASE_REAL_SIZE_NORMALIZATION.md`

## Result being sought

Defense 4 will call a new mechanism **real size normalization** only when a passive, protocol-aware observer on the declared protected link cannot distinguish protected inner DNP3 lengths from the outer size transcript within a declared policy domain.

This is a new claim and requires new evidence. The frozen `[49] -> [28,21]` result is not evidence for this property.

## Policy domains

### RN-L: length hiding conditioned on transaction class

`m1` and `m2` are protected instances of the same declared request/transaction class but may carry different inner lengths. The observer may know the class. Outer packet sizes, packet counts, direction sequence, and policy slots must not reveal the inner length.

This is the minimum domain for **PASS: real size normalization**. It supports a length-independent-transcript claim, not a claim that the DNP3 function or transaction class is hidden. An RN-L evaluation domain must contain at least two distinct inner lengths; the already constant 49-byte workload alone would be vacuous.

### RN-T: complete protected-transaction concealment

`m1` and `m2` may differ in inner length and protected transaction class. The full request/ACK/response outer schedule is identical or computationally indistinguishable, including unused encrypted cover cells.

Only RN-T supports transaction-class concealment. S0 does not assume the current testbed can meet RN-T; S2 must select and justify the supported domain.

## Observer-visible transcript

For protected epoch `e`, define:

\[
\mathsf{ObsSize}_e = \left[(d_i,w_i,s_i,f_i,a_i,r_i)\right]_{i=1}^{n_e}
\]

where:

- `d_i` is direction;
- `w_i` is complete captured wire length under one declared convention;
- `s_i` is the policy slot or timestamp offset from the public epoch start;
- `f_i` is the outer flow identifier and visible protocol metadata;
- `a_i` is acknowledgment or sequence behavior, if visible;
- `r_i` marks fragmentation, duplication, retransmission, or recovery behavior.

Payload content is excluded from `ObsSize` only when protected by a reviewed authenticated-encryption construction. A clear inner length, type, final-cell marker, padding boundary, or distinguishable cover flag is a failure even if packet sizes are fixed.

## Required property

For any `m1,m2` in the selected domain `D`, using the same public policy parameters and exogenous network-loss schedule:

\[
\mathsf{ObsSize}(\mathsf{Protect}(m_1))
\equiv
\mathsf{ObsSize}(\mathsf{Protect}(m_2)).
\]

The preferred deterministic construction makes sizes, counts, directions, and slots exactly equal. Randomized authenticated encryption makes cell contents computationally indistinguishable.

The empirical target is:

\[
I(L;\mathsf{ObsSize}) \approx 0.
\]

This must be supported by permutation-calibrated mutual information and a transaction-disjoint classifier whose balanced-accuracy confidence interval includes chance. Statistical non-detection alone is insufficient; the mechanism must enforce fixed sizes and counts by construction.

## Construction obligations

A conforming design must specify and later verify:

1. exactly `K` fixed-wire-size cells for every protected slot or epoch;
2. authenticated capacity for a declared `L_max`;
3. encrypted inner length, protected type, cell occupancy, final marker, and padding boundary;
4. unique nonces, key separation, replay rejection, ordering, rekeying, and epoch lifecycle;
5. indistinguishable data and cover-cell handling at the observed boundary;
6. length-independent loss, duplication, timeout, and overflow behavior, or a fail-closed escape that invalidates the claim for that epoch;
7. exact inner-byte recovery at both trusted boundaries;
8. no length-dependent serialization or cell-release delay in the protected schedule;
9. no native cleartext bypass across the observed link while protection is active.

`C`, `K_req`, `K_ack`, `K_resp`, and `L_max` remain unset until the actual MTU, overheads, traffic corpus, and compute path are audited.

## What is hidden

Subject to later S3-S7 evidence, the target hides:

- protected inner DNP3 length within the selected domain;
- real bytes versus random padding inside authenticated encrypted cells;
- data cells versus cover cells;
- inner length and final-cell metadata;
- transaction class only if RN-T is selected and verified.

## What is not hidden

The phase does not claim to hide:

- link presence, endpoints, policy identity, cell size, or epoch start;
- the fixed schedule or its bandwidth cost;
- loss or congestion caused outside the shims, except that handling must not depend on inner length;
- traffic volume outside protected epochs or long-term transaction arrival rate unless continuous-rate cover is selected;
- endpoint, key, or trusted-shim compromise;
- denial of service by an active attacker;
- multi-device indistinguishability without at least two devices or stacks;
- transaction class under RN-L.

## Result labels

- **PASS: real size normalization** — fixed outer size and count across multiple protected inner lengths, encrypted length/type metadata, and exact trusted-boundary recovery.
- **PARTIAL: bucketed normalization** — the observer learns a size bucket.
- **SEGMENT SHAPE ONLY** — TCP reassembly or other metadata exposes exact total length.
- **NOT DEMONSTRATED** — required observer-link or trusted-boundary evidence is absent.

## Evidence anchors

- `defense4/CODEX_NEXT_PHASE_REAL_SIZE_NORMALIZATION.md`
- `defense4/README.md`
- `defense4/CLAIMS.md`
- `defense4/size/native_parity/evidence/E_FINAL/`

# Adversarial S0 Impossibility Review

Status: reviewed
Verdict: **sound with explicit boundary conditions**

## Proof assessment

The one-sided impossibility claim holds for the declared observer when the master and relay remain unmodified, the observer sees the same master-side stream, and no trusted depadding or decapsulation boundary exists before endpoint delivery.

For a response byte stream `B(m)`, a TCP-aware observer counts the union of new in-window TCP sequence intervals. Retransmissions do not increase this union. Endpoint transparency requires the unmodified master to receive exactly `B(m)`, so the observed novel-byte count is `|B(m)|`. Different true lengths therefore remain distinguishable under any resegmentation.

## Required wording constraints

- State that the observer can also use ACK progression when both directions are visible.
- Do not call a policy containing only one fixed 49-byte workload general size hiding.
- Separate response-length hiding conditioned on a known transaction from transaction-class concealment.
- Apply computational indistinguishability only after length, type, occupancy, final markers, and padding boundaries are encrypted.
- Keep multi-device indistinguishability outside the claim because the frozen evidence contains one SEL-751.
- Require fail-closed behavior and prohibit a native cleartext bypass on the observed link.

## Counterexample review

| Candidate | Result |
| --- | --- |
| Segmentation, IP fragmentation, Ethernet padding, TCP options | Rejected; total accepted application bytes remain derivable. |
| Invalid, out-of-window, or retransmitted chaff | Rejected; the protocol-aware observer filters or de-duplicates it. |
| Cover on another flow | Rejected; it is separable from the protected flow. |
| Clear DNP3 padding | Rejected; the structure and removal boundary remain visible or unavailable. |
| Ordinary TLS, WireGuard, or IPsec without fixed records | Insufficient; encrypted packet length remains correlated with plaintext length. |
| Fixed-count encrypted cover cells | Conditionally valid only with two trusted endpoints, fixed schedule, encrypted metadata, and safe failure. |

## S2 blocker raised by the critic

The presence of the Tofino onboard CPU and `ens1` does not establish the second trusted boundary. S1 must verify an endpoint-transparent CPU-port punt/reinject path and S2 must make it a hard prerequisite. If current hardware cannot supply that path, the result is **impossible under the current testbed constraint**.

## Evidence anchors

- `defense4/CODEX_NEXT_PHASE_REAL_SIZE_NORMALIZATION.md`
- `defense4/CLAIMS.md`
- `defense4/size/native_parity/evidence/E_FINAL/scripts/size_reconstruct.py`
- `defense4/size/real_size_normalization/ONE_SIDED_IMPOSSIBILITY.md`
